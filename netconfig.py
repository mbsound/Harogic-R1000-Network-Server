#!/usr/bin/env python3
"""
netconfig.py - A small web page on a Harogic network analyzer for setting its address.

The analyzer (a Raspberry Pi inside) keeps its network setting in an ip.config file and
applies it with Harogic's own Net.sh: DHCP first if enabled, else (or if no DHCP server
answers) the static address. This page edits that same file and runs Net.sh the way
Harogic's restart script does, so the setting is the unit's own and survives a reboot.

It also sets the unit's name on the network (the "<name>.local" it answers to), which lives
in avahi's own configuration; the device ID Harogic's software uses is left alone.

Reaching it from any subnet: every computer and the analyzer have an IPv6 link-local
address on the cable whatever their IPv4 settings, and mDNS gives it with the name. Harogic's
SDK server listens on IPv4 only, so this service relays IPv6 connections on its port to it
(RELAY), and answers on IPv6 itself. fReqon uses that when the analyzer's IPv4 address is not
on any of the computer's networks. GET /harogic-info (no password) says what the unit is.

Safety: a change that leaves the page unreachable undoes itself. After an address change
the new address has to be opened and "Keep" pressed within CONFIRM_SECONDS, or the previous
setting is put back.

Standard library only (Python 3.9+). Runs as root (Net.sh must), from a systemd unit.
Settings for testing come from environment variables (see the CONFIG section).
"""

import hashlib
import re
import hmac
import html
import ipaddress
import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
from base64 import b64decode
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

# --- CONFIG (environment overrides are for testing off the analyzer) -------------------
IFACE = os.environ.get("NETCONFIG_IFACE", "eth0")
IP_CONFIG = os.environ.get("NETCONFIG_IP_CONFIG", "/home/htra/.config/ip.config")
NET_SH = os.environ.get("NETCONFIG_NET_SH", "/opt/Function/Net/Net.sh")
DEVICE_ID_FILE = os.environ.get("NETCONFIG_DEVICE_ID", "/etc/device/device_id.conf")
AVAHI_CONF = os.environ.get("NETCONFIG_AVAHI_CONF", "/etc/avahi/avahi-daemon.conf")
STATE_DIR = os.environ.get("NETCONFIG_STATE_DIR", "/var/lib/harogic-netconfig")
PORT = int(os.environ.get("NETCONFIG_PORT", "8080"))
DRY_RUN = os.environ.get("NETCONFIG_DRY_RUN") == "1"     # never run Net.sh or touch the interface
CONFIRM_SECONDS = int(os.environ.get("NETCONFIG_CONFIRM_SECONDS", "120"))
APPLY_DELAY_S = float(os.environ.get("NETCONFIG_APPLY_DELAY", "2"))   # the answer reaches the browser first
OWNER = os.environ.get("NETCONFIG_OWNER", "htra")        # ip.config belongs to this user
# IPv6 port -> IPv4 address:port it is relayed to ("" for none)
RELAY = os.environ.get("NETCONFIG_RELAY", "5000=127.0.0.1:5000")

AUTH_FILE = os.path.join(STATE_DIR, "auth.json")
PREV_FILE = os.path.join(STATE_DIR, "previous-ip.config")
PENDING_FILE = os.path.join(STATE_DIR, "pending.json")
LOG_FILE = os.path.join(STATE_DIR, "netconfig.log")

DEFAULTS = {"dhcp_enabled": True, "static_cidr": "192.168.1.100/24", "static_gateway_enabled": False,
            "static_gateway_address": "192.168.1.1", "dns": [], "dhcp_probe_interval_seconds": 12,
            "dhcp_probe_fail_max": 5, "dhcp_wait_seconds": 8, "nmcli_up_timeout_seconds": 3}

_lock = threading.Lock()          # one change at a time
CSRF_TOKEN = secrets.token_urlsafe(24)


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


# --- The unit's setting ----------------------------------------------------------------
def read_config():
    try:
        with open(IP_CONFIG) as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError("not an object")
    except (OSError, ValueError):
        cfg = {}
    return {**DEFAULTS, **cfg}


def write_config(cfg):
    """Write ip.config the way Net.sh reads it (atomically, owned as before)."""
    os.makedirs(os.path.dirname(IP_CONFIG), exist_ok=True)
    tmp = IP_CONFIG + ".netconfig.tmp"
    with open(tmp, "w") as f:
        json.dump(cfg, f, indent=2)
        f.write("\n")
    try:
        shutil.chown(tmp, OWNER, OWNER)
    except (LookupError, PermissionError, OSError):
        pass
    os.replace(tmp, IP_CONFIG)


def device_id():
    try:
        with open(DEVICE_ID_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line.split("=", 1)[-1].strip().strip('"')
    except OSError:
        pass
    return socket.gethostname()


# --- The name on the network ---------------------------------------------------------------
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def mdns_name():
    """The name the unit answers to as <name>.local (avahi's host-name), else its device ID."""
    try:
        section = ""
        with open(AVAHI_CONF) as f:
            for line in f:
                s = line.strip()
                if s.startswith("["):
                    section = s
                elif section == "[server]" and s.startswith("host-name=") and not s.startswith("#"):
                    return s.split("=", 1)[1].strip() or device_id()
    except OSError:
        pass
    return device_id()


def check_name(name):
    """(the name to use, error or None). A trailing ".local" is dropped."""
    name = name.strip()
    if name.lower().endswith(".local"):
        name = name[:-6]
    if not NAME_RE.match(name):
        return name, ("A name is 1 to 63 letters, digits and hyphens, not starting or ending with a hyphen "
                      "(no spaces, dots or underscores).")
    return name, None


def set_mdns_name(name):
    """Put host-name=<name> in avahi's [server] section (the rest of the file as it was), restart avahi."""
    with open(AVAHI_CONF) as f:
        lines = f.read().splitlines()
    backup = AVAHI_CONF + ".netconfig-orig"
    if not os.path.exists(backup):
        shutil.copy2(AVAHI_CONF, backup)
    out, section, done, server_at = [], "", False, None
    for line in lines:
        s = line.strip()
        if s.startswith("["):
            if section == "[server]" and not done:
                out.append(f"host-name={name}")      # [server] had none: add it at its end
                done = True
            section = s
            if s == "[server]":
                server_at = len(out)
        if section == "[server]" and re.match(r"^#?\s*host-name\s*=", s):
            if not done:
                out.append(f"host-name={name}")
                done = True
            continue
        out.append(line)
    if not done:
        if server_at is None:
            out = ["[server]", f"host-name={name}", ""] + out
        else:
            out.append(f"host-name={name}")
    tmp = AVAHI_CONF + ".netconfig.tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, AVAHI_CONF)
    log(f"network name set to {name}.local")
    if not DRY_RUN:
        subprocess.run(["systemctl", "restart", "avahi-daemon"], capture_output=True, timeout=30)


def run_net_sh():
    """Apply ip.config with Harogic's Net.sh, as their restart script does, then refresh mDNS."""
    if DRY_RUN:
        log("dry run: Net.sh not run")
        return 0
    rc = 1
    for _attempt in range(5):           # Net.sh exits at once if another run holds its lock
        try:
            p = subprocess.run(["sh", NET_SH, IFACE, device_id(), IP_CONFIG], capture_output=True, text=True, timeout=90)
            rc = p.returncode
            out = (p.stdout + p.stderr).strip().splitlines()
            log(f"Net.sh rc={rc}: " + " | ".join(l for l in out if "Final mode" in l or "Error" in l or "already" in l))
            if not any("already handling" in l for l in out):
                break
        except (OSError, subprocess.TimeoutExpired) as e:
            log(f"Net.sh failed: {e}")
        time.sleep(3)
    subprocess.run(["systemctl", "restart", "avahi-daemon"], capture_output=True, timeout=30)
    return rc


def live_status():
    """What the interface has now: address, how it got it, gateway, MAC."""
    st = {"iface": IFACE, "addresses": [], "dhcp": False, "gateway": "", "mac": "", "hostname": mdns_name()}
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show", "dev", IFACE], capture_output=True, text=True, timeout=5).stdout
        for line in out.splitlines():
            parts = line.split()
            if "inet" in parts:
                st["addresses"].append(parts[parts.index("inet") + 1])
                st["dhcp"] |= "dynamic" in parts
        out = subprocess.run(["ip", "-4", "route", "show", "default", "dev", IFACE], capture_output=True, text=True, timeout=5).stdout
        if out.split()[:3] and out.split()[0] == "default":
            st["gateway"] = out.split()[2]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        pass
    try:
        with open(f"/sys/class/net/{IFACE}/address") as f:
            st["mac"] = f.read().strip()
    except OSError:
        pass
    return st


# --- Checking what was typed -----------------------------------------------------------
def parse_form(form, current):
    """(new ip.config, [errors]) from the submitted form."""
    errors = []
    mode = form.get("mode", "static")
    ip_s, prefix_s = form.get("ip", "").strip(), form.get("prefix", "").strip()
    gw_s, dns_s = form.get("gateway", "").strip(), form.get("dns", "").strip()
    try:
        prefix = int(prefix_s)
        if not 8 <= prefix <= 30:
            raise ValueError
    except ValueError:
        errors.append("Subnet prefix must be a number from 8 to 30 (24 is 255.255.255.0).")
        prefix = None
    try:
        ip = ipaddress.IPv4Address(ip_s)
        if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
            errors.append(f"{ip} cannot be used as the analyzer's address.")
    except ValueError:
        errors.append("The address must be four numbers separated by dots, e.g. 192.168.1.101.")
        ip = None
    net = None
    if ip is not None and prefix is not None:
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        if ip in (net.network_address, net.broadcast_address):
            errors.append(f"{ip} is the network's {'own' if ip == net.network_address else 'broadcast'} address; pick another.")
    gw = None
    if gw_s:
        try:
            gw = ipaddress.IPv4Address(gw_s)
            if net is not None and gw not in net:
                errors.append(f"The gateway {gw} is not on the analyzer's network ({net}).")
            if gw == ip:
                errors.append("The gateway cannot be the analyzer's own address.")
        except ValueError:
            errors.append("The gateway must be an address like 192.168.1.1, or left empty.")
    dns = []
    for item in dns_s.replace(",", " ").split():
        try:
            dns.append(str(ipaddress.IPv4Address(item)))
        except ValueError:
            errors.append(f"DNS server '{item}' is not an address.")
    new = dict(current)
    new.update({"dhcp_enabled": mode == "dhcp",
                "static_cidr": f"{ip}/{prefix}" if ip is not None and prefix is not None else current.get("static_cidr"),
                "static_gateway_enabled": gw is not None,
                "static_gateway_address": str(gw) if gw is not None else current.get("static_gateway_address", "192.168.1.1"),
                "dns": dns})
    return new, errors


# --- Pending change and its automatic undo ---------------------------------------------
def pending():
    try:
        with open(PENDING_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def apply_change(new_cfg):
    with _lock:
        os.makedirs(STATE_DIR, exist_ok=True)
        prev_text = open(IP_CONFIG).read() if os.path.exists(IP_CONFIG) else json.dumps(DEFAULTS, indent=2)
        if not pending():                       # keep the last setting known to work, not a half-tried one
            with open(PREV_FILE, "w") as f:
                f.write(prev_text)
        write_config(new_cfg)
        p = {"deadline": time.time() + CONFIRM_SECONDS + APPLY_DELAY_S, "config": new_cfg}
        with open(PENDING_FILE, "w") as f:
            json.dump(p, f)
        log(f"change written: dhcp={new_cfg['dhcp_enabled']} static={new_cfg['static_cidr']} "
            f"gateway={new_cfg['static_gateway_address'] if new_cfg['static_gateway_enabled'] else 'none'} dns={new_cfg['dns']}")

    def later():
        time.sleep(APPLY_DELAY_S)
        run_net_sh()
        watch_pending()
    threading.Thread(target=later, daemon=True).start()


def watch_pending():
    """Undo the change if nobody confirms it in time."""
    p = pending()
    while p:
        left = p["deadline"] - time.time()
        if left <= 0:
            revert("not confirmed in time")
            return
        time.sleep(min(left, 2))
        p = pending()


def revert(why):
    with _lock:
        if not pending():
            return
        try:
            with open(PREV_FILE) as f:
                prev = json.load(f)
            write_config(prev)
            log(f"reverted ({why}): back to dhcp={prev.get('dhcp_enabled')} static={prev.get('static_cidr')}")
        except (OSError, ValueError) as e:
            log(f"revert failed, no previous setting: {e}")
        os.remove(PENDING_FILE)
    threading.Thread(target=run_net_sh, daemon=True).start()


def confirm():
    with _lock:
        if pending():
            os.remove(PENDING_FILE)
            log("change kept")


# --- Page password -----------------------------------------------------------------------
def _hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000).hex()


def password_set():
    return os.path.exists(AUTH_FILE)


def set_password(password):
    os.makedirs(STATE_DIR, exist_ok=True)
    salt = secrets.token_bytes(16)
    with open(AUTH_FILE, "w") as f:
        json.dump({"salt": salt.hex(), "hash": _hash(password, salt)}, f)
    os.chmod(AUTH_FILE, 0o600)
    log("page password set")


def check_password(password):
    try:
        with open(AUTH_FILE) as f:
            a = json.load(f)
        return hmac.compare_digest(_hash(password, bytes.fromhex(a["salt"])), a["hash"])
    except (OSError, ValueError, KeyError):
        return False


# --- Pages ---------------------------------------------------------------------------------
CSS = """
:root{--bg:#0d1117;--card:#161b22;--line:#30363d;--text:#e6edf3;--muted:#8b949e;--accent:#38bdf8;--ok:#10b981;--warn:#f59e0b;--bad:#f43f5e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
main{max-width:640px;margin:0 auto;padding:24px 16px}h1{font-size:20px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px}
.card h2{font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);margin:0 0 12px}
dl{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}dt{color:var(--muted)}dd{margin:0;font-family:ui-monospace,Menlo,monospace}
label{display:block;margin:12px 0 4px;color:var(--muted);font-size:13px}
input[type=text],input[type=password]{width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--line);border-radius:6px;color:var(--text);font:14px ui-monospace,Menlo,monospace}
.row{display:flex;gap:12px}.row>div{flex:1}.row>div.narrow{flex:0 0 90px}
.modes{display:flex;gap:8px}.modes label{flex:1;margin:0;padding:10px;border:1px solid var(--line);border-radius:6px;cursor:pointer;color:var(--text);text-align:center}
.modes input{display:none}.modes input:checked+span{color:var(--accent);font-weight:600}.modes label:has(input:checked){border-color:var(--accent)}
button{margin-top:16px;padding:10px 16px;border:0;border-radius:6px;background:#1f6feb;color:#fff;font-size:15px;cursor:pointer}
button.secondary{background:#21262d;border:1px solid var(--line)}.note{color:var(--muted);font-size:13px;margin-top:8px}
.err{background:#3d1d24;border:1px solid var(--bad);border-radius:6px;padding:10px;margin-bottom:12px}.err li{margin-left:-12px}
.banner{border-color:var(--warn)}.banner b{color:var(--warn)}a{color:var(--accent)}code{font-family:ui-monospace,Menlo,monospace}
"""


def page(title, body):
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{CSS}</style></head><body><main>{body}</main></body></html>")


def e(x):
    return html.escape(str(x))


def links_for(cfg, st):
    """Where the page will be after the change."""
    host = f"http://{e(st['hostname'])}.local:{PORT}/"
    if cfg["dhcp_enabled"]:
        return (f"<a href='{host}'>{host}</a> (the network's DHCP server picks the address; if none answers, "
                f"<a href='http://{e(cfg['static_cidr'].split('/')[0])}:{PORT}/'>http://{e(cfg['static_cidr'].split('/')[0])}:{PORT}/</a>)")
    ip = cfg["static_cidr"].split("/")[0]
    return f"<a href='http://{e(ip)}:{PORT}/'>http://{e(ip)}:{PORT}/</a> or <a href='{host}'>{host}</a>"


def main_page(errors=(), form=None, notice="", name_value=None):
    cfg, st, p = read_config(), live_status(), pending()
    ip, prefix = cfg["static_cidr"].split("/")
    gw = cfg["static_gateway_address"] if cfg["static_gateway_enabled"] else ""
    dns = " ".join(cfg.get("dns") or [])
    mode = "dhcp" if cfg["dhcp_enabled"] else "static"
    if form:
        mode, ip, prefix, gw, dns = (form.get("mode", mode), form.get("ip", ip), form.get("prefix", prefix),
                                     form.get("gateway", gw), form.get("dns", dns))
    body = [f"<h1>Analyzer network</h1><p class=sub>{e(st['hostname'])} &middot; MAC {e(st['mac'] or '?')}</p>"]
    if p:
        left = max(0, int(p["deadline"] - time.time()))
        body.append(f"<div class='card banner'><h2>Change waiting for confirmation</h2><p><b>{left} s left.</b> "
                    f"If this page loaded at the new address, the change works: keep it. Otherwise it goes back "
                    f"to the previous setting by itself.</p><form method=post action=/confirm><input type=hidden name=t value={CSRF_TOKEN}>"
                    f"<button>Keep this setting</button></form><form method=post action=/revert><input type=hidden name=t value={CSRF_TOKEN}>"
                    f"<button class=secondary>Undo now</button></form></div>")
    body.append("<div class=card><h2>Now</h2><dl>"
                f"<dt>Address</dt><dd>{e(', '.join(st['addresses']) or 'none')}</dd>"
                f"<dt>Obtained by</dt><dd>{'DHCP' if st['dhcp'] else 'static setting'}</dd>"
                f"<dt>Gateway</dt><dd>{e(st['gateway'] or 'none')}</dd>"
                f"<dt>Name</dt><dd>{e(st['hostname'])}.local</dd></dl></div>")
    if errors:
        body.append("<div class=err><b>Not changed:</b><ul>" + "".join(f"<li>{e(x)}</li>" for x in errors) + "</ul></div>")
    if notice:
        body.append(f"<div class='card banner'>{notice}</div>")
    chk = lambda m: "checked" if mode == m else ""
    body.append(f"""<form class=card method=post action=/apply><h2>Setting</h2><input type=hidden name=t value={CSRF_TOKEN}>
<div class=modes><label><input type=radio name=mode value=static {chk('static')} onchange=sync()><span>Static</span></label>
<label><input type=radio name=mode value=dhcp {chk('dhcp')} onchange=sync()><span>DHCP</span></label></div>
<p class=note id=modenote></p>
<div class=row><div><label for=ip id=iplabel>Address</label><input type=text id=ip name=ip value="{e(ip)}" required></div>
<div class=narrow><label for=prefix>Prefix</label><input type=text id=prefix name=prefix value="{e(prefix)}" required></div></div>
<label for=gateway>Gateway (optional)</label><input type=text id=gateway name=gateway value="{e(gw)}" placeholder="none: the analyzer is only reached on this network">
<label for=dns>DNS servers (optional)</label><input type=text id=dns name=dns value="{e(dns)}" placeholder="e.g. 192.168.1.1 8.8.8.8">
<button>Apply</button>
<p class=note>Prefix 24 means 255.255.255.0. After Apply, open the analyzer at its new address and press <b>Keep</b>
within {CONFIRM_SECONDS // 60} minutes; if that does not happen, it returns to the current setting by itself.</p></form>
<form class=card method=post action=/rename><h2>Name on the network</h2><input type=hidden name=t value={CSRF_TOKEN}>
<label for=name>Name (reached as <code>name.local</code>)</label><input type=text id=name name=name value="{e(name_value if name_value is not None else st['hostname'])}" required>
<button>Save name</button>
<p class=note>Letters, digits and hyphens. Changing it does not change the address, so nothing is lost if the name is not found;
programs that saved the old name (fReqon's Connection dialog, for one) need the new one. Factory name: <code>{e(device_id())}</code>.</p>
<button class=secondary name=factory value=1>Restore factory name</button></form>
<script>function sync(){{var d=document.querySelector('input[value=dhcp]').checked;
document.getElementById('iplabel').textContent=d?'Fallback address (used when no DHCP server answers)':'Address';
document.getElementById('modenote').textContent=d?'The network\\'s DHCP server assigns the address. If none answers within a few seconds, the analyzer uses the fallback address below, and keeps looking for a DHCP server.':'The analyzer always uses this address.';}}sync();</script>""")
    return page("Analyzer network", "".join(body))


def setup_page(error=""):
    err = f"<div class=err>{e(error)}</div>" if error else ""
    return page("Set a password", f"""<h1>Set a password for this page</h1>
<p class=sub>Anyone who can reach this page with the password can change the analyzer's address. Choose one before handing the unit to anyone else.</p>
{err}<form class=card method=post action=/setup><input type=hidden name=t value={CSRF_TOKEN}>
<label for=p1>Password (at least 8 characters)</label><input type=password id=p1 name=p1 autocomplete=new-password required>
<label for=p2>Again</label><input type=password id=p2 name=p2 autocomplete=new-password required>
<button>Save password</button><p class=note>The user name is ignored; the browser may ask for one, type anything.</p></form>""")


# --- IPv6 relay to Harogic's IPv4-only server --------------------------------------------
def _pump(src, dst):
    try:
        while True:
            data = src.recv(262144)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _relay_conn(client, target):
    try:
        upstream = socket.create_connection(target, timeout=5)
        upstream.settimeout(None)
    except OSError as ex:
        log(f"relay: {target[0]}:{target[1]} refused ({ex})")
        client.close()
        return
    for s in (client, upstream):
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    threading.Thread(target=_pump, args=(client, upstream), daemon=True).start()
    _pump(upstream, client)
    client.close()
    upstream.close()


def start_relays(spec=None):
    """Listen on IPv6 only (Harogic's server keeps the IPv4 side of the port) and relay to it."""
    started = []
    for item in filter(None, (spec if spec is not None else RELAY).split(",")):
        try:
            port_s, target = item.split("=")
            host, tport = target.rsplit(":", 1)
            srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            srv.bind(("::", int(port_s)))
            srv.listen(16)
        except (OSError, ValueError) as ex:
            log(f"relay {item}: not started ({ex})")
            continue

        def serve(srv=srv, target=(host, int(tport))):
            while True:
                try:
                    client, _addr = srv.accept()
                except OSError:
                    return
                threading.Thread(target=_relay_conn, args=(client, target), daemon=True).start()
        threading.Thread(target=serve, daemon=True).start()
        started.append(srv)
        log(f"relay: IPv6 port {port_s} -> {host}:{tport}")
    return started


class DualStackServer(ThreadingHTTPServer):
    """The page on IPv4 and IPv6 alike."""
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


class Handler(BaseHTTPRequestHandler):
    server_version = "harogic-netconfig"

    def log_message(self, fmt, *args):
        pass

    def _send(self, body, code=200, headers=()):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                _user, _, pw = b64decode(h[6:]).decode().partition(":")
                if check_password(pw):
                    return True
            except Exception:
                pass
            time.sleep(1.0)                   # slow down guessing
        self._send(page("Password needed", "<h1>Password needed</h1>"), 401,
                   [("WWW-Authenticate", 'Basic realm="Analyzer network", charset="UTF-8"')])
        return False

    def _form(self):
        n = min(int(self.headers.get("Content-Length") or 0), 10_000)
        raw = self.rfile.read(n).decode(errors="replace")
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def do_GET(self):
        if self.path == "/harogic-info":
            # What this unit is (no password: the factory name broadcasts the same)
            data = json.dumps({"harogic": True, "device_id": device_id(), "name": mdns_name(),
                               "relay": RELAY}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path not in ("/", "/index.html"):
            self._send(page("Not found", "<h1>Not found</h1>"), 404)
            return
        if not password_set():
            self._send(setup_page())
            return
        if self._authorized():
            self._send(main_page())

    def do_POST(self):
        form = self._form()
        if not hmac.compare_digest(form.get("t", ""), CSRF_TOKEN):
            self._send(page("Expired", "<h1>That form has expired</h1><p><a href=/>Reload the page</a> and try again.</p>"), 400)
            return
        if self.path == "/setup":
            if password_set():
                self._send(page("Already set", "<h1>A password is already set</h1><p><a href=/>Go to the page</a></p>"), 403)
            elif len(form.get("p1", "")) < 8:
                self._send(setup_page("At least 8 characters, please."))
            elif form.get("p1") != form.get("p2"):
                self._send(setup_page("The two passwords differ."))
            else:
                set_password(form["p1"])
                self.send_response(303)
                self.send_header("Location", "/")
                self.end_headers()
            return
        if not self._authorized():
            return
        if self.path == "/apply":
            current = read_config()
            new, errors = parse_form(form, current)
            if errors:
                self._send(main_page(errors, form))
                return
            if all(new.get(k) == current.get(k) for k in ("dhcp_enabled", "static_cidr", "static_gateway_enabled",
                                                           "static_gateway_address", "dns")):
                self._send(main_page(["That is the setting it already has."], form))
                return
            apply_change(new)
            self._send(page("Applying", f"""<h1>Applying the new setting</h1>
<div class='card banner'><p>In a few seconds the analyzer moves. Open it at {links_for(new, live_status())}
and press <b>Keep this setting</b> within {CONFIRM_SECONDS // 60} minutes.</p>
<p>If you cannot reach it there, do nothing: after {CONFIRM_SECONDS // 60} minutes it goes back to its previous setting and this page
comes back at the old address. Your computer may also need an address on the new network to reach it.</p></div>"""))
        elif self.path == "/rename":
            name, err = check_name(device_id() if form.get("factory") else form.get("name", ""))
            if err:
                self._send(main_page([err], name_value=form.get("name", "")))
                return
            if name == mdns_name():
                self._send(main_page(["That is the name it already has."]))
                return
            set_mdns_name(name)
            ip = (live_status()["addresses"] or ["?"])[0].split("/")[0]
            self._send(main_page(notice=f"<p>Now reached as <a href='http://{e(name)}.local:{PORT}/'>http://{e(name)}.local:{PORT}/</a> "
                                        f"(and still at <a href='http://{e(ip)}:{PORT}/'>http://{e(ip)}:{PORT}/</a>). "
                                        f"Computers may take a few seconds to find the new name.</p>"))
        elif self.path == "/confirm":
            confirm()
            self._send(page("Kept", "<h1>Setting kept</h1><p>The analyzer keeps this setting from now on, through restarts.</p><p><a href=/>Back</a></p>"))
        elif self.path == "/revert":
            revert("undone from the page")
            self._send(page("Undoing", "<h1>Going back to the previous setting</h1><p>The analyzer returns to its previous address in a few seconds.</p>"))
        else:
            self._send(page("Not found", "<h1>Not found</h1>"), 404)


def main():
    os.makedirs(STATE_DIR, exist_ok=True)
    if pending():
        # Restarted with a change never confirmed (power cut, crash): back to what worked
        threading.Thread(target=lambda: revert("service restarted before the change was confirmed"), daemon=True).start()
    start_relays()
    try:
        srv = DualStackServer(("::", PORT), Handler)
    except OSError:
        srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)     # no IPv6 here: IPv4 only
    log(f"listening on port {PORT} for {IFACE}; config {IP_CONFIG}{' (dry run)' if DRY_RUN else ''}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--reset-password":
        try:
            os.remove(AUTH_FILE)
            print("Page password removed: the next visit to the page sets a new one.")
        except FileNotFoundError:
            print("No page password was set.")
        sys.exit(0)
    main()
