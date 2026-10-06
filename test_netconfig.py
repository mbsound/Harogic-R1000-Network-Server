"""
Tests for netconfig.py, off the analyzer: a copy of ip.config, Net.sh never run.
Run: python3 test_netconfig.py
"""
import base64
import html
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

AVAHI = """[server]
host-name=67-example
use-ipv4=yes
use-ipv6=yes

[wide-area]
enable-wide-area=yes

[publish]
publish-workstation=yes
"""
HERE = os.path.dirname(os.path.abspath(__file__))
ORIGINAL = {"dhcp_enabled": True, "static_cidr": "192.168.1.100/24", "static_gateway_enabled": False,
            "static_gateway_address": "192.168.1.1", "dns": [], "dhcp_probe_interval_seconds": 12,
            "dhcp_probe_fail_max": 5, "dhcp_wait_seconds": 8, "nmcli_up_timeout_seconds": 3}


def start(tmp, port, confirm_s=3):
    env = dict(os.environ, NETCONFIG_IP_CONFIG=os.path.join(tmp, "ip.config"), NETCONFIG_STATE_DIR=os.path.join(tmp, "state"),
               NETCONFIG_PORT=str(port), NETCONFIG_DRY_RUN="1", NETCONFIG_CONFIRM_SECONDS=str(confirm_s),
               NETCONFIG_APPLY_DELAY="0.2", NETCONFIG_DEVICE_ID=os.path.join(tmp, "device_id.conf"), NETCONFIG_IFACE="lo0",
               NETCONFIG_AVAHI_CONF=os.path.join(tmp, "avahi-daemon.conf"), NETCONFIG_RELAY="")
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "netconfig.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=1)
            break
        except urllib.error.HTTPError:
            break
        except OSError:
            time.sleep(0.1)
    return p


def get(port, password=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/")
    if password is not None:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"x:{password}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, html.unescape(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, html.unescape(e.read().decode())


def post(port, path, fields, password=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=urllib.parse.urlencode(fields).encode())
    if password is not None:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"x:{password}".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, html.unescape(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, html.unescape(e.read().decode())


def token(body):
    return re.search(r"name=t value=([\w-]+)", body).group(1)


def config(tmp):
    with open(os.path.join(tmp, "ip.config")) as f:
        return json.load(f)


def main():
    tmp = tempfile.mkdtemp()
    with open(os.path.join(tmp, "ip.config"), "w") as f:
        json.dump(ORIGINAL, f, indent=2)
    with open(os.path.join(tmp, "device_id.conf"), "w") as f:
        f.write("67-example\n")
    with open(os.path.join(tmp, "avahi-daemon.conf"), "w") as f:
        f.write(AVAHI)
    port = 18080
    srv = start(tmp, port)
    try:
        # First visit: set a password, no access before that
        code, body = get(port)
        assert code == 200 and "Set a password" in body, code
        t = token(body)
        assert "too short" not in post(port, "/setup", {"t": t, "p1": "short", "p2": "short"})[1]
        assert "At least 8" in post(port, "/setup", {"t": t, "p1": "short", "p2": "short"})[1]
        assert "differ" in post(port, "/setup", {"t": t, "p1": "goodpass1", "p2": "goodpass2"})[1]
        code, _ = post(port, "/setup", {"t": t, "p1": "goodpass1", "p2": "goodpass1"})
        assert code == 401, code          # redirected to the page, which now wants the password
        assert post(port, "/setup", {"t": t, "p1": "other123", "p2": "other123"})[0] == 403, "setup only once"
        print("ok  password set on first visit, only once")

        # Password needed from now on; a wrong one is refused
        assert get(port)[0] == 401
        assert get(port, "wrongpass")[0] == 401
        code, body = get(port, "goodpass1")
        assert code == 200 and "Analyzer network" in body and "67-example" in body
        assert 'value="192.168.1.100"' in body and "checked" in body
        print("ok  password required; page shows the current setting")

        # A form without the page's token is refused (another site posting with the saved password)
        assert post(port, "/apply", {"mode": "static", "ip": "192.168.1.101", "prefix": "24"}, "goodpass1")[0] == 400
        # Bad input is refused and nothing is written
        bad = [({"ip": "192.168.1.300", "prefix": "24"}, "four numbers"),
               ({"ip": "192.168.1.0", "prefix": "24"}, "network's own"),
               ({"ip": "192.168.1.255", "prefix": "24"}, "broadcast"),
               ({"ip": "127.0.0.5", "prefix": "24"}, "cannot be used"),
               ({"ip": "192.168.1.101", "prefix": "33"}, "8 to 30"),
               ({"ip": "192.168.1.101", "prefix": "24", "gateway": "10.0.0.1"}, "not on the analyzer"),
               ({"ip": "192.168.1.101", "prefix": "24", "dns": "8.8.8"}, "not an address"),
               ({"ip": "192.168.1.100", "prefix": "24", "mode": "dhcp"}, "already has")]
        for fields, expect in bad:
            f = {"t": t, "mode": "static", **fields}
            code, body = post(port, "/apply", f, "goodpass1")
            assert code == 200 and expect in body, (fields, expect)
        assert config(tmp) == ORIGINAL
        print("ok  bad input refused, nothing written")

        # A good change is written in Harogic's format, other keys kept
        code, body = post(port, "/apply", {"t": t, "mode": "static", "ip": "192.168.1.101", "prefix": "24",
                                           "gateway": "192.168.1.1", "dns": "192.168.1.1, 8.8.8.8"}, "goodpass1")
        assert code == 200 and "192.168.1.101:18080" in body
        c = config(tmp)
        assert c["dhcp_enabled"] is False and c["static_cidr"] == "192.168.1.101/24"
        assert c["static_gateway_enabled"] is True and c["static_gateway_address"] == "192.168.1.1"
        assert c["dns"] == ["192.168.1.1", "8.8.8.8"] and c["dhcp_probe_interval_seconds"] == 12
        assert "waiting for confirmation" in get(port, "goodpass1")[1]
        # ... not kept in time: it goes back by itself
        time.sleep(4.5)
        assert config(tmp) == ORIGINAL, config(tmp)
        assert "waiting for confirmation" not in get(port, "goodpass1")[1]
        print("ok  unconfirmed change goes back by itself")

        # Kept: stays
        post(port, "/apply", {"t": t, "mode": "dhcp", "ip": "192.168.50.20", "prefix": "24"}, "goodpass1")
        assert post(port, "/confirm", {"t": t}, "goodpass1")[0] == 200
        time.sleep(4.5)
        c = config(tmp)
        assert c["dhcp_enabled"] is True and c["static_cidr"] == "192.168.50.20/24" and c["static_gateway_enabled"] is False
        print("ok  confirmed change stays (DHCP with a fallback address)")

        # Undo now
        post(port, "/apply", {"t": t, "mode": "static", "ip": "10.0.0.5", "prefix": "8"}, "goodpass1")
        post(port, "/revert", {"t": t}, "goodpass1")
        time.sleep(0.5)
        assert config(tmp)["static_cidr"] == "192.168.50.20/24"
        print("ok  undo returns to the last kept setting")

        # The name on the network: only avahi's host-name changes, the rest of its file stays
        avahi = os.path.join(tmp, "avahi-daemon.conf")
        for bad_name in ("has space", "-lead", "under_score", "a.b", "x" * 64):
            assert "1 to 63 letters" in post(port, "/rename", {"t": t, "name": bad_name}, "goodpass1")[1], bad_name
        assert open(avahi).read() == AVAHI
        code, body = post(port, "/rename", {"t": t, "name": "FOH-Analyzer.local"}, "goodpass1")
        assert code == 200 and "http://FOH-Analyzer.local:18080/" in body, body[-400:]
        text = open(avahi).read()
        assert "host-name=FOH-Analyzer\n" in text and text.count("host-name") == 1
        assert text.replace("host-name=FOH-Analyzer", "host-name=67-example") == AVAHI, text
        assert os.path.exists(avahi + ".netconfig-orig")
        assert 'value="FOH-Analyzer"' in get(port, "goodpass1")[1]
        assert "already has" in post(port, "/rename", {"t": t, "name": "FOH-Analyzer"}, "goodpass1")[1]
        post(port, "/rename", {"t": t, "name": "", "factory": "1"}, "goodpass1")
        assert open(avahi).read() == AVAHI
        print("ok  network name set, refused when invalid, factory name restored")

        # What the unit is, without the password, on IPv4 and IPv6
        info = json.loads(urllib.request.urlopen(f"http://127.0.0.1:{port}/harogic-info", timeout=5).read())
        assert info["harogic"] is True and info["device_id"] == "67-example" and info["name"] == "67-example"
        info6 = json.loads(urllib.request.urlopen(f"http://[::1]:{port}/harogic-info", timeout=5).read())
        assert info6 == info
        print("ok  /harogic-info on IPv4 and IPv6")

        # A restart with a change never confirmed puts the last kept one back
        post(port, "/apply", {"t": t, "mode": "static", "ip": "10.0.0.6", "prefix": "8"}, "goodpass1")
        srv.terminate(); srv.wait()
        srv = start(tmp, port, confirm_s=60)
        time.sleep(1.0)
        assert config(tmp)["static_cidr"] == "192.168.50.20/24", config(tmp)
        print("ok  restart before confirming goes back")
    finally:
        srv.terminate()
        srv.wait()
        out = srv.stdout.read().decode()
    print("log tail:", " | ".join(out.strip().splitlines()[-3:]))
    print("All netconfig tests passed.")


def test_relay():
    """IPv6 connections on the relay port reach an IPv4-only server, both ways, intact."""
    import socket, threading, random
    sys.path.insert(0, HERE)
    import netconfig
    echo = socket.socket(); echo.bind(("127.0.0.1", 0)); echo.listen(4)
    eport = echo.getsockname()[1]
    def serve():
        c, _ = echo.accept()
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
        c.close()
    threading.Thread(target=serve, daemon=True).start()
    rport = random.randint(20000, 30000)
    srvs = netconfig.start_relays(f"{rport}=127.0.0.1:{eport}")
    assert srvs, "relay started"
    c = socket.create_connection(("::1", rport), timeout=5)
    blob = os.urandom(3_000_000)
    got = bytearray()
    def reader():
        while len(got) < len(blob):
            d = c.recv(262144)
            if not d: break
            got.extend(d)
    t = threading.Thread(target=reader); t.start()
    t0 = time.monotonic(); c.sendall(blob); t.join(10)
    assert bytes(got) == blob
    print(f"ok  relay: 3 MB through and back intact ({3 / (time.monotonic() - t0):.0f} MB/s on this machine)")
    c.close()
    for s in srvs: s.close()


if __name__ == "__main__":
    main()
    test_relay()
    print("All netconfig tests passed (relay included).")
