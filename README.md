# Harogic R1000 Network Server

A small web page that runs **on** a Harogic network-based analyzer (the R1000: a Raspberry Pi
with a Harogic analyzer module inside, model 067) and lets anyone you give a password to:

- switch the analyzer between **Static** and **DHCP** addressing,
- set its **static address**, prefix, gateway and DNS,
- change the **name** it answers to on the network (`<name>.local`),

from a web browser, without SSH access to the unit. It is meant for owners who rent units
out: the renter gets a page password, never a shell.

It also lets [fReqon](https://github.com/mbsound/fReqon---RF-Analysis-Tool-for-Harogic-Analyzers)
reach the analyzer **by name from any IPv4 subnet** on the same cable or switch (see
[Across subnets](#across-subnets)).

## How it works

The analyzer keeps its network setting in `/home/htra/.config/ip.config` and applies it at
boot with Harogic's own `/opt/Function/Net/Net.sh` (DHCP first if enabled, falling back to the
static address when no DHCP server answers). This page edits that same file and runs `Net.sh`
exactly as Harogic's restart script does, so:

- the setting is the unit's real one and survives reboots,
- Harogic's software and files are not modified.

The `.local` name is avahi's `host-name` in `/etc/avahi/avahi-daemon.conf`. Only that line is
changed (the original file is backed up the first time). The device ID that Harogic's software
uses, `/etc/device/device_id.conf`, and the Linux hostname are left alone. "Restore factory
name" puts the original `<model>-<serial>` name back.

### A bad change undoes itself

After **Apply**, open the analyzer at its new address and press **Keep this setting** within
2 minutes. If nobody does (the new address is unreachable, a typo, wrong subnet), the previous
setting is restored automatically. The same happens if the service restarts before the change
is confirmed. A renaming cannot strand the unit (the address does not change), so it applies
at once.

### Across subnets

Every computer and the analyzer have an IPv6 link-local address (`fe80::…`) on the cable,
whatever their IPv4 settings, and mDNS publishes it with the name. Harogic's SDK server
listens on IPv4 only, so this service also relays IPv6 connections on port 5000 to it and
answers its own page on IPv6. fReqon uses that automatically when the analyzer's IPv4 address
is not on any of the computer's networks. Link-local does not cross routers: same cable or
switch only.

`GET /harogic-info` (no password) returns what the unit is
(`{"harogic": true, "device_id": "67-…", "name": "…"}`), which fReqon's discovery uses to
recognise renamed units. It reveals nothing the factory name does not already broadcast.

## Install

From a computer on the analyzer's network, with this repository checked out (you will be
asked for the analyzer's login password once; the `htra` account has passwordless `sudo`):

```bash
COPYFILE_DISABLE=1 tar --no-xattrs -cz netconfig.py harogic-netconfig.service install.sh uninstall.sh | ssh htra@<analyzer-address> 'rm -rf /tmp/hnc && mkdir -p /tmp/hnc && tar -xzm -C /tmp/hnc && sudo sh /tmp/hnc/install.sh && sudo cp /tmp/hnc/uninstall.sh /opt/harogic-netconfig/'
```

(`COPYFILE_DISABLE` and `--no-xattrs` keep macOS's `._` files out; on Linux they do nothing.)

It installs to `/opt/harogic-netconfig`, runs as the systemd service `harogic-netconfig`
(root, as `Net.sh` requires) and starts at boot. Python 3 from the analyzer's Debian is all it
needs; there are no other dependencies. Running the same command again updates it.

## Use

Open `http://<analyzer-address>/` or `http://<name>.local/` (port 80; port 8080 serves the
same page, and is where fReqon and the SoundBase plugin probe `/harogic-info`).

1. **First visit:** set the page password (8 characters or more). Do this yourself before
   handing the unit to anyone: until it is set, whoever opens the page first chooses it.
2. Sign in (the browser may ask for a user name too: anything works).
3. Choose Static or DHCP, enter the address, Apply, then open the new address and press
   **Keep this setting**. In DHCP mode the address field is the fallback used when no DHCP
   server answers.

From fReqon, the Connection dialog's **Settings page** buttons open it, also from another
subnet.

**Changing the page password:** the *Page password* card at the bottom of the page asks for
the current password and the new one twice; the browser asks for the new one straight away.

## Maintenance (over SSH, on the analyzer)

| Task | Command |
|---|---|
| Forgotten page password | `sudo python3 /opt/harogic-netconfig/netconfig.py --reset-password` (the next visit sets a new one; a known password is changed on the page itself) |
| Serve on other ports | `NETCONFIG_PORT=80,8080` in the service's environment (the first port is the one the page's links use) |
| Service log | `sudo cat /var/lib/harogic-netconfig/netconfig.log` or `journalctl -u harogic-netconfig` |
| Remove it | `sudo sh /opt/harogic-netconfig/uninstall.sh` (the analyzer keeps whatever setting it has) |

## Security notes

- The page is plain HTTP: the page password crosses the local network unencrypted. Fine on a
  show LAN; do not reuse an important password for it.
- Wrong passwords are slowed down, forms carry a per-run token (another website cannot submit
  them with a saved password), and the page refuses invalid addresses, network and broadcast
  addresses, gateways off the subnet and malformed names.
- The page password is stored as a salted PBKDF2 hash in `/var/lib/harogic-netconfig/auth.json`
  (root only).

## Tests

Off the analyzer, against a copy of `ip.config` (nothing is applied, `Net.sh` is never run):

```bash
python3 test_netconfig.py
```

Tested on an R1000 (model 067, firmware 0.55.109, Raspberry Pi Compute Module 5, Debian 12).
Other Harogic network units with the same `/opt/Function` layout should work; others are untested.

## Licence

[CC BY-NC 4.0](LICENSE), as fReqon.
