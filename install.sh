#!/bin/sh
# Install (or update) the analyzer network settings page. Run on the analyzer as root:
#   sudo sh install.sh
set -e
here="$(cd "$(dirname "$0")" && pwd)"
install -d -m 755 /opt/harogic-netconfig
install -m 755 "$here/netconfig.py" /opt/harogic-netconfig/netconfig.py
install -m 644 "$here/harogic-netconfig.service" /etc/systemd/system/harogic-netconfig.service
install -d -m 700 /var/lib/harogic-netconfig
systemctl daemon-reload
systemctl enable harogic-netconfig.service >/dev/null 2>&1
systemctl restart harogic-netconfig.service
sleep 2
if systemctl is-active --quiet harogic-netconfig.service; then
    echo "Installed and running. Open http://$(hostname -I | awk '{print $1}'):8080/ (or http://<name>.local:8080/)."
    [ -f /var/lib/harogic-netconfig/auth.json ] || echo "First visit: you will be asked to set the page password."
else
    echo "The service did not start:"; journalctl -u harogic-netconfig.service -n 20 --no-pager
    exit 1
fi
