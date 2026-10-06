#!/bin/sh
# Remove the page (the analyzer keeps whatever network setting it has). Run as root.
systemctl disable --now harogic-netconfig.service 2>/dev/null || true
rm -f /etc/systemd/system/harogic-netconfig.service
systemctl daemon-reload
rm -rf /opt/harogic-netconfig /var/lib/harogic-netconfig
echo "Removed."
