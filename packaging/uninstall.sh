#!/bin/sh
# Removes xrayop and everything it changed on the router.
#
#     sh uninstall.sh          keep the server list
#     sh uninstall.sh --purge  remove it too
#
# The order matters: firewall rules and the resolver hand-off come out before
# the service does. Stopping the daemon first would leave the LAN redirected to
# a port with nothing behind it, which is the exact failure this project spends
# most of its safety machinery preventing.

set -eu
PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

say() { printf '  %s\n' "$1"; }

echo
echo "Removing xrayop"
echo "==============="
echo

# 1. Firewall and routing.
if nft list table inet xrayop >/dev/null 2>&1; then
    nft delete table inet xrayop 2>/dev/null || true
    say "removed the nftables table"
fi
for fam in -4 -6; do
    while ip $fam rule del fwmark 494 table 494 2>/dev/null; do :; done
done
ip -4 route del local 0.0.0.0/0 dev lo table 494 2>/dev/null || true
ip -6 route del local ::/0 dev lo table 494 2>/dev/null || true
say "removed the policy routing"

# 2. Hand DNS back before dnsmasq is asked to reload for any other reason.
REMOVED_DNS=0
for f in /tmp/dnsmasq.*.d/zz-xrayop.conf /var/dnsmasq.*.d/zz-xrayop.conf; do
    [ -f "$f" ] && { rm -f "$f"; REMOVED_DNS=1; }
done
if [ "$REMOVED_DNS" = 1 ]; then
    /etc/init.d/dnsmasq restart >/dev/null 2>&1 || true
    say "restored dnsmasq to its own upstream resolvers"
fi

# 3. Only now the service.
if [ -f /etc/init.d/xrayop ]; then
    /etc/init.d/xrayop stop 2>/dev/null || true
    /etc/init.d/xrayop disable 2>/dev/null || true
    rm -f /etc/init.d/xrayop
    say "stopped and removed the service"
fi
pkill -f 'xray run -c /var/etc/xrayop' 2>/dev/null || true

rm -f /usr/bin/xrayopd /etc/hotplug.d/iface/99-xrayop
rm -rf /var/etc/xrayop
say "removed the binary, the hotplug hook and the runtime files"

# Leave /etc/sysupgrade.conf tidy.
if [ -f /etc/sysupgrade.conf ]; then
    sed -i '\#^/etc/init.d/xrayop$#d; \#^/etc/hotplug.d/iface/99-xrayop$#d; \#^/etc/xrayop/$#d; \#^/usr/bin/xrayopd$#d' \
        /etc/sysupgrade.conf
    say "cleaned /etc/sysupgrade.conf"
fi

if [ "$PURGE" = 1 ]; then
    rm -rf /etc/xrayop /etc/config/xrayop
    say "removed the server list and settings"
else
    say "kept /etc/xrayop (servers and settings) and /etc/config/xrayop"
    say "  pass --purge to remove those too"
fi

echo
echo "Done. Checking what the router looks like now:"
printf '  nftables tables: '; nft list tables 2>/dev/null | tr '\n' ' '; echo
printf '  DNS resolves:    '; nslookup openwrt.org 2>/dev/null | awk '/^Address/{print $2}' | tail -1
printf '  internet:        '; curl -s --max-time 8 -o /dev/null -w '%{http_code}\n' http://cp.cloudflare.com/generate_204 2>/dev/null || echo "check manually"
