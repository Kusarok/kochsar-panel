#!/bin/sh
# xrayop installer for OpenWrt.
#
# Run it on the router, from the directory this script came in:
#
#     sh install.sh
#
# It refuses rather than half-installs. Every prerequisite is checked first and
# reported together, so a router that cannot run this says so once instead of
# failing somewhere in the middle with the service already enabled.

set -eu

BIN=/usr/bin/xrayopd
STATE_DIR=/etc/xrayop
RUNTIME_DIR=/var/etc/xrayop
here="$(cd "$(dirname "$0")" && pwd)"

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
FAIL=0

echo
echo "xrayop installer"
echo "================"
echo
echo "Checking this router:"

# --- what it is ---
if [ -f /etc/openwrt_release ]; then
    . /etc/openwrt_release
    ok "OpenWrt ${DISTRIB_RELEASE:-?} on ${DISTRIB_TARGET:-?}"
else
    bad "this does not look like OpenWrt"
fi

# --- does the binary match the CPU ---
ARCH="$(uname -m)"
if [ -f "$here/xrayopd" ]; then
    # The binary is static, so the only thing that has to line up is the
    # machine type. A mismatch here fails at exec with a message nobody can
    # act on, so it is worth catching by name.
    case "$ARCH" in
        armv7l|armv6l) EXPECT=ARM ;;
        aarch64)       EXPECT=aarch64 ;;
        mips|mipsel)   EXPECT=MIPS ;;
        x86_64)        EXPECT=x86-64 ;;
        *)             EXPECT="" ;;
    esac
    if [ -n "$EXPECT" ] && command -v file >/dev/null 2>&1; then
        if file "$here/xrayopd" | grep -q "$EXPECT"; then
            ok "binary matches this CPU ($ARCH)"
        else
            bad "binary is not built for $ARCH -- get the right release"
        fi
    else
        ok "CPU is $ARCH"
    fi
else
    bad "xrayopd is missing from $here"
fi

# --- the core ---
XRAY=""
for p in /usr/bin/xray /usr/sbin/xray /usr/bin/xray-core; do
    [ -x "$p" ] && { XRAY="$p"; break; }
done
if [ -n "$XRAY" ]; then
    ok "xray found at $XRAY ($("$XRAY" version 2>/dev/null | head -1 | cut -c1-40))"
else
    bad "xray-core is not installed -- install it first (apk add xray-core, or opkg)"
fi

# --- the kernel modules transparent proxying needs ---
#
# Checked because without them the ruleset loads cleanly and simply never
# works, which is the hardest kind of failure to diagnose.
MISSING_KMOD=""
for m in nft_tproxy nft_socket; do
    if lsmod 2>/dev/null | grep -q "^$m " || modprobe "$m" 2>/dev/null; then :; else
        MISSING_KMOD="$MISSING_KMOD $m"
    fi
done
if [ -z "$MISSING_KMOD" ]; then
    ok "TPROXY kernel modules present"
else
    warn "missing:$MISSING_KMOD -- proxy mode will work, global mode will not"
    warn "  install with: apk add kmod-nft-tproxy kmod-nft-socket"
fi

# --- the resolver we hand LAN queries to ---
if pgrep dnsmasq >/dev/null 2>&1; then
    ok "dnsmasq is running"
else
    warn "dnsmasq is not running -- tunnelled DNS needs it"
fi

# --- used to fetch subscriptions, and by the health probe ---
if command -v curl >/dev/null 2>&1; then
    ok "curl present"
else
    bad "curl is missing -- install it: apk add curl"
fi

# --- flow offloading silently bypasses the tproxy hooks ---
if [ "$(uci -q get firewall.@defaults[0].flow_offloading || echo 0)" = "1" ] ||
   [ "$(uci -q get firewall.@defaults[0].flow_offloading_hw || echo 0)" = "1" ]; then
    warn "flow offloading is enabled -- it short-circuits the hooks global mode"
    warn "  uses. Turn it off in Network > Firewall before enabling global mode."
else
    ok "flow offloading is off"
fi

# --- something else already intercepting ---
for other in passwall passwall2 shadowsocksr openclash; do
    if nft list table inet "$other" >/dev/null 2>&1 &&
       [ "$(nft list table inet "$other" 2>/dev/null | grep -cE 'tproxy|redirect')" -gt 0 ]; then
        warn "$other is currently intercepting traffic -- stop it before"
        warn "  enabling global mode, or the two will fight over the same hooks."
    fi
done

echo
if [ "$FAIL" -gt 0 ]; then
    echo "Cannot install: $FAIL requirement(s) not met. Nothing was changed."
    exit 1
fi

# --- install ---
echo "Installing:"
[ -f "$BIN" ] && /etc/init.d/xrayop stop 2>/dev/null || true

mkdir -p "$STATE_DIR" "$RUNTIME_DIR" /etc/hotplug.d/iface
chmod 0700 "$STATE_DIR" "$RUNTIME_DIR"

# Written beside and renamed: a running binary cannot be overwritten in place,
# but it can be replaced.
cp "$here/xrayopd" "$BIN.new"
chmod 0755 "$BIN.new"
mv "$BIN.new" "$BIN"
ok "$BIN"

cp "$here/etc/init.d/xrayop" /etc/init.d/xrayop
chmod 0755 /etc/init.d/xrayop
ok "/etc/init.d/xrayop"

cp "$here/etc/hotplug.d/iface/99-xrayop" /etc/hotplug.d/iface/99-xrayop
chmod 0755 /etc/hotplug.d/iface/99-xrayop
ok "/etc/hotplug.d/iface/99-xrayop"

# Never clobber an existing one: it holds the chosen port.
if [ -f /etc/config/xrayop ]; then
    ok "/etc/config/xrayop (kept, already present)"
else
    cp "$here/etc/config/xrayop" /etc/config/xrayop
    ok "/etc/config/xrayop"
fi

# Survive sysupgrade and config-restore. The default backup only covers
# /etc/config, which would leave the server list and the service behind.
KEEP="/etc/init.d/xrayop
/etc/hotplug.d/iface/99-xrayop
/etc/xrayop/
/usr/bin/xrayopd"
for path in $KEEP; do
    grep -qxF "$path" /etc/sysupgrade.conf 2>/dev/null || echo "$path" >> /etc/sysupgrade.conf
done
ok "added to /etc/sysupgrade.conf so backups include it"

/etc/init.d/xrayop enable
/etc/init.d/xrayop start
sleep 3

echo
if pgrep -f 'bin/xrayopd' >/dev/null; then
    LAN_IP="$(uci -q get network.lan.ipaddr || echo 192.168.1.1)"
    PORT="$(uci -q get xrayop.main.listen | sed 's/.*://')"
    TOKEN="$(sed -n 's/.*"panel_token": "\([^"]*\)".*/\1/p' "$STATE_DIR/state.json" 2>/dev/null)"
    echo "Installed and running."
    echo
    echo "  Panel:  http://${LAN_IP}:${PORT:-8088}"
    echo "  Token:  ${TOKEN:-<check: logread | grep -A2 'panel token'>}"
    echo
    # A reinstall keeps whatever mode was already set, so only describe the
    # starting point when this really is one.
    # Each node carries its own "mode" (the transport: gun, multi, auto), and
    # those are usually empty. Requiring a non-empty value and taking the last
    # match picks the settings one, which is written after the node list.
    MODE="$(sed -n 's/.*"mode": "\([a-z][a-z]*\)".*/\1/p' "$STATE_DIR/state.json" 2>/dev/null | tail -1)"
    case "${MODE:-proxy}" in
        global)
            echo "Restored in global mode: the whole LAN goes through the tunnel."
            ;;
        off)
            echo "Restored with the tunnel switched off."
            ;;
        *)
            echo "Running in proxy mode: a SOCKS5 proxy on port 1080 and an HTTP"
            echo "proxy on 1081, for clients you point at them. Add a subscription,"
            echo "pick a server, then switch to global mode for the whole LAN."
            ;;
    esac
else
    echo "Installed, but the service did not start. What it said:"
    logread | grep -i xrayop | tail -5
    exit 1
fi
