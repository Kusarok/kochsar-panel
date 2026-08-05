#!/usr/bin/env bash
# Install xrayopd and its service files on the router.
#
#   ./scripts/deploy.sh           # binary + init script + default config
#   ./scripts/deploy.sh --bin     # binary only (fast iteration)
#
# Env:
#   ROUTER    ssh host of the router   (default: router)
#   BINARY    local binary to install  (default: ./dist/xrayopd)
#
# Uses `cat | ssh` rather than scp throughout: OpenWrt's dropbear ships without
# sftp-server, so scp fails with "sftp-server: not found".

set -euo pipefail

ROUTER="${ROUTER:-router}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY="${BINARY:-$here/dist/xrayopd}"

[ -f "$BINARY" ] || { echo "no binary at $BINARY -- run scripts/build.sh --fetch first" >&2; exit 1; }

echo "==> installing binary on ${ROUTER}"
# Write beside the target then rename: a running binary cannot be overwritten
# in place, but it can be replaced.
ssh "$ROUTER" '/etc/init.d/xrayop stop 2>/dev/null; cat > /usr/bin/xrayopd.new' < "$BINARY"
ssh "$ROUTER" 'chmod +x /usr/bin/xrayopd.new && mv /usr/bin/xrayopd.new /usr/bin/xrayopd'

if [ "${1:-}" != "--bin" ]; then
  echo "==> installing service files"
  ssh "$ROUTER" 'cat > /etc/init.d/xrayop && chmod +x /etc/init.d/xrayop' \
    < "$here/openwrt/etc/init.d/xrayop"
  # Never clobber an existing config -- it holds the user's chosen port.
  ssh "$ROUTER" '[ -f /etc/config/xrayop ] || cat > /etc/config/xrayop' \
    < "$here/openwrt/etc/config/xrayop"
  ssh "$ROUTER" '/etc/init.d/xrayop enable'
fi

echo "==> starting"
ssh "$ROUTER" '/etc/init.d/xrayop restart && sleep 1 && /usr/bin/xrayopd --version'

listen=$(ssh "$ROUTER" 'uci -q get xrayop.main.listen || echo 0.0.0.0:8088')
addr=$(ssh "$ROUTER" 'uci -q get network.lan.ipaddr || echo 192.168.1.1')
echo "==> panel: http://${addr}:${listen##*:}"
