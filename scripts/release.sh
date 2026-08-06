#!/usr/bin/env bash
# Builds a release tarball someone else can install without a toolchain.
#
#   ./scripts/release.sh                    # the default target
#   TARGET=aarch64-unknown-linux-musl ./scripts/release.sh
#
# Produces dist/xrayop-<version>-<target>.tar.gz containing the binary, the
# service files and an installer that checks the router before touching it.
#
# Env:
#   BUILDER   ssh host with the rust toolchain  (default: rack)
#   TARGET    rust target triple               (default: armv7-unknown-linux-musleabihf)
#   REMOTE    working directory on the builder (default: ~/xrayop)

set -euo pipefail

BUILDER="${BUILDER:-rack}"
TARGET="${TARGET:-armv7-unknown-linux-musleabihf}"
REMOTE="${REMOTE:-\$HOME/xrayop}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"
NAME="xrayop-${VERSION}-${TARGET}"

echo "==> building ${NAME}"
"$here/scripts/build.sh" --fetch

STAGE="$here/dist/$NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE/etc/init.d" "$STAGE/etc/config" "$STAGE/etc/hotplug.d/iface"

cp dist/xrayopd                                  "$STAGE/xrayopd"
cp openwrt/etc/init.d/xrayop                     "$STAGE/etc/init.d/xrayop"
cp openwrt/etc/config/xrayop                     "$STAGE/etc/config/xrayop"
cp openwrt/etc/hotplug.d/iface/99-xrayop         "$STAGE/etc/hotplug.d/iface/99-xrayop"
cp packaging/install.sh packaging/uninstall.sh   "$STAGE/"
cp README.md                                     "$STAGE/README.md"

# Shell scripts written on Windows carry CRLF, which /bin/sh on the router
# rejects with a message that blames the wrong line.
find "$STAGE" -name '*.sh' -o -name 'xrayop' -o -name '99-xrayop' | while read -r f; do
    [ -f "$f" ] && sed -i 's/\r$//' "$f"
done
chmod +x "$STAGE"/*.sh "$STAGE/xrayopd" "$STAGE/etc/init.d/xrayop" \
         "$STAGE/etc/hotplug.d/iface/99-xrayop"

tar -C "$here/dist" -czf "$here/dist/$NAME.tar.gz" "$NAME"
rm -rf "$STAGE"

echo
echo "==> dist/$NAME.tar.gz  ($(du -h "$here/dist/$NAME.tar.gz" | cut -f1))"
echo
echo "To install on a router:"
echo "    scp -O dist/$NAME.tar.gz root@ROUTER:/tmp/"
echo "    ssh root@ROUTER 'cd /tmp && tar xzf $NAME.tar.gz && cd $NAME && sh install.sh'"
echo
echo "OpenWrt's dropbear has no sftp-server, so scp needs -O (or pipe through ssh)."
