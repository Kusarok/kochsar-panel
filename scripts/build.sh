#!/usr/bin/env bash
# Cross-compile xrayopd for the router on a remote Linux builder.
#
# The router is armv7 musl and the workstation is Windows, so the build runs on
# a Linux host over SSH. Every dependency is pure Rust, so the builder needs
# nothing beyond rustup and the target -- no C cross-toolchain.
#
#   ./scripts/build.sh            # build, leave the binary on the builder
#   ./scripts/build.sh --fetch    # also download it to ./dist
#
# Env:
#   BUILDER   ssh host to build on          (default: rack)
#   TARGET    rust target triple            (default: armv7-unknown-linux-musleabihf)
#   REMOTE    working directory on builder  (default: ~/xrayop)

set -euo pipefail

BUILDER="${BUILDER:-rack}"
TARGET="${TARGET:-armv7-unknown-linux-musleabihf}"
REMOTE="${REMOTE:-\$HOME/xrayop}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

echo "==> syncing source to ${BUILDER}"
tar czf - Cargo.toml .cargo src web | ssh "$BUILDER" "
  rm -rf ${REMOTE}/src ${REMOTE}/web
  mkdir -p ${REMOTE}
  tar xzf - -C ${REMOTE}
"

# The panel is compiled into the binary, so a JS syntax error ships silently:
# the page renders blank and everything server-side looks healthy. Catch it
# here when a parser is available.
if command -v node >/dev/null 2>&1; then
  echo "==> checking panel javascript"
  sed -n '/<script>/,/<\/script>/p' web/index.html | sed '1d;$d' > /tmp/xrayop-panel.js
  node --check /tmp/xrayop-panel.js || { echo "panel javascript does not parse" >&2; exit 1; }
  rm -f /tmp/xrayop-panel.js
fi

echo "==> building ${TARGET}"
ssh "$BUILDER" "
  set -e
  . \$HOME/.cargo/env
  cd ${REMOTE}
  cargo fmt --check 2>/dev/null || true
  cargo test --quiet
  cargo build --release --target ${TARGET}
  ls -lh target/${TARGET}/release/xrayopd
"

if [ "${1:-}" = "--fetch" ]; then
  mkdir -p dist
  echo "==> fetching binary to dist/"
  # The router's dropbear has no sftp-server, and neither does every builder;
  # a plain cat over ssh works everywhere.
  ssh "$BUILDER" "cat ${REMOTE}/target/${TARGET}/release/xrayopd" > dist/xrayopd
  chmod +x dist/xrayopd
  ls -lh dist/xrayopd
fi

echo "==> done"
