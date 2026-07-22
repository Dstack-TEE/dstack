#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
DEST=${1:?staging tree required}
install -d "$DEST/usr/bin" "$DEST/usr/lib/systemd/system" \
  "$DEST/etc/systemd/journald.conf.d" "$DEST/etc/systemd/resolved.conf.d" \
  "$DEST/etc/systemd/system/docker.service.d" \
  "$DEST/etc/systemd/system/containerd.service.d" "$DEST/etc/sysctl.d"
for s in dstack-prepare ephemeral-docker wg-checker app-compose; do
  install -m0755 "$ROOT/os/common/rootfs/$s.sh" "$DEST/usr/bin/$s.sh"
done
install -m0644 "$ROOT/os/common/rootfs/"*.service \
  "$ROOT/os/common/rootfs/dstack-guest-agent.socket" "$DEST/usr/lib/systemd/system/"
install -m0644 "$ROOT/os/common/rootfs/journald.conf" "$DEST/etc/systemd/journald.conf.d/dstack.conf"
install -m0644 "$ROOT/os/common/rootfs/llmnr.conf" "$DEST/etc/systemd/resolved.conf.d/dstack.conf"
install -m0644 "$ROOT/os/common/rootfs/tdx-attest.conf" "$DEST/etc/"
install -m0644 "$ROOT/os/common/rootfs/sysctl.d/99-dstack.conf" "$DEST/etc/sysctl.d/"
cp -a "$ROOT/os/common/rootfs/docker.service.d/." "$DEST/etc/systemd/system/docker.service.d/"
cp -a "$ROOT/os/common/rootfs/containerd.service.d/." "$DEST/etc/systemd/system/containerd.service.d/"

# Cargo.lock pins Rust dependencies. Offline mode makes a warm, vendored/cache
# build deterministic and prevents an accidental lockfile update.
if [[ ${DSTACK_SKIP_RUST:-0} != 1 ]]; then
  export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true
  export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/usr/src/dstack -C strip=debuginfo"
  cargo build --locked --offline --release --manifest-path "$ROOT/dstack/Cargo.toml" \
    -p dstack-guest-agent -p dstack-util
  install -m0755 "$ROOT/dstack/target/release/dstack-guest-agent" \
    "$ROOT/dstack/target/release/dstack-util" "$DEST/usr/bin/"
fi
find "$DEST" -print0 | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH:?}"

