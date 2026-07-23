#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
DEST=${1:?staging tree required}
DEST=$(realpath -m "$DEST")
FLAVOR=${2:-prod}
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
  build_root=$(dirname "$DEST")
  export CARGO_TARGET_DIR="$build_root/dstack-cargo-target"
  export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/usr/src/dstack --remap-path-prefix=$build_root=/usr/src/dstack-build -C strip=debuginfo"
  cargo build --locked --offline --release --manifest-path "$ROOT/dstack/Cargo.toml" \
    -p dstack-guest-agent -p dstack-util
  install -m0755 "$CARGO_TARGET_DIR/release/dstack-guest-agent" \
    "$CARGO_TARGET_DIR/release/dstack-util" "$DEST/usr/bin/"
  if [[ $FLAVOR == dev ]]; then
    cargo build --locked --offline --release --manifest-path "$ROOT/dstack/Cargo.toml" \
      -p dstack-tee-simulator
    install -m0755 "$CARGO_TARGET_DIR/release/dstack-tee-simulator" "$DEST/usr/bin/"
    install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-tee-simulator/files/dstack-tee-simulator.service" \
      "$DEST/usr/lib/systemd/system/dstack-tee-simulator.service"
    install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-tee-simulator/files/tee-simulator.conf" \
      "$DEST/etc/tee-simulator.conf"
  fi
fi
find "$DEST" -print0 | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH:?}"
