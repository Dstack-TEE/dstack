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
install -m0644 "$ROOT/os/common/rootfs/docker.service.d/"* \
  "$DEST/etc/systemd/system/docker.service.d/"
install -m0644 "$ROOT/os/common/rootfs/containerd.service.d/"* \
  "$DEST/etc/systemd/system/containerd.service.d/"

# Cargo.lock and --locked pin every registry/git dependency. The hermetic
# mkosi build root may fetch missing inputs but cannot update the lock file.
if [[ ${DSTACK_SKIP_RUST:-0} != 1 ]]; then
  export CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=${CARGO_NET_OFFLINE:-false}
  build_root=$(dirname "$DEST")
  ephemeral_target="$build_root/dstack-cargo-target"
  target_remap=
  if [[ -n ${DSTACK_CARGO_TARGET_DIR:-} ]]; then
    # A cached build keeps the target directory outside the per-build sandbox
    # so an edit rebuilds only the touched crates. That moves it out from under
    # the $build_root remap below, and rustc embeds absolute paths from the
    # target directory (build script OUT_DIRs among them). Without mapping it
    # back onto the path the throwaway layout produced, a cached build would
    # differ from a cold one byte for byte -- silently, and only inside the
    # binaries. Remapped first so it wins over the broader $build_root rule.
    export CARGO_TARGET_DIR="$DSTACK_CARGO_TARGET_DIR"
    target_remap="--remap-path-prefix=$CARGO_TARGET_DIR=/usr/src/dstack-build/dstack-cargo-target"
  else
    export CARGO_TARGET_DIR="$ephemeral_target"
  fi
  # Not `[[ ... ]] && export ...`: under set -e a false test makes the whole
  # list non-zero and kills the build on the cold path, where this is unset.
  if [[ -n ${DSTACK_CARGO_HOME:-} ]]; then export CARGO_HOME="$DSTACK_CARGO_HOME"; fi
  # A single codegen unit avoids LLVM partition/scheduling differences across
  # hosts with different CPU counts while retaining parallel crate builds.
  export RUSTFLAGS="${RUSTFLAGS:-} $target_remap --remap-path-prefix=$ROOT=/usr/src/dstack --remap-path-prefix=$build_root=/usr/src/dstack-build -C codegen-units=1 -C strip=debuginfo"
  cargo build --locked --release --manifest-path "$ROOT/dstack/Cargo.toml" \
    -p dstack-guest-agent -p dstack-util
  install -m0755 "$CARGO_TARGET_DIR/release/dstack-guest-agent" \
    "$CARGO_TARGET_DIR/release/dstack-util" "$DEST/usr/bin/"
  if [[ $FLAVOR == dev ]]; then
    cargo build --locked --release --manifest-path "$ROOT/dstack/Cargo.toml" \
      -p dstack-tee-simulator
    install -m0755 "$CARGO_TARGET_DIR/release/dstack-tee-simulator" "$DEST/usr/bin/"
    install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-tee-simulator/files/dstack-tee-simulator.service" \
      "$DEST/usr/lib/systemd/system/dstack-tee-simulator.service"
    # meta-dstack installs this as a dstack-prepare.service drop-in. Anywhere
    # else systemd never reads it and dstack-prepare loses its ordering against
    # the simulator that has to publish the TEE ABI first.
    install -Dm0644 "$ROOT/os/yocto/layers/meta-dstack/recipes-core/dstack-tee-simulator/files/tee-simulator.conf" \
      "$DEST/etc/systemd/system/dstack-prepare.service.d/tee-simulator.conf"
  fi
fi
find "$DEST" -print0 | xargs -0r touch --no-dereference --date="@${SOURCE_DATE_EPOCH:?}"
