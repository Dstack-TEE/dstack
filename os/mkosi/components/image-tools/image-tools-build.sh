#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
# shellcheck source=/dev/null
source "$ROOT/os/mkosi/versions.env"
TARGET=$(realpath -m "${1:?target directory required}")
DEST=$(realpath -m "${2:?staging tree required}")
BIN="$DEST/usr/lib/dstack/image-tools"

mkdir -p "$TARGET" "$BIN"
export CARGO_TARGET_DIR="$TARGET/dstack"
export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$ROOT=/usr/src/dstack --remap-path-prefix=$TARGET=/usr/src/image-tools -C codegen-units=1 -C strip=debuginfo"
cargo build --locked --release --manifest-path "$ROOT/dstack/Cargo.toml" \
  -p dstack-mr
install -m0755 "$CARGO_TARGET_DIR/release/dstack-mr" "$BIN/"

export CARGO_TARGET_DIR="$TARGET/nitro-tpm"
cargo install --locked \
  --git https://github.com/aws/NitroTPM-Tools \
  --rev "$NITRO_TPM_TOOLS_REVISION" \
  --root "$TARGET/nitro-install" nitro-tpm-pcr-compute
install -m0755 "$TARGET/nitro-install/bin/nitro-tpm-pcr-compute" "$BIN/"

find "$DEST" -print0 | xargs -0r touch --no-dereference \
  --date="@${SOURCE_DATE_EPOCH:?}"
