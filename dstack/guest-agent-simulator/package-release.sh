#!/bin/bash

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: package-release.sh <version> <target-triple> [--binary <path>] [--out-dir <path>]

Create a self-contained dstack-simulator release tarball that includes:
  - the simulator binary
  - default simulator config and fixture data
  - a systemd unit template
  - the install-systemd.sh helper
EOF
}

if [[ $# -lt 2 ]]; then
    usage >&2
    exit 1
fi

VERSION="$1"
TARGET="$2"
shift 2

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$SCRIPT_DIR/dist"
BINARY_PATH="$ROOT_DIR/target/$TARGET/release/dstack-simulator"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        --out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

if [[ ! -f "$BINARY_PATH" ]]; then
    echo "Simulator binary not found: $BINARY_PATH" >&2
    exit 1
fi

PACKAGE_NAME="dstack-simulator-${VERSION}-${TARGET}"
STAGE_DIR="$OUT_DIR/$PACKAGE_NAME"
TARBALL_PATH="$OUT_DIR/${PACKAGE_NAME}.tar.gz"
CHECKSUM_PATH="${TARBALL_PATH}.sha256"

rm -rf "$STAGE_DIR" "$TARBALL_PATH" "$CHECKSUM_PATH"
mkdir -p "$STAGE_DIR"

install -m 755 "$BINARY_PATH" "$STAGE_DIR/dstack-simulator"
install -m 644 "$ROOT_DIR/sdk/simulator/dstack.toml" "$STAGE_DIR/dstack.toml"
install -m 644 "$ROOT_DIR/sdk/simulator/app-compose.json" "$STAGE_DIR/app-compose.json"
install -m 644 "$ROOT_DIR/sdk/simulator/appkeys.json" "$STAGE_DIR/appkeys.json"
install -m 644 "$ROOT_DIR/sdk/simulator/sys-config.json" "$STAGE_DIR/sys-config.json"
install -m 644 "$ROOT_DIR/sdk/simulator/attestation.bin" "$STAGE_DIR/attestation.bin"
install -m 644 "$SCRIPT_DIR/dstack-simulator.service" "$STAGE_DIR/dstack-simulator.service"
install -m 755 "$SCRIPT_DIR/install-systemd.sh" "$STAGE_DIR/install-systemd.sh"

tar -C "$OUT_DIR" -czf "$TARBALL_PATH" "$PACKAGE_NAME"
(
    cd "$OUT_DIR"
    sha256sum "$(basename "$TARBALL_PATH")" > "$(basename "$CHECKSUM_PATH")"
)

echo "Created release bundle:"
echo "  $TARBALL_PATH"
echo "  $CHECKSUM_PATH"
