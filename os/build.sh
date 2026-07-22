#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

usage() {
    cat <<EOF
Usage: ${0##*/} [--backend NAME] [--flavors "FLAVOR ..."] [--build-dir DIR]

Build dstack guest OS release artifacts with a selected backend.

Available backends:
  yocto    Reproducible Yocto build (default)
  mkosi    Experimental pinned Debian/mkosi build

A backend lives at os/<name>/build.sh and implements the "image" action.
The common image contract is documented in os/README.md.
EOF
}

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BACKEND=yocto
FLAVORS=${FLAVORS:-prod}
BUILD_DIR=

while [ $# -gt 0 ]; do
    case "$1" in
        --backend)
            [ $# -ge 2 ] || { echo "Error: --backend requires a value" >&2; exit 1; }
            BACKEND=$2
            shift 2
            ;;
        --flavors)
            [ $# -ge 2 ] || { echo "Error: --flavors requires a value" >&2; exit 1; }
            FLAVORS=$2
            shift 2
            ;;
        --build-dir)
            [ $# -ge 2 ] || { echo "Error: --build-dir requires a value" >&2; exit 1; }
            BUILD_DIR=$2
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "$BACKEND" in
    ''|*[!0-9A-Za-z_-]*)
        echo "Error: invalid OS backend name: $BACKEND" >&2
        exit 1
        ;;
esac

BACKEND_SCRIPT="$SCRIPT_DIR/$BACKEND/build.sh"
if [ ! -x "$BACKEND_SCRIPT" ]; then
    echo "Error: OS backend is not available: $BACKEND" >&2
    echo "Expected executable: $BACKEND_SCRIPT" >&2
    exit 1
fi

export FLAVORS
if [ -n "$BUILD_DIR" ]; then
    exec "$BACKEND_SCRIPT" image "$BUILD_DIR"
else
    exec "$BACKEND_SCRIPT" image
fi
