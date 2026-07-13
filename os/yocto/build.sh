#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: BUSL-1.1

# Yocto implementation of the guest-OS backend contract in os/README.md.
set -eo pipefail

usage() {
    cat <<'USAGE'
Usage: build.sh image [build-dir]

Build dstack guest-OS artifacts with Yocto and assemble release archives.
The guest action is accepted as a compatibility alias for image.

Environment:
  FLAVORS    space-separated image flavors (default: prod)
  DIST_DIR   release output directory (default: <current-directory>/images)
USAGE
}

ACTION=${1:-}
BUILD_DIR=${2:-}
if [ "$#" -gt 2 ]; then
    usage >&2
    exit 1
fi

case "$ACTION" in
    image|guest)
        ;;
    help|-h|--help)
        usage
        exit 0
        ;;
    *)
        if [ -n "$ACTION" ]; then
            echo "Invalid action: $ACTION" >&2
        fi
        usage >&2
        exit 1
        ;;
esac

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DIST_DIR=${DIST_DIR:-"$PWD/images"}
FLAVORS=${FLAVORS:-prod}
read -r -a FLAVOR_LIST <<< "$FLAVORS"
if [ "${#FLAVOR_LIST[@]}" -eq 0 ]; then
    echo "Error: at least one Yocto image flavor is required" >&2
    exit 1
fi
for flavor in "${FLAVOR_LIST[@]}"; do
    case "$flavor" in
        prod|dev)
            ;;
        *)
            echo "Error: unsupported Yocto image flavor: $flavor" >&2
            exit 1
            ;;
    esac
done

if [ -z "${BBPATH:-}" ]; then
    # Always pass a directory explicitly. A sourced script otherwise inherits
    # this script's positional parameters and would mistake `image` for the
    # build directory.
    BUILD_DIR=${BUILD_DIR:-"$SCRIPT_DIR/bb-build"}
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/dev-setup" "$BUILD_DIR"
elif [ -n "$BUILD_DIR" ] && [ "$(realpath "$BUILD_DIR")" != "$(realpath "$BBPATH")" ]; then
    echo "Error: BBPATH is already set to $BBPATH, not requested build directory $BUILD_DIR" >&2
    exit 1
fi

cat <<'NOTE'
Note: the first docker-compose fetch contains hundreds of separately
checksummed Go modules. BitBake's 0-100% display resets for each module; this
is forward progress, not the same archive being downloaded repeatedly.
Interrupted downloads are retained and reused on the next run.
NOTE

make -C "$SCRIPT_DIR" dist \
    DIST_DIR="$DIST_DIR" \
    BB_BUILD_DIR="$BBPATH" \
    FLAVORS="$FLAVORS"
