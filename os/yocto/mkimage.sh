#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) Hashforest Technology LLC
#
# SPDX-License-Identifier: BUSL-1.1

# Compatibility entrypoint: export Yocto-specific outputs, then invoke the
# backend-neutral image assembler.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
BB_BUILD_DIR=${BB_BUILD_DIR:-build}
DIST_NAME=
FLAVOR=

while [ $# -gt 0 ]; do
    case "$1" in
        --dist-name)
            DIST_NAME=$2
            shift 2
            ;;
        --flavor)
            FLAVOR=$2
            shift 2
            ;;
        -h|--help)
            exec "$SCRIPT_DIR/scripts/export-artifacts.sh" --help
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$DIST_NAME" ] || [ -z "$FLAVOR" ]; then
    echo "Error: --dist-name and --flavor are required" >&2
    exit 1
fi

ARTIFACT_DIR=${ARTIFACT_DIR:-"$BB_BUILD_DIR/dstack-artifacts/$FLAVOR"}
"$SCRIPT_DIR/scripts/export-artifacts.sh" \
    --dist-name "$DIST_NAME" \
    --flavor "$FLAVOR" \
    --build-dir "$BB_BUILD_DIR" \
    --output-dir "$ARTIFACT_DIR"

exec "$SCRIPT_DIR/../image/assemble.sh" \
    --manifest "$ARTIFACT_DIR/artifact-manifest.json"
