#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Build the gateway as a static musl binary and wrap it in the alpine runtime
# image both test suites run. Shared so the two suites cannot end up testing
# different builds.
#
# Usage: build-gateway-image.sh <dest-dir> [--skip-build]
#   <dest-dir>   where to place the binary; also the docker build context

set -e

TEST_RUN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DSTACK="$(cd "$TEST_RUN_DIR/../.." && pwd)"

DEST_DIR="${1:?usage: build-gateway-image.sh <dest-dir> [--skip-build]}"
SKIP_BUILD="${2:-}"

if [ "$SKIP_BUILD" != "--skip-build" ]; then
    echo "[INFO] building dstack-gateway (musl static)..." >&2
    (cd "$REPO_DSTACK" && cargo build --release -p dstack-gateway \
        --target x86_64-unknown-linux-musl)
    cp "$REPO_DSTACK/target/x86_64-unknown-linux-musl/release/dstack-gateway" "$DEST_DIR/"
fi

if [ ! -f "$DEST_DIR/dstack-gateway" ]; then
    echo "[ERROR] $DEST_DIR/dstack-gateway is missing; run without --skip-build" >&2
    exit 1
fi

echo "[INFO] building the gateway image..." >&2
docker build -t dstack-gateway:test -f "$TEST_RUN_DIR/Dockerfile.gateway" "$DEST_DIR"
