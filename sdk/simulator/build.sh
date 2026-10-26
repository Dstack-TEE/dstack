#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cargo build \
    --manifest-path "$REPO_ROOT/dstack/Cargo.toml" \
    --release \
    -p dstack-guest-agent-simulator
cp "$REPO_ROOT/dstack/target/release/dstack-simulator" "$SCRIPT_DIR/"
