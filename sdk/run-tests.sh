#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# shellcheck source=simulator/lifecycle.sh
source "$ROOT_DIR/simulator/lifecycle.sh"

trap 'simulator_print_logs' ERR
trap simulator_stop EXIT INT TERM

simulator_start

pushd "$ROOT_DIR/rust"
cargo test -- --show-output
cargo run --example tappd_client_usage
cargo run --example dstack_client_usage
cargo test -p dstack-sdk-types --test no_std_test --no-default-features
popd

pushd "$ROOT_DIR/go"
go clean -testcache
go test -v ./dstack
DSTACK_SIMULATOR_ENDPOINT=$TAPPD_SIMULATOR_ENDPOINT go test -v ./tappd
popd

pushd "$ROOT_DIR/python"
# Ensure PDM is installed
if ! command -v pdm &> /dev/null; then
    echo "Installing PDM..."
    pip install pdm
fi
# Install dependencies and setup environment using PDM
pdm install --dev
# Run tests
pdm run test
# Run formatting check
pdm run check
popd

pushd "$ROOT_DIR/js"
npm install
npm run test -- --run
popd
