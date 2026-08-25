#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

CORE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd "$CORE_DIR/.." && pwd -P)"

# The third runner sharing `sdk/simulator/`: same binary, same four sockets.
# It used to transcribe the lifecycle instead of sourcing it, and inherited the
# lost-pid bug documented in `simulator_start` -- cleanup killed the wrapper and
# left the simulator holding its binary open, so the next run's `build.sh` hit
# "Text file busy". Sourcing keeps the fix in one place.
# shellcheck source=../sdk/simulator/lifecycle.sh
# shellcheck disable=SC1091  # the hook runs without -x, so it cannot follow this
source "$REPO_ROOT/sdk/simulator/lifecycle.sh"

trap 'simulator_print_logs' ERR
trap simulator_stop EXIT INT TERM

simulator_start

echo "DSTACK_SIMULATOR_ENDPOINT: $DSTACK_SIMULATOR_ENDPOINT"
echo "TAPPD_SIMULATOR_ENDPOINT: $TAPPD_SIMULATOR_ENDPOINT"

(cd "$CORE_DIR" && cargo test --all-features -- --show-output)
