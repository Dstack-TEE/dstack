#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

ROOT_DIR="$(pwd -P)"
SIMULATOR_DIR="$ROOT_DIR/sdk/simulator"
SIMULATOR_LOG="$SIMULATOR_DIR/dstack-simulator.log"
DSTACK_SOCKET="$SIMULATOR_DIR/dstack.sock"
TAPPD_SOCKET="$SIMULATOR_DIR/tappd.sock"
SIMULATOR_PID=""

cleanup() {
    if [[ -n "${SIMULATOR_PID:-}" ]]; then
        kill "$SIMULATOR_PID" 2>/dev/null || true
        wait "$SIMULATOR_PID" 2>/dev/null || true
    fi
}

print_simulator_logs() {
    if [[ -f "$SIMULATOR_LOG" ]]; then
        echo "Last simulator logs:"
        tail -100 "$SIMULATOR_LOG" || true
    fi
}

wait_for_socket() {
    local socket_path="$1"
    local name="$2"

    for _ in {1..100}; do
        if [[ -S "$socket_path" ]]; then
            return 0
        fi
        if [[ -n "${SIMULATOR_PID:-}" ]] && ! kill -0 "$SIMULATOR_PID" 2>/dev/null; then
            echo "Simulator exited before $name socket became ready."
            print_simulator_logs
            return 1
        fi
        sleep 0.2
    done

    echo "Timed out waiting for $name socket at $socket_path"
    print_simulator_logs
    return 1
}

trap 'print_simulator_logs' ERR
trap cleanup EXIT INT TERM

rm -f "$DSTACK_SOCKET" "$TAPPD_SOCKET" "$SIMULATOR_LOG"
(
    cd "$SIMULATOR_DIR"
    ./build.sh
)

(
    cd "$SIMULATOR_DIR"
    ./dstack-simulator >"$SIMULATOR_LOG" 2>&1
) &
SIMULATOR_PID=$!
echo "Simulator process (PID: $SIMULATOR_PID) started."

wait_for_socket "$DSTACK_SOCKET" "dstack"
wait_for_socket "$TAPPD_SOCKET" "tappd"

export DSTACK_SIMULATOR_ENDPOINT="$DSTACK_SOCKET"
export TAPPD_SIMULATOR_ENDPOINT="$TAPPD_SOCKET"

echo "DSTACK_SIMULATOR_ENDPOINT: $DSTACK_SIMULATOR_ENDPOINT"
echo "TAPPD_SIMULATOR_ENDPOINT: $TAPPD_SIMULATOR_ENDPOINT"

cargo test --all-features -- --show-output
