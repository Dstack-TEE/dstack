#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Build/start/stop for the agent-backed simulator, shared by the SDK test
# runners: `sdk/run-tests.sh` and `sdk/compat/run-compat-tests.sh`. Both need a
# simulator built from the current checkout listening on the same two sockets,
# and the compat runner needs to keep one alive across several SDK checkouts,
# so the lifecycle lives here rather than being transcribed twice.
#
# Source this file, do not execute it: `simulator_start` exports
# DSTACK_SIMULATOR_ENDPOINT and TAPPD_SIMULATOR_ENDPOINT into the caller's
# environment, which is how every SDK test suite finds the agent. Traps stay
# with the caller so that cleanup order is visible in the script that owns it;
# the caller is expected to install `simulator_stop` on EXIT and
# `simulator_print_logs` on ERR.

SIMULATOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SIMULATOR_LOG="$SIMULATOR_DIR/dstack-simulator.log"
DSTACK_SOCKET="$SIMULATOR_DIR/dstack.sock"
TAPPD_SOCKET="$SIMULATOR_DIR/tappd.sock"
GUEST_SOCKET="$SIMULATOR_DIR/guest.sock"
EXTERNAL_SOCKET="$SIMULATOR_DIR/external.sock"
SIMULATOR_PID=""

simulator_stop() {
    if [[ -n "${SIMULATOR_PID:-}" ]]; then
        kill "$SIMULATOR_PID" 2>/dev/null || true
        wait "$SIMULATOR_PID" 2>/dev/null || true
        SIMULATOR_PID=""
    fi
    rm -f "$DSTACK_SOCKET" "$TAPPD_SOCKET" "$GUEST_SOCKET" "$EXTERNAL_SOCKET"
}

# Printed at most once per run. The callers set `-E`, so an ERR trap propagates
# into every function and subshell: without a guard, a failure inside a suite
# dumps the same 100 lines on the way out of each frame, and the test failure an
# operator came to read ends up scrolled off the top.
#
# The marker is a file, not a variable, precisely because the duplicate print
# comes from a subshell -- an assignment there would not be visible to the
# parent that prints second.
SIMULATOR_LOGS_PRINTED_MARKER="$SIMULATOR_DIR/.simulator-logs-printed"

simulator_print_logs() {
    if ! (set -o noclobber; : >"$SIMULATOR_LOGS_PRINTED_MARKER") 2>/dev/null; then
        return 0
    fi
    if [[ -f "$SIMULATOR_LOG" ]]; then
        echo "Last simulator logs:"
        tail -100 "$SIMULATOR_LOG" || true
    fi
}

simulator_wait_for_socket() {
    local socket_path="$1"
    local name="$2"

    for _ in {1..100}; do
        if [[ -S "$socket_path" ]]; then
            return 0
        fi
        if [[ -n "${SIMULATOR_PID:-}" ]] && ! kill -0 "$SIMULATOR_PID" 2>/dev/null; then
            echo "Simulator exited before $name socket became ready."
            simulator_print_logs
            return 1
        fi
        sleep 0.2
    done

    echo "Timed out waiting for $name socket at $socket_path"
    simulator_print_logs
    return 1
}

simulator_build() {
    (
        # `|| exit` rather than relying on the caller's `set -e`: this file is
        # sourced, so it inherits whatever shell options the caller happens to
        # have set, and building in the wrong directory is not a failure worth
        # discovering three steps later.
        cd "$SIMULATOR_DIR" || exit 1
        ./build.sh || exit 1
    )
}

# Builds the simulator from the current checkout, starts it, waits for both
# sockets, and exports the endpoints the SDK suites read.
simulator_start() {
    rm -f \
        "$DSTACK_SOCKET" \
        "$TAPPD_SOCKET" \
        "$GUEST_SOCKET" \
        "$EXTERNAL_SOCKET" \
        "$SIMULATOR_LOGS_PRINTED_MARKER" \
        "$SIMULATOR_LOG"

    export DSTACK_SIMULATOR_ENDPOINT="$DSTACK_SOCKET"
    export TAPPD_SIMULATOR_ENDPOINT="$TAPPD_SOCKET"

    simulator_build

    # `exec` matters: without it `$!` is the subshell rather than the simulator,
    # so `simulator_stop` kills the wrapper and leaves the simulator orphaned,
    # holding its binary open until the next run's build.sh fails to overwrite
    # it with "Text file busy".
    #
    # It takes both of the conditions below to lose the pid, which is why this
    # is easy to get wrong by testing only one of them (measured, bash 5.2):
    #
    #   traps   body            `$!` is
    #   none    single command  the command   (bash collapses `( cmd ) &`)
    #   none    cd; command     the command   (last-command exec applies)
    #   set     single command  the command   (collapsed before traps matter)
    #   set     cd; command     THE SUBSHELL  <- this script
    #
    # A trap that must still run after the last command is what disables the
    # exec-in-place, and a body that does something first is what stops the
    # whole subshell being collapsed instead. This function has a `cd` and its
    # callers install four traps, so `exec` is the only thing making `$!` the
    # simulator.
    (
        cd "$SIMULATOR_DIR" || exit 1
        exec ./dstack-simulator >"$SIMULATOR_LOG" 2>&1
    ) &
    SIMULATOR_PID=$!

    simulator_wait_for_socket "$DSTACK_SOCKET" "dstack"
    simulator_wait_for_socket "$TAPPD_SOCKET" "tappd"
}
