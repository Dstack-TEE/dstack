#!/bin/bash

# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Compatibility regression: run released SDK test suites against a current agent.
#
# dstack 0.6.0 froze the unversioned guest-agent API at exactly what v0.5.11
# served (`DstackGuest` and `Worker` in agent_rpc.proto), so a released 0.5.x
# SDK keeps working against a 0.6 agent unchanged. This script is what makes
# that a testable claim rather than a promise: for each released tag it checks
# out the SDKs *as they shipped* and runs their own test suites against a
# simulator built from the CURRENT tree. Old client, new agent -- any drift in
# the frozen surface fails here.
#
# The simulator is always the current one. The SDKs are always the old ones.
# Nothing from the tag's tree is built into the agent, and nothing from the
# current tree is copied into the SDKs; the only thing crossing between them is
# the wire protocol, which is the whole subject of the test.
#
# Usage: sdk/compat/run-compat-tests.sh <tag> [<tag>...]
#   e.g. sdk/compat/run-compat-tests.sh v0.5.11
#        sdk/compat/run-compat-tests.sh v0.5.9 v0.5.11   # one simulator, both tags
#
# Any tag works, but check that the pair you pick differs: several release tags
# share an SDK tree byte for byte (v0.5.10 and v0.5.11 do), and running both
# reports one result twice.
#
# CI runs one tag per matrix job. Passing several tags locally builds and starts
# the simulator once and shares one Cargo target directory across them.
#
# ---------------------------------------------------------------------------
# Skip-list policy
# ---------------------------------------------------------------------------
#
# Each skip entry below names a behaviour 0.6.0 deliberately changed, with a
# pointer to where that decision is written down. Nothing else belongs there.
#
# A growing skip list is not maintenance: it is the signal that the frozen
# v0.5.11 surface has drifted, which is the one thing this job exists to catch.
# If an old test fails and you cannot point at a CHANGELOG entry or a spec that
# sanctions the change, it is a regression -- fix the agent, not this list.

set -Eeuo pipefail

COMPAT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SDK_DIR="$(cd "$COMPAT_DIR/.." && pwd -P)"
REPO_ROOT="$(cd "$SDK_DIR/.." && pwd -P)"

# shellcheck source=../simulator/lifecycle.sh
# shellcheck disable=SC1091  # the hook runs without -x, so it cannot follow this
source "$SDK_DIR/simulator/lifecycle.sh"

# Old SDK builds go to a target directory of their own: shared across tags so a
# second tag reuses the first one's dependency build, and kept out of the
# simulator's so the two workspaces neither thrash each other's artifacts nor
# leave the tag's build where `sdk/simulator/build.sh` looks for the binary.
# Applied only to the old Rust suite, never to the simulator build.
COMPAT_CARGO_TARGET_DIR="${COMPAT_CARGO_TARGET_DIR:-$REPO_ROOT/dstack/target/sdk-compat}"

WORKTREES=()

cleanup() {
    local worktree
    for worktree in "${WORKTREES[@]+"${WORKTREES[@]}"}"; do
        git -C "$REPO_ROOT" worktree remove --force "$worktree" 2>/dev/null || true
        rm -rf "$worktree"
    done
    WORKTREES=()
    simulator_stop
}

trap 'simulator_print_logs' ERR
trap cleanup EXIT INT TERM

usage() {
    echo "usage: ${BASH_SOURCE[0]} <tag> [<tag>...]" >&2
    echo "  e.g. ${BASH_SOURCE[0]} v0.5.10 v0.5.11" >&2
}

# ---------------------------------------------------------------------------
# Skip lists -- see the policy at the top of this file.
# ---------------------------------------------------------------------------

# All four lists are empty, and that is the result, not an oversight: the
# released suites pass in full against the 0.6.0 agent, so the freeze currently
# holds with no exceptions. Two 0.6.0 changes were expected to land here and
# did not -- but for different reasons, and only one of them is reassuring:
#
#   - `GetQuote` is Intel TDX only now (CHANGELOG, Changed). The simulator
#     serves a TDX quote, so it answers, which is what the released suites
#     assert. Genuinely covered: the suites exercise the path and agree.
#   - `EmitEvent` always fails now (CHANGELOG, Removed: "runtime RTMR3 events
#     are system-owned"). Rust, Go and JS never tested it. Python's
#     `assert_emit_event_behavior` asserts HTTP 400 whenever
#     DSTACK_SIMULATOR_ENDPOINT is set, because the simulator had no RTMR to
#     extend at v0.5.11 either -- so it asserts 400 whether the method works or
#     is a stub, and it would pass either way. Not covered. The absence of a
#     skip entry here says nothing about `EmitEvent`; do not read it as
#     evidence.
#
# Both point at CHANGELOG.md's `[Unreleased]` section -- 0.6.0 is not cut yet,
# so there is no `## [0.6.0]` heading to cite.
#
# Entries with spaces must be quoted; a bare word list splits on them.
#
# The four lists do NOT share matching semantics, so an entry cannot be moved
# between them unchanged:
#
#   RUST_SKIP    literal substring of the full test path (`cargo test --skip`).
#                Reaches `cargo test` only -- the two `cargo run --example`
#                invocations below cannot be skipped.
#   GO_SKIP      REGEXP over the test name (`go test -skip`), joined with `|`.
#   PYTHON_SKIP  literal nodeid prefix (`pytest --deselect`); pytest matches
#                with `startswith`, so `::test_foo` also takes `::test_foo_bar`.
#   JS_SKIP      REGEXP, woven into one negative-lookahead `--testNamePattern`.
#
# The two regexp lists interpolate entries unescaped: a `(`, `+` or `.` in an
# entry changes its meaning. Escape it, or the skip silently widens.

# Rust: `cargo test -- --skip <substring>`, matched against the full test path.
RUST_SKIP=(
)

# Go: `go test -skip <regexp>`, matched against the test name.
GO_SKIP=(
)

# Python: `pytest --deselect <file>::<test>`. Matched as a nodeid prefix, so
# `::test_foo` also deselects `::test_foo_bar` -- name the test exactly.
PYTHON_SKIP=(
)

# JS: vitest has no negative name filter, so the entries are woven into one
# negative-lookahead `--testNamePattern`. They are matched as substrings of the
# full test name, `describe` prefixes included.
JS_SKIP=(
)

run_rust_suite() {
    local sdk_root="$1"
    local skip_args=()
    local pattern

    for pattern in "${RUST_SKIP[@]+"${RUST_SKIP[@]}"}"; do
        skip_args+=(--skip "$pattern")
    done

    echo "=== rust ==="
    (
        cd "$sdk_root/rust"
        export CARGO_TARGET_DIR="$COMPAT_CARGO_TARGET_DIR"
        cargo test -- --show-output "${skip_args[@]+"${skip_args[@]}"}"
        # The examples are client exercises too: they drive the agent end to end
        # the way a README reader would.
        cargo run --example tappd_client_usage
        cargo run --example dstack_client_usage
    )
}

run_go_suite() {
    local sdk_root="$1"
    local skip_args=()
    local joined=""
    local pattern

    for pattern in "${GO_SKIP[@]+"${GO_SKIP[@]}"}"; do
        joined+="${joined:+|}$pattern"
    done
    if [[ -n "$joined" ]]; then
        skip_args+=(-skip "$joined")
    fi

    echo "=== go ==="
    (
        cd "$sdk_root/go"
        go clean -testcache
        go test -v "${skip_args[@]+"${skip_args[@]}"}" ./dstack
        DSTACK_SIMULATOR_ENDPOINT="$TAPPD_SIMULATOR_ENDPOINT" \
            go test -v "${skip_args[@]+"${skip_args[@]}"}" ./tappd
    )
}

run_python_suite() {
    local sdk_root="$1"
    local skip_args=()
    local pattern

    for pattern in "${PYTHON_SKIP[@]+"${PYTHON_SKIP[@]}"}"; do
        skip_args+=(--deselect "$pattern")
    done

    echo "=== python ==="
    (
        cd "$sdk_root/python"
        if ! command -v pdm >/dev/null 2>&1; then
            echo "Installing PDM..."
            pip install pdm
        fi
        pdm install --dev
        # `pdm run check` is deliberately not run: it lints the released SDK's
        # source with today's ruff and mypy, which says nothing about the agent's
        # wire surface and would fail on tool version drift alone.
        pdm run pytest "${skip_args[@]+"${skip_args[@]}"}"
    )
}

run_js_suite() {
    local sdk_root="$1"
    local name_args=()
    local joined=""
    local pattern

    for pattern in "${JS_SKIP[@]+"${JS_SKIP[@]}"}"; do
        joined+="${joined:+|}$pattern"
    done
    if [[ -n "$joined" ]]; then
        name_args+=(--testNamePattern "^(?!.*(?:$joined))")
    fi

    echo "=== js ==="
    (
        cd "$sdk_root/js"
        npm install
        npx vitest --run "${name_args[@]+"${name_args[@]}"}"
    )
}

run_tag() {
    local tag="$1"
    local worktree

    worktree="$(mktemp -d -t "dstack-sdk-compat-${tag}-XXXXXX")"
    WORKTREES+=("$worktree")
    git -C "$REPO_ROOT" worktree add --detach --quiet "$worktree" "refs/tags/$tag"

    echo
    echo "############################################################"
    echo "# $tag SDKs against the current agent"
    echo "#   sdks:      $worktree/sdk"
    echo "#   simulator: $DSTACK_SIMULATOR_ENDPOINT"
    echo "############################################################"

    run_rust_suite "$worktree/sdk"
    run_go_suite "$worktree/sdk"
    run_python_suite "$worktree/sdk"
    run_js_suite "$worktree/sdk"

    # Drop it now rather than at exit, so running several tags does not keep a
    # full checkout per tag on disk. `cleanup` retries harmlessly at exit.
    git -C "$REPO_ROOT" worktree remove --force "$worktree"
    rm -rf "$worktree"

    echo "--- $tag: all suites passed against the current agent"
}

main() {
    if [[ $# -lt 1 ]]; then
        usage
        exit 2
    fi

    local tag
    for tag in "$@"; do
        if ! git -C "$REPO_ROOT" rev-parse --verify --quiet "refs/tags/$tag^{commit}" >/dev/null; then
            echo "unknown tag: $tag -- fetch tags first (git fetch --tags)" >&2
            exit 1
        fi
    done

    simulator_start

    for tag in "$@"; do
        run_tag "$tag"
    done

    echo
    echo "compat: $* passed against the agent in $REPO_ROOT"
}

main "$@"
