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
#        sdk/compat/run-compat-tests.sh v0.5.8 v0.5.11   # one simulator, both tags
#
# Any tag works, but check that the pair you pick differs in the client, not
# just in the tree hash: v0.5.10 and v0.5.11 share an sdk/ tree byte for byte,
# and v0.5.9 differs from v0.5.11 only by a dependency spec in
# sdk/rust/Cargo.toml. Running either pair reports one result twice.
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
    echo "  e.g. ${BASH_SOURCE[0]} v0.5.8 v0.5.11" >&2
}

# ---------------------------------------------------------------------------
# Skip lists -- see the policy at the top of this file.
# ---------------------------------------------------------------------------

# The lists are keyed by tag, and that is not incidental. A skip is a claim
# about one released client, not about the frozen surface in general, and the
# two tags in the matrix disagree about the same method: `test_emit_event`
# exists under that name at both, but at v0.5.8 it asserts the call succeeds
# and at v0.5.11 it asserts HTTP 400. A single global entry would silence both
# and hide which one was a real break.
#
# What the current entries say: of the two 0.6.0 changes to the frozen surface,
# one is genuinely agreed on and the other is the single sanctioned break.
#
#   - `GetQuote` is Intel TDX only now (CHANGELOG, Changed). The simulator
#     serves a TDX quote, so it answers, which is what the released suites
#     assert. Genuinely covered at both tags: they exercise the path and agree.
#   - `EmitEvent` always fails now (CHANGELOG, Removed: "runtime RTMR3 events
#     are system-owned"). Caught only at v0.5.8, whose entries are below.
#     Every v0.5.11 assertion about it is vacuous under a simulator endpoint:
#     Go and JS never test it; `assert_emit_event_behavior` asserts 400
#     whenever DSTACK_SIMULATOR_ENDPOINT is set, so it holds whether the method
#     works or is a stub; and the example swallows the error under the same
#     condition. Those three accommodations were added in v0.5.9..v0.5.11
#     ("fix(ci): restore simulator test stability") to make the suite pass
#     against a simulator that could not extend an RTMR. v0.5.8 predates them
#     and still asserts the call succeeds, which is why it is in the matrix.
#
# Both point at CHANGELOG.md's `[Unreleased]` section -- 0.6.0 is not cut yet,
# so there is no `## [0.6.0]` heading to cite.
#
# The lists do NOT share matching semantics, so an entry cannot be moved
# between them unchanged:
#
#   RUST_SKIP          literal substring of the full test path
#                      (`cargo test --skip`). Reaches `cargo test` only.
#   RUST_EXAMPLE_SKIP  exact example name. `cargo run --example` has no name
#                      filter, so the unit is the whole example binary rather
#                      than one call inside it -- say what the skip costs.
#   GO_SKIP            REGEXP over the test name (`go test -skip`), joined
#                      with `|`.
#   PYTHON_SKIP        literal nodeid prefix (`pytest --deselect`); pytest
#                      matches with `startswith`, so `::test_foo` also takes
#                      `::test_foo_bar` -- name the test exactly.
#   JS_SKIP            REGEXP, woven into one negative-lookahead
#                      `--testNamePattern`, matched as a substring of the full
#                      test name with `describe` prefixes included.
#
# The two regexp lists interpolate entries unescaped: a `(`, `+` or `.` in an
# entry changes its meaning. Escape it, or the skip silently widens.
#
# Entries with spaces must be quoted; a bare word list splits on them.

# The Rust examples the compat run drives, in order. They are client exercises
# too: they walk the agent end to end the way a README reader would, which is
# how the v0.5.8 break below was found.
RUST_EXAMPLES=(tappd_client_usage dstack_client_usage)

# Sets the five lists for one tag. Called once per tag, before its suites run;
# every list is reset here, so a tag with no entries clears the previous tag's.
set_skips_for_tag() {
    RUST_SKIP=()
    RUST_EXAMPLE_SKIP=()
    GO_SKIP=()
    PYTHON_SKIP=()
    JS_SKIP=()

    case "$1" in
        v0.5.8)
            # `EmitEvent` was removed in 0.6.0 -- CHANGELOG.md,
            # `[Unreleased]` / Removed: "runtime RTMR3 events are system-owned
            # and cannot be extended by apps". v0.5.8 is the newest released
            # client that still expects it to work -- in Python, which asserts
            # the call succeeds, and in a Rust example, which propagates the
            # error with `?`.
            #
            # This is what a sanctioned break looks like from the outside: a
            # released client called a method that no longer exists and cannot
            # be edited to stop. These entries record that the break is
            # deliberate; they do not make the client work.

            # The first two assert the call raises nothing ("This should not
            # raise an error"); both now raise HTTPStatusError 400.
            #
            # The third is collateral, not a break, and it is listed because
            # pytest deselects by nodeid *prefix*: an entry for
            # `::test_emit_event` takes `::test_emit_event_validation` with it
            # whether or not it is named here. Listing it keeps this list equal
            # to what the run actually skips -- otherwise pytest reports "3
            # deselected" against two entries and the difference is invisible.
            # It costs nothing: it asserts client-side rejection of an empty
            # event name, raises before any request is built, and never
            # contacts the agent. The equivalent client-side validation still
            # runs in the Rust, Go and JS suites.
            PYTHON_SKIP=(
                "tests/test_client.py::test_emit_event"
                "tests/test_client.py::test_sync_emit_event"
                "tests/test_client.py::test_emit_event_validation"
            )

            # `dstack_client_usage` step 4 calls `emit_event(...).await?`, so
            # the whole example exits non-zero. Cost of skipping the binary:
            # nothing that is not still checked -- its other four steps (Info,
            # GetKey, GetQuote, GetTlsKey) are each covered by
            # `tests/test_client.rs`, which runs unskipped in this same leg.
            RUST_EXAMPLE_SKIP=(dstack_client_usage)
            ;;
        v0.5.11)
            # Nothing skipped: every released test and example passes against
            # the 0.6.0 agent. Note what that does and does not mean -- see the
            # `EmitEvent` note above for the three assertions that pass here
            # without exercising anything.
            ;;
    esac
}

# Exact-match membership test: `[[ $x == $y ]]` on each element rather than a
# substring search over a joined string, so an entry `foo` cannot also skip
# `foobar`.
contains_element() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

run_rust_suite() {
    local sdk_root="$1"
    local tag="$2"
    local skip_args=()
    local pattern
    local example

    for pattern in "${RUST_SKIP[@]+"${RUST_SKIP[@]}"}"; do
        skip_args+=(--skip "$pattern")
    done

    echo "=== rust ==="
    (
        cd "$sdk_root/rust"
        export CARGO_TARGET_DIR="$COMPAT_CARGO_TARGET_DIR"
        cargo test -- --show-output "${skip_args[@]+"${skip_args[@]}"}"
        for example in "${RUST_EXAMPLES[@]}"; do
            if contains_element "$example" \
                "${RUST_EXAMPLE_SKIP[@]+"${RUST_EXAMPLE_SKIP[@]}"}"; then
                echo "--- skipping example $example at $tag (see set_skips_for_tag)"
                continue
            fi
            cargo run --example "$example"
        done
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

    set_skips_for_tag "$tag"

    run_rust_suite "$worktree/sdk" "$tag"
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
