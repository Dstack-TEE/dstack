#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Host-side driver for the gateway proxy data-path suite.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_RUN_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

FIXTURE_NS="dstack-fixture-proxy"
export FIXTURE_NS

SKIP_BUILD=""
case "${1:-}" in
    --skip-build) SKIP_BUILD="--skip-build" ;;
    down)
        docker compose -f "$SCRIPT_DIR/docker-compose.yml" down -v --remove-orphans
        # The fixture too: it is a project of its own, so a suite-only teardown
        # leaves it and its global network and volumes on the runner forever.
        docker compose -p "$FIXTURE_NS" -f "$TEST_RUN_DIR/attestation/fixture.yml" \
            down -v --remove-orphans >/dev/null 2>&1 || true
        exit 0 ;;
    -h|--help) echo "Usage: $0 [--skip-build] | down"; exit 0 ;;
    "") ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
esac

# The suite needs the gateway binary and its own copies of the scripts in the
# build context.
"$TEST_RUN_DIR/build-gateway-image.sh" "$SCRIPT_DIR" $SKIP_BUILD >/dev/null
cp "$TEST_RUN_DIR/test_proxy.sh" "$SCRIPT_DIR/test_proxy.sh"
rm -rf "$SCRIPT_DIR/proxy" && cp -r "$TEST_RUN_DIR/proxy" "$SCRIPT_DIR/proxy"

# Two runs share one compose project, one set of container names and one work
# directory, so a second run tears down what the first is using. The damage does
# not look like a collision -- it looks like flaky tests, because state vanishes
# mid-run. Refuse to start instead.
# Locked on the directory, not on a file inside it. Deleting a lock FILE does
# not release the lock, it detaches it: the holder keeps its inode while the
# next run creates a fresh one and flocks that successfully. Three runs of the
# cluster suite overlapped exactly that way -- each wiping the others' state,
# with the failures reading as flaky sync rather than as a collision -- because
# a "clean up before rerunning" step had removed the lock file by name.
mkdir -p "$SCRIPT_DIR/run"
exec 9<"$SCRIPT_DIR/run"
if ! flock -n 9; then
    echo "[ERROR] another run of this suite is already in progress ($SCRIPT_DIR/run)" >&2
    exit 1
fi

compose() { docker compose -f "$SCRIPT_DIR/docker-compose.yml" "$@"; }

# The attestation fixture, namespaced to this suite.
#
# Each suite runs its own copy rather than sharing one project. The seed that
# signs quotes and the seed that derives the verifying roots come from files in
# `attestation/`, so separate instances agree by construction -- while a shared
# instance meant whichever suite finished first tore it down under the others,
# and meant the three CI workflows could not run at the same time.
fixture_compose() {
    docker compose -p "$FIXTURE_NS" -f "$TEST_RUN_DIR/attestation/fixture.yml" "$@"
}

# Both arms share one work directory; wipe it so a run never reads a previous
# run's logs. Two things this cannot do:
#
#   - `rm -rf` it from the host. The suite container runs as root, so the certs
#     and logs it leaves behind are root-owned and the host cannot remove them.
#     The whole suite died here on its second local run, before a single
#     assertion, with a wall of "Permission denied". CI never saw it because a
#     fresh runner has no previous run to clean up. A throwaway container has
#     the privileges the host lacks.
#
#   - remove the directory ITSELF. `run` is what the lock above is held on, and
#     replacing it with a fresh mkdir would detach that lock exactly the way a
#     deleted lock file does -- the failure this suite's lock was just changed
#     to prevent. Clear the contents and keep the inode.
mkdir -p "$SCRIPT_DIR/run"
docker run --rm -v "$SCRIPT_DIR/run:/r" alpine:latest \
    find /r -mindepth 1 -delete >/dev/null 2>&1 || true

# Probed BEFORE the trap is installed. Reading it next to the `up` further down
# meant any failure in between ran cleanup with the variable unset, took the
# `:-0` default, and tore down a fixture another suite was using.
FIXTURE_WAS_UP=$(fixture_compose ps -q 2>/dev/null | wc -l)

cleanup() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    # Only if this run started it. The fixture is meant to outlive a single
    # suite; tearing down one this run found already up is what made the next
    # run fail with "network dstack-attestation declared as external, but could
    # not be found".
    if [ "${FIXTURE_WAS_UP:-0}" -eq 0 ]; then
        fixture_compose down -v --remove-orphans 2>/dev/null || true
    fi >/dev/null 2>&1 || true
}
trap cleanup EXIT

compose build
fixture_compose build >/dev/null
echo "[INFO] starting the attestation fixture" >&2
fixture_compose up -d --wait >/dev/null

# `set -e` is on, so a bare call aborts the script the moment an arm fails and
# `$?` is never read -- both variables could only ever be 0 and the comparison
# below was a tautology. Worse, the no-TLS-ULP arm was skipped on exactly the
# runs where something was already wrong, and that arm is the only place the
# kTLS truncation regression is covered. Capture the status instead.
echo "[INFO] running the proxy suite" >&2
MAIN_RC=0
compose run --rm proxy-tests || MAIN_RC=$?

echo "[INFO] running the no-TLS-ULP arm" >&2
NOTLS_RC=0
compose run --rm proxy-tests-notls || NOTLS_RC=$?

# Readable by the host: the suite runs as root in the container and writes into
# the bind-mounted work directory, so CI cannot collect what it cannot open.
docker run --rm -v "$SCRIPT_DIR/run:/r" alpine:latest \
    chmod -R a+rX /r >/dev/null 2>&1 || true

echo "[INFO] proxy-tests exit=$MAIN_RC  proxy-tests-notls exit=$NOTLS_RC" >&2
[ "$MAIN_RC" -eq 0 ] && [ "$NOTLS_RC" -eq 0 ]
