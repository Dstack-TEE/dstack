#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

# Gateway cluster (WaveKV) integration suite, driven from the host.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
# shellcheck source=rpc.sh
source "$SCRIPT_DIR/rpc.sh"
# shellcheck source=tests.sh
source "$SCRIPT_DIR/tests.sh"

SKIP_BUILD=""
KEEP_RUNNING=false
ONLY=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)   SKIP_BUILD="--skip-build"; shift ;;
        --keep-running) KEEP_RUNNING=true; shift ;;
        --only)         ONLY="$2"; shift 2 ;;
        down)
            # Every per-test project, not just the one CURRENT_TEST happens to
            # name, plus the shared fixture -- otherwise CI's teardown leaves
            # the fixture project and its global network and volumes behind on
            # any runner that outlives the job.
            down_all
            fixture_compose down -v --remove-orphans >/dev/null 2>&1 || true
            exit 0 ;;
        -h|--help)
            echo "Usage: $0 [--skip-build] [--keep-running] [--only <test>] | down"
            exit 0 ;;
        *) log_error "unknown option: $1"; exit 1 ;;
    esac
done

# Two runs of this suite share one compose project, one set of container names
# and one data directory, so a second run stops the containers the first is
# using and wipes the store out from under it. The result does not look like a
# collision -- it looks like flaky cross-node sync, because a node's writes
# vanish mid-test. Refuse to start instead.
# The lock is taken on the run directory itself, not on a file inside it.
# Deleting a lock FILE does not release the lock -- it detaches it: the holder
# keeps its inode while the next run creates a fresh one and flocks that
# successfully. Three runs of this suite overlapped that way, each wiping the
# others' state, and the failures read as flaky cross-node sync rather than as
# a collision. A directory is not something a cleanup step removes by name, and
# `rm -rf run/data run/configs run/logs` leaves it in place.
mkdir -p "$RUN_DIR"
exec 9<"$RUN_DIR"
if ! flock -n 9; then
    log_error "another run of this suite is already in progress ($RUN_DIR)"
    exit 1
fi

# No process-name guard beyond the lock. One was tried and false-positived on
# its own first run: `$(...)` forks a subshell whose argv is identical to the
# script's, so `pgrep -f` counted the check itself as a second instance. The
# directory lock above is the correct primitive -- it is race-free and needs no
# pattern matching.

cleanup() {
    $KEEP_RUNNING && return 0
    # The last test's project is still up; the fixture outlives them all.
    compose down -v --remove-orphans 2>/dev/null || true
    # Only if this run started it. The fixture is meant to outlive a single
    # suite; tearing down one this run found already up is what made the next
    # run fail with "network dstack-attestation declared as external, but could
    # not be found".
    if [ "${FIXTURE_WAS_UP:-0}" -eq 0 ]; then
        fixture_compose down -v --remove-orphans 2>/dev/null || true
    fi
}
trap cleanup EXIT

TESTS_PASSED=0
TESTS_FAILED=0
check() {
    local name="$1"; shift
    if "$@"; then
        log_success "$name"; TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "$name"; TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# ---------------------------------------------------------------- assertions

# Every node must see all three, on every node.
cluster_has_three_nodes() {
    local node_id=$1 port count
    port=$(debug_port "$node_id")
    count=$(curl -sf -X POST "http://127.0.0.1:${port}/prpc/Debug.GetSyncData" \
                -H 'Content-Type: application/json' -d '{}' 2>/dev/null \
            | python3 -c 'import sys,json; print(len(json.load(sys.stdin).get("nodes",[])))' 2>/dev/null) || return 1
    [ "$count" = "3" ]
}

# Positive evidence that the cluster's mTLS is real: the certificate a node
# serves carries the app_id extension its peers pin, which only happens when it
# was issued through the guest agent against a verifiable quote. Absence of
# errors would not prove this -- a validator that never ran is also silent.
cert_carries_app_id() {
    local node_id=$1
    data_op "cat /data/node${node_id}/certs/gateway-rpc.cert" 2>/dev/null \
        | openssl x509 -noout -text 2>/dev/null \
        | grep -q "1.3.6.1.4.1.62397.1.3"
}

# And the negative: no peer was ever turned away.
#
# Deliberately not matching "bootnode discovery retry failed". A node whose
# bootnode is not listening yet retries and succeeds, which is a startup race,
# not an authentication failure -- treating it as one made this assertion fail
# on whichever node happened to start first. Convergence is what proves the
# retry worked, and that is asserted separately.
no_peer_was_rejected() {
    local node_id=$1 log
    log=$(dump_log "$node_id")
    # `dump_log` ends in `|| true`, and `! grep -q` on an empty file is true, so
    # without this the assertion passed whenever the log could not be collected
    # at all -- the failure mode a negative assertion is most exposed to. Prove
    # there is something to have searched first.
    [ -s "$log" ] || { log_error "node ${node_id} produced no log to check"; return 1; }
    ! grep -qE "does not contain app_id|invalid quote|app_id mismatch" "$log"
}

# ---------------------------------------------------------------- main

log_info "=========================================="
log_info "dstack-gateway cluster suite"
log_info "=========================================="

# Discard anything a previous run left: node state is a bind mount that
# `compose down -v` does not remove and the host user cannot delete.
down_all
wipe_run_tree
mkdir -p "$DATA_DIR"

log_info "starting the attestation fixture"
fixture_compose build >/dev/null
fixture_compose up -d --wait >/dev/null

"$SCRIPT_DIR/../build-gateway-image.sh" "$SCRIPT_DIR" $SKIP_BUILD

log_info "building the suite image"
compose build >/dev/null

# The smoke checks get a project of their own for the same reason every test
# does: the first test's new_test_project tears down whatever came before it,
# and without this the smoke nodes were what it tore down.
#
# It has to come before the configs are written: config and data paths are named
# after CURRENT_TEST, so generating them first puts them where nothing looks.
new_test_project smoke

log_info "generating node configs"
generate_config 1 ""
generate_config 2 "https://gateway-1:9012"
generate_config 3 "https://gateway-1:9012"

log_info "starting the cluster"
compose up -d >/dev/null

for n in 1 2 3; do
    check "node $n debug service is up" wait_for_debug "$n" 90
done

log_info "waiting for the cluster to converge"
converged=false
for _ in $(seq 1 30); do
    if cluster_has_three_nodes 1 && cluster_has_three_nodes 2 && cluster_has_three_nodes 3; then
        converged=true; break
    fi
    sleep 2
done
$converged || log_warn "cluster did not converge within 60s"

for n in 1 2 3; do
    check "node $n sees all three nodes" cluster_has_three_nodes "$n"
    check "node $n serves a certificate carrying its app_id" cert_carries_app_id "$n"
    check "node $n rejected no peer" no_peer_was_rejected "$n"
done

# ------------------------------------------------------------- ported tests
#
# Every row here must also be ticked in the port checklist only once it has been
# seen to FAIL against a broken cluster. Green on its own proves nothing.
run_ported() {
    local name="$1"
    log_info "---------- $name ----------"
    new_test_project "$name"
    if "$name"; then
        log_success "$name"; TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        log_fail "$name"; TESTS_FAILED=$((TESTS_FAILED + 1))
        # Under one project per test the next test's new_test_project tears this
        # one down, so a failure's container logs are gone before anyone can
        # read them. Dumping them here is what makes a failure diagnosable at
        # all: test_partial_cluster_bootstrap failed with nothing in the suite
        # log but its own config lines, and there was no way to tell which step
        # had failed. An explicit `if` rather than `A && B`, because SC2015 has
        # already made a successful run exit non-zero once.
        for _n in 1 2 3; do
            if compose ps -q "gateway-${_n}" 2>/dev/null | grep -q .; then
                log_info "  saved log: $(dump_log "$_n")"
            fi
        done
    fi
}

ALL_TESTS=(test_persistence test_status_endpoint test_prpc_register \
         test_prpc_info test_wal_integrity \
         test_multi_node_sync test_node_recovery test_cross_node_data_sync \
         test_push_fast_path test_periodic_repair_after_missed_push \
         test_bootstrap_after_data_dir_loss test_divergent_partition_writes \
         test_push_periodic_overlap test_delayed_bootnode_recovery \
         test_interrupted_sync_recovery test_ephemeral_recovery \
         test_partial_cluster_bootstrap test_node_id_reuse_rejected \
         test_client_registration_persistence test_stress_writes \
         test_network_partition test_three_node_cluster \
         test_three_node_bootnode test_periodic_persistence \
         test_admin_set_node_url test_admin_set_node_status \
         test_node_status_register_exclude test_node_status_register_reject)

# An unknown --only name used to select nothing, leave TESTS_FAILED at 0 and
# exit 0: a green run of zero tests, which is the one result this suite must
# never produce.
if [ -n "$ONLY" ]; then
    printf '%s\n' "${ALL_TESTS[@]}" | grep -qx -- "$ONLY" || {
        log_error "unknown test: $ONLY"
        exit 1
    }
fi

for t in "${ALL_TESTS[@]}"; do
    [ -n "$ONLY" ] && [ "$t" != "$ONLY" ] && continue
    run_ported "$t"
done

log_info "=========================================="
log_info "Passed: $TESTS_PASSED"
log_info "Failed: $TESTS_FAILED"
log_info "=========================================="
[ "$TESTS_FAILED" -eq 0 ]
