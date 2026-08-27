# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Ported from test-run/test_suite.sh. Each test keeps the assertions it had;
# what changed is how nodes are started, stopped and reset.

# Nothing to clean: the runner gave this test a compose project of its own, so
# its containers and its data directory are new. Kept as a no-op so each test
# still reads as declaring where it starts from.
cleanup_cluster() { :; }

# ------------------------------------------------------------------ quick

test_persistence() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1

    sleep 2
    local keys_after_write
    keys_after_write=$(get_n_keys 1)
    log_info "keys after startup: $keys_after_write"

    stop_node 1
    start_node 1 || return 1

    local keys_after_restart
    keys_after_restart=$(get_n_keys 1)
    log_info "keys after restart: $keys_after_restart"

    # get_n_keys ends in `|| echo 0`, so an unreachable node reports zero keys
    # rather than failing. Without this guard a node that never wrote anything
    # gives 0 >= 0 and the test passes having proved nothing -- the same shape
    # as the empty-store digest match that made test_ephemeral_recovery hollow.
    [ "${keys_after_write:-0}" -gt 0 ] 2>/dev/null || {
        log_error "nothing was in the store before the restart, so surviving it proves nothing: keys=${keys_after_write:-0}"
        return 1; }
    if [ "$keys_after_restart" -ge "$keys_after_write" ] 2>/dev/null; then
        return 0
    fi
    log_error "expected >= $keys_after_write keys, got $keys_after_restart"
    return 1
}

test_status_endpoint() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1

    admin_wavekv_status 1 | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert d['enabled'] is True, 'enabled should be True'
assert 'persistent' in d, 'missing persistent'
assert 'ephemeral' in d, 'missing ephemeral'
assert d['persistent']['wal_enabled'] is True, 'persistent wal should be enabled'
assert d['ephemeral']['wal_enabled'] is False, 'ephemeral wal should be disabled'
assert 'peers' in d['persistent'], 'missing peers in persistent'
"
}

test_prpc_register() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1

    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local response
    response=$(debug_register_cvm 1 "$(test_public_key 501)" deadbeef cafebabe)
    verify_register_response "$response" >/dev/null || {
        log_error "RegisterCvm did not return a client_ip"; return 1; }
}

test_prpc_info() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1

    local ca port
    ca=$(export_ca_cert 1) || { log_error "could not read the node's CA certificate"; return 1; }
    port=$(rpc_port 1) || return 1

    curl -s --cacert "$ca" --resolve "gateway-1:${port}:127.0.0.1" \
        -X POST "https://gateway-1:${port}/prpc/Info" \
        -H "Content-Type: application/json" -d '{}' 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d:
    print(f'ERROR: {d[\"error\"]}', file=sys.stderr)
    sys.exit(1)
assert 'base_domain' in d, 'missing base_domain'
assert 'external_port' in d, 'missing external_port'
"
}

test_wal_integrity() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1

    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local i key response success=0
    for i in $(seq 1 5); do
        key=$(test_public_key $((800 + i)))
        response=$(debug_register_cvm 1 "$key" "wal_app$i" "wal_inst$i")
        verify_register_response "$response" >/dev/null 2>&1 && success=$((success + 1))
    done
    [ "$success" -eq 5 ] || { log_error "registered only $success/5 clients"; return 1; }

    # The WAL has to exist and be non-empty: a store that silently stopped
    # journalling would still answer every RPC above.
    local wal_size
    wal_size=$(data_op "stat -c%s /data/node1/wavekv/node_1.wal 2>/dev/null || echo 0" | tr -d '\r')
    log_info "WAL size: ${wal_size} bytes"
    [ "${wal_size:-0}" -gt 0 ] 2>/dev/null
}

# ------------------------------------------------------------------- sync

# Two nodes must learn each other's address and node record, in both directions.
test_multi_node_sync() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 10

    local ok=0
    has_peer_addr 1 2 || { log_error "node 1 missing peer_addr for node 2"; ok=1; }
    has_peer_addr 2 1 || { log_error "node 2 missing peer_addr for node 1"; ok=1; }
    has_node_info 1 2 || { log_error "node 1 missing node_info for node 2"; ok=1; }
    has_node_info 2 1 || { log_error "node 2 missing node_info for node 1"; ok=1; }
    return $ok
}

# A node that was down has to catch up once it is back.
test_node_recovery() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 5

    stop_node 2
    sleep 3
    start_node 2 || return 1
    setup_peers 1 2
    sleep 10

    local ok=0
    has_peer_addr 2 1 || { log_error "node 2 missing peer_addr for node 1 after recovery"; ok=1; }
    has_node_info 2 1 || { log_error "node 2 missing node_info for node 1 after recovery"; ok=1; }
    return $ok
}

# A CVM registered on one node must appear on the other, and each node's two
# views of it -- the replicated store and the proxy's own state -- must agree.
test_cross_node_data_sync() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 5

    check_debug_service 1 || { log_error "debug service not available on node 1"; return 1; }

    local client_ip
    client_ip=$(verify_register_response \
        "$(debug_register_cvm 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" app1 inst1)")
    [ -n "$client_ip" ] || { log_error "registration failed"; return 1; }

    sleep 20
    local kv1 kv2 ps1 ps2 ok=0
    kv1=$(get_n_instances 1); kv2=$(get_n_instances 2)
    ps1=$(get_n_proxy_state_instances 1); ps2=$(get_n_proxy_state_instances 2)

    { [ "$kv1" -ge 1 ] && [ "$kv2" -ge 1 ]; } || {
        log_error "KvStore sync failed: kv1=$kv1 kv2=$kv2"; ok=1; }
    { [ "$ps1" -ge 1 ] && [ "$ps2" -ge 1 ]; } || {
        log_error "ProxyState sync failed: ps1=$ps1 ps2=$ps2"; ok=1; }
    [ "$kv1" -eq "$ps1" ] || { log_error "node 1 inconsistent: KvStore=$kv1 ProxyState=$ps1"; ok=1; }
    [ "$kv2" -eq "$ps2" ] || { log_error "node 2 inconsistent: KvStore=$kv2 ProxyState=$ps2"; ok=1; }
    return $ok
}

# An opportunistic push must land well inside the 5s periodic interval.
test_push_fast_path() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 6

    local before
    before=$(get_n_instances 2)
    verify_register_response \
        "$(debug_register_cvm 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" push_app push_instance)" \
        >/dev/null || return 1

    # 3s < the 5s periodic interval, so arriving in time is what proves the push
    # path ran rather than the anti-entropy round that would have caught it anyway.
    wait_for_instances 2 $((before + 1)) 3 || {
        log_error "node 2 did not receive the write before the periodic interval"; return 1; }
    wait_for_digest_match persistent 1 2 3 || {
        log_error "persistent digests did not converge after push"; return 1; }
}

# A write made while a peer was down must still reach it, via the periodic round.
test_periodic_repair_after_missed_push() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 6

    local before
    before=$(get_n_instances 2)
    stop_node 2
    verify_register_response \
        "$(debug_register_cvm 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" repair_app repair_instance)" \
        >/dev/null || return 1
    sleep 1
    start_node 2 || return 1
    setup_peers 1 2

    wait_for_instances 2 $((before + 1)) 15 || {
        log_error "periodic sync did not repair the missed write"; return 1; }
}

# Losing the local store must not cost the node its identity, and it must
# refill from the peer rather than come back empty.
test_bootstrap_after_data_dir_loss() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 "https://gateway-1:9012"
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 6

    verify_register_response \
        "$(debug_register_cvm 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" bootstrap_app bootstrap_instance)" \
        >/dev/null || return 1
    wait_for_instances 2 1 10 || return 1

    local old_uuid new_uuid
    old_uuid=$(get_node_uuid 2)
    { [ -n "$old_uuid" ] && [ "$old_uuid" != "null" ]; } || {
        log_error "node 2 did not report its identity before recovery"; return 1; }

    stop_node 2
    wipe_data_keeping_uuid 2 || return 1
    start_node 2 || return 1

    wait_for_instances 2 1 15 || {
        log_error "node 2 did not bootstrap after losing its local store"; return 1; }
    # get_store_digest ends in `|| true`, so an unreachable node yields an empty
    # string and empty equals empty. wait_for_instances above speaks for node 2;
    # nothing has spoken for node 1, so check both are non-empty before
    # concluding anything from their being equal.
    local d1 d2
    d1=$(get_store_digest 1 persistent); d2=$(get_store_digest 2 persistent)
    { [ -n "$d1" ] && [ -n "$d2" ]; } || {
        log_error "could not read both digests, so comparing them proves nothing: node1='${d1}' node2='${d2}'"
        return 1; }
    [ "$d1" = "$d2" ] || {
        log_error "persistent digests differ after bootstrap: node1='${d1}' node2='${d2}'"; return 1; }

    setup_peers 1 2
    sleep 6
    new_uuid=$(get_node_uuid 2)
    { [ -n "$new_uuid" ] && [ "$new_uuid" != "null" ]; } || {
        log_error "node 2 did not report its post-recovery identity"; return 1; }
    [ "$old_uuid" = "$new_uuid" ] || {
        log_error "losing the WaveKV store unexpectedly changed the node UUID"; return 1; }
}

# Writes made on both sides of a partition must both survive the merge.
test_divergent_partition_writes() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 6

    stop_node 2
    verify_register_response \
        "$(debug_register_cvm 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" left_app left_instance)" \
        >/dev/null || return 1

    stop_node 1
    start_node 2 || return 1
    verify_register_response \
        "$(debug_register_cvm 2 "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=" right_app right_instance)" \
        >/dev/null || return 1

    start_node 1 || return 1
    setup_peers 1 2
    { wait_for_instances 1 2 15 && wait_for_instances 2 2 15; } || {
        log_error "divergent partition writes did not merge"; return 1; }
    wait_for_digest_match persistent 1 2 10 || {
        log_error "persistent digests did not converge after divergent writes"; return 1; }
}

# Writes that land while a periodic round is in flight must neither be lost nor
# counted twice.
test_push_periodic_overlap() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 4

    local before i
    before=$(get_n_instances 1)
    for i in $(seq 1 6); do
        verify_register_response \
            "$(debug_register_cvm 1 "$(test_public_key $((100 + i)))" "overlap_app_$i" "overlap_instance_$i")" \
            >/dev/null || { log_error "overlap write $i was rejected"; return 1; }
        sleep 0.2
    done

    wait_for_instances 2 $((before + 6)) 15 || {
        log_error "writes racing periodic sync did not arrive"; return 1; }
    [ "$(get_n_instances 1)" -eq $((before + 6)) ] || {
        log_error "overlapping push and sync produced duplicate instances"; return 1; }
    wait_for_digest_match persistent 1 2 10
}

# A node whose bootnode is not up yet must keep retrying and still converge.
test_delayed_bootnode_recovery() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 "https://gateway-1:9012"
    start_node 2 || return 1
    verify_register_response \
        "$(debug_register_cvm 2 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" delayed_app delayed_instance)" \
        >/dev/null || return 1

    sleep 2
    start_node 1 || return 1

    local _
    for _ in $(seq 1 25); do
        has_peer_addr 1 2 && has_peer_addr 2 1 && break
        sleep 1
    done
    { has_peer_addr 1 2 && has_peer_addr 2 1; } || {
        log_error "bootnode retry did not form the cluster"; return 1; }
    wait_for_instances 1 1 15 || {
        log_error "data did not converge after delayed bootnode recovery"; return 1; }
}

# Killing a node mid-sync must not wedge it; the next round has to finish the job.
test_interrupted_sync_recovery() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 6

    stop_node 2
    local i
    for i in $(seq 1 20); do
        verify_register_response \
            "$(debug_register_cvm 1 "$(test_public_key $((200 + i)))" "interrupt_app_$i" "interrupt_instance_$i")" \
            >/dev/null || { log_error "interrupted-sync fixture write $i was rejected"; return 1; }
    done

    # Bring it up, let a sync begin, then cut it off again. The exact instant
    # does not matter -- what is asserted is that the following round still
    # converges, not that the cut landed at a particular byte.
    start_node 2 || return 1
    setup_peers 1 2
    sleep 0.2
    stop_node 2

    start_node 2 || return 1
    setup_peers 1 2
    wait_for_instances 2 20 20 || {
        log_error "sync did not recover after interruption"; return 1; }
    wait_for_digest_match persistent 1 2 10
}

# The ephemeral store is not journalled, so after a restart it has to be rebuilt
# from peers rather than read back from disk.
test_ephemeral_recovery() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 8

    stop_node 2
    sleep 2
    start_node 2 || return 1
    setup_peers 1 2

    local keys1 keys2 _
    for _ in $(seq 1 20); do
        keys1=$(debug_get_sync_data 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['ephemeral_keys'])" 2>/dev/null || echo 0)
        keys2=$(debug_get_sync_data 2 | python3 -c "import sys,json; print(json.load(sys.stdin)['ephemeral_keys'])" 2>/dev/null || echo 0)
        { [ "${keys1:-0}" -gt 0 ] && [ "${keys2:-0}" -gt 0 ]; } && break
        sleep 1
    done

    # Assert what the loop above only waited for. Matching digests are not
    # enough on their own: two nodes that never found each other both hold an
    # empty ephemeral store, and empty matches empty. Stubbing out setup_peers
    # left this test green, which is how the gap was found.
    { [ "${keys1:-0}" -gt 0 ] && [ "${keys2:-0}" -gt 0 ]; } || {
        log_error "ephemeral stores are empty, so a digest match proves nothing: keys1=${keys1:-0} keys2=${keys2:-0}"
        return 1; }

    wait_for_digest_match ephemeral 1 2 15 || {
        log_error "ephemeral store did not converge after restart"; return 1; }
}

# A joining node must be able to bootstrap from the one peer that is up, even
# though another cluster member is unreachable.
test_partial_cluster_bootstrap() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    generate_config 3 "https://gateway-1:9012"
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 6

    verify_register_response \
        "$(debug_register_cvm 1 "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" partial_app partial_instance)" \
        >/dev/null || { log_error "node 1 rejected the registration"; return 1; }
    # 15s, not 10: every comparable wait in this suite allows 15, and this one
    # is a peer sync over a link that setup_peers has only just established.
    wait_for_instances 2 1 15 || {
        log_error "node 2 never saw the instance registered on node 1"; return 1; }

    stop_node 2
    start_node 3 || return 1
    wait_for_instances 3 1 20 || {
        log_error "node 3 did not bootstrap while node 2 was unavailable"; return 1; }
}

# A node that lost its identity but kept its node id must be rejected on the
# first exchange, must not cost the established peer any data, and must then be
# allowed to rejoin under its new identity rather than staying wedged.
test_node_id_reuse_rejected() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 10

    has_peer_addr 1 2 || { log_error "node 1 missing peer_addr for node 2"; return 1; }
    has_peer_addr 2 1 || { log_error "node 2 missing peer_addr for node 1"; return 1; }

    verify_register_response \
        "$(debug_register_cvm 1 "$(test_public_key 400)" reuse_app reuse_fixture)" \
        >/dev/null || return 1
    wait_for_instances 2 1 10 || { log_error "node 2 did not receive the recovery fixture"; return 1; }

    local old_uuid new_uuid keys_before keys_after
    old_uuid=$(get_node_uuid 2)
    keys_before=$(get_n_keys 1)


    stop_node 2
    wipe_data 2 || return 1
    start_node 2 || return 1

    new_uuid=$(get_node_uuid 2)
    { [ -n "$old_uuid" ] && [ -n "$new_uuid" ] && [ "$old_uuid" != "$new_uuid" ]; } || {
        log_error "fresh node 2 did not receive a new UUID"; return 1; }

    setup_peers 1 2

    local seen=false log1 log2 _
    for _ in $(seq 1 15); do
        log1=$(dump_log 1); log2=$(dump_log 2)
        if grep -q "UUID mismatch" "$log1" "$log2" 2>/dev/null; then seen=true; break; fi
        sleep 1
    done
    [ "$seen" = true ] || { log_error "reused node ID was not rejected"; return 1; }

    # Deliberate deviation from the suite this was ported from, which compared
    # total key counts before and after and required the count not to drop.
    #
    # It does drop, by exactly one, and permanently: node 1 discards node 2's
    # superseded identity record, which is the correct thing to do with it.
    # Measured 9 -> 8, still 8 thirty seconds later, with the registered
    # instance present throughout. So the old assertion forbids a legitimate
    # deletion, and passed only when the replacement record happened to land
    # before the count was taken.
    #
    # What the test is actually about -- its own comment says "node 1's data is
    # still intact" -- is the replicated instance records, so assert on those.
    local instances_after
    instances_after=$(get_n_instances 1)
    [ "$instances_after" -ge 1 ] 2>/dev/null || {
        log_error "node 1 lost its registered instances after node 2 restarted with a reused ID: $instances_after"
        return 1; }
    log_info "node 1 keys ${keys_before} -> $(get_n_keys 1), instances ${instances_after}"

    wait_for_instances 2 1 20 || {
        log_error "fresh node did not recover after the UUID rejection"; return 1; }
    # 40s, not the 15 this asked for before.
    #
    # Recovery here needs the rejected node's fresh identity record to reach
    # node 1 in a sync *response* -- its own requests still fail node 1's
    # inbound check -- and then an anti-entropy round to carry the store, so it
    # costs several 5s intervals rather than one. Measured three times on an
    # idle machine: 16s, 17s, 18s.
    #
    # It passed at 15 only because the wait helpers used to count iterations
    # instead of seconds and so ran roughly twice as long as they claimed (see
    # `wait_until` in rpc.sh). With the timer made honest this became a coin
    # flip -- it passed on one full run and failed on the next. The number now
    # says what the operation needs, with headroom for a loaded runner.
    wait_for_digest_match persistent 1 2 40 || {
        log_error "stores did not converge after UUID recovery"; return 1; }

    verify_register_response \
        "$(debug_register_cvm 2 "$(test_public_key 401)" reuse_app post_recovery)" \
        >/dev/null || return 1
    wait_for_instances 1 2 15 || { log_error "post-recovery write did not propagate"; return 1; }
    wait_for_digest_match persistent 1 2 10
}

# --------------------------------------------------------------- advanced

# A registration must survive a restart, and the store must hold more than the
# handful of keys a bare node writes for itself.
test_client_registration_persistence() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1
    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local client_ip keys_before keys_after
    client_ip=$(verify_register_response \
        "$(debug_register_cvm 1 "$(test_public_key 502)" persist_app persist_inst)")
    [ -n "$client_ip" ] || { log_error "registration failed"; return 1; }

    keys_before=$(get_n_keys 1)
    stop_node 1
    start_node 1 || return 1
    keys_after=$(get_n_keys 1)

    { [ "$keys_after" -ge "$keys_before" ] && [ "$keys_before" -gt 2 ]; } || {
        log_error "keys_before=$keys_before keys_after=$keys_after"; return 1; }
}

test_stress_writes() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1
    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local i key app inst success=0
    for i in $(seq 1 10); do
        key=$(test_public_key $((600 + i)))
        app=$(printf "stressapp%02d" "$i")
        inst=$(printf "stressinst%02d" "$i")
        verify_register_response "$(debug_register_cvm 1 "$key" "$app" "$inst")" >/dev/null 2>&1 \
            && success=$((success + 1))
    done
    sleep 2

    local keys_after
    keys_after=$(get_n_keys 1)
    { [ "$success" -eq 10 ] && [ "$keys_after" -gt 2 ]; } || {
        log_error "success=$success keys_after=$keys_after"; return 1; }
}

# Writes accepted while the peer was gone must reach it afterwards, and each
# node's two views must still agree once they do.
test_network_partition() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 5
    check_debug_service 1 || { log_error "debug service not available on node 1"; return 1; }

    stop_node 2
    local i key success=0
    for i in $(seq 1 3); do
        key=$(test_public_key $((700 + i)))
        verify_register_response "$(debug_register_cvm 1 "$key" "partition_app$i" "partition_inst$i")" \
            >/dev/null 2>&1 && success=$((success + 1))
    done

    local kv1_during ps1_during
    kv1_during=$(get_n_instances 1)
    ps1_during=$(get_n_proxy_state_instances 1)

    start_node 2 || return 1
    setup_peers 1 2
    sleep 15

    local kv1 kv2 ps1 ps2 ok=0
    kv1=$(get_n_instances 1); kv2=$(get_n_instances 2)
    ps1=$(get_n_proxy_state_instances 1); ps2=$(get_n_proxy_state_instances 2)

    { [ "$success" -eq 3 ] && [ "$kv1_during" -ge 3 ]; } || {
        log_error "registration or KvStore write failed during partition"; ok=1; }
    [ "$kv2" -ge "$kv1_during" ] || {
        log_error "node 2 KvStore sync failed: kv2=$kv2 expected >= $kv1_during"; ok=1; }
    [ "$ps2" -ge "$kv1_during" ] || {
        log_error "node 2 ProxyState sync failed: ps2=$ps2 expected >= $kv1_during"; ok=1; }
    [ "$kv1" -eq "$ps1" ] || { log_error "node 1 inconsistent: KvStore=$kv1 ProxyState=$ps1"; ok=1; }
    [ "$kv2" -eq "$ps2" ] || { log_error "node 2 inconsistent: KvStore=$kv2 ProxyState=$ps2"; ok=1; }
    log_info "ps1_during=$ps1_during"
    return $ok
}

_three_node_views_agree() {
    local kv1 kv2 kv3 ps1 ps2 ps3 ok=0
    kv1=$(get_n_instances 1); kv2=$(get_n_instances 2); kv3=$(get_n_instances 3)
    ps1=$(get_n_proxy_state_instances 1); ps2=$(get_n_proxy_state_instances 2)
    ps3=$(get_n_proxy_state_instances 3)
    { [ "$kv1" -ge 1 ] && [ "$kv2" -ge 1 ] && [ "$kv3" -ge 1 ]; } || {
        log_error "KvStore sync failed: kv1=$kv1 kv2=$kv2 kv3=$kv3"; ok=1; }
    { [ "$ps1" -ge 1 ] && [ "$ps2" -ge 1 ] && [ "$ps3" -ge 1 ]; } || {
        log_error "ProxyState sync failed: ps1=$ps1 ps2=$ps2 ps3=$ps3"; ok=1; }
    { [ "$kv1" -eq "$ps1" ] && [ "$kv2" -eq "$ps2" ] && [ "$kv3" -eq "$ps3" ]; } || {
        log_error "inconsistency between KvStore and ProxyState"; ok=1; }
    return $ok
}

test_three_node_cluster() {
    cleanup_cluster
    generate_config 1 ""; generate_config 2 ""; generate_config 3 ""
    start_node 1 || return 1
    start_node 2 || return 1
    start_node 3 || return 1
    setup_peers 1 2 3
    sleep 10
    check_debug_service 1 || { log_error "debug service not available on node 1"; return 1; }

    verify_register_response \
        "$(debug_register_cvm 1 "$(test_public_key 503)" threenode_app threenode_inst)" \
        >/dev/null || { log_error "registration failed"; return 1; }
    sleep 20
    _three_node_views_agree
}

# The same shape, but the two joiners discover the cluster through a bootnode
# instead of being told about each other.
test_three_node_bootnode() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 "https://gateway-1:9012"
    generate_config 3 "https://gateway-1:9012"
    start_node 1 || return 1
    sleep 2
    start_node 2 || return 1
    start_node 3 || return 1
    sleep 15
    check_debug_service 1 || { log_error "debug service not available on node 1"; return 1; }

    verify_register_response \
        "$(debug_register_cvm 1 "$(test_public_key 504)" bootnode_app bootnode_inst)" \
        >/dev/null || { log_error "registration failed"; return 1; }
    sleep 20
    _three_node_views_agree
}

# The periodic persist must actually run -- and be seen to run -- and what it
# wrote must come back after a restart.
test_periodic_persistence() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1
    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local i key success=0
    for i in $(seq 1 3); do
        key=$(test_public_key $((900 + i)))
        verify_register_response "$(debug_register_cvm 1 "$key" "persist_app$i" "persist_inst$i")" \
            >/dev/null 2>&1 && success=$((success + 1))
    done
    [ "$success" -eq 3 ] || { log_error "registered only $success/3 clients"; return 1; }

    local keys_before keys_after log wal_size
    keys_before=$(get_n_keys 1)
    sleep 8

    log=$(dump_log 1)
    grep -q "periodic persist completed" "$log" || {
        log_error "periodic persist message not found in the log"; return 1; }

    wal_size=$(data_op "stat -c%s /data/node1/wavekv/node_1.wal 2>/dev/null || echo 0" | tr -d '\r')
    [ "${wal_size:-0}" -gt 0 ] 2>/dev/null || { log_error "WAL file missing or empty"; return 1; }
    log_info "WAL size after periodic persist: ${wal_size} bytes"

    stop_node 1
    start_node 1 || return 1
    keys_after=$(get_n_keys 1)
    [ "$keys_after" -ge "$keys_before" ] || {
        log_error "keys_before=$keys_before keys_after=$keys_after"; return 1; }
}

# ------------------------------------------------------------------ admin

test_admin_set_node_url() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1
    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local new_url="https://new-node2.example.com:8011" response stored
    response=$(admin_set_node_url 1 2 "$new_url")
    echo "$response" | grep -q '"error"' && { log_error "SetNodeUrl returned: $response"; return 1; }

    sleep 2
    stored=$(get_peer_url_from_sync 1 2)
    [ "$stored" = "$new_url" ] || {
        log_error "expected '$new_url', got '$stored'"; return 1; }
}

test_admin_set_node_status() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1
    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    admin_set_node_url 1 2 "https://node2.example.com:8011" >/dev/null
    sleep 1

    local response
    for state in down up; do
        response=$(admin_set_node_status 1 2 "$state")
        # Absence of "error" is not enough on its own: a request that never
        # reached the node yields an empty string, which contains no "error"
        # either, so a total connectivity failure would pass.
        [ -n "$response" ] || {
            log_error "SetNodeStatus($state) returned nothing at all"; return 1; }
        echo "$response" | grep -q '"error"' && {
            log_error "SetNodeStatus($state) returned: $response"; return 1; }
        sleep 1
    done

    # Kept as a warning, exactly as the original had it: whether an unknown
    # status is refused is not what this test is here to pin down.
    response=$(admin_set_node_status 1 2 invalid)
    echo "$response" | grep -q '"error"' || \
        log_warn "invalid status was not rejected (may be acceptable)"
    return 0
}

# A node marked down must not be handed to registering CVMs, and must be handed
# out again once it is back up.
test_node_status_register_exclude() {
    cleanup_cluster
    generate_config 1 ""
    generate_config 2 ""
    start_node 1 || return 1
    start_node 2 || return 1
    setup_peers 1 2
    sleep 5
    check_debug_service 1 || { log_error "debug service not available on node 1"; return 1; }

    admin_set_node_status 1 2 down >/dev/null
    sleep 2
    local response
    response=$(debug_register_cvm 1 "$(test_public_key 505)" downtest_app downtest_inst)
    verify_register_response "$response" >/dev/null || { log_error "registration failed"; return 1; }
    response_lists_gateway "$response" 2 && {
        log_error "node 2 (down) was included in the registration response"; return 1; }

    admin_set_node_status 1 2 up >/dev/null
    sleep 2
    response=$(debug_register_cvm 1 "$(test_public_key 506)" uptest_app uptest_inst2)
    response_lists_gateway "$response" 2 || {
        log_error "node 2 (up) was not included in the registration response"; return 1; }
}

# A node marked down must refuse to register CVMs itself.
test_node_status_register_reject() {
    cleanup_cluster
    generate_config 1 ""
    start_node 1 || return 1
    check_debug_service 1 || { log_error "debug service not available"; return 1; }

    local response
    response=$(debug_register_cvm 1 "$(test_public_key 507)" upnode_app upnode_inst)
    verify_register_response "$response" >/dev/null || {
        log_error "registration failed while the node was up"; return 1; }

    admin_set_node_status 1 1 down >/dev/null
    sleep 2
    response=$(debug_register_cvm 1 "$(test_public_key 508)" downnode_app downnode_inst)
    echo "$response" | grep -qi "error" || {
        log_error "registration was not rejected while the node is down"; return 1; }

    admin_set_node_status 1 1 up >/dev/null
    sleep 2
    response=$(debug_register_cvm 1 "$(test_public_key 509)" backup_app backup_inst)
    verify_register_response "$response" >/dev/null || {
        log_error "registration failed once the node was back up"; return 1; }
}
