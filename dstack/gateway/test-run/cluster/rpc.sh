# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# RPC helpers for the cluster suite.
#
# These take a node id rather than a port. The process-based suite passed ports
# around because they were fixed and computable; here docker assigns them, so
# resolving one is a lookup and every caller would otherwise have to do it.

debug_call() {
    local node_id=$1
    local method=$2
    local body=${3:-'{}'}
    local port
    port=$(debug_port "$node_id") || return 1
    curl -s -X POST "http://127.0.0.1:${port}/prpc/${method}" \
        -H "Content-Type: application/json" -d "$body" 2>/dev/null
}

admin_call() {
    local node_id=$1
    local method=$2
    local body=${3:-'{}'}
    local port
    port=$(admin_port "$node_id") || return 1
    curl -s -X POST "http://127.0.0.1:${port}/prpc/${method}" \
        -H "Content-Type: application/json" -d "$body" 2>/dev/null
}

json_field() { python3 -c "$1" 2>/dev/null; }

check_debug_service() {
    debug_call "$1" Debug.Info \
        | json_field "import sys,json; d=json.load(sys.stdin); assert 'base_domain' in d"
}

debug_get_sync_data() { debug_call "$1" Debug.GetSyncData; }

# A WireGuard public key is 32 bytes; derive a distinct one per seed so
# registrations do not collide.
test_public_key() {
    python3 -c "import base64; print(base64.b64encode(int($1).to_bytes(32, 'big')).decode())"
}

debug_register_cvm() {
    local node_id=$1
    local public_key=$2
    local app_id=${3:-testapp}
    local instance_id=${4:-testinstance}
    debug_call "$node_id" RegisterCvm \
        "{\"client_public_key\": \"$public_key\", \"app_id\": \"$app_id\", \"instance_id\": \"$instance_id\"}"
}

# Prints the allocated client_ip, or fails.
verify_register_response() {
    echo "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    if 'error' in d:
        print(f'ERROR: {d[\"error\"]}', file=sys.stderr)
        sys.exit(1)
    assert 'wg' in d, 'missing wg config'
    assert 'client_ip' in d['wg'], 'missing client_ip'
    print(d['wg']['client_ip'])
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" 2>/dev/null
}

_sync_data_has() {
    local node_id=$1
    local collection=$2
    local peer_node_id=$3
    debug_get_sync_data "$node_id" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for entry in d.get('$collection', []):
        if entry.get('node_id') == $peer_node_id:
            sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
"
}

has_peer_addr() { _sync_data_has "$1" peer_addrs "$2"; }
has_node_info() { _sync_data_has "$1" nodes "$2"; }

get_n_instances() {
    debug_get_sync_data "$1" | python3 -c "
import sys, json
try:
    print(len(json.load(sys.stdin).get('instances', [])))
except Exception:
    print(0)
" 2>/dev/null
}

get_n_nodes() {
    debug_get_sync_data "$1" | python3 -c "
import sys, json
try:
    print(len(json.load(sys.stdin).get('nodes', [])))
except Exception:
    print(0)
" 2>/dev/null
}

# Two different endpoints, and conflating them silently breaks whatever reads
# the wrong one: WaveKvStatus carries the store digests and key counts, Status
# carries node identity and the peer list.
admin_wavekv_status() { admin_call "$1" Admin.WaveKvStatus; }
admin_status()        { admin_call "$1" Admin.Status; }

get_store_digest() {
    local node_id=$1
    local store=$2
    admin_wavekv_status "$node_id" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['$store']['digest'])" 2>/dev/null || true
}

# A node's own uuid, as it reports itself in its node list.
get_node_uuid() {
    local node_id=$1
    admin_status "$node_id" | python3 -c "
import sys, json
d = json.load(sys.stdin)
me = d.get('id')
for n in d.get('nodes', []):
    if n.get('id') == me:
        print(n.get('uuid', ''))
        break
" 2>/dev/null || true
}

admin_set_node_url() {
    admin_call "$1" Admin.SetNodeUrl "{\"id\": $2, \"url\": \"$3\"}"
}

# Peers address each other by container hostname, not by a published port: the
# gateways talk over the compose network, and only the driver goes through the
# host.
setup_peers() {
    local node_ids=("$@")
    local src dst
    for src in "${node_ids[@]}"; do
        for dst in "${node_ids[@]}"; do
            [ "$src" = "$dst" ] && continue
            admin_set_node_url "$src" "$dst" "https://gateway-${dst}:9012" >/dev/null
        done
    done
}

wait_for_instances() {
    local node_id=$1
    local expected=$2
    local timeout_seconds=$3
    local _
    for _ in $(seq 1 $((timeout_seconds * 10))); do
        [ "$(get_n_instances "$node_id")" -ge "$expected" ] 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

wait_for_digest_match() {
    local store=$1
    local node_a=$2
    local node_b=$3
    local timeout_seconds=$4
    local d1 d2 _
    for _ in $(seq 1 $((timeout_seconds * 10))); do
        d1=$(get_store_digest "$node_a" "$store")
        d2=$(get_store_digest "$node_b" "$store")
        if [ -n "$d1" ] && [ "$d1" = "$d2" ]; then return 0; fi
        sleep 0.1
    done
    return 1
}

get_n_keys() {
    admin_wavekv_status "$1" \
        | python3 -c "import sys,json; print(json.load(sys.stdin)['persistent']['n_keys'])" 2>/dev/null || echo 0
}

# The gateway writes its CA where only root can read it, so copy it out for the
# one test that validates the RPC chain rather than skipping verification.
export_ca_cert() {
    local node_id=$1
    local dest="$RUN_DIR/node${node_id}-ca.cert"
    data_op "cat /data/node${node_id}/certs/gateway-ca.cert" >"$dest" 2>/dev/null
    [ -s "$dest" ] || return 1
    echo "$dest"
}

get_n_peer_addrs() {
    debug_get_sync_data "$1" | python3 -c "
import sys, json
try:
    print(len(json.load(sys.stdin).get('peer_addrs', [])))
except Exception:
    print(0)
" 2>/dev/null
}

debug_get_proxy_state() { debug_call "$1" GetProxyState; }

get_n_proxy_state_instances() {
    debug_get_proxy_state "$1" | python3 -c "
import sys, json
try:
    print(len(json.load(sys.stdin).get('instances', [])))
except Exception:
    print(0)
" 2>/dev/null
}

admin_set_node_status() {
    admin_call "$1" Admin.SetNodeStatus "{\"id\": $2, \"status\": \"$3\"}"
}

get_peer_url_from_sync() {
    local node_id=$1
    local peer_node_id=$2
    debug_get_sync_data "$node_id" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for pa in d.get('peer_addrs', []):
        if pa.get('node_id') == $peer_node_id:
            print(pa.get('url', ''))
            sys.exit(0)
    print('')
except Exception:
    print('')
" 2>/dev/null
}

# Whether a RegisterCvm response offered the CVM a given gateway.
response_lists_gateway() {
    echo "$1" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for gw in d.get('gateways', []):
        if gw.get('id') == $2:
            sys.exit(0)
    sys.exit(1)
except Exception:
    sys.exit(1)
"
}
