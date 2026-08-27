# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=bash

# Host-side driver primitives for the gateway cluster suite.
#
# The tests need to stop a node, rewrite its config, wipe or doctor its data
# directory and start it again. All of that happens here, on the host, against
# bind mounts and `docker compose`.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="$SCRIPT_DIR/run"
CONFIG_DIR="$RUN_DIR/configs"
DATA_DIR="$RUN_DIR/data"
LOG_DIR="$RUN_DIR/logs"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info()    { printf "${BLUE}[INFO]${NC} %s\n" "$1" >&2; }
log_warn()    { printf "${YELLOW}[WARN]${NC} %s\n" "$1" >&2; }
log_error()   { printf "${RED}[ERROR]${NC} %s\n" "$1" >&2; }
log_success() { printf "${GREEN}[PASS]${NC} %s\n" "$1" >&2; }
log_fail()    { printf "${RED}[FAIL]${NC} %s\n" "$1" >&2; }

# Host-side ports are assigned by docker, not fixed, so the suite cannot
# collide with whatever else is listening on the machine. Look them up once a
# container is running and cache the answer -- `docker compose port` is a
# process spawn, and the tests ask for these constantly.
declare -A _PORT_CACHE=()
container_port() {
    local node_id=$1
    local container_port=$2
    # Keyed by project too: each test gets its own containers, so a port
    # cached under a previous test's project points at something that no longer
    # exists -- which reads as "the node did not come up".
    local key="${CURRENT_TEST:-suite}:${node_id}:${container_port}"
    local mapped
    if [[ -n "${_PORT_CACHE[$key]:-}" ]]; then
        echo "${_PORT_CACHE[$key]}"; return 0
    fi
    mapped=$(compose port "gateway-${node_id}" "$container_port" 2>/dev/null | awk -F: 'NF{print $NF}')
    [[ -n "$mapped" ]] || return 1
    _PORT_CACHE[$key]="$mapped"
    echo "$mapped"
}

# A restarted container gets a new host port, so anything that stops a node has
# to drop the cache or later lookups address a port nothing is listening on.
forget_ports() {
    local node_id=$1
    local t="${CURRENT_TEST:-suite}"
    unset '_PORT_CACHE['"$t:$node_id"':9012]' \
          '_PORT_CACHE['"$t:$node_id"':9015]' \
          '_PORT_CACHE['"$t:$node_id"':9016]'
}

rpc_port()   { container_port "$1" 9012; }
debug_port() { container_port "$1" 9015; }
admin_port() { container_port "$1" 9016; }

# Write node $1's config, wiring its bootnode to $2 (empty for none).
#
# Everything except the bootnode is derived from the node id, which is why the
# original suite could regenerate this 30-odd times and only ever change one
# field.
generate_config() {
    local node_id=$1
    local bootnode_url=${2:-""}
    local dir="$CONFIG_DIR/${CURRENT_TEST:-suite}/node${node_id}"
    mkdir -p "$dir"
    cat >"$dir/gateway.toml" <<EOF
log_level = "info"
address = "0.0.0.0:9012"

[tls]
key = "/var/lib/gateway/certs/gateway-rpc.key"
certs = "/var/lib/gateway/certs/gateway-rpc.cert"

[tls.mutual]
ca_certs = "/var/lib/gateway/certs/gateway-ca.cert"
mandatory = false

[core]
# Non-empty so the gateway provisions its RPC certificate from the guest agent
# instead of being handed a hand-rolled one. That certificate carries the quote
# and the app_id the cluster's mTLS checks, which is what lets this suite run
# with attestation on rather than switched off.
rpc_domain = "gateway-${node_id}"

[core.debug]
# TEST ONLY - do not use in production; enables debug RPC
insecure_enable_debug_rpc = true
address = "0.0.0.0:9015"

[core.admin]
enabled = true
address = "0.0.0.0:9016"
# TEST ONLY - do not use in production; disables admin API authentication
insecure_no_auth = true

# Verify peer quotes against the development roots the mock collateral service
# derives from the simulator's seed. Verification runs the normal production
# path; this only says the anchor may come from outside the vendor set.
[core.attestation]
insecure_allow_external_trust_anchors = true

[core.attestation.urls]
pccs = "http://mock-attestation:8088"

[core.attestation.root_ca]
tdx = "/var/lib/attestation/tdx-root-ca.pem"

[core.sync]
enabled = true
interval = "5s"
timeout = "10s"
my_url = "https://gateway-${node_id}:9012"
bootnode = "${bootnode_url}"
node_id = ${node_id}
data_dir = "/var/lib/gateway/wavekv"
persist_interval = "5s"

[core.certbot]
enabled = false

[core.wg]
private_key = "SEcoI37oGWynhukxXo5Mi8/8zZBU6abg6T1TOJRMj1Y="
public_key = "xc+7qkdeNFfl4g4xirGGGXHMc0cABuE5IHaLeCASVWM="
listen_port = 9013
ip = "10.0.3${node_id}.1/24"
reserved_net = ["10.0.3${node_id}.1/31"]
client_ip_range = "10.0.3${node_id}.1/24"
config_path = "/var/lib/gateway/wg.conf"
interface = "wg-cluster${node_id}"
endpoint = "gateway-${node_id}:9013"

[core.proxy]
cert_chain = "/etc/gateway/proxy.cert"
cert_key = "/etc/gateway/proxy.key"
base_domain = "cluster.test"
listen_addr = "0.0.0.0"
listen_port = 9014
tappd_port = 8090
external_port = 9014
EOF
    # The proxy listener wants its certificate beside the config, and each test
    # has a config directory of its own now -- so generating it separately, once,
    # left every test after the first with a gateway that exits at startup with
    # "failed to read proxy cert_chain".
    generate_proxy_cert "$node_id"
    log_info "wrote node${node_id} config (bootnode=${bootnode_url:-none})"
}

# The proxy listener wants a certificate even though this suite never drives the
# data path. Self-signed is enough; the RPC certificates that actually gate
# cluster membership come from the guest agent, not from here.
generate_proxy_cert() {
    local node_id=$1
    local dir="$CONFIG_DIR/${CURRENT_TEST:-suite}/node${node_id}"
    [ -f "$dir/proxy.cert" ] && return 0
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
        -keyout "$dir/proxy.key" -out "$dir/proxy.cert" \
        -subj "/CN=cluster.test" \
        -addext "subjectAltName=DNS:cluster.test,DNS:*.cluster.test" 2>/dev/null
}

# Each test runs in a compose project of its own, so its containers, its logs
# and its data start empty because they are new -- not because something cleaned
# them. CURRENT_TEST is set by the runner before each test.
compose() {
    docker compose -p "cluster-${CURRENT_TEST:-suite}" \
        -f "$SCRIPT_DIR/docker-compose.yml" "$@"
}

# The attestation fixture is a separate, long-lived project; the runner owns it.
fixture_compose() {
    docker compose -p dstack-fixture \
        -f "$SCRIPT_DIR/../attestation/fixture.yml" "$@"
}

# Discard whatever the previous test used and start this one from nothing.
new_test_project() {
    compose down -v --remove-orphans >/dev/null 2>&1 || true
    _PORT_CACHE=()
    CURRENT_TEST="$1"
    export CURRENT_TEST
    mkdir -p "$DATA_DIR/$CURRENT_TEST"
}

start_node() {
    local node_id=$1
    # `compose start` exits 0 when the service has no container yet -- it prints
    # "has no container to start" and succeeds -- so an `||` fallback to
    # `compose up -d` never fires. Under one project per test the container
    # usually does not exist, which made every node after the first look like it
    # failed to come up. `up -d` both creates and starts, and is a no-op for a
    # container that is already running.
    compose up -d "gateway-${node_id}" >/dev/null 2>&1 ||
        compose start "gateway-${node_id}" >/dev/null 2>&1
    forget_ports "$node_id"
    wait_for_debug "$node_id" 60 || { log_error "node ${node_id} did not come up"; return 1; }
}

stop_node() {
    local node_id=$1
    compose stop -t 5 "gateway-${node_id}" >/dev/null 2>&1 || true
    forget_ports "$node_id"
}

wait_for_debug() {
    local node_id=$1
    local timeout=${2:-60}
    local waited=0
    local port
    while [ "$waited" -lt "$timeout" ]; do
        # Resolved inside the loop on purpose: docker only reports the mapping
        # once the container is running, so looking it up once up front would
        # leave every later request aimed at an empty port.
        if port=$(debug_port "$node_id") && [ -n "$port" ] &&
           curl -sf -X POST "http://127.0.0.1:${port}/prpc/Debug.Info" \
             -H 'Content-Type: application/json' -d '{}' >/dev/null 2>&1; then
            return 0
        fi
        sleep 1; waited=$((waited + 1))
    done
    return 1
}

# Two ported tests assert on what a node logged. Containers keep that in the
# daemon rather than a file, so materialise it on demand and leave the
# assertions themselves unchanged.
#
# $2 bounds the window. The suite it replaces wrote a fresh log file per test,
# so a grep could not see anything an earlier test produced; `docker logs`
# accumulates for the life of the container, and without a bound a test looking
# for a message an earlier one legitimately caused would pass without that
# message ever being emitted again.
dump_log() {
    local node_id=$1
    mkdir -p "$LOG_DIR"
    # No time window. This container was created for this test, so everything in
    # its log belongs to this test -- and the window the shared-container design
    # needed is what made the docker-logs timezone bug possible.
    compose logs --no-color "gateway-${node_id}" \
        >"$LOG_DIR/${CURRENT_TEST}-node${node_id}.log" 2>&1 || true
    echo "$LOG_DIR/${CURRENT_TEST}-node${node_id}.log"
}


node_data_dir() { echo "$DATA_DIR/${CURRENT_TEST:-suite}/node$1"; }

# The gateway runs as root inside its container, so everything it writes into
# the bind-mounted data directory is root-owned. Reading it from the host is
# fine -- node_uuid and the WAL are world-readable, which is all the surgery
# tests need -- but removing or replacing it is not. Do that in a throwaway
# root container rather than reaching for sudo, which is exactly the dependency
# this port exists to shed.
#
# $1 is a shell snippet run against /data, the parent of the per-node dirs.
data_op() {
    docker run --rm -v "$DATA_DIR/${CURRENT_TEST}:/data" alpine:latest sh -c "$1"
}

# Wipe a stopped node's store but let it keep the identity it already published,
# which is what a node looks like after losing its disk but not its config.
wipe_data_keeping_uuid() {
    local node_id=$1
    data_op "cp /data/node${node_id}/wavekv/node_uuid /tmp/uuid &&
             rm -rf /data/node${node_id}/wavekv/* /data/node${node_id}/wavekv/.[!.]* 2>/dev/null;
             cp /tmp/uuid /data/node${node_id}/wavekv/node_uuid"
}

# Wipe a stopped node completely, identity included -- a stranger turning up
# with a node id that is already taken. Contents only: the directory itself is a
# bind-mount source, and replacing it swaps the inode the mount was set against.
wipe_data() {
    local node_id=$1
    data_op "rm -rf /data/node${node_id}/..?* /data/node${node_id}/.[!.]* /data/node${node_id}/*" \
        2>/dev/null || true
}
