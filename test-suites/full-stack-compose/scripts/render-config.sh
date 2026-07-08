#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
CONFIG_DIR=${DSTACK_E2E_CONFIG_DIR:-$STATE_DIR/config}
RUN_DIR=${DSTACK_E2E_RUN_DIR:-$STATE_DIR/run}
VM_DIR=${DSTACK_E2E_VM_DIR:-$STATE_DIR/vm}
VOLUMES_DIR=${DSTACK_E2E_VOLUMES_DIR:-$STATE_DIR/volumes}
IMAGE_ROOT=${DSTACK_E2E_IMAGE_ROOT:-/images}
IMAGE_NAME=${DSTACK_E2E_IMAGE_NAME:-dstack-0.6.0}
PLATFORM=${DSTACK_E2E_PLATFORM:-tdx}

VMM_PORT=${DSTACK_E2E_VMM_PORT:-29080}
AUTH_PORT=${DSTACK_E2E_AUTH_PORT:-28011}
KMS_HOST_PORT=${DSTACK_E2E_KMS_HOST_PORT:-28082}
GATEWAY_RPC_HOST_PORT=${DSTACK_E2E_GATEWAY_RPC_HOST_PORT:-28000}
GATEWAY_ADMIN_HOST_PORT=${DSTACK_E2E_GATEWAY_ADMIN_HOST_PORT:-28001}
GATEWAY_PROXY_HOST_PORT=${DSTACK_E2E_GATEWAY_PROXY_HOST_PORT:-28443}
GATEWAY_WG_HOST_PORT=${DSTACK_E2E_GATEWAY_WG_HOST_PORT:-28120}
GATEWAY_WG_INTERFACE=${DSTACK_E2E_GATEWAY_WG_INTERFACE:-wg-ds-e2e}
GATEWAY_WG_IP=${DSTACK_E2E_GATEWAY_WG_IP:-10.8.0.1/16}
GATEWAY_WG_RESERVED_NET=${DSTACK_E2E_GATEWAY_WG_RESERVED_NET:-10.8.0.1/32}
GATEWAY_WG_CLIENT_RANGE=${DSTACK_E2E_GATEWAY_WG_CLIENT_RANGE:-10.8.0.0/18}
GATEWAY_APP_ID=${DSTACK_E2E_GATEWAY_APP_ID:-any}
KEY_PROVIDER_PORT=${DSTACK_E2E_KEY_PROVIDER_PORT:-13443}
HOST_API_PORT=${DSTACK_E2E_HOST_API_PORT:-20011}
CID_START=${DSTACK_E2E_CID_START:-15000}
QGS_PORT=${DSTACK_E2E_QGS_PORT:-4050}
QEMU_PATH=${DSTACK_E2E_QEMU_PATH:-/usr/bin/qemu-system-x86_64}
BASE_DOMAIN=${DSTACK_E2E_BASE_DOMAIN:-e2e.test}
MOCK_CF_HTTP_PORT=${DSTACK_E2E_MOCK_CF_HTTP_PORT:-38080}
PEBBLE_HTTP_PORT=${DSTACK_E2E_PEBBLE_HTTP_PORT:-34000}
APP_IMAGE=${DSTACK_E2E_APP_IMAGE:-nginx:alpine}
APP_NAME=${DSTACK_E2E_APP_NAME:-dstack-e2e-nginx}
SUITE_PREFIX=${DSTACK_E2E_NAME_PREFIX:-dstack-e2e}

KMS_CERT_DIR=${DSTACK_E2E_KMS_CERT_DIR:-$STATE_DIR/kms-certs}
GATEWAY_CERT_DIR=${DSTACK_E2E_GATEWAY_CERT_DIR:-$STATE_DIR/gateway-certs}
GATEWAY_DATA_DIR=${DSTACK_E2E_GATEWAY_DATA_DIR:-$STATE_DIR/gateway-data}

mkdir -p \
  "$CONFIG_DIR" "$RUN_DIR" "$VM_DIR" "$VOLUMES_DIR" "$STATE_DIR/work" \
  "$KMS_CERT_DIR" "$GATEWAY_CERT_DIR" "$GATEWAY_DATA_DIR"

image_dir="$IMAGE_ROOT/$IMAGE_NAME"
if [[ ! -d "$image_dir" ]]; then
  echo "ERROR: image directory not found: $image_dir" >&2
  echo "Set DSTACK_E2E_IMAGE_STORE to a host directory containing $IMAGE_NAME/" >&2
  exit 1
fi

digest_file="digest.txt"
if [[ "$PLATFORM" == "amd-sev-snp" || "$PLATFORM" == "sev-snp" || "$PLATFORM" == "snp" ]]; then
  PLATFORM="amd-sev-snp"
  digest_file="digest.sev.txt"
elif [[ "$PLATFORM" != "tdx" ]]; then
  echo "ERROR: unsupported DSTACK_E2E_PLATFORM=$PLATFORM (expected tdx or amd-sev-snp)" >&2
  exit 1
fi

OS_IMAGE_HASH=""
if [[ -s "$image_dir/$digest_file" ]]; then
  OS_IMAGE_HASH=$(tr -d '[:space:]' < "$image_dir/$digest_file")
elif [[ "${DSTACK_E2E_ALLOW_UNPINNED_IMAGE:-false}" == "true" ]]; then
  echo "WARN: missing $image_dir/$digest_file; auth allowlist will not pin OS image" >&2
else
  echo "ERROR: missing $image_dir/$digest_file" >&2
  echo "Set DSTACK_E2E_ALLOW_UNPINNED_IMAGE=true only for local experiments." >&2
  exit 1
fi

ADMIN_TOKEN_FILE="$STATE_DIR/gateway-admin-token"
if [[ ! -s "$ADMIN_TOKEN_FILE" ]]; then
  openssl rand -hex 24 > "$ADMIN_TOKEN_FILE"
  chmod 0600 "$ADMIN_TOKEN_FILE" || true
fi
GATEWAY_ADMIN_TOKEN=$(cat "$ADMIN_TOKEN_FILE")

openssl_gen_ec_key() {
  local path=$1
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$path" >/dev/null 2>&1
  chmod 0600 "$path" || true
}

openssl_gen_ca() {
  local key=$1 cert=$2 subject=$3
  openssl_gen_ec_key "$key"
  openssl req -x509 -new -key "$key" -sha256 -days 3650 -out "$cert" \
    -subj "$subject" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
}

openssl_gen_kms_rpc_cert() {
  local dir=$1 tmp csr
  tmp=$(mktemp)
  csr="$dir/rpc.csr"
  cat > "$tmp" <<'OPENSSL_CONF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = 10.0.2.2

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = @alt_names
1.3.6.1.4.1.62397.1.4 = DER:04:07:6B:6D:73:3A:72:70:63

[alt_names]
IP.1 = 10.0.2.2
IP.2 = 127.0.0.1
DNS.1 = localhost
OPENSSL_CONF
  openssl_gen_ec_key "$dir/rpc.key"
  openssl req -new -key "$dir/rpc.key" -out "$csr" -config "$tmp" >/dev/null 2>&1
  openssl x509 -req -in "$csr" -CA "$dir/root-ca.crt" -CAkey "$dir/root-ca.key" \
    -CAcreateserial -out "$dir/rpc.crt" -days 3650 -sha256 \
    -extfile "$tmp" -extensions v3_req >/dev/null 2>&1
  rm -f "$tmp" "$csr"
}

openssl_gen_gateway_rpc_cert() {
  local dir=$1 tmp
  tmp=$(mktemp)
  cat > "$tmp" <<'OPENSSL_CONF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_req

[dn]
CN = 10.0.2.2

[v3_req]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
IP.1 = 10.0.2.2
IP.2 = 127.0.0.1
DNS.1 = localhost
OPENSSL_CONF
  openssl_gen_ec_key "$dir/gateway-rpc.key"
  openssl req -x509 -new -key "$dir/gateway-rpc.key" -sha256 -days 3650 \
    -out "$dir/gateway-rpc.crt" -config "$tmp" -extensions v3_req >/dev/null 2>&1
  rm -f "$tmp"
}

write_k256_key() {
  local path=$1
  python3 - "$path" <<'PY'
import os
import sys
# secp256k1 curve order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
path = sys.argv[1]
while True:
    b = os.urandom(32)
    x = int.from_bytes(b, "big")
    if 1 <= x < N:
        with open(path, "wb") as f:
            f.write(b)
        break
PY
  chmod 0600 "$path" || true
}

if [[ ! -s "$KMS_CERT_DIR/root-ca.key" || ! -s "$KMS_CERT_DIR/root-ca.crt" || \
      ! -s "$KMS_CERT_DIR/tmp-ca.key" || ! -s "$KMS_CERT_DIR/tmp-ca.crt" || \
      ! -s "$KMS_CERT_DIR/rpc.key" || ! -s "$KMS_CERT_DIR/rpc.crt" || \
      ! -s "$KMS_CERT_DIR/root-k256.key" ]]; then
  echo "Generating dev KMS key material in $KMS_CERT_DIR"
  rm -f "$KMS_CERT_DIR"/{root-ca.key,root-ca.crt,root-ca.srl,tmp-ca.key,tmp-ca.crt,rpc.key,rpc.crt,rpc.csr,root-k256.key,rpc-domain}
  openssl_gen_ca "$KMS_CERT_DIR/root-ca.key" "$KMS_CERT_DIR/root-ca.crt" "/O=Dstack/CN=Dstack KMS CA"
  openssl_gen_ca "$KMS_CERT_DIR/tmp-ca.key" "$KMS_CERT_DIR/tmp-ca.crt" "/O=Dstack/CN=Dstack Client Temp CA"
  openssl_gen_kms_rpc_cert "$KMS_CERT_DIR"
  write_k256_key "$KMS_CERT_DIR/root-k256.key"
  printf '10.0.2.2' > "$KMS_CERT_DIR/rpc-domain"
fi

if [[ ! -s "$GATEWAY_CERT_DIR/gateway-rpc.key" || ! -s "$GATEWAY_CERT_DIR/gateway-rpc.crt" ]]; then
  echo "Generating dev Gateway RPC certificate in $GATEWAY_CERT_DIR"
  rm -f "$GATEWAY_CERT_DIR"/{gateway-rpc.key,gateway-rpc.crt}
  openssl_gen_gateway_rpc_cert "$GATEWAY_CERT_DIR"
fi

WG_KEY_FILE="$GATEWAY_DATA_DIR/wg.key"
if [[ ! -s "$WG_KEY_FILE" ]]; then
  (umask 077; wg genkey > "$WG_KEY_FILE")
  chmod 0600 "$WG_KEY_FILE" || true
fi
GATEWAY_WG_PRIVATE_KEY=$(tr -d '[:space:]' < "$WG_KEY_FILE")
GATEWAY_WG_PUBLIC_KEY=$(printf '%s' "$GATEWAY_WG_PRIVATE_KEY" | wg pubkey)

cat > "$CONFIG_DIR/auth-allowlist.json" <<JSON
{
  "osImages": $(if [[ -n "$OS_IMAGE_HASH" ]]; then printf '["%s"]' "$OS_IMAGE_HASH"; else printf '[]'; fi),
  "gatewayAppId": "$GATEWAY_APP_ID",
  "kms": {
    "mrAggregated": [],
    "devices": [],
    "allowAnyDevice": true
  },
  "apps": {}
}
JSON

cat > "$CONFIG_DIR/kms.toml" <<EOF_KMS
# generated by dstack full-stack compose E2E

[rpc]
address = "0.0.0.0"
port = ${KMS_HOST_PORT}

[rpc.tls]
key = "${KMS_CERT_DIR}/rpc.key"
certs = "${KMS_CERT_DIR}/rpc.crt"

[rpc.tls.mutual]
ca_certs = "${KMS_CERT_DIR}/tmp-ca.crt"
mandatory = false

[core]
cert_dir = "${KMS_CERT_DIR}"
admin_token_hash = ""
enforce_self_authorization = false
sev_snp_key_release = false
pccs_url = ""
amd_kds_base_url = ""

[core.image]
verify = false
cache_dir = "${STATE_DIR}/kms-image-cache"
download_url = "https://download.dstack.org/os-images/mr_{OS_IMAGE_HASH}.tar.gz"
download_timeout = "2m"

[core.metrics]
enabled = true

[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "http://127.0.0.1:${AUTH_PORT}"

[core.onboard]
enabled = false
auto_bootstrap_domain = ""
address = "127.0.0.1"
port = ${KMS_HOST_PORT}
EOF_KMS

cat > "$CONFIG_DIR/gateway.toml" <<EOF_GATEWAY
# generated by dstack full-stack compose E2E

keep_alive = 10
log_level = "info"
address = "0.0.0.0:${GATEWAY_RPC_HOST_PORT}"

[tls]
key = "${GATEWAY_CERT_DIR}/gateway-rpc.key"
certs = "${GATEWAY_CERT_DIR}/gateway-rpc.crt"

[tls.mutual]
ca_certs = "${KMS_CERT_DIR}/root-ca.crt"
mandatory = false

[core]
kms_url = "https://127.0.0.1:${KMS_HOST_PORT}"
set_ulimit = true
rpc_domain = ""
pccs_url = ""

[core.auth]
enabled = false
url = "http://127.0.0.1:${AUTH_PORT}/bootAuth/app"
timeout = "5s"

[core.admin]
enabled = true
address = "127.0.0.1"
port = ${GATEWAY_ADMIN_HOST_PORT}
admin_token = "${GATEWAY_ADMIN_TOKEN}"
insecure_no_auth = false

[core.debug]
insecure_enable_debug_rpc = false
insecure_skip_attestation = true
key_file = ""
address = "127.0.0.1:0"

[core.wg]
public_key = "${GATEWAY_WG_PUBLIC_KEY}"
private_key = "${GATEWAY_WG_PRIVATE_KEY}"
listen_port = ${GATEWAY_WG_HOST_PORT}
ip = "${GATEWAY_WG_IP}"
reserved_net = ["${GATEWAY_WG_RESERVED_NET}"]
client_ip_range = "${GATEWAY_WG_CLIENT_RANGE}"
config_path = "${GATEWAY_DATA_DIR}/wg-ds-e2e.conf"
interface = "${GATEWAY_WG_INTERFACE}"
endpoint = "10.0.2.2:${GATEWAY_WG_HOST_PORT}"

[core.proxy]
tls_crypto_provider = "aws-lc-rs"
tls_versions = ["1.2"]
listen_addr = "0.0.0.0"
listen_port = ${GATEWAY_PROXY_HOST_PORT}
agent_port = 8090
buffer_size = 8192
connect_top_n = 3
localhost_enabled = false
app_address_ns_prefix = "_dstack-app-address"
app_address_ns_compat = true
workers = 4
external_port = ${GATEWAY_PROXY_HOST_PORT}
max_connections_per_app = 0
inbound_pp_enabled = false

[core.proxy.port_policy_fetch]
timeout = "5s"
max_retries = 12
backoff_initial = "1s"
backoff_max = "5s"

[core.proxy.timeouts]
connect = "5s"
handshake = "5s"
cache_top_n = "30s"
dns_resolve = "2s"
data_timeout_enabled = true
idle = "10m"
write = "5s"
shutdown = "5s"
total = "5h"
pp_header = "5s"

[core.recycle]
enabled = true
interval = "5m"
timeout = "10h"
node_timeout = "10m"

[core.sync]
enabled = false
node_id = 1
my_url = "https://127.0.0.1:${GATEWAY_RPC_HOST_PORT}"
interval = "5s"
timeout = "10s"
bootnode = ""
data_dir = "${GATEWAY_DATA_DIR}"
persist_interval = "5s"
sync_connections_enabled = true
sync_connections_interval = "5s"
EOF_GATEWAY

cat > "$CONFIG_DIR/vmm.toml" <<EOF_VMM
# generated by dstack full-stack compose E2E

workers = 8
max_blocking = 64
ident = "dstack E2E VMM"
temp_dir = "/tmp"
keep_alive = 10
log_level = "info"
address = "tcp:127.0.0.1:${VMM_PORT}"
reuse = true
kms_url = ""
event_buffer_size = 100
node_name = "compose-e2e"
run_path = "${VM_DIR}"

[image]
path = "${IMAGE_ROOT}"
registry = ""

[cvm]
platform = "${PLATFORM}"
qemu_path = "${QEMU_PATH}"
kms_urls = ["https://10.0.2.2:${KMS_HOST_PORT}"]
gateway_urls = ["https://10.0.2.2:${GATEWAY_RPC_HOST_PORT}"]
pccs_url = ""
docker_registry = ""
volumes_dir = "${VOLUMES_DIR}"
cid_start = ${CID_START}
cid_pool_size = 1000
max_allocable_vcpu = 64
max_allocable_memory_in_mb = 262144
qmp_socket = false
user = ""
use_mrconfigid = false
qemu_pci_hole64_size = 0
qemu_hotplug_off = false
host_share_mode = "9p"
qgs_port = ${QGS_PORT}

[cvm.product]
sys_vendor = "dstack"
product_name = "dstack-e2e"

[cvm.networking]
mode = "user"
net = "10.0.2.0/24"
dhcp_start = "10.0.2.10"
restrict = false
forward_service_enabled = false

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = 1, to = 65535 },
    { protocol = "udp", from = 1, to = 65535 },
]

[cvm.auto_restart]
enabled = true
interval = 20

[cvm.gpu]
enabled = false
listing = []
exclude = []
include = []
allow_attach_all = false

[gateway]
base_domain = "${BASE_DOMAIN}"
port = ${GATEWAY_PROXY_HOST_PORT}
agent_port = 8090

[auth]
enabled = false
tokens = []

[supervisor]
exe = "/workspace/target/release/supervisor"
sock = "${RUN_DIR}/supervisor.sock"
pid_file = "${RUN_DIR}/supervisor.pid"
log_file = "${RUN_DIR}/supervisor.log"
detached = true
auto_start = true

[host_api]
address = "vsock:2"
port = ${HOST_API_PORT}

[key_provider]
enabled = true
address = "127.0.0.1"
port = ${KEY_PROVIDER_PORT}
EOF_VMM

cat > "$STATE_DIR/state.env" <<EOF_ENV
STATE_DIR=$STATE_DIR
CONFIG_DIR=$CONFIG_DIR
RUN_DIR=$RUN_DIR
VM_DIR=$VM_DIR
IMAGE_ROOT=$IMAGE_ROOT
IMAGE_NAME=$IMAGE_NAME
PLATFORM=$PLATFORM
OS_IMAGE_HASH=$OS_IMAGE_HASH
VMM_PORT=$VMM_PORT
AUTH_PORT=$AUTH_PORT
KMS_HOST_PORT=$KMS_HOST_PORT
GATEWAY_RPC_HOST_PORT=$GATEWAY_RPC_HOST_PORT
GATEWAY_ADMIN_HOST_PORT=$GATEWAY_ADMIN_HOST_PORT
GATEWAY_PROXY_HOST_PORT=$GATEWAY_PROXY_HOST_PORT
GATEWAY_WG_HOST_PORT=$GATEWAY_WG_HOST_PORT
GATEWAY_APP_ID=$GATEWAY_APP_ID
KEY_PROVIDER_PORT=$KEY_PROVIDER_PORT
HOST_API_PORT=$HOST_API_PORT
BASE_DOMAIN=$BASE_DOMAIN
MOCK_CF_HTTP_PORT=$MOCK_CF_HTTP_PORT
PEBBLE_HTTP_PORT=$PEBBLE_HTTP_PORT
APP_IMAGE=$APP_IMAGE
APP_NAME=$APP_NAME
SUITE_PREFIX=$SUITE_PREFIX
GATEWAY_ADMIN_TOKEN=$GATEWAY_ADMIN_TOKEN
EOF_ENV

chmod 0600 "$STATE_DIR/state.env" || true

echo "Rendered dstack E2E config:"
echo "  vmm:       http://127.0.0.1:${VMM_PORT}"
echo "  auth:      http://127.0.0.1:${AUTH_PORT}"
echo "  kms:       https://127.0.0.1:${KMS_HOST_PORT}"
echo "  gateway:   https://127.0.0.1:${GATEWAY_RPC_HOST_PORT}"
echo "  image:     ${IMAGE_NAME} (${OS_IMAGE_HASH:-unpinned})"
echo "  gw app id: ${GATEWAY_APP_ID}"
