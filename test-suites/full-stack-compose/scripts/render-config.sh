#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
CONFIG_DIR=${DSTACK_E2E_CONFIG_DIR:-$STATE_DIR/config}
RUN_DIR=${DSTACK_E2E_RUN_DIR:-$STATE_DIR/run}
VM_DIR=${DSTACK_E2E_VM_DIR:-$STATE_DIR/vm}
VOLUMES_DIR=${DSTACK_E2E_VOLUMES_DIR:-$STATE_DIR/volumes}
ARTIFACT_DIR=${DSTACK_E2E_ARTIFACT_DIR:-$STATE_DIR/artifacts}
IMAGE_ROOT=${DSTACK_E2E_IMAGE_ROOT:-/images}
IMAGE_NAME=${DSTACK_E2E_IMAGE_NAME:-dstack-0.6.0}
OLD_IMAGE_NAME=${DSTACK_E2E_OLD_IMAGE_NAME:-dstack-0.5.11}
PLATFORM=${DSTACK_E2E_PLATFORM:-tdx}
PHASE=${DSTACK_E2E_PHASE:-upgrade}

VMM_PORT=${DSTACK_E2E_VMM_PORT:-29080}
AUTH_PORT=${DSTACK_E2E_AUTH_PORT:-28011}
ARTIFACT_PORT=${DSTACK_E2E_ARTIFACT_PORT:-38081}
KMS_OLD_HOST_PORT=${DSTACK_E2E_KMS_OLD_HOST_PORT:-28082}
KMS_LATEST_HOST_PORT=${DSTACK_E2E_KMS_LATEST_HOST_PORT:-28083}
KMS_RPC_DOMAIN=${DSTACK_E2E_KMS_RPC_DOMAIN:-}
GATEWAY1_RPC_HOST_PORT=${DSTACK_E2E_GATEWAY1_RPC_HOST_PORT:-28000}
GATEWAY1_ADMIN_HOST_PORT=${DSTACK_E2E_GATEWAY1_ADMIN_HOST_PORT:-28001}
GATEWAY1_PROXY_HOST_PORT=${DSTACK_E2E_GATEWAY1_PROXY_HOST_PORT:-28443}
GATEWAY1_WG_HOST_PORT=${DSTACK_E2E_GATEWAY1_WG_HOST_PORT:-28120}
GATEWAY2_RPC_HOST_PORT=${DSTACK_E2E_GATEWAY2_RPC_HOST_PORT:-28100}
GATEWAY2_ADMIN_HOST_PORT=${DSTACK_E2E_GATEWAY2_ADMIN_HOST_PORT:-28101}
GATEWAY2_PROXY_HOST_PORT=${DSTACK_E2E_GATEWAY2_PROXY_HOST_PORT:-28543}
GATEWAY2_WG_HOST_PORT=${DSTACK_E2E_GATEWAY2_WG_HOST_PORT:-28121}
GATEWAY_APP_ID=${DSTACK_E2E_GATEWAY_APP_ID:-$(printf dstack-e2e-gateway | sha256sum | cut -c1-40)}
KEY_PROVIDER_PORT=${DSTACK_E2E_KEY_PROVIDER_PORT:-13443}
HOST_API_PORT=${DSTACK_E2E_HOST_API_PORT:-20011}
CID_START=${DSTACK_E2E_CID_START:-15000}
QGS_PORT=${DSTACK_E2E_QGS_PORT:-4050}
QEMU_PATH=${DSTACK_E2E_QEMU_PATH:-/usr/bin/qemu-system-x86_64}
BASE_DOMAIN=${DSTACK_E2E_BASE_DOMAIN:-e2e.test}
MOCK_CF_HTTP_PORT=${DSTACK_E2E_MOCK_CF_HTTP_PORT:-38080}
PEBBLE_HTTP_PORT=${DSTACK_E2E_PEBBLE_HTTP_PORT:-34000}
APP_NAME=${DSTACK_E2E_APP_NAME:-dstack-e2e-nginx}
SUITE_PREFIX=${DSTACK_E2E_NAME_PREFIX:-dstack-e2e}

mkdir -p \
  "$CONFIG_DIR" "$RUN_DIR" "$VM_DIR" "$VOLUMES_DIR" \
  "$ARTIFACT_DIR/images" "$ARTIFACT_DIR/os" "$ARTIFACT_DIR/control" \
  "$STATE_DIR/work"
chmod 0777 "$STATE_DIR/work" "$ARTIFACT_DIR" "$ARTIFACT_DIR/images" "$ARTIFACT_DIR/control"

if [[ ! "$GATEWAY_APP_ID" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "ERROR: DSTACK_E2E_GATEWAY_APP_ID must be an exact 20-byte hex app id" >&2
  exit 1
fi
GATEWAY_APP_ID=${GATEWAY_APP_ID,,}

if [[ -z "$KMS_RPC_DOMAIN" ]]; then
  host_ip=$(ip -4 route get 1.1.1.1 2>/dev/null \
    | sed -n 's/.* src \([^ ]*\).*/\1/p' | head -n1)
  if [[ ! "$host_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "ERROR: unable to derive a host IPv4 address; set DSTACK_E2E_KMS_RPC_DOMAIN" >&2
    exit 1
  fi
  KMS_RPC_DOMAIN="${host_ip}.nip.io"
fi
if ! getent ahostsv4 "$KMS_RPC_DOMAIN" >/dev/null 2>&1; then
  echo "ERROR: DSTACK_E2E_KMS_RPC_DOMAIN does not resolve: $KMS_RPC_DOMAIN" >&2
  exit 1
fi

digest_file=digest.txt
if [[ "$PLATFORM" == "amd-sev-snp" || "$PLATFORM" == "sev-snp" || "$PLATFORM" == "snp" ]]; then
  PLATFORM=amd-sev-snp
  digest_file=digest.sev.txt
elif [[ "$PLATFORM" != tdx ]]; then
  echo "ERROR: unsupported DSTACK_E2E_PLATFORM=$PLATFORM (expected tdx or amd-sev-snp)" >&2
  exit 1
fi

package_os_image() {
  local name=$1 image_dir="$IMAGE_ROOT/$1" image_hash
  if [[ ! -d "$image_dir" ]]; then
    echo "ERROR: image directory not found: $image_dir" >&2
    echo "Set DSTACK_E2E_IMAGE_STORE to a host directory containing $name/" >&2
    exit 1
  fi
  if [[ ! -s "$image_dir/$digest_file" ]]; then
    echo "ERROR: missing $image_dir/$digest_file; production-compatible E2E never permits an unpinned OS image" >&2
    exit 1
  fi
  image_hash=$(tr -d '[:space:]' < "$image_dir/$digest_file")
  if [[ ! "$image_hash" =~ ^[0-9a-f]{64}$ ]]; then
    echo "ERROR: invalid OS image digest for $name: $image_hash" >&2
    exit 1
  fi

  # Build the exact flat archive consumed by the KMS verifier. Verify the
  # source first and include only files named by sha256sum.txt.
  (
    cd "$image_dir"
    sha256sum -c sha256sum.txt >&2
    mapfile -t measured_files < <(awk '{print $2}' sha256sum.txt)
    for file in "${measured_files[@]}"; do
      [[ "$file" != */* && -f "$file" ]] || {
        echo "ERROR: unsafe or missing measured image file: $file" >&2
        exit 1
      }
    done
    tar -czf "$ARTIFACT_DIR/os/mr_${image_hash}.tar.gz.tmp" \
      sha256sum.txt "${measured_files[@]}"
  )
  mv "$ARTIFACT_DIR/os/mr_${image_hash}.tar.gz.tmp" \
    "$ARTIFACT_DIR/os/mr_${image_hash}.tar.gz"
  printf '%s' "$image_hash"
}

OS_IMAGE_HASH=$(package_os_image "$IMAGE_NAME")
# Only the upgrade phase boots the compatibility image. A phase that never
# deploys one must not require it to be present -- and must not widen the
# authorization allowlist with a second OS digest it will never launch.
if [[ "$OLD_IMAGE_NAME" == "$IMAGE_NAME" || "$PHASE" != upgrade ]]; then
  OLD_OS_IMAGE_HASH=$OS_IMAGE_HASH
else
  OLD_OS_IMAGE_HASH=$(package_os_image "$OLD_IMAGE_NAME")
fi

token_file="$STATE_DIR/gateway-admin-token"
if [[ ! -s "$token_file" ]]; then
  (umask 077; openssl rand -hex 24 > "$token_file")
fi
GATEWAY_ADMIN_TOKEN=$(tr -d '[:space:]' < "$token_file")

cat > "$CONFIG_DIR/auth-allowlist.json" <<JSON
{
  "osImages": ["$OS_IMAGE_HASH", "$OLD_OS_IMAGE_HASH"],
  "gatewayAppId": "$GATEWAY_APP_ID",
  "kms": {
    "mrAggregated": [],
    "devices": [],
    "allowAnyDevice": false
  },
  "apps": {}
}
JSON

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
kms_url = "https://127.0.0.1:${KMS_OLD_HOST_PORT}"
event_buffer_size = 100
node_name = "compose-e2e"
run_path = "${VM_DIR}"

[image]
path = "${IMAGE_ROOT}"
registry = ""

[cvm]
platform = "${PLATFORM}"
qemu_path = "${QEMU_PATH}"
kms_urls = ["https://${KMS_RPC_DOMAIN}:${KMS_OLD_HOST_PORT}"]
gateway_urls = [
  "https://${KMS_RPC_DOMAIN}:${GATEWAY1_RPC_HOST_PORT}",
  "https://${KMS_RPC_DOMAIN}:${GATEWAY2_RPC_HOST_PORT}",
]
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
tdx_attestation_variant = "auto"
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
port = ${GATEWAY1_PROXY_HOST_PORT}
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
ARTIFACT_DIR=$ARTIFACT_DIR
IMAGE_ROOT=$IMAGE_ROOT
IMAGE_NAME=$IMAGE_NAME
OLD_IMAGE_NAME=$OLD_IMAGE_NAME
PLATFORM=$PLATFORM
OS_IMAGE_HASH=$OS_IMAGE_HASH
OLD_OS_IMAGE_HASH=$OLD_OS_IMAGE_HASH
VMM_PORT=$VMM_PORT
AUTH_PORT=$AUTH_PORT
ARTIFACT_PORT=$ARTIFACT_PORT
KMS_OLD_HOST_PORT=$KMS_OLD_HOST_PORT
KMS_LATEST_HOST_PORT=$KMS_LATEST_HOST_PORT
KMS_RPC_DOMAIN=$KMS_RPC_DOMAIN
GATEWAY1_RPC_HOST_PORT=$GATEWAY1_RPC_HOST_PORT
GATEWAY1_ADMIN_HOST_PORT=$GATEWAY1_ADMIN_HOST_PORT
GATEWAY1_PROXY_HOST_PORT=$GATEWAY1_PROXY_HOST_PORT
GATEWAY1_WG_HOST_PORT=$GATEWAY1_WG_HOST_PORT
GATEWAY2_RPC_HOST_PORT=$GATEWAY2_RPC_HOST_PORT
GATEWAY2_ADMIN_HOST_PORT=$GATEWAY2_ADMIN_HOST_PORT
GATEWAY2_PROXY_HOST_PORT=$GATEWAY2_PROXY_HOST_PORT
GATEWAY2_WG_HOST_PORT=$GATEWAY2_WG_HOST_PORT
GATEWAY_APP_ID=$GATEWAY_APP_ID
KEY_PROVIDER_PORT=$KEY_PROVIDER_PORT
HOST_API_PORT=$HOST_API_PORT
BASE_DOMAIN=$BASE_DOMAIN
MOCK_CF_HTTP_PORT=$MOCK_CF_HTTP_PORT
PEBBLE_HTTP_PORT=$PEBBLE_HTTP_PORT
APP_NAME=$APP_NAME
SUITE_PREFIX=$SUITE_PREFIX
GATEWAY_ADMIN_TOKEN=$GATEWAY_ADMIN_TOKEN
EOF_ENV
chmod 0600 "$STATE_DIR/state.env"

echo "Rendered production-compatible dstack E2E config:"
echo "  vmm:          http://127.0.0.1:${VMM_PORT}"
echo "  auth:         http://10.0.2.2:${AUTH_PORT}"
echo "  artifacts:    http://10.0.2.2:${ARTIFACT_PORT}"
echo "  old KMS:      https://${KMS_RPC_DOMAIN}:${KMS_OLD_HOST_PORT}"
echo "  latest KMS:   https://${KMS_RPC_DOMAIN}:${KMS_LATEST_HOST_PORT}"
echo "  current image: ${IMAGE_NAME} (${OS_IMAGE_HASH})"
if [[ "$OLD_OS_IMAGE_HASH" == "$OS_IMAGE_HASH" ]]; then
  echo "  old image:     not used by phase ${PHASE}"
else
  echo "  old image:     ${OLD_IMAGE_NAME} (${OLD_OS_IMAGE_HASH})"
fi
echo "  gateway app:  ${GATEWAY_APP_ID}"
