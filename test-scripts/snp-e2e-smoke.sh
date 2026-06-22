#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Manual AMD SEV-SNP hardware smoke for dstack-managed KMS/app key release.
#
# This is intentionally not a CI script. It requires an SNP-capable host with the
# AMDSEV QEMU/OVMF build used by the PR smoke, sudo for QEMU/KVM, and locally
# built release binaries.
#
# Minimal setup used by the original smoke:
#   cargo build --release -p dstack-vmm -p supervisor -p dstack-kms
#   export DSTACK_SNP_SMOKE_BIN_DIR=$PWD/target/release
#   export DSTACK_SNP_SMOKE_ALLOW_OUT_OF_DATE_TCB=1  # lab hosts only; auth API policy
#   test-scripts/snp-e2e-smoke.sh
#
# Useful overrides:
#   DSTACK_SNP_SMOKE_BASE=$HOME/dstack-snp-e2e
#   DSTACK_SNP_SMOKE_REPO=$PWD
#   DSTACK_SNP_SMOKE_QEMU=/opt/AMDSEV/usr/local/bin/qemu-system-x86_64
#   DSTACK_SNP_SMOKE_OVMF=/opt/AMDSEV/usr/local/share/qemu/OVMF.fd
#   DSTACK_SNP_SMOKE_IMAGE_URL=https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.11/dstack-dev-0.5.11.tar.gz
#   DSTACK_SNP_SMOKE_IMAGE_NAME=dstack-dev-0.5.11-snp-dnsfix
#   DSTACK_SNP_SMOKE_ALLOW_OLD_QEMU=1  # bypasses the QEMU >= 10 preflight
#
# Host/image caveat: QEMU >= 10 is necessary but not sufficient. One local SNP
# host could boot a newer Lit SNP guest kernel but reset before Linux serial
# output with the stock meta-dstack v0.5.11 6.9.0-dstack kernel. If this smoke
# stops after `EFI stub: Loaded initrd ...` with `cpus are not resettable`, first
# validate the guest image/kernel on that host before debugging KMS or apps.
#
# Guest userspace caveat: rebuilding the host-side PR binaries is not enough for
# full app-key success if the downloaded meta-dstack image still embeds an older
# dstack-util/dstack-attest. On that skewed image the app guest can reach
# dstack-prepare.sh and fail at GetTempCaCert/GetAppKey with:
#   amd sev-snp cert_chain must contain either ASK and VCEK certificates or one
#   kernel certificate table auxblob
# For full SNP_APP_CONTAINER_STARTED / GetAppKey success, use a coherent
# meta-dstack guest image that includes the same PR cert-chain/KDS fallback code.
# If AMD KDS throttles VCEK/cert-chain retrieval (for example HTTP 429 from
# kdsintf.amd.com), keep verification fail-closed and set
# DSTACK_SNP_SMOKE_KDS_BASE_URL to a trusted AMD-KDS-compatible mirror/cache
# base, e.g. https://mirror.example.com/vcek/v1. For a path-prefix relay, set
# the full relayed base, e.g.:
#   https://cors.litgateway.com/https://kdsintf.amd.com/vcek/v1
# This is an external collateral-fetch boundary, not a guest boot or KMS startup
# failure.
# One reproducible way is to build meta-dstack with its dstack submodule checked
# out to this PR branch, set the Yocto build MACHINE to `sev-snp` (not the
# default `tdx`, otherwise the guest kernel can miss AMD memory-encryption
# support and reset immediately after OVMF loads the kernel/initrd), then point
# DSTACK_SNP_SMOKE_IMAGE_NAME at the resulting dstack-dev image directory.

set -euo pipefail

BASE="${DSTACK_SNP_SMOKE_BASE:-$HOME/dstack-snp-e2e}"
REPO="${DSTACK_SNP_SMOKE_REPO:-$(pwd)}"
BIN="${DSTACK_SNP_SMOKE_BIN_DIR:-$REPO/target/release}"
ART="$BASE/artifacts"
LOG="$ART/snp-e2e-smoke.log"
IMAGE_NAME="${DSTACK_SNP_SMOKE_IMAGE_NAME:-dstack-dev-0.5.11-snp-dnsfix}"
IMAGE_URL="${DSTACK_SNP_SMOKE_IMAGE_URL:-https://github.com/Dstack-TEE/meta-dstack/releases/download/v0.5.11/dstack-dev-0.5.11.tar.gz}"
QEMU_PATH="${DSTACK_SNP_SMOKE_QEMU:-/opt/AMDSEV/usr/local/bin/qemu-system-x86_64}"
OVMF_PATH="${DSTACK_SNP_SMOKE_OVMF:-/opt/AMDSEV/usr/local/share/qemu/OVMF.fd}"
HOST_ART_PORT="${DSTACK_SNP_SMOKE_HOST_ART_PORT:-18080}"
AUTH_PORT="${DSTACK_SNP_SMOKE_AUTH_PORT:-18081}"
KMS_HOST_PORT="${DSTACK_SNP_SMOKE_KMS_HOST_PORT:-15443}"
STRICT_KMS_HOST_PORT="${DSTACK_SNP_SMOKE_STRICT_KMS_HOST_PORT:-15444}"
APP_HOST_PORT="${DSTACK_SNP_SMOKE_APP_HOST_PORT:-15543}"
STRICT_APP_HOST_PORT="${DSTACK_SNP_SMOKE_STRICT_APP_HOST_PORT:-15544}"
VMM_PORT="${DSTACK_SNP_SMOKE_VMM_PORT:-18082}"
VMM_URL="${DSTACK_SNP_SMOKE_VMM_URL:-http://127.0.0.1:$VMM_PORT}"
ALLOW_OUT_OF_DATE_TCB="${DSTACK_SNP_SMOKE_ALLOW_OUT_OF_DATE_TCB:-0}"
RUN_STRICT_TCB_PROBE="${DSTACK_SNP_SMOKE_STRICT_TCB_PROBE:-1}"
ALLOW_OLD_QEMU="${DSTACK_SNP_SMOKE_ALLOW_OLD_QEMU:-0}"

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

need curl
need jq
need python3
need sudo

test -x "$BIN/dstack-vmm" || { echo "missing $BIN/dstack-vmm; run cargo build --release -p dstack-vmm" >&2; exit 1; }
test -x "$BIN/supervisor" || { echo "missing $BIN/supervisor; run cargo build --release -p supervisor" >&2; exit 1; }
test -x "$BIN/dstack-kms" || { echo "missing $BIN/dstack-kms; run cargo build --release -p dstack-kms" >&2; exit 1; }
test -x "$QEMU_PATH" || { echo "missing SNP QEMU: $QEMU_PATH" >&2; exit 1; }
test -r "$OVMF_PATH" || { echo "missing SNP OVMF: $OVMF_PATH" >&2; exit 1; }
test -f "$REPO/vmm/src/vmm-cli.py" || { echo "missing vmm-cli.py; set DSTACK_SNP_SMOKE_REPO" >&2; exit 1; }

qemu_version_output=$("$QEMU_PATH" --version | head -1)
qemu_version=$(printf '%s\n' "$qemu_version_output" | sed -n 's/.*version \([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1.\2/p')
qemu_major=${qemu_version%%.*}
if [[ -z "$qemu_version" ]]; then
	echo "Warning: could not parse QEMU version from: $qemu_version_output" >&2
elif (( qemu_major < 10 )) && [[ "$ALLOW_OLD_QEMU" != "1" ]]; then
	cat >&2 <<EOF
Unsupported SNP smoke QEMU version: $qemu_version_output

The known-good PR #703 smoke used AMDSEV QEMU 10.0.2. A local Chipotle
attempt with QEMU 9.1.0 reached OVMF/EFI stub and then exited with:
  qemu-system-x86_64: cpus are not resettable, terminating

Use an AMDSEV QEMU >= 10 build, or set DSTACK_SNP_SMOKE_ALLOW_OLD_QEMU=1
if you intentionally want to reproduce/debug the older-QEMU failure.
EOF
	exit 1
fi

mkdir -p "$ART" "$BASE/images" "$BASE/run" "$BASE/http-root"
exec > >(tee "$LOG") 2>&1

echo "== SNP E2E smoke start: $(date -Is) =="
echo "repo=$REPO"
echo "repo_head=$(git -C "$REPO" rev-parse --short=16 HEAD 2>/dev/null || echo unknown)"
echo "qemu=$QEMU_PATH"
echo "qemu_version=$qemu_version_output"
echo "ovmf_sha256=$(sha256sum "$OVMF_PATH" | awk '{print $1}')"
echo "image=$IMAGE_NAME"
if [[ -n "${DSTACK_SNP_SMOKE_KDS_BASE_URL:-}" ]]; then
	echo "amd_kds_base_url=${DSTACK_SNP_SMOKE_KDS_BASE_URL}"
fi

cleanup() {
	set +e
	if [[ -f "$BASE/vmm.pid" ]]; then sudo kill "$(cat "$BASE/vmm.pid")" 2>/dev/null || true; fi
	if [[ -f "$BASE/artifacts-http.pid" ]]; then kill "$(cat "$BASE/artifacts-http.pid")" 2>/dev/null || true; fi
	if [[ -f "$BASE/auth.pid" ]]; then kill "$(cat "$BASE/auth.pid")" 2>/dev/null || true; fi
	sudo pkill -f "$BIN/dstack-vmm" 2>/dev/null || true
	sudo pkill -f "qemu-system-x86_64.*$BASE" 2>/dev/null || true
	sudo pkill -f "$BASE/images" 2>/dev/null || true
	if command -v fuser >/dev/null 2>&1; then
		fuser -k "${HOST_ART_PORT}/tcp" "${AUTH_PORT}/tcp" "${KMS_HOST_PORT}/tcp" "${STRICT_KMS_HOST_PORT}/tcp" "${APP_HOST_PORT}/tcp" "${STRICT_APP_HOST_PORT}/tcp" "${VMM_PORT}/tcp" 2>/dev/null || true
	fi
}
trap cleanup EXIT
cleanup
sudo pkill -f "$BIN/supervisor" 2>/dev/null || true
sudo rm -rf "$BASE/run"/* "$BASE/tmp"/*

cp "$BIN/dstack-kms" "$BASE/http-root/dstack-kms"
chmod +x "$BASE/http-root/dstack-kms"

if [[ ! -d "$BASE/images/$IMAGE_NAME" ]]; then
	echo "== Downloading/extracting $IMAGE_NAME =="
	curl -L "$IMAGE_URL" -o "$BASE/$IMAGE_NAME.tar.gz"
	mkdir -p "$BASE/images/$IMAGE_NAME"
	tar -xzf "$BASE/$IMAGE_NAME.tar.gz" -C "$BASE/images/$IMAGE_NAME" --strip-components=1
fi
cp "$OVMF_PATH" "$BASE/images/$IMAGE_NAME/ovmf.fd"
tmp_metadata="$(mktemp)"
jq '.bios = "ovmf.fd"' "$BASE/images/$IMAGE_NAME/metadata.json" >"$tmp_metadata"
mv "$tmp_metadata" "$BASE/images/$IMAGE_NAME/metadata.json"
jq . "$BASE/images/$IMAGE_NAME/metadata.json" | tee "$ART/image-metadata.json"

cat >"$BASE/auth-server.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import time


ALLOW_OUT_OF_DATE_TCB = os.environ.get("ALLOW_OUT_OF_DATE_TCB") == "1"


class H(BaseHTTPRequestHandler):
    def _send(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(time.strftime("%Y-%m-%dT%H:%M:%S"), self.path, fmt % args, flush=True)

    def do_GET(self):
        self._send({
            "status": "ok",
            "kmsContractAddr": "0x0000000000000000000000000000000000000000",
            "ethRpcUrl": "",
            "gatewayAppId": "",
            "chainId": 1,
            "appImplementation": "0x0000000000000000000000000000000000000000",
        })

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length)
        try:
            data = json.loads(body or b"{}")
        except Exception:
            data = {}
        summary = {k: data.get(k) for k in ["attestationMode", "tcbStatus", "advisoryIds"] if k in data}
        for key in ["appId", "mrAggregated", "osImageHash", "composeHash", "instanceId"]:
            if key in data:
                summary[key] = str(data[key])[:96]
        print(json.dumps({"path": self.path, "summary": summary}), flush=True)

        # TCB/advisory policy belongs to the auth API. The normal smoke can
        # explicitly allow an OutOfDate lab host; the /strict auth namespace is
        # used by the negative probe to prove denial comes from auth policy, not
        # KMS-local config.
        if self.path.endswith("/bootAuth/app"):
            tcb_status = data.get("tcbStatus") or ""
            advisory_ids = data.get("advisoryIds") or []
            strict_tcb = self.path.startswith("/strict/")
            if tcb_status not in ("", "UpToDate"):
                if strict_tcb or tcb_status != "OutOfDate" or not ALLOW_OUT_OF_DATE_TCB:
                    self._send({
                        "isAllowed": False,
                        "gatewayAppId": "",
                        "reason": f"tcb_status is not allowed by auth api: {tcb_status}",
                    })
                    return
            if advisory_ids:
                self._send({
                    "isAllowed": False,
                    "gatewayAppId": "",
                    "reason": f"advisory_id is not allowed by auth api: {advisory_ids[0]}",
                })
                return

        self._send({"isAllowed": True, "gatewayAppId": "", "reason": "snp smoke auth"})


HTTPServer(("0.0.0.0", int(os.environ["AUTH_PORT"])), H).serve_forever()
PY

(cd "$BASE/http-root" && python3 -m http.server "$HOST_ART_PORT" >"$ART/artifacts-http.log" 2>&1 & echo $! >"$BASE/artifacts-http.pid")
AUTH_PORT="$AUTH_PORT" ALLOW_OUT_OF_DATE_TCB="$ALLOW_OUT_OF_DATE_TCB" python3 "$BASE/auth-server.py" >"$ART/auth-server.log" 2>&1 & echo $! >"$BASE/auth.pid"
sleep 1
curl -fsS "http://127.0.0.1:$HOST_ART_PORT/dstack-kms" -o /dev/null
curl -fsS "http://127.0.0.1:$AUTH_PORT/" | jq . | tee "$ART/auth-info.json"

cat >"$BASE/vmm.toml" <<EOF
workers = 8
max_blocking = 64
ident = "dstack SNP smoke VMM"
temp_dir = "$BASE/tmp"
keep_alive = 10
log_level = "debug"
address = "127.0.0.1"
port = $VMM_PORT
reuse = true
kms_url = "https://127.0.0.1:$KMS_HOST_PORT"
event_buffer_size = 50
node_name = "snp-smoke"
run_path = "$BASE/run"

[image]
path = "$BASE/images"
registry = ""

[cvm]
platform = "amd-sev-snp"
qemu_path = "$QEMU_PATH"
kms_urls = ["https://10.0.2.2:$KMS_HOST_PORT"]
gateway_urls = []
pccs_url = ""
docker_registry = ""
cid_start = 1400
cid_pool_size = 200
max_allocable_vcpu = 16
max_allocable_memory_in_mb = 65536
qmp_socket = false
user = ""
use_mrconfigid = true
qemu_pci_hole64_size = 0
qemu_hotplug_off = false
host_share_mode = "vhd"
qgs_port = 4050

[cvm.product]
sys_vendor = "dstack"
product_name = "dstack"

[cvm.networking]
mode = "user"
net = "10.0.2.0/24"
dhcp_start = "10.0.2.10"
restrict = false
forward_service_enabled = false

[cvm.port_mapping]
enabled = true
address = "127.0.0.1"
range = [{ protocol = "tcp", from = 1, to = 20000 }]

[cvm.auto_restart]
enabled = false
interval = 20

[cvm.gpu]
enabled = false
listing = []
exclude = []
include = []
allow_attach_all = false

[gateway]
base_domain = "localhost"
port = 8082
agent_port = 8090

[auth]
enabled = false
tokens = []

[supervisor]
exe = "$BIN/supervisor"
sock = "$BASE/run/supervisor.sock"
pid_file = "$BASE/run/supervisor.pid"
log_file = "$ART/supervisor.log"
detached = false
auto_start = true

[host_api]
ident = "dstack SNP smoke VMM"
address = "vsock:0xffffffff"
port = 10000

[key_provider]
enabled = true
address = "127.0.0.1"
port = 3443
EOF

# Redirect to a user-owned artifact file; only the VMM process itself needs sudo.
# shellcheck disable=SC2024
sudo "$BIN/dstack-vmm" -c "$BASE/vmm.toml" serve >"$ART/vmm.log" 2>&1 & echo $! >"$BASE/vmm.pid"
for i in $(seq 1 60); do
	if python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" lsvm --json >/dev/null 2>&1; then break; fi
	sleep 1
	if [[ $i -eq 60 ]]; then echo "VMM did not become ready"; tail -80 "$ART/vmm.log"; exit 1; fi
done
echo "== VMM ready =="

write_kms_config() {
	local auth_prefix="$1"
	local auth_url="http://10.0.2.2:$AUTH_PORT"
	if [[ -n "$auth_prefix" ]]; then
		auth_url="$auth_url/$auth_prefix"
	fi
	cat >"$BASE/http-root/kms.toml" <<EOF
[rpc]
address = "0.0.0.0"
port = 8000

[rpc.tls]
key = "/dstack/kms-certs/rpc.key"
certs = "/dstack/kms-certs/rpc.crt"

[rpc.tls.mutual]
ca_certs = "/dstack/kms-certs/tmp-ca.crt"
mandatory = false

[core]
cert_dir = "/dstack/kms-certs"
admin_token_hash = "00"
pccs_url = ""
enforce_self_authorization = true
amd_kds_base_url = "${DSTACK_SNP_SMOKE_KDS_BASE_URL:-}"
sev_snp_key_release = true

[core.metrics]
enabled = true

[core.image]
verify = false
cache_dir = "/dstack/kms-images"
download_url = ""
download_timeout = "2m"

[core.auth_api]
type = "webhook"

[core.auth_api.webhook]
url = "$auth_url"

[core.onboard]
enabled = true
auto_bootstrap_domain = "10.0.2.2"
EOF
}

DNS_INIT_SCRIPT=$(cat <<'SH'
set -eux
mkdir -p /etc/docker
cat >/etc/docker/daemon.json <<'JSON'
{"dns":["10.0.2.3","1.1.1.1","8.8.8.8"]}
JSON
rm -f /etc/resolv.conf
printf 'nameserver 10.0.2.3\nnameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:3\n' >/etc/resolv.conf
if command -v systemctl >/dev/null 2>&1 && systemctl is-active docker >/dev/null 2>&1; then
  systemctl restart docker
fi
SH
)

KMS_BASH_SCRIPT=$(cat <<'SH'
set -eux
mkdir -p /dstack/kms-certs /dstack/kms-images
curl -fsS http://10.0.2.2:__DSTACK_HOST_ART_PORT__/dstack-kms -o /dstack/dstack-kms
curl -fsS http://10.0.2.2:__DSTACK_HOST_ART_PORT__/kms.toml -o /dstack/kms.toml
chmod +x /dstack/dstack-kms
echo SNP_KMS_CONTAINER_STARTED
RUST_LOG=info /dstack/dstack-kms -c /dstack/kms.toml
SH
)
KMS_BASH_SCRIPT=${KMS_BASH_SCRIPT/__DSTACK_HOST_ART_PORT__/$HOST_ART_PORT}
KMS_BASH_SCRIPT=${KMS_BASH_SCRIPT//__DSTACK_HOST_ART_PORT__/$HOST_ART_PORT}

deploy_kms() {
	local name="$1"
	local auth_prefix="$2"
	local host_port="$3"
	write_kms_config "$auth_prefix"
	cat >"$BASE/kms-compose.yaml" <<'YAML'
services:
  kms:
    image: debian:bookworm-slim
    command: sh -c 'echo unused-container-compose; sleep 300'
YAML
	python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" compose --docker-compose "$BASE/kms-compose.yaml" --name "$name" --public-logs --public-sysinfo --no-instance-id --output "$BASE/$name.app-compose.json" | tee "$ART/$name-compose-create.txt" >&2
	jq --arg init_script "$DNS_INIT_SCRIPT" --arg bash_script "$KMS_BASH_SCRIPT" '.storage_fs="ext4" | .init_script=$init_script | .runner="bash" | .bash_script=$bash_script | del(.docker_compose_file)' "$BASE/$name.app-compose.json" >"$BASE/$name.app-compose.json.tmp"
	mv "$BASE/$name.app-compose.json.tmp" "$BASE/$name.app-compose.json"
	python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" deploy --name "$name" --compose "$BASE/$name.app-compose.json" --image "$IMAGE_NAME" --port "tcp:127.0.0.1:$host_port:8000" --vcpu 2 --memory 4096 --disk 20G | tee "$ART/$name-deploy.txt" >&2
	sed -n 's/Created VM with ID: //p' "$ART/$name-deploy.txt" | tail -1
}

wait_for_kms_metrics() {
	local vm_id="$1"
	local host_port="$2"
	local label="$3"
	for i in $(seq 1 240); do
		if curl -kfsS "https://127.0.0.1:$host_port/metrics" >/dev/null 2>&1; then echo "$label KMS runtime ready after ${i}s"; break; fi
		sleep 2
		if [[ $((i % 30)) -eq 0 ]]; then echo "waiting for $label KMS..."; python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$vm_id" -n 30 || true; fi
		if [[ $i -eq 240 ]]; then echo "$label KMS did not become ready"; python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$vm_id" -n 200 || true; exit 1; fi
	done
}

deploy_app() {
	local name="$1"
	local kms_port="$2"
	local app_port="$3"
	cat >"$BASE/$name-compose.yaml" <<'YAML'
services:
  smoke:
    image: debian:bookworm-slim
    command: sh -c 'echo SNP_APP_CONTAINER_STARTED; sleep 300'
YAML
	python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" compose --docker-compose "$BASE/$name-compose.yaml" --name "$name" --kms --public-logs --public-sysinfo --no-instance-id --output "$BASE/$name.app-compose.json" | tee "$ART/$name-compose-create.txt" >&2
	jq --arg init_script "$DNS_INIT_SCRIPT" '.storage_fs="ext4" | .init_script=$init_script' "$BASE/$name.app-compose.json" >"$BASE/$name.app-compose.json.tmp"
	mv "$BASE/$name.app-compose.json.tmp" "$BASE/$name.app-compose.json"
	python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" deploy --name "$name" --compose "$BASE/$name.app-compose.json" --image "$IMAGE_NAME" --kms-url "https://10.0.2.2:$kms_port" --port "tcp:127.0.0.1:$app_port:8000" --vcpu 2 --memory 4096 --disk 20G | tee "$ART/$name-deploy.txt" >&2
	sed -n 's/Created VM with ID: //p' "$ART/$name-deploy.txt" | tail -1
}

if [[ "$RUN_STRICT_TCB_PROBE" = "1" && "$ALLOW_OUT_OF_DATE_TCB" = "1" ]]; then
	echo "== Strict TCB probe: expect app GetAppKey denial on lab OutOfDate host =="
	STRICT_KMS_VM_ID=$(deploy_kms snp-smoke-kms-strict strict "$STRICT_KMS_HOST_PORT")
	echo "STRICT_KMS_VM_ID=$STRICT_KMS_VM_ID"
	wait_for_kms_metrics "$STRICT_KMS_VM_ID" "$STRICT_KMS_HOST_PORT" strict
	STRICT_APP_VM_ID=$(deploy_app snp-smoke-app-strict "$STRICT_KMS_HOST_PORT" "$STRICT_APP_HOST_PORT")
	echo "STRICT_APP_VM_ID=$STRICT_APP_VM_ID"
	for i in $(seq 1 240); do
		logs=$(python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$STRICT_APP_VM_ID" -n 180 2>/dev/null || true)
		kms_logs=$(python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$STRICT_KMS_VM_ID" -n 220 2>/dev/null || true)
		if { echo "$logs"; echo "$kms_logs"; } | grep -q "tcb_status is not allowed"; then
			{ echo "$logs"; echo "$kms_logs"; } | tee "$ART/strict-tcb-denial-log.txt"
			echo "strict_tcb_probe=denied_as_expected"
			break
		fi
		if { echo "$logs"; echo "$kms_logs"; } | grep -q "KDS collateral unavailable\|HTTP status client error"; then
			{ echo "$logs"; echo "$kms_logs"; } | tee "$ART/strict-tcb-kds-blocked-log.txt"
			echo "strict_tcb_probe=blocked_by_kds_collateral"
			break
		fi
		if echo "$logs" | grep -Eq "SNP_APP_CONTAINER_STARTED|Container dstack-smoke-1 Started"; then echo "$logs" | tee "$ART/strict-tcb-unexpected-success-log.txt"; echo "strict TCB probe unexpectedly reached app container"; exit 1; fi
		sleep 2
		if [[ $((i % 30)) -eq 0 ]]; then echo "waiting for strict APP denial..."; echo "$logs" | tail -60; echo "$kms_logs" | tail -60; fi
		if [[ $i -eq 240 ]]; then echo "strict TCB probe did not reach expected denial"; { echo "$logs"; echo "$kms_logs"; } | tee "$ART/strict-tcb-timeout-log.txt"; exit 1; fi
	done
fi

echo "== KMS success run =="
KMS_VM_ID=$(deploy_kms snp-smoke-kms "" "$KMS_HOST_PORT")
echo "KMS_VM_ID=$KMS_VM_ID"
wait_for_kms_metrics "$KMS_VM_ID" "$KMS_HOST_PORT" success
curl -kfsS "https://127.0.0.1:$KMS_HOST_PORT/metrics" | tee "$ART/kms-metrics-before-app.txt"

APP_VM_ID=$(deploy_app snp-smoke-app "$KMS_HOST_PORT" "$APP_HOST_PORT")
echo "APP_VM_ID=$APP_VM_ID"

for i in $(seq 1 240); do
	logs=$(python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$APP_VM_ID" -n 160 2>/dev/null || true)
	if echo "$logs" | grep -Eq "SNP_APP_CONTAINER_STARTED|Container dstack-smoke-1 Started"; then echo "$logs" | tee "$ART/app-ready-log.txt"; echo "APP ready after ${i}s"; break; fi
	if echo "$logs" | grep -q "Failed to get app key\|amd sev-snp key release\|measurement mismatch\|App not allowed\|KMS self authorization failed\|KDS collateral unavailable\|HTTP status client error"; then echo "$logs" | tee "$ART/app-failure-log.txt"; exit 2; fi
	sleep 2
	if [[ $((i % 30)) -eq 0 ]]; then echo "waiting for APP..."; echo "$logs" | tail -60; fi
	if [[ $i -eq 240 ]]; then echo "APP did not become ready"; echo "$logs" | tee "$ART/app-timeout-log.txt"; exit 1; fi
done

curl -kfsS "https://127.0.0.1:$KMS_HOST_PORT/metrics" | tee "$ART/kms-metrics-after-app.txt"
python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" info "$KMS_VM_ID" --json | tee "$ART/kms-info.json"
python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" info "$APP_VM_ID" --json | tee "$ART/app-info.json"
python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$KMS_VM_ID" -n 200 | tee "$ART/kms-final-log.txt" || true
python3 "$REPO/vmm/src/vmm-cli.py" --url "$VMM_URL" logs "$APP_VM_ID" -n 200 | tee "$ART/app-final-log.txt" || true

echo "== SNP E2E smoke success: $(date -Is) =="
echo "Artifacts: $ART"
