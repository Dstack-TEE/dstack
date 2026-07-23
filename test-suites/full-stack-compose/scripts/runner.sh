#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
CONFIG_DIR=${DSTACK_E2E_CONFIG_DIR:-$STATE_DIR/config}
WORK_DIR=${DSTACK_E2E_WORK_DIR:-$STATE_DIR/work}
VM_DIR=${DSTACK_E2E_VM_DIR:-$STATE_DIR/vm}
PHASE=${DSTACK_E2E_PHASE:-upgrade}
CURRENT_VERSION=${DSTACK_E2E_CURRENT_VERSION:?missing current workspace version}
CURRENT_REV=${DSTACK_E2E_CURRENT_REV:?missing current workspace revision}
mkdir -p "$WORK_DIR"
# shellcheck disable=SC1091
source "$STATE_DIR/state.env"
# shellcheck disable=SC1091
source "$STATE_DIR/artifacts/images.env"

VMM_URL="http://127.0.0.1:${VMM_PORT}"
VMM_CLI=(python3 /workspace/vmm/src/vmm-cli.py --url "$VMM_URL")
DSTACK_CLI=(/workspace/target/release/dstack --host "$VMM_URL")
ALLOWLIST="$CONFIG_DIR/auth-allowlist.json"
KMS_OLD_URL="https://${KMS_RPC_DOMAIN}:${KMS_OLD_HOST_PORT}"
KMS_LATEST_URL="https://${KMS_RPC_DOMAIN}:${KMS_LATEST_HOST_PORT}"
GATEWAY1_URL="https://${KMS_RPC_DOMAIN}:${GATEWAY1_RPC_HOST_PORT}"
GATEWAY2_URL="https://${KMS_RPC_DOMAIN}:${GATEWAY2_RPC_HOST_PORT}"
probe_pid=""
ATTESTED_DEVICE_ID=""

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

need_bin() {
  [[ -x "$1" ]] || die "missing executable $1"
}

wait_vmm() {
  log "waiting for VMM at $VMM_URL"
  for _ in $(seq 1 120); do
    if "${DSTACK_CLI[@]}" apps -j >/dev/null 2>&1; then
      log "VMM ready"
      return
    fi
    sleep 2
  done
  die "VMM not ready"
}

vm_ids_by_prefix() {
  local prefix=$1
  "${VMM_CLI[@]}" lsvm --json 2>/dev/null \
    | jq -r --arg p "$prefix" '.[] | select(.name | startswith($p)) | .id'
}

remove_vm() {
  local id=$1
  [[ -n "$id" ]] || return 0
  log "removing VM $id"
  "${VMM_CLI[@]}" remove "$id" >/dev/null 2>&1 || true
}

clean_start() {
  [[ "${DSTACK_E2E_CLEAN_START:-true}" == true ]] || return 0
  while read -r id; do
    remove_vm "$id"
  done < <(vm_ids_by_prefix "$SUITE_PREFIX")
  for _ in $(seq 1 90); do
    [[ -z "$(vm_ids_by_prefix "$SUITE_PREFIX")" ]] && return 0
    sleep 2
  done
  die "stale VMs were not removed"
}

print_vm_info_safe() {
  jq '{id,name,status,uptime,app_id,instance_id,boot_progress,boot_error,image_version,events}' <<<"$1"
}

wait_boot_done() {
  local id=$1 label=$2 timeout=${3:-720}
  local deadline=$((SECONDS + timeout)) last=""
  while (( SECONDS < deadline )); do
    local info status progress error line
    info=$("${VMM_CLI[@]}" info "$id" --json 2>/dev/null || true)
    if [[ -n "$info" ]]; then
      status=$(jq -r '.status // ""' <<<"$info")
      progress=$(jq -r '.boot_progress // ""' <<<"$info")
      error=$(jq -r '.boot_error // ""' <<<"$info")
      line="status=$status progress=${progress:-none} error=${error:-none}"
      if [[ "$line" != "$last" ]]; then
        log "$label: $line"
        last=$line
      fi
      if [[ -n "$error" && "$error" != null ]]; then
        print_vm_info_safe "$info" >&2 || true
        "${VMM_CLI[@]}" logs "$id" -n 240 >&2 || true
        die "$label boot failed: $error"
      fi
      if [[ "$status" == running && "$progress" == "done" ]]; then
        printf '%s' "$info" > "$WORK_DIR/${label}.info.json"
        return
      fi
      if [[ "$status" == exited || "$status" == stopped ]]; then
        print_vm_info_safe "$info" >&2 || true
        "${VMM_CLI[@]}" logs "$id" -n 240 >&2 || true
        die "$label exited before boot finished"
      fi
    fi
    sleep 5
  done
  "${VMM_CLI[@]}" logs "$id" -n 300 >&2 || true
  die "timed out waiting for $label"
}

wait_vm_stopped() {
  local id=$1 deadline=$((SECONDS + 180)) status
  while (( SECONDS < deadline )); do
    status=$("${VMM_CLI[@]}" info "$id" --json 2>/dev/null | jq -r '.status // ""' || true)
    [[ "$status" == stopped || "$status" == exited ]] && return
    sleep 2
  done
  die "VM $id did not stop"
}

stop_vm() {
  local id=$1 label=$2
  log "stopping $label ($id)"
  "${VMM_CLI[@]}" stop "$id" --force >/dev/null
  wait_vm_stopped "$id"
}

start_vm() {
  local id=$1 label=$2
  log "starting $label ($id)"
  "${VMM_CLI[@]}" start "$id" >/dev/null
  wait_boot_done "$id" "$label"
}

register_app() {
  local app_id=$1 hash=$2
  [[ -n "$ATTESTED_DEVICE_ID" ]] || die "cannot authorize app before pinning the attested TDX device"
  /suite/scripts/allowlist.py add-app --path "$ALLOWLIST" \
    --app-id "$app_id" --compose-hash "$hash" \
    --device-id "$ATTESTED_DEVICE_ID" >/dev/null
}

register_kms_measurement() {
  local measurement=$1 device_id=$2
  /suite/scripts/allowlist.py add-kms --path "$ALLOWLIST" \
    --mr-aggregated "$measurement" --device-id "$device_id" >/dev/null
}

render_kms() {
  local stage=$1 image_ref=$2 archive=$3 meta
  meta=$(/suite/scripts/app_compose.py kms \
    --name "dstack-e2e-kms-${stage}" \
    --image-ref "$image_ref" \
    --image-archive "$archive" \
    --artifact-port "$ARTIFACT_PORT" \
    --auth-port "$AUTH_PORT" \
    --output "$WORK_DIR/kms-${stage}.app-compose.json")
  printf '%s\n' "$meta" > "$WORK_DIR/kms-${stage}.manifest-meta.json"
}

deploy_kms_onboard() {
  local stage=$1 port=$2 out vm_id
  log "deploying $stage KMS CVM in Local-Key-Provider mode"
  if ! out=$("${VMM_CLI[@]}" deploy \
    --name "${SUITE_PREFIX}-kms-${stage}" \
    --image "$IMAGE_NAME" \
    --compose "$WORK_DIR/kms-${stage}.app-compose.json" \
    --port "tcp:0.0.0.0:${port}:8000" \
    --vcpu "${DSTACK_E2E_KMS_VCPU:-4}" \
    --memory "${DSTACK_E2E_KMS_MEMORY:-4096}" \
    --disk "${DSTACK_E2E_KMS_DISK:-30}" 2>&1); then
    die "failed to deploy $stage KMS CVM: $out"
  fi
  printf '%s\n' "$out" | tee "$WORK_DIR/kms-${stage}.deploy.log"
  vm_id=$(sed -n 's/^Created VM with ID: //p' <<<"$out" | tail -n1)
  [[ -n "$vm_id" ]] || die "failed to parse $stage KMS VM id"
  printf '%s' "$vm_id" > "$WORK_DIR/kms-${stage}.vm_id"
  wait_boot_done "$vm_id" "kms-${stage}"
}

wait_onboard() {
  local stage=$1 port=$2 deadline=$((SECONDS + 300)) url
  url="http://127.0.0.1:${port}/prpc/Onboard.GetAttestationInfo?json"
  log "waiting for $stage KMS quote-enabled onboarding endpoint"
  while (( SECONDS < deadline )); do
    if curl -fsS "$url" -o "$WORK_DIR/kms-${stage}.attestation-info.json"; then
      jq -e '((.mr_aggregated // .mrAggregated // "") | length) > 0 and ((.device_id // .deviceId // "") | length) > 0' \
        "$WORK_DIR/kms-${stage}.attestation-info.json" >/dev/null && return
    fi
    sleep 3
  done
  "${VMM_CLI[@]}" logs "$(cat "$WORK_DIR/kms-${stage}.vm_id")" -n 300 >&2 || true
  die "$stage KMS onboarding endpoint not ready"
}

authorize_kms_from_attestation() {
  local stage=$1 measurement device_id
  measurement=$(jq -r '.mr_aggregated // .mrAggregated' "$WORK_DIR/kms-${stage}.attestation-info.json")
  device_id=$(jq -r '.device_id // .deviceId' "$WORK_DIR/kms-${stage}.attestation-info.json")
  [[ "$measurement" =~ ^[0-9a-fA-F]+$ ]] || die "invalid $stage KMS mrAggregated"
  [[ "$device_id" =~ ^[0-9a-fA-F]{64}$ ]] || die "invalid $stage KMS device ID"
  if [[ -n "$ATTESTED_DEVICE_ID" && "$device_id" != "$ATTESTED_DEVICE_ID" ]]; then
    die "$stage KMS quote came from unexpected TDX device $device_id"
  fi
  ATTESTED_DEVICE_ID=$device_id
  register_kms_measurement "$measurement" "$device_id"
  log "authorized exact $stage KMS mrAggregated=${measurement} on device=${device_id}"
}

onboard_rpc() {
  local port=$1 method=$2 data=$3 out=$4
  curl -fsS -X POST -H 'Content-Type: application/json' \
    "http://127.0.0.1:${port}/prpc/Onboard.${method}?json" \
    --data-raw "$data" -o "$out"
  jq -e 'has("error") | not' "$out" >/dev/null \
    || die "Onboard.${method} returned an error: $(cat "$out")"
  log "Onboard.${method} completed"
}

finish_onboarding() {
  local stage=$1 port=$2
  curl -fsS "http://127.0.0.1:${port}/finish" > "$WORK_DIR/kms-${stage}.finish.txt"
  wait_kms_tls "$stage" "$port"
}

wait_kms_tls() {
  local stage=$1 port=$2 deadline=$((SECONDS + 300))
  log "waiting for $stage KMS TLS service"
  while (( SECONDS < deadline )); do
    if curl -kfsS "https://127.0.0.1:${port}/prpc/GetMeta?json" \
      -o "$WORK_DIR/kms-${stage}.ready-meta.json"; then
      log "$stage KMS TLS service ready"
      return
    fi
    sleep 3
  done
  "${VMM_CLI[@]}" logs "$(cat "$WORK_DIR/kms-${stage}.vm_id")" -n 300 >&2 || true
  die "$stage KMS TLS service not ready"
}

kms_rpc_get() {
  local port=$1 method=$2
  curl -kfsS "https://127.0.0.1:${port}/prpc/${method}?json"
}

kms_rpc_post() {
  local port=$1 method=$2 data=$3
  curl -kfsS -X POST -H 'Content-Type: application/json' \
    "https://127.0.0.1:${port}/prpc/${method}?json" --data-raw "$data"
}

capture_kms_identity() {
  local stage=$1 port=$2 app_id=$3 ca_pem ca_spki k256_pubkey
  ca_pem="$WORK_DIR/kms-${stage}.ca.pem"
  kms_rpc_get "$port" GetMeta | tee "$WORK_DIR/kms-${stage}.meta.raw.json" \
    | jq -S '{ca_cert, k256_pubkey}' > "$WORK_DIR/kms-${stage}.meta.json"
  jq -er '.ca_cert' "$WORK_DIR/kms-${stage}.meta.json" > "$ca_pem"
  openssl x509 -in "$ca_pem" -noout -checkend 0 >/dev/null
  ca_spki=$(openssl x509 -in "$ca_pem" -pubkey -noout \
    | openssl pkey -pubin -outform DER \
    | openssl dgst -sha256 \
    | awk '{print $NF}')
  k256_pubkey=$(jq -er '.k256_pubkey' "$WORK_DIR/kms-${stage}.meta.json")
  jq -nS --arg ca_spki_sha256 "$ca_spki" --arg k256_pubkey "$k256_pubkey" \
    '{ca_spki_sha256:$ca_spki_sha256,k256_pubkey:$k256_pubkey}' \
    > "$WORK_DIR/kms-${stage}.identity.json"
  kms_rpc_post "$port" GetAppEnvEncryptPubKey \
    "$(jq -cn --arg id "$app_id" '{app_id:$id}')" \
    | tee "$WORK_DIR/kms-${stage}.app-key.raw.json" \
    | jq -S '{public_key}' > "$WORK_DIR/kms-${stage}.app-key.json"
  jq -e '.ca_spki_sha256 != "" and .k256_pubkey != ""' \
    "$WORK_DIR/kms-${stage}.identity.json" >/dev/null
  jq -e '.public_key != ""' "$WORK_DIR/kms-${stage}.app-key.json" >/dev/null
}

assert_kms_identity_unchanged() {
  # Onboarding deliberately reissues the self-signed CA certificate with a new
  # validity end time.  The transferable identity is its private key/SPKI, not
  # the DER bytes of that freshly issued certificate.
  diff -u "$WORK_DIR/kms-old.identity.json" "$WORK_DIR/kms-latest.identity.json" \
    || die "KMS CA key or root k256 key changed during 0.5.8 -> current onboarding"
  diff -u "$WORK_DIR/kms-old.app-key.json" "$WORK_DIR/kms-latest.app-key.json" \
    || die "per-app environment encryption key changed during KMS upgrade"
  log "KMS CA SPKI, root k256 key and per-app environment key are unchanged"
}

render_gateway_manifests() {
  local stage=$1 image_ref=$2 archive=$3 meta
  meta=$(/suite/scripts/app_compose.py gateway \
    --name dstack-e2e-gateway \
    --image-ref "$image_ref" \
    --image-archive "$archive" \
    --artifact-port "$ARTIFACT_PORT" \
    --output "$WORK_DIR/gateway-${stage}.app-compose.json")
  printf '%s\n' "$meta" > "$WORK_DIR/gateway-${stage}.manifest-meta.json"
  register_app "$GATEWAY_APP_ID" "$(jq -r .composeHash <<<"$meta")"
}

write_gateway_env() {
  local node=$1 rpc_port wg_port third_octet bootnode
  if [[ "$node" == 1 ]]; then
    rpc_port=$GATEWAY1_RPC_HOST_PORT
    wg_port=$GATEWAY1_WG_HOST_PORT
    third_octet=0
    bootnode=""
  else
    rpc_port=$GATEWAY2_RPC_HOST_PORT
    wg_port=$GATEWAY2_WG_HOST_PORT
    third_octet=64
    bootnode="$GATEWAY1_URL"
  fi
  cat > "$WORK_DIR/gateway${node}.env" <<EOF
WG_ENDPOINT=10.0.2.2:${wg_port}
MY_URL=https://${KMS_RPC_DOMAIN}:${rpc_port}
BOOTNODE_URL=${bootnode}
WG_IP=10.8.${third_octet}.1/16
WG_RESERVED_NET=10.8.${third_octet}.1/32
WG_CLIENT_RANGE=10.8.${third_octet}.0/18
NODE_ID=${node}
PCCS_URL=
RPC_DOMAIN=${KMS_RPC_DOMAIN}
ADMIN_API_TOKEN=${GATEWAY_ADMIN_TOKEN}
EOF
  chmod 0600 "$WORK_DIR/gateway${node}.env"
}

gateway_ports() {
  local node=$1
  if [[ "$node" == 1 ]]; then
    printf '%s %s %s %s\n' "$GATEWAY1_RPC_HOST_PORT" "$GATEWAY1_ADMIN_HOST_PORT" \
      "$GATEWAY1_PROXY_HOST_PORT" "$GATEWAY1_WG_HOST_PORT"
  else
    printf '%s %s %s %s\n' "$GATEWAY2_RPC_HOST_PORT" "$GATEWAY2_ADMIN_HOST_PORT" \
      "$GATEWAY2_PROXY_HOST_PORT" "$GATEWAY2_WG_HOST_PORT"
  fi
}

deploy_gateway() {
  local node=$1 stage=$2 kms_url=$3 rpc admin proxy wg out vm_id
  read -r rpc admin proxy wg < <(gateway_ports "$node")
  log "deploying Gateway node $node ($stage) with pinned app id $GATEWAY_APP_ID"
  if ! out=$("${VMM_CLI[@]}" deploy \
    --name "${SUITE_PREFIX}-gateway-${node}" \
    --app-id "$GATEWAY_APP_ID" \
    --image "$IMAGE_NAME" \
    --compose "$WORK_DIR/gateway-${stage}.app-compose.json" \
    --env-file "$WORK_DIR/gateway${node}.env" \
    --kms-url "$kms_url" \
    --port "tcp:0.0.0.0:${rpc}:8000" \
    --port "tcp:127.0.0.1:${admin}:8001" \
    --port "tcp:127.0.0.1:${proxy}:443" \
    --port "udp:0.0.0.0:${wg}:51820" \
    --vcpu "${DSTACK_E2E_GATEWAY_VCPU:-4}" \
    --memory "${DSTACK_E2E_GATEWAY_MEMORY:-4096}" \
    --disk "${DSTACK_E2E_GATEWAY_DISK:-30}" 2>&1); then
    die "failed to deploy Gateway node $node ($stage): $out"
  fi
  printf '%s\n' "$out" | tee "$WORK_DIR/gateway${node}.${stage}.deploy.log"
  vm_id=$(sed -n 's/^Created VM with ID: //p' <<<"$out" | tail -n1)
  [[ -n "$vm_id" ]] || die "failed to parse Gateway node $node VM id"
  printf '%s' "$vm_id" > "$WORK_DIR/gateway${node}.vm_id"
  wait_boot_done "$vm_id" "gateway${node}-${stage}"
  wait_gateway "$node"
}

gateway_version() {
  local node=$1 stage=$2 rpc _
  read -r rpc _ < <(gateway_ports "$node")
  curl -kfsS -D "$WORK_DIR/gateway${node}-${stage}.headers" -o /dev/null \
    "https://127.0.0.1:${rpc}/prpc/Info?json"
  tr -d '\r' < "$WORK_DIR/gateway${node}-${stage}.headers" \
    | awk 'tolower($1)=="x-app-version:" {$1=""; sub(/^ /,""); print}' \
    > "$WORK_DIR/gateway${node}-${stage}.version.txt"
  [[ -s "$WORK_DIR/gateway${node}-${stage}.version.txt" ]] \
    || die "Gateway node $node did not return X-App-Version"
  if [[ "$stage" == old ]]; then
    grep -E '^v0\.5\.8 \(git:' "$WORK_DIR/gateway${node}-${stage}.version.txt" >/dev/null \
      || die "Gateway node $node did not run released v0.5.8"
  else
    grep -E "^v${CURRENT_VERSION//./\\.} \\(git:" \
      "$WORK_DIR/gateway${node}-${stage}.version.txt" >/dev/null \
      || die "Gateway node $node did not run current v$CURRENT_VERSION"
    grep -F "$CURRENT_REV" "$WORK_DIR/gateway${node}-${stage}.version.txt" >/dev/null \
      || die "Gateway node $node did not run current revision $CURRENT_REV"
  fi
  log "Gateway node $node $stage: $(cat "$WORK_DIR/gateway${node}-${stage}.version.txt")"
}

admin_curl() {
  local node=$1 method=$2 data=${3:-'{}'} admin out code
  read -r _ admin _ < <(gateway_ports "$node")
  out=$(mktemp)
  code=$(curl -sS -o "$out" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${GATEWAY_ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' \
    "http://127.0.0.1:${admin}/prpc/Admin.${method}?json" \
    --data-raw "$data" || true)
  if [[ "$code" =~ ^2 ]]; then
    cat "$out"
    rm -f "$out"
    return
  fi
  log "Gateway $node Admin.${method} failed HTTP $code: $(cat "$out")" >&2
  rm -f "$out"
  return 1
}

wait_gateway() {
  local node=$1 rpc deadline=$((SECONDS + 300))
  read -r rpc _ < <(gateway_ports "$node")
  while (( SECONDS < deadline )); do
    if curl -kfsS "https://127.0.0.1:${rpc}/prpc/Info?json" >/dev/null 2>&1 \
      && admin_curl "$node" Status >/dev/null 2>&1; then
      log "Gateway node $node ready"
      return
    fi
    sleep 3
  done
  "${VMM_CLI[@]}" logs "$(cat "$WORK_DIR/gateway${node}.vm_id")" -n 300 >&2 || true
  die "Gateway node $node not ready"
}

bootstrap_gateway() {
  log "configuring Gateway cluster through node 1"
  admin_curl 1 SetCertbotConfig \
    "$(jq -cn --arg u "http://10.0.2.2:${PEBBLE_HTTP_PORT}/dir" \
      '{acme_url:$u, renew_before_expiration_secs:3600}')" >/dev/null
  admin_curl 1 CreateDnsCredential \
    "$(jq -cn --arg u "http://10.0.2.2:${MOCK_CF_HTTP_PORT}/client/v4" \
      '{name:"mock-cloudflare",provider_type:"cloudflare",cf_api_token:"test-token",cf_api_url:$u,set_as_default:true,dns_txt_ttl:1,max_dns_wait:0}')" \
    >/dev/null
  admin_curl 1 AddZtDomain \
    "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d,port:443,priority:100}')" \
    >/dev/null
  admin_curl 1 RenewZtDomainCert \
    "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d,force:true}')" \
    | tee "$WORK_DIR/gateway-renew-cert.json"
  wait_gateway_cert 1
  wait_gateway_cluster_sync
  wait_gateway_cert 2
}

wait_gateway_cluster_sync() {
  local deadline=$((SECONDS + 240)) domains certbot
  log "waiting for Gateway WaveKV config/certificate sync to node 2"
  while (( SECONDS < deadline )); do
    domains=$(admin_curl 2 ListZtDomains 2>/dev/null || true)
    certbot=$(admin_curl 2 GetCertbotConfig 2>/dev/null || true)
    if jq -e --arg d "$BASE_DOMAIN" '.domains[]? | (.domain // .config.domain) == $d' \
      <<<"$domains" >/dev/null 2>&1 \
      && jq -e '.acme_url != ""' <<<"$certbot" >/dev/null 2>&1; then
      log "Gateway cluster state synced"
      return
    fi
    sleep 3
  done
  die "Gateway node 2 did not receive synced cluster state"
}

wait_gateway_cert() {
  local node=$1 proxy deadline=$((SECONDS + 300)) sni="gateway.${BASE_DOMAIN}"
  read -r _ _ proxy _ < <(gateway_ports "$node")
  while (( SECONDS < deadline )); do
    if echo | timeout 8 openssl s_client -connect "127.0.0.1:${proxy}" -servername "$sni" 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null \
      | grep -Fq "*.${BASE_DOMAIN}"; then
      log "Gateway node $node wildcard certificate active"
      return
    fi
    sleep 3
  done
  die "Gateway node $node wildcard certificate not active"
}

gateway_cert_fingerprint() {
  local node=$1 proxy sni="gateway.${BASE_DOMAIN}"
  read -r _ _ proxy _ < <(gateway_ports "$node")
  echo | timeout 8 openssl s_client -connect "127.0.0.1:${proxy}" -servername "$sni" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null
}

wait_gateway_persisted() {
  local node=$1 deadline=$((SECONDS + 120)) status
  while (( SECONDS < deadline )); do
    status=$(admin_curl "$node" WaveKvStatus 2>/dev/null || true)
    if jq -e '.persistent.dirty == false and .persistent.n_keys > 0' <<<"$status" >/dev/null 2>&1; then
      return
    fi
    sleep 2
  done
  die "Gateway node $node persistent store did not flush"
}

capture_gateway_state() {
  local node=$1 stage=$2
  wait_gateway_persisted "$node"
  admin_curl "$node" Status | tee "$WORK_DIR/gateway${node}-${stage}.status.raw.json" \
    | jq -S '. as $status | {
        id: $status.id,
        uuid: ([$status.nodes[] | select(.id == $status.id)][0].uuid),
        # The active WireGuard address can move to the surviving Gateway
        # subnet during a rolling restart. It is runtime routing state, not a
        # durable identity invariant.
        hosts: ([$status.hosts[] | {instance_id,app_id,base_domain}] | sort_by(.instance_id))
      }' \
    > "$WORK_DIR/gateway${node}-${stage}.status.json"
  admin_curl "$node" GetCertbotConfig | jq -S \
    '{acme_url,renew_interval_secs,renew_before_expiration_secs,renew_timeout_secs}' \
    > "$WORK_DIR/gateway${node}-${stage}.certbot.json"
  admin_curl "$node" ListDnsCredentials | jq -S \
    '{default_id,credentials:([.credentials[]|{
      id,name,provider_type,
      cf_api_token_set: ((.cf_api_token // "") | length > 0),
      cf_zone_id,cf_api_url,dns_txt_ttl,max_dns_wait
    }]|sort_by(.id))}' \
    > "$WORK_DIR/gateway${node}-${stage}.dns.json"
  admin_curl "$node" ListZtDomains | jq -S \
    '{domains:([.domains[]|(.config // .)]|sort_by(.domain))}' \
    > "$WORK_DIR/gateway${node}-${stage}.domains.json"
  gateway_cert_fingerprint "$node" > "$WORK_DIR/gateway${node}-${stage}.cert.txt"
}

assert_gateway_state_unchanged() {
  local node=$1 file
  capture_gateway_state "$node" after
  for file in status certbot dns domains; do
    diff -u "$WORK_DIR/gateway${node}-before.${file}.json" \
      "$WORK_DIR/gateway${node}-after.${file}.json" \
      || die "Gateway node $node $file state changed across upgrade"
  done
  diff -u "$WORK_DIR/gateway${node}-before.cert.txt" "$WORK_DIR/gateway${node}-after.cert.txt" \
    || die "Gateway node $node wildcard certificate changed across upgrade"
  log "Gateway node $node durable state is unchanged"
}

assert_gateway_dns_credential_usable() {
  local node=$1 result deadline=$((SECONDS + 90))
  log "proving Gateway node $node retained the Cloudflare credential"
  while (( SECONDS < deadline )); do
    result=$(admin_curl "$node" RenewZtDomainCert \
      "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d,force:true}')")
    printf '%s\n' "$result" > "$WORK_DIR/gateway${node}-post-upgrade-renew.json"
    if jq -e '.renewed == true and .not_after > 0' <<<"$result" >/dev/null; then
      wait_gateway_cert "$node"
      return
    fi
    # WaveKV's distributed certificate lock may still be held by the peer's
    # immediately preceding issuance.
    sleep 3
  done
  die "Gateway node $node could not issue with its persisted DNS credential"
}

render_app() {
  local label=$1 mode=$2 meta app_id hash
  meta=$(/suite/scripts/app_compose.py nginx \
    --name "${APP_NAME}-${label}" \
    --image-ref "$APP_IMAGE_ID" \
    --image-archive app.tar \
    --artifact-port "$ARTIFACT_PORT" \
    --attestation-mode "$mode" \
    --output "$WORK_DIR/${label}.app-compose.json")
  printf '%s\n' "$meta" > "$WORK_DIR/${label}.manifest-meta.json"
  app_id=$(jq -r .appId <<<"$meta")
  hash=$(jq -r .composeHash <<<"$meta")
  printf '%s' "$app_id" > "$WORK_DIR/${label}.app_id"
  register_app "$app_id" "$hash"
}

deploy_app() {
  local label=$1 mode=$2 kms_url=$3 guest_image=${4:-$IMAGE_NAME} out vm_id
  render_app "$label" "$mode"
  log "deploying $label app CVM (forced TDX $mode)"
  if ! out=$("${VMM_CLI[@]}" deploy \
    --name "${SUITE_PREFIX}-${label}" \
    --image "$guest_image" \
    --compose "$WORK_DIR/${label}.app-compose.json" \
    --kms-url "$kms_url" \
    --gateway-url "$GATEWAY1_URL" \
    --gateway-url "$GATEWAY2_URL" \
    --vcpu "${DSTACK_E2E_APP_VCPU:-2}" \
    --memory "${DSTACK_E2E_APP_MEMORY:-2048}" \
    --disk "${DSTACK_E2E_APP_DISK:-20}" 2>&1); then
    die "failed to deploy $label app CVM: $out"
  fi
  printf '%s\n' "$out" | tee "$WORK_DIR/${label}.deploy.log"
  vm_id=$(sed -n 's/^Created VM with ID: //p' <<<"$out" | tail -n1)
  [[ -n "$vm_id" ]] || die "failed to parse $label VM id"
  printf '%s' "$vm_id" > "$WORK_DIR/${label}.vm_id"
  wait_boot_done "$vm_id" "$label"
  assert_attestation_mode "$label" "$mode"
}

assert_attestation_mode() {
  local label=$1 expected=$2 id sys_config actual
  id=$(cat "$WORK_DIR/${label}.vm_id")
  sys_config="$VM_DIR/$id/shared/.sys-config.json"
  [[ -s "$sys_config" ]] || die "missing $label sys config"
  actual=$(jq -r '.vm_config | fromjson | .tdx_attestation_variant // "legacy"' "$sys_config")
  [[ "$actual" == "$expected" ]] || die "$label mode=$actual, expected $expected"
  jq -e '(.kms_urls | length) > 0 and (.gateway_urls | length) == 2' "$sys_config" >/dev/null
  log "$label completed boot-time KMS key provisioning in TDX $actual mode"
}

verify_app_via_gateway() {
  local label=$1 node=$2 instance sni proxy url deadline
  instance=$(jq -r '.instance_id' "$WORK_DIR/${label}.info.json")
  read -r _ _ proxy _ < <(gateway_ports "$node")
  sni="${instance}-80.${BASE_DOMAIN}"
  url="https://${sni}:${proxy}/"
  deadline=$((SECONDS + 300))
  while (( SECONDS < deadline )); do
    if curl -kfsS --max-time 5 \
      --connect-to "${sni}:${proxy}:127.0.0.1:${proxy}" "$url" \
      | grep -qi 'welcome to nginx'; then
      log "$label reachable through Gateway node $node"
      return
    fi
    sleep 3
  done
  die "$label not reachable through Gateway node $node"
}

verify_all_routes() {
  local label node
  for label in legacy lite; do
    for node in 1 2; do
      verify_app_via_gateway "$label" "$node"
    done
  done
}

restart_legacy_on_latest_kms() {
  local id
  id=$(cat "$WORK_DIR/legacy.vm_id")
  stop_vm "$id" legacy
  "${VMM_CLI[@]}" update "$id" --kms-url "$KMS_LATEST_URL" >/dev/null
  start_vm "$id" legacy
  assert_attestation_mode legacy legacy
}

upgrade_gateway_node() {
  local node=$1 id
  id=$(cat "$WORK_DIR/gateway${node}.vm_id")
  stop_vm "$id" "Gateway node $node"
  "${VMM_CLI[@]}" update-app-compose "$id" "$WORK_DIR/gateway-latest.app-compose.json" >/dev/null
  "${VMM_CLI[@]}" update "$id" --kms-url "$KMS_LATEST_URL" >/dev/null
  start_vm "$id" "gateway${node}-latest"
  wait_gateway "$node"
  wait_gateway_cert "$node"
  gateway_version "$node" latest
  # The newly restarted node must carry traffic before its peer is touched.
  verify_app_via_gateway legacy "$node"
  verify_app_via_gateway lite "$node"
  assert_gateway_state_unchanged "$node"
}

start_network_probe() {
  rm -f "$WORK_DIR/network-probe."{ready,stop,result.json,log}
  /suite/scripts/network-probe.sh > "$WORK_DIR/network-probe.log" 2>&1 &
  probe_pid=$!
  for _ in $(seq 1 120); do
    [[ -e "$WORK_DIR/network-probe.ready" ]] && return
    kill -0 "$probe_pid" 2>/dev/null || {
      cat "$WORK_DIR/network-probe.log" >&2
      die "HA network probe exited during warmup"
    }
    sleep 1
  done
  die "HA network probe did not become ready"
}

stop_network_probe() {
  touch "$WORK_DIR/network-probe.stop"
  if ! wait "$probe_pid"; then
    cat "$WORK_DIR/network-probe.log" >&2
    die "CVM traffic had downtime during rolling Gateway upgrade"
  fi
  probe_pid=""
  cat "$WORK_DIR/network-probe.log"
  jq -e '.attempts > 0 and .failures == 0 and .successful_failovers > 0' \
    "$WORK_DIR/network-probe.result.json" >/dev/null \
    || die "HA probe reported downtime"
}

assert_no_insecure_shortcuts() {
  log "auditing rendered manifests for production trust settings"
  local manifest
  local forbidden='quote_enabled[[:space:]]*=[[:space:]]*false|enforce_self_authorization[[:space:]]*=[[:space:]]*false|verify[[:space:]]*=[[:space:]]*false'
  if grep -R -E "$forbidden" "$WORK_DIR"/*.app-compose.json; then
    die "rendered app manifest contains a forbidden development trust setting"
  fi

  for manifest in "$WORK_DIR/kms-old.app-compose.json" \
    "$WORK_DIR/kms-latest.app-compose.json"; do
    if ! python3 - "$manifest" <<'PY'
import json
import sys
import tomllib

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert manifest["local_key_provider_enabled"] is True
assert manifest["kms_enabled"] is False

# Parse the actual kms.toml embedded in the rendered Compose YAML.  Checking
# TOML values instead of matching adjacent strings keeps this guard strict
# while allowing comments and blank lines in the production-style config.
marker = "configs:\n  kms_config:\n    content: |\n"
compose = manifest["docker_compose_file"]
assert compose.count(marker) == 1
indented_config = compose.split(marker, 1)[1]
config_lines = []
for line in indented_config.splitlines():
    if line and not line.startswith("      "):
        break
    config_lines.append(line[6:] if line else "")
config = tomllib.loads("\n".join(config_lines))

core = config["core"]
assert core["enforce_self_authorization"] is True
assert core["image"]["verify"] is True
assert core["auth_api"]["type"] == "webhook"
assert core["onboard"]["enabled"] is True
assert core["onboard"]["quote_enabled"] is True
PY
    then
      die "$manifest does not use quote-attested production KMS settings"
    fi
  done

  for manifest in "$WORK_DIR/gateway-old.app-compose.json" \
    "$WORK_DIR/gateway-latest.app-compose.json"; do
    jq -e '.kms_enabled == true and .local_key_provider_enabled == false' \
      "$manifest" >/dev/null \
      || die "$manifest does not obtain its keys from KMS"
  done

  jq -e '
    .kms_enabled == true and .gateway_enabled == true
    and .manifest_version == "3"
    and .requirements.tdx_measure_acpi_tables == true
  ' "$WORK_DIR/legacy.app-compose.json" >/dev/null \
    || die "legacy app manifest did not force the legacy TDX verifier"
  jq -e '
    .kms_enabled == true and .gateway_enabled == true
    and .manifest_version == "3"
    and .requirements.tdx_measure_acpi_tables == false
  ' "$WORK_DIR/lite.app-compose.json" >/dev/null \
    || die "lite app manifest did not force the lite TDX verifier"

  jq -e --arg id "$GATEWAY_APP_ID" \
    --arg device "$ATTESTED_DEVICE_ID" \
    '.gatewayAppId == $id and .gatewayAppId != "any"
      and (.osImages | length) == 1
      and (.kms.mrAggregated | length) == 2
      and (.kms.allowAnyDevice == false)
      and (.kms.devices == [$device])
      and (.apps | length) == 3
      and ([.apps[].allowAnyDevice] | all(. == false))
      and ([.apps[].devices] | all(. == [$device]))' \
    "$ALLOWLIST" >/dev/null
}

save_vm_logs() {
  local name file id
  for file in "$WORK_DIR"/*.vm_id; do
    [[ -s "$file" ]] || continue
    name=$(basename "$file" .vm_id)
    id=$(cat "$file")
    "${VMM_CLI[@]}" logs "$id" -n 2000 > "$WORK_DIR/${name}.vm.log" 2>&1 || true
  done
}

cleanup_after() {
  [[ "${DSTACK_E2E_CLEANUP_AFTER:-false}" == true ]] || return 0
  local file
  for file in "$WORK_DIR"/*.vm_id; do
    [[ -s "$file" ]] && remove_vm "$(cat "$file")"
  done
}

phase_upgrade() {
  [[ "$PLATFORM" == tdx ]] || die "upgrade phase requires TDX"
  wait_vmm
  clean_start

  render_kms old "$OLD_KMS_IMAGE_ID" kms-0.5.8.tar
  deploy_kms_onboard old "$KMS_OLD_HOST_PORT"
  wait_onboard old "$KMS_OLD_HOST_PORT"
  authorize_kms_from_attestation old
  onboard_rpc "$KMS_OLD_HOST_PORT" Bootstrap \
    "$(jq -cn --arg d "$KMS_RPC_DOMAIN" '{domain:$d}')" \
    "$WORK_DIR/kms-old.bootstrap.json"
  jq -e '(.attestation // "") | length > 0' "$WORK_DIR/kms-old.bootstrap.json" >/dev/null \
    || die "KMS 0.5.8 bootstrap did not return quote-bound attestation"
  log "KMS 0.5.8 bootstrap returned quote-bound attestation"
  finish_onboarding old "$KMS_OLD_HOST_PORT"

  render_gateway_manifests old "$OLD_GATEWAY_IMAGE_ID" gateway-0.5.8.tar
  render_gateway_manifests latest "$CURRENT_GATEWAY_IMAGE_ID" gateway-current.tar
  write_gateway_env 1
  write_gateway_env 2
  deploy_gateway 1 old "$KMS_OLD_URL"
  gateway_version 1 old
  deploy_gateway 2 old "$KMS_OLD_URL"
  gateway_version 2 old
  bootstrap_gateway

  deploy_app legacy legacy "$KMS_OLD_URL" "$OLD_IMAGE_NAME"
  verify_app_via_gateway legacy 1
  verify_app_via_gateway legacy 2
  capture_kms_identity old "$KMS_OLD_HOST_PORT" "$(cat "$WORK_DIR/legacy.app_id")"

  # Production KMS upgrades are rolling, quote-attested replication into a new
  # Local-Key-Provider CVM, not an unmeasured binary swap in the old CVM.
  render_kms latest "$CURRENT_KMS_IMAGE_ID" kms-current.tar
  deploy_kms_onboard latest "$KMS_LATEST_HOST_PORT"
  wait_onboard latest "$KMS_LATEST_HOST_PORT"
  authorize_kms_from_attestation latest
  onboard_rpc "$KMS_LATEST_HOST_PORT" Onboard \
    "$(jq -cn --arg s "$KMS_OLD_URL" --arg d "$KMS_RPC_DOMAIN" '{source_url:$s,domain:$d}')" \
    "$WORK_DIR/kms-latest.onboard.json"
  # Current Onboard returns only the replicated public key. Quote evidence is
  # carried by the mutual RA-TLS connection and authorized above through the
  # target's exact quote-derived measurement and physical TDX device ID.
  finish_onboarding latest "$KMS_LATEST_HOST_PORT"
  capture_kms_identity latest "$KMS_LATEST_HOST_PORT" "$(cat "$WORK_DIR/legacy.app_id")"
  assert_kms_identity_unchanged

  stop_vm "$(cat "$WORK_DIR/kms-old.vm_id")" "KMS 0.5.8 after cutover"
  restart_legacy_on_latest_kms
  deploy_app lite lite "$KMS_LATEST_URL"
  verify_all_routes

  capture_gateway_state 1 before
  capture_gateway_state 2 before
  start_network_probe
  upgrade_gateway_node 1
  upgrade_gateway_node 2
  stop_network_probe
  verify_all_routes
  # The current API redacts stored tokens, so metadata equality alone cannot
  # prove the secret survived. The mock rejects any token other than the exact
  # original value; a forced issuance through each upgraded node proves it.
  assert_gateway_dns_credential_usable 1
  assert_gateway_dns_credential_usable 2

  assert_no_insecure_shortcuts
  save_vm_logs
  # dstack-kms runs in an inner container, whose stdout is not part of the CVM
  # serial log returned by VMM.  Each KMS has a fresh data disk, so two 200 GETs
  # for the exact measured archive prove that both verifiers downloaded it.
  local os_archive_gets
  os_archive_gets=$(grep -Fc \
    "GET /os/mr_${OS_IMAGE_HASH}.tar.gz HTTP/1.1\" 200" \
    "$WORK_DIR/artifacts-access.log" || true)
  (( os_archive_gets >= 2 )) \
    || die "expected verified OS image downloads by both KMS versions, saw ${os_archive_gets}"
  if grep -E 'Image verification is disabled|self-authorization is disabled' \
    "$WORK_DIR/kms-"*.vm.log; then
    die "KMS logs contain a forbidden disabled verification path"
  fi

  log "production-compatible KMS/Gateway rolling-upgrade E2E success"
  cleanup_after
}

on_exit() {
  local rc=$?
  if [[ -n "$probe_pid" ]] && kill -0 "$probe_pid" 2>/dev/null; then
    touch "$WORK_DIR/network-probe.stop" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
  fi
  if (( rc != 0 )); then
    save_vm_logs || true
  fi
  exit "$rc"
}
trap on_exit EXIT

main() {
  need_bin /workspace/target/release/dstack
  [[ -s "$STATE_DIR/artifacts/images.env" ]] || die "missing prepared image metadata"
  case "$PHASE" in
    upgrade) phase_upgrade ;;
    *) die "unknown DSTACK_E2E_PHASE=$PHASE" ;;
  esac
  log "Work artifacts: $WORK_DIR"
}

main "$@"
