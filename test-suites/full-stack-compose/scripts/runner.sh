#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
CONFIG_DIR=${DSTACK_E2E_CONFIG_DIR:-$STATE_DIR/config}
WORK_DIR=${DSTACK_E2E_WORK_DIR:-$STATE_DIR/work}
VM_DIR=${DSTACK_E2E_VM_DIR:-$STATE_DIR/vm}
PHASE=${DSTACK_E2E_PHASE:-full}
mkdir -p "$WORK_DIR"
# shellcheck disable=SC1091
source "$STATE_DIR/state.env"

VMM_URL="http://127.0.0.1:${VMM_PORT}"
VMM_CLI=(python3 /workspace/vmm/src/vmm-cli.py --url "$VMM_URL")
DSTACK_CLI=(/workspace/target/release/dstack --host "$VMM_URL")
ALLOWLIST="$CONFIG_DIR/auth-allowlist.json"

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

need_bin() {
  [[ -x "$1" ]] || die "missing executable $1; run: cargo build --release -p dstack-cli -p dstack-auth -p dstack-vmm -p dstack-kms -p dstack-gateway -p supervisor"
}

need_current_bins() {
  need_bin /workspace/target/release/dstack
  need_bin /workspace/target/release/dstack-auth
  need_bin /workspace/target/release/dstack-vmm
  need_bin /workspace/target/release/dstack-kms
  need_bin /workspace/target/release/dstack-gateway
  need_bin /workspace/target/release/supervisor
}

require_tdx() {
  [[ "$PLATFORM" == "tdx" ]] || die "$PHASE requires DSTACK_E2E_PLATFORM=tdx"
}

wait_vmm() {
  log "waiting for VMM at $VMM_URL"
  for _ in $(seq 1 90); do
    if "${DSTACK_CLI[@]}" apps -j >/dev/null 2>&1; then
      log "VMM ready"
      return 0
    fi
    sleep 2
  done
  die "VMM not ready"
}

vm_ids_by_prefix() {
  local prefix=$1
  "${VMM_CLI[@]}" lsvm --json 2>/dev/null | jq -r --arg p "$prefix" '.[] | select(.name | startswith($p)) | .id'
}

remove_vm() {
  local id=$1
  [[ -n "$id" ]] || return 0
  log "removing VM $id"
  "${VMM_CLI[@]}" remove "$id" >/dev/null 2>&1 || true
}

clean_start() {
  if [[ "${DSTACK_E2E_CLEAN_START:-true}" != "true" ]]; then
    return 0
  fi
  log "cleaning stale VMs with prefix ${SUITE_PREFIX}"
  while read -r id; do
    remove_vm "$id"
  done < <(vm_ids_by_prefix "$SUITE_PREFIX")
  for _ in $(seq 1 60); do
    [[ -z "$(vm_ids_by_prefix "$SUITE_PREFIX")" ]] && return 0
    sleep 2
  done
  die "stale VMs were not removed"
}

print_vm_info_safe() {
  jq '{
    id,
    name,
    status,
    uptime,
    app_id,
    instance_id,
    boot_progress,
    boot_error,
    shutdown_progress,
    image_version,
    events
  }' <<<"$1"
}

wait_boot_done() {
  local id=$1 label=$2 timeout=${3:-480}
  local deadline=$((SECONDS + timeout))
  local last=""
  while (( SECONDS < deadline )); do
    local info status progress error instance
    info=$("${VMM_CLI[@]}" info "$id" --json 2>/dev/null || true)
    if [[ -n "$info" ]]; then
      status=$(jq -r '.status // ""' <<<"$info")
      progress=$(jq -r '.boot_progress // ""' <<<"$info")
      error=$(jq -r '.boot_error // ""' <<<"$info")
      instance=$(jq -r '.instance_id // ""' <<<"$info")
      local line="status=$status progress=${progress:-none} instance=${instance:-none} error=${error:-none}"
      if [[ "$line" != "$last" ]]; then
        log "$label: $line"
        last=$line
      fi
      if [[ -n "$error" && "$error" != "null" ]]; then
        print_vm_info_safe "$info" >&2 || true
        die "$label boot failed: $error"
      fi
      if [[ "$status" == "running" && "$progress" == "done" ]]; then
        printf '%s' "$info" > "$WORK_DIR/${label}.info.json"
        return 0
      fi
      if [[ "$status" == "exited" || "$status" == "stopped" ]]; then
        print_vm_info_safe "$info" >&2 || true
        die "$label exited before boot finished"
      fi
    fi
    sleep 5
  done
  print_vm_info_safe "$("${VMM_CLI[@]}" info "$id" --json)" >&2 || true
  die "timed out waiting for $label"
}

wait_vm_stopped() {
  local id=$1 deadline=$((SECONDS + 120))
  while (( SECONDS < deadline )); do
    local status
    status=$("${VMM_CLI[@]}" info "$id" --json 2>/dev/null | jq -r '.status // ""' || true)
    if [[ "$status" != "running" && "$status" != "starting" ]]; then
      return 0
    fi
    sleep 2
  done
  die "VM $id did not stop"
}

wait_vm_running() {
  local id=$1 label=$2 deadline=$((SECONDS + 90)) last=""
  while (( SECONDS < deadline )); do
    local info status error
    info=$("${VMM_CLI[@]}" info "$id" --json 2>/dev/null || true)
    if [[ -n "$info" ]]; then
      status=$(jq -r '.status // ""' <<<"$info")
      error=$(jq -r '.boot_error // ""' <<<"$info")
      if [[ "$status" != "$last" ]]; then
        log "$label restart: status=${status:-unknown}"
        last=$status
      fi
      if [[ -n "$error" && "$error" != "null" ]]; then
        print_vm_info_safe "$info" >&2 || true
        die "$label restart failed: $error"
      fi
      [[ "$status" == "running" ]] && return 0
    fi
    sleep 1
  done
  die "$label did not enter running state after restart"
}

register_app() {
  local app_id=$1 hash=$2 gateway_id=${3:-}
  local args=(/suite/scripts/allowlist.py add-app --path "$ALLOWLIST" --app-id "$app_id" --compose-hash "$hash")
  if [[ -n "$gateway_id" ]]; then
    args+=(--gateway-app-id "$gateway_id")
  fi
  python3 "${args[@]}" >/dev/null
}

wait_kms() {
  log "waiting for KMS at https://127.0.0.1:${KMS_HOST_PORT}"
  for _ in $(seq 1 90); do
    if curl -kfsS "https://127.0.0.1:${KMS_HOST_PORT}/prpc/GetMeta?json" >/dev/null 2>&1; then
      log "KMS ready"
      return 0
    fi
    sleep 2
  done
  die "KMS not ready"
}

kms_rpc_get() {
  local method=$1
  curl -kfsS "https://127.0.0.1:${KMS_HOST_PORT}/prpc/KMS.${method}?json"
}

kms_rpc_post() {
  local method=$1 data=$2
  curl -kfsS -X POST -H 'Content-Type: application/json' \
    "https://127.0.0.1:${KMS_HOST_PORT}/prpc/KMS.${method}?json" \
    --data-raw "$data"
}

capture_kms_identity() {
  local stage=$1 app_id
  app_id=$(cat "$WORK_DIR/legacy.app_id")
  log "capturing KMS identity ($stage) for app_id=$app_id"
  kms_rpc_get GetMeta | tee "$WORK_DIR/kms-${stage}.meta.raw.json" \
    | jq -S '{ca_cert, k256_pubkey}' > "$WORK_DIR/kms-${stage}.meta.json"
  kms_rpc_post GetAppEnvEncryptPubKey "$(jq -cn --arg id "$app_id" '{app_id:$id}')" \
    | tee "$WORK_DIR/kms-${stage}.app-key.raw.json" \
    | jq -S '{public_key}' > "$WORK_DIR/kms-${stage}.app-key.json"
  jq -e '.ca_cert != "" and .k256_pubkey != ""' "$WORK_DIR/kms-${stage}.meta.json" >/dev/null
  jq -e '.public_key != ""' "$WORK_DIR/kms-${stage}.app-key.json" >/dev/null
}

assert_kms_identity_unchanged() {
  capture_kms_identity after
  diff -u "$WORK_DIR/kms-before.meta.json" "$WORK_DIR/kms-after.meta.json" \
    || die "KMS CA or root k256 public key changed across upgrade"
  diff -u "$WORK_DIR/kms-before.app-key.json" "$WORK_DIR/kms-after.app-key.json" \
    || die "per-app environment encryption key changed across KMS upgrade"
  log "KMS persistent identity and per-app key are unchanged"
}

admin_curl() {
  local method=$1
  local data=${2:-'{}'}
  local out code
  out=$(mktemp)
  code=$(curl -sS -o "$out" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${GATEWAY_ADMIN_TOKEN}" \
    -H 'Content-Type: application/json' \
    "http://127.0.0.1:${GATEWAY_ADMIN_HOST_PORT}/prpc/Admin.${method}?json" \
    --data-raw "$data" || true)
  if [[ "$code" =~ ^2 ]]; then
    cat "$out"
    rm -f "$out"
    return 0
  fi
  log "Admin.${method} failed HTTP ${code}: $(cat "$out")" >&2
  rm -f "$out"
  return 1
}

wait_gateway_admin() {
  log "waiting for Gateway admin API on 127.0.0.1:${GATEWAY_ADMIN_HOST_PORT}"
  for _ in $(seq 1 90); do
    if admin_curl Status >/dev/null 2>&1; then
      log "Gateway admin ready"
      return 0
    fi
    sleep 2
  done
  die "Gateway admin API not ready"
}

bootstrap_gateway_certbot() {
  local acme_url="http://127.0.0.1:${PEBBLE_HTTP_PORT}/dir"
  local cf_url="http://127.0.0.1:${MOCK_CF_HTTP_PORT}/client/v4"
  log "configuring Gateway certbot: acme=$acme_url cf=$cf_url domain=$BASE_DOMAIN"
  # Pebble's test certificates are short-lived. Keep the renewal threshold
  # below their lifetime so a Gateway restart tests certificate restoration
  # instead of intentionally rotating the certificate during startup.
  admin_curl SetCertbotConfig "$(jq -cn --arg u "$acme_url" '{acme_url:$u, renew_before_expiration_secs:3600}')" >/dev/null
  admin_curl CreateDnsCredential "$(jq -cn --arg u "$cf_url" '{name:"mock-cloudflare", provider_type:"cloudflare", cf_api_token:"test-token", cf_api_url:$u, set_as_default:true, dns_txt_ttl:1, max_dns_wait:0}')" >/dev/null || true
  admin_curl AddZtDomain "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d, port:443, priority:100}')" >/dev/null || true
  log "requesting wildcard cert for *.${BASE_DOMAIN}"
  admin_curl RenewZtDomainCert "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d, force:true}')" \
    | tee "$WORK_DIR/renew-cert.json"
}

wait_gateway_cert() {
  local sni="gateway.${BASE_DOMAIN}" deadline=$((SECONDS + ${DSTACK_E2E_CERT_TIMEOUT:-240}))
  log "waiting for Gateway TLS certificate with SNI $sni"
  while (( SECONDS < deadline )); do
    if echo | timeout 8 openssl s_client \
      -connect "127.0.0.1:${GATEWAY_PROXY_HOST_PORT}" \
      -servername "$sni" 2>/dev/null \
      | openssl x509 -noout -ext subjectAltName 2>/dev/null \
      | grep -Fq "*.${BASE_DOMAIN}"; then
      log "Gateway wildcard certificate is active"
      return 0
    fi
    sleep 5
  done
  die "timed out waiting for Gateway certificate"
}

gateway_cert_fingerprint() {
  local sni="gateway.${BASE_DOMAIN}"
  echo | timeout 8 openssl s_client \
    -connect "127.0.0.1:${GATEWAY_PROXY_HOST_PORT}" \
    -servername "$sni" 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null
}

wait_gateway_persisted() {
  log "waiting for Gateway WaveKV persistence"
  local deadline=$((SECONDS + 90)) status
  while (( SECONDS < deadline )); do
    status=$(admin_curl WaveKvStatus 2>/dev/null || true)
    if [[ -n "$status" ]] \
      && jq -e '.persistent.dirty == false and .persistent.n_keys > 0' <<<"$status" >/dev/null 2>&1; then
      log "Gateway persistent store is clean ($(jq -r '.persistent.n_keys' <<<"$status") keys)"
      return 0
    fi
    sleep 1
  done
  die "Gateway persistent store did not flush"
}

capture_gateway_state() {
  local stage=$1
  log "capturing Gateway durable state ($stage)"
  admin_curl Status | tee "$WORK_DIR/gateway-${stage}.status.raw.json" \
    | jq -S '{uuid, hosts: ([.hosts[] | {instance_id, ip, app_id, base_domain}] | sort_by(.instance_id))}' \
    > "$WORK_DIR/gateway-${stage}.status.json"
  admin_curl GetCertbotConfig | tee "$WORK_DIR/gateway-${stage}.certbot.raw.json" \
    | jq -S '{acme_url, renew_interval_secs, renew_before_expiration_secs, renew_timeout_secs}' \
    > "$WORK_DIR/gateway-${stage}.certbot.json"
  admin_curl ListDnsCredentials | tee "$WORK_DIR/gateway-${stage}.dns.raw.json" \
    | jq -S '{default_id, credentials: ([.credentials[] | {id, name, provider_type, cf_zone_id, cf_api_url, dns_txt_ttl, max_dns_wait}] | sort_by(.id))}' \
    > "$WORK_DIR/gateway-${stage}.dns.json"
  admin_curl ListZtDomains | tee "$WORK_DIR/gateway-${stage}.domains.raw.json" \
    | jq -S '{domains: ([.domains[] | .config] | sort_by(.domain))}' \
    > "$WORK_DIR/gateway-${stage}.domains.json"
  gateway_cert_fingerprint > "$WORK_DIR/gateway-${stage}.cert-fingerprint.txt"
}

assert_gateway_state_unchanged() {
  capture_gateway_state after
  local file
  for file in status certbot dns domains; do
    diff -u "$WORK_DIR/gateway-before.${file}.json" "$WORK_DIR/gateway-after.${file}.json" \
      || die "Gateway $file state changed across upgrade"
  done
  diff -u "$WORK_DIR/gateway-before.cert-fingerprint.txt" "$WORK_DIR/gateway-after.cert-fingerprint.txt" \
    || die "Gateway wildcard certificate changed across upgrade"
  log "Gateway registrations, identity, certbot config, DNS/domain config and certificate are unchanged"
}

deploy_app() {
  local label=$1 attestation_mode=$2
  local out meta app_id hash vm_id
  log "rendering $label nginx app-compose (TDX $attestation_mode)"
  meta=$(python3 /suite/scripts/app_compose.py nginx \
    --name "${APP_NAME}-${label}" \
    --app-image "$APP_IMAGE" \
    --attestation-mode "$attestation_mode" \
    --output "$WORK_DIR/${label}.app-compose.json")
  read -r app_id hash < <(jq -r '"\(.appId) \(.composeHash)"' <<<"$meta")
  printf '%s' "$app_id" > "$WORK_DIR/${label}.app_id"
  local gateway_id
  gateway_id=$(jq -r '.gatewayAppId' "$ALLOWLIST")
  log "registering $label app in auth allowlist app_id=$app_id gateway_app_id=$gateway_id"
  register_app "$app_id" "$hash" "$gateway_id"
  log "deploying $label nginx app CVM"
  out=$("${VMM_CLI[@]}" deploy \
    --name "${SUITE_PREFIX}-${label}" \
    --image "$IMAGE_NAME" \
    --compose "$WORK_DIR/${label}.app-compose.json" \
    --vcpu "${DSTACK_E2E_APP_VCPU:-2}" \
    --memory "${DSTACK_E2E_APP_MEMORY:-2048}" \
    --disk "${DSTACK_E2E_APP_DISK:-20}")
  printf '%s\n' "$out" | tee "$WORK_DIR/${label}.deploy.log"
  vm_id=$(sed -n 's/^Created VM with ID: //p' <<<"$out" | tail -n1)
  [[ -n "$vm_id" ]] || die "failed to parse $label app VM id"
  printf '%s' "$vm_id" > "$WORK_DIR/${label}.vm_id"
  wait_boot_done "$vm_id" "$label" "${DSTACK_E2E_APP_BOOT_TIMEOUT:-600}"
  assert_attestation_mode "$label" "$attestation_mode"
}

assert_attestation_mode() {
  local label=$1 expected=$2 id sys_config actual
  id=$(cat "$WORK_DIR/${label}.vm_id")
  sys_config="$VM_DIR/$id/shared/.sys-config.json"
  [[ -s "$sys_config" ]] || die "missing $label sys config: $sys_config"
  actual=$(jq -r '.vm_config | fromjson | .tdx_attestation_variant // "legacy"' "$sys_config")
  [[ "$actual" == "$expected" ]] \
    || die "$label resolved attestation mode is $actual, expected $expected"
  jq -e '.kms_urls | length > 0' "$sys_config" >/dev/null \
    || die "$label has no KMS URL"
  log "$label booted with resolved TDX mode=$actual and completed KMS key provisioning"
}

restart_app_after_kms_upgrade() {
  local label=$1 id
  id=$(cat "$WORK_DIR/${label}.vm_id")
  log "force-stopping $label CVM to require a fresh boot-time KMS key request"
  "${VMM_CLI[@]}" stop "$id" --force >/dev/null
  wait_vm_stopped "$id"
  log "restarting $label CVM against upgraded KMS"
  "${VMM_CLI[@]}" start "$id" >/dev/null
  # The Start RPC returns before the supervisor updates the persisted VM state.
  # Avoid treating that short, expected `exited` window as a failed boot.
  wait_vm_running "$id" "$label"
  wait_boot_done "$id" "$label" "${DSTACK_E2E_APP_BOOT_TIMEOUT:-600}"
  assert_attestation_mode "$label" legacy
}

verify_app_via_gateway() {
  local label=$1 app_info instance_id sni url deadline
  app_info=$(cat "$WORK_DIR/${label}.info.json")
  instance_id=$(jq -r '.instance_id // ""' <<<"$app_info")
  [[ -n "$instance_id" && "$instance_id" != "null" ]] || die "$label app has no instance_id"
  sni="${instance_id}-80.${BASE_DOMAIN}"
  url="https://${sni}:${GATEWAY_PROXY_HOST_PORT}/"
  log "verifying $label app through Gateway: $url"
  deadline=$((SECONDS + ${DSTACK_E2E_APP_HTTP_TIMEOUT:-240}))
  while (( SECONDS < deadline )); do
    if curl -fsS -k --connect-to "${sni}:${GATEWAY_PROXY_HOST_PORT}:127.0.0.1:${GATEWAY_PROXY_HOST_PORT}" \
      "$url" > "$WORK_DIR/${label}.http.out" 2>"$WORK_DIR/${label}.http.err"; then
      if grep -qi 'welcome to nginx' "$WORK_DIR/${label}.http.out"; then
        log "$label Gateway -> app HTTP check passed"
        return 0
      fi
    fi
    sleep 5
  done
  cat "$WORK_DIR/${label}.http.err" >&2 || true
  die "timed out verifying $label app through Gateway"
}

write_network_targets() {
  local status label instance ip
  status=$(admin_curl Status)
  : > "$WORK_DIR/network-targets.tsv"
  for label in legacy lite; do
    instance=$(jq -r '.instance_id' "$WORK_DIR/${label}.info.json")
    ip=$(jq -r --arg id "$instance" '.hosts[] | select(.instance_id == $id) | .ip' <<<"$status")
    [[ -n "$ip" && "$ip" != "null" ]] || die "Gateway has no WireGuard IP for $label ($instance)"
    printf '%s\t%s\n' "$label" "$ip" >> "$WORK_DIR/network-targets.tsv"
    curl -fsS --max-time 3 "http://${ip}:80/" | grep -qi 'welcome to nginx' \
      || die "cannot reach $label directly over WireGuard at $ip"
  done
  log "CVM WireGuard targets: $(tr '\n' ' ' < "$WORK_DIR/network-targets.tsv")"
}

cleanup_after() {
  if [[ "${DSTACK_E2E_CLEANUP_AFTER:-false}" != "true" ]]; then
    return 0
  fi
  log "DSTACK_E2E_CLEANUP_AFTER=true: removing suite VMs"
  local f
  for f in "$WORK_DIR"/*.vm_id; do
    [[ -s "$f" ]] && remove_vm "$(cat "$f")"
  done
}

prepare_common() {
  wait_vmm
  clean_start
  wait_kms
  wait_gateway_admin
  bootstrap_gateway_certbot
  wait_gateway_cert
}

phase_full() {
  prepare_common
  if [[ "$PLATFORM" == "tdx" ]]; then
    deploy_app legacy legacy
    deploy_app lite lite
    verify_app_via_gateway legacy
    verify_app_via_gateway lite
    capture_kms_identity full
    wait_gateway_persisted
    capture_gateway_state full
    write_network_targets
  else
    deploy_app app auto
    verify_app_via_gateway app
  fi
  log "E2E success"
  cleanup_after
}

phase_prepare_old() {
  require_tdx
  prepare_common
  deploy_app legacy legacy
  verify_app_via_gateway legacy
  capture_kms_identity before
  printf 'ok\n' > "$WORK_DIR/prepare-old.done"
  log "old KMS/Gateway phase complete"
}

phase_after_kms_upgrade() {
  require_tdx
  wait_vmm
  wait_kms
  wait_gateway_admin
  assert_kms_identity_unchanged
  restart_app_after_kms_upgrade legacy
  verify_app_via_gateway legacy
  deploy_app lite lite
  verify_app_via_gateway lite
  wait_gateway_persisted
  capture_gateway_state before
  write_network_targets
  printf 'ok\n' > "$WORK_DIR/after-kms-upgrade.done"
  log "KMS upgrade and latest lite/legacy key-provisioning phase complete"
}

phase_after_gateway_upgrade() {
  require_tdx
  wait_vmm
  wait_kms
  wait_gateway_admin
  wait_gateway_cert
  assert_gateway_state_unchanged
  verify_app_via_gateway legacy
  verify_app_via_gateway lite
  write_network_targets
  printf 'ok\n' > "$WORK_DIR/after-gateway-upgrade.done"
  log "Gateway upgrade compatibility phase complete"
  cleanup_after
}

main() {
  need_current_bins
  log "running E2E phase=$PHASE"
  case "$PHASE" in
    full) phase_full ;;
    prepare-old) phase_prepare_old ;;
    after-kms-upgrade) phase_after_kms_upgrade ;;
    after-gateway-upgrade) phase_after_gateway_upgrade ;;
    *) die "unknown DSTACK_E2E_PHASE=$PHASE" ;;
  esac
  log "VMM dashboard:  $VMM_URL"
  log "Work artifacts: $WORK_DIR"
}

main "$@"
