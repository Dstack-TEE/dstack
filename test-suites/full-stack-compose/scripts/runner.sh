#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
CONFIG_DIR=${DSTACK_E2E_CONFIG_DIR:-$STATE_DIR/config}
WORK_DIR=${DSTACK_E2E_WORK_DIR:-$STATE_DIR/work}
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
need_bin /workspace/target/release/dstack
need_bin /workspace/target/release/dstack-auth
need_bin /workspace/target/release/dstack-vmm
need_bin /workspace/target/release/dstack-kms
need_bin /workspace/target/release/dstack-gateway
need_bin /workspace/target/release/supervisor

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
  sleep 2
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

compose_meta() {
  jq -r '"\(.appId) \(.composeHash)"'
}

register_app() {
  local app_id=$1 hash=$2 gateway_id=${3:-}
  local args=(/suite/scripts/allowlist.py add-app --path "$ALLOWLIST" --app-id "$app_id" --compose-hash "$hash")
  if [[ -n "$gateway_id" ]]; then
    args+=(--gateway-app-id "$gateway_id")
  fi
  python3 "${args[@]}" >/dev/null
}

set_gateway_app_id() {
  python3 /suite/scripts/allowlist.py set-gateway --path "$ALLOWLIST" --gateway-app-id "$1" >/dev/null
}


wait_kms() {
  log "waiting for KMS at https://127.0.0.1:${KMS_HOST_PORT}"
  for _ in $(seq 1 90); do
    if curl -kfsS "https://127.0.0.1:${KMS_HOST_PORT}/metrics" >/dev/null 2>&1; then
      log "KMS ready"
      return 0
    fi
    sleep 2
  done
  die "KMS not ready"
}

admin_curl() {
  local method=$1
  local data
  if [[ $# -ge 2 ]]; then
    data=$2
  else
    data='{}'
  fi
  local out code
  out=$(mktemp)
  code=$(curl -sS -o "$out" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer ${GATEWAY_ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    "http://127.0.0.1:${GATEWAY_ADMIN_HOST_PORT}/prpc/Admin.${method}" \
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
    if curl -fsS -H "Authorization: Bearer ${GATEWAY_ADMIN_TOKEN}" \
      "http://127.0.0.1:${GATEWAY_ADMIN_HOST_PORT}/prpc/Admin.Status" >/dev/null 2>&1; then
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
  admin_curl SetCertbotConfig "$(jq -cn --arg u "$acme_url" '{acme_url:$u}')" >/dev/null
  # Idempotency for reruns: duplicate credentials/domains are harmless but noisy, so ignore create conflicts.
  admin_curl CreateDnsCredential "$(jq -cn --arg u "$cf_url" '{name:"mock-cloudflare", provider_type:"cloudflare", cf_api_token:"test-token", cf_api_url:$u, set_as_default:true, dns_txt_ttl:1, max_dns_wait:0}')" >/dev/null || true
  admin_curl AddZtDomain "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d, port:443, priority:100}')" >/dev/null || true
  log "requesting wildcard cert for *.${BASE_DOMAIN}"
  admin_curl RenewZtDomainCert "$(jq -cn --arg d "$BASE_DOMAIN" '{domain:$d, force:true}')" | tee "$WORK_DIR/renew-cert.json"
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

deploy_app() {
  local out meta app_id hash vm_id
  log "rendering nginx test app-compose"
  meta=$(python3 /suite/scripts/app_compose.py nginx \
    --name "$APP_NAME" \
    --app-image "$APP_IMAGE" \
    --output "$WORK_DIR/app-compose.json")
  read -r app_id hash < <(jq -r '"\(.appId) \(.composeHash)"' <<<"$meta")
  local gateway_id
  gateway_id=$(jq -r '.gatewayAppId' "$ALLOWLIST")
  log "registering test app in auth allowlist app_id=$app_id gateway_app_id=$gateway_id"
  register_app "$app_id" "$hash" "$gateway_id"
  log "deploying nginx app CVM"
  out=$("${VMM_CLI[@]}" deploy \
    --name "${SUITE_PREFIX}-app" \
    --image "$IMAGE_NAME" \
    --compose "$WORK_DIR/app-compose.json" \
    --vcpu "${DSTACK_E2E_APP_VCPU:-2}" \
    --memory "${DSTACK_E2E_APP_MEMORY:-2048}" \
    --disk "${DSTACK_E2E_APP_DISK:-20}")
  printf '%s\n' "$out" | tee "$WORK_DIR/app.deploy.log"
  vm_id=$(sed -n 's/^Created VM with ID: //p' <<<"$out" | tail -n1)
  [[ -n "$vm_id" ]] || die "failed to parse app VM id"
  echo "$vm_id" > "$WORK_DIR/app.vm_id"
  wait_boot_done "$vm_id" app "${DSTACK_E2E_APP_BOOT_TIMEOUT:-600}"
}

verify_app_via_gateway() {
  local app_info instance_id sni url deadline
  app_info=$(cat "$WORK_DIR/app.info.json")
  instance_id=$(jq -r '.instance_id // ""' <<<"$app_info")
  [[ -n "$instance_id" && "$instance_id" != "null" ]] || die "app has no instance_id"
  sni="${instance_id}-80.${BASE_DOMAIN}"
  url="https://${sni}:${GATEWAY_PROXY_HOST_PORT}/"
  log "verifying app through Gateway: $url"
  deadline=$((SECONDS + ${DSTACK_E2E_APP_HTTP_TIMEOUT:-240}))
  while (( SECONDS < deadline )); do
    if curl -fsS -k --connect-to "${sni}:${GATEWAY_PROXY_HOST_PORT}:127.0.0.1:${GATEWAY_PROXY_HOST_PORT}" \
      "$url" > "$WORK_DIR/app-http.out" 2>"$WORK_DIR/app-http.err"; then
      if grep -qi "welcome to nginx" "$WORK_DIR/app-http.out"; then
        log "Gateway -> app HTTP check passed"
        head -c 160 "$WORK_DIR/app-http.out" | tr '\n' ' '; echo
        return 0
      fi
    fi
    sleep 5
  done
  cat "$WORK_DIR/app-http.err" >&2 || true
  die "timed out verifying app through Gateway"
}

cleanup_after() {
  if [[ "${DSTACK_E2E_CLEANUP_AFTER:-false}" != "true" ]]; then
    return 0
  fi
  log "DSTACK_E2E_CLEANUP_AFTER=true: removing suite VMs"
  for f in app.vm_id gateway.vm_id kms.vm_id; do
    if [[ -s "$WORK_DIR/$f" ]]; then
      remove_vm "$(cat "$WORK_DIR/$f")"
    fi
  done
}

main() {
  wait_vmm
  clean_start
  wait_kms
  wait_gateway_admin
  bootstrap_gateway_certbot
  wait_gateway_cert
  deploy_app
  verify_app_via_gateway
  log "E2E success"
  log "VMM dashboard:      $VMM_URL"
  log "Gateway proxy:      https://*.${BASE_DOMAIN}:${GATEWAY_PROXY_HOST_PORT} (connect to 127.0.0.1:${GATEWAY_PROXY_HOST_PORT})"
  log "Gateway admin:      http://127.0.0.1:${GATEWAY_ADMIN_HOST_PORT} (token in $STATE_DIR/gateway-admin-token)"
  log "Work artifacts:     $WORK_DIR"
  cleanup_after
}

main "$@"
