#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/../.." && pwd)
STATE_DIR="$SCRIPT_DIR/state"
WORK_DIR="$STATE_DIR/work"
ENV_FILE=${DSTACK_E2E_ENV_FILE:-$SCRIPT_DIR/.env}

setting() {
  local name=$1 fallback=$2 line value
  if [[ -v $name ]]; then
    printf '%s' "${!name}"
    return
  fi
  if [[ -f "$ENV_FILE" ]]; then
    line=$(grep -E "^[[:space:]]*${name}=" "$ENV_FILE" | tail -n1 || true)
    if [[ -n "$line" ]]; then
      value=${line#*=}
      value=${value%$'\r'}
      if [[ "$value" == \"*\" && "$value" == *\" ]]; then
        value=${value:1:${#value}-2}
      elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
        value=${value:1:${#value}-2}
      fi
      printf '%s' "$value"
      return
    fi
  fi
  printf '%s' "$fallback"
}

OLD_KMS_IMAGE=$(setting DSTACK_E2E_OLD_KMS_IMAGE dstacktee/dstack-kms:0.5.7)
OLD_GATEWAY_IMAGE=$(setting DSTACK_E2E_OLD_GATEWAY_IMAGE dstacktee/dstack-gateway:0.5.8)
LATEST_RUNTIME_IMAGE=$(setting DSTACK_E2E_LATEST_RUNTIME_IMAGE dstack-e2e-runtime:local)
OLD_KMS_BIN=$(setting DSTACK_E2E_OLD_KMS_BIN /usr/local/bin/dstack-kms)
OLD_GATEWAY_BIN=$(setting DSTACK_E2E_OLD_GATEWAY_BIN /usr/local/bin/dstack-gateway)
LATEST_KMS_BIN=/workspace/target/release/dstack-kms
LATEST_GATEWAY_BIN=/workspace/target/release/dstack-gateway
KEEP_STACK=$(setting DSTACK_E2E_KEEP_STACK true)
CLEAN_STATE=$(setting DSTACK_E2E_UPGRADE_CLEAN_STATE true)
KMS_HOST_PORT=$(setting DSTACK_E2E_KMS_HOST_PORT 28082)
GATEWAY_RPC_HOST_PORT=$(setting DSTACK_E2E_GATEWAY_RPC_HOST_PORT 28000)
GATEWAY_WG_INTERFACE=$(setting DSTACK_E2E_GATEWAY_WG_INTERFACE wg-ds-e2e)
probe_pid=""

COMPOSE=(docker compose -f "$SCRIPT_DIR/compose.yml")
if [[ -f "$ENV_FILE" ]]; then
  COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$SCRIPT_DIR/compose.yml")
fi

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

compose() {
  "${COMPOSE[@]}" "$@"
}

need_bin() {
  [[ -x "$1" ]] || die "missing current binary $1; build the release binaries documented in README.md"
}

pull_released_image() {
  local image=$1 component=$2
  log "pulling old $component image from Docker Hub: $image"
  if ! docker pull "$image"; then
    die "cannot pull $image from Docker Hub; set DSTACK_E2E_OLD_${component^^}_IMAGE only if an exact replacement was intentionally published"
  fi
}

wait_http() {
  local name=$1 url=$2 deadline=$((SECONDS + 180))
  while (( SECONDS < deadline )); do
    if curl -kfsS "$url" >/dev/null 2>&1; then
      log "$name ready"
      return 0
    fi
    sleep 2
  done
  compose logs --tail=200 "$name" >&2 || true
  die "$name did not become ready: $url"
}

container_version() {
  local service=$1 binary=$2 stage=$3 id image version
  id=$(compose ps -q "$service")
  [[ -n "$id" ]] || die "$service container not found"
  image=$(docker inspect -f '{{.Config.Image}}' "$id")
  version=$(docker exec "$id" "$binary" --version 2>&1)
  jq -n --arg stage "$stage" --arg service "$service" --arg image "$image" \
    --arg image_id "$(docker inspect -f '{{.Image}}' "$id")" --arg version "$version" \
    '{stage:$stage, service:$service, image:$image, image_id:$image_id, version:$version}' \
    > "$WORK_DIR/${service}-${stage}.version.json"
  log "$service $stage: $version ($image)"
}

run_phase() {
  local phase=$1
  log "running runner phase: $phase"
  DSTACK_E2E_PHASE="$phase" compose run --rm --no-deps \
    -e DSTACK_E2E_PHASE="$phase" runner
}

reset_state() {
  log "resetting Compose stack and E2E state"
  compose down --remove-orphans >/dev/null 2>&1 || true
  docker run --rm --privileged --network host alpine:3.22 sh -c \
    'ip link delete "$1" 2>/dev/null || true' -- "$GATEWAY_WG_INTERFACE"
  docker run --rm -v "$STATE_DIR:/state" alpine:3.22 sh -c \
    'find /state -mindepth 1 ! -name .gitkeep -exec rm -rf {} +'
}

on_exit() {
  local rc=$?
  if [[ -n "$probe_pid" ]] && kill -0 "$probe_pid" 2>/dev/null; then
    touch "$WORK_DIR/network-probe.stop" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
  fi
  if (( rc != 0 )); then
    log "upgrade E2E failed; recent service logs follow"
    compose logs --tail=250 kms gateway vmm runner >&2 || true
  fi
  if [[ "$KEEP_STACK" != "true" ]]; then
    compose down --remove-orphans >/dev/null 2>&1 || true
  else
    log "leaving stack running for inspection (DSTACK_E2E_KEEP_STACK=true)"
  fi
  exit "$rc"
}
trap on_exit EXIT

main() {
  need_bin "$REPO_DIR/dstack/target/release/dstack"
  need_bin "$REPO_DIR/dstack/target/release/dstack-auth"
  need_bin "$REPO_DIR/dstack/target/release/dstack-vmm"
  need_bin "$REPO_DIR/dstack/target/release/dstack-kms"
  need_bin "$REPO_DIR/dstack/target/release/dstack-gateway"
  need_bin "$REPO_DIR/dstack/target/release/supervisor"

  pull_released_image "$OLD_KMS_IMAGE" kms
  pull_released_image "$OLD_GATEWAY_IMAGE" gateway
  [[ "$CLEAN_STATE" == "true" ]] && reset_state

  log "building support containers"
  compose build init-config mock-cf-dns-api aesmd local-keyprovider
  compose up init-config
  compose up -d mock-cf-dns-api pebble aesmd local-keyprovider auth

  log "starting old KMS and Gateway"
  DSTACK_E2E_KMS_IMAGE="$OLD_KMS_IMAGE" DSTACK_E2E_KMS_BIN="$OLD_KMS_BIN" \
    compose up -d --no-deps --force-recreate kms
  wait_http kms "https://127.0.0.1:${KMS_HOST_PORT}/prpc/GetMeta?json"
  DSTACK_E2E_GATEWAY_IMAGE="$OLD_GATEWAY_IMAGE" DSTACK_E2E_GATEWAY_BIN="$OLD_GATEWAY_BIN" \
    compose up -d --no-deps --force-recreate gateway
  wait_http gateway "https://127.0.0.1:${GATEWAY_RPC_HOST_PORT}/prpc/Info?json"
  compose up -d --no-deps vmm
  mkdir -p "$WORK_DIR"
  container_version kms "$OLD_KMS_BIN" old
  container_version gateway "$OLD_GATEWAY_BIN" old
  run_phase prepare-old

  log "upgrading KMS in place to the current checkout"
  compose stop -t 30 kms
  DSTACK_E2E_KMS_IMAGE="$LATEST_RUNTIME_IMAGE" DSTACK_E2E_KMS_BIN="$LATEST_KMS_BIN" \
    compose up -d --no-deps --force-recreate kms
  wait_http kms "https://127.0.0.1:${KMS_HOST_PORT}/prpc/GetMeta?json"
  container_version kms "$LATEST_KMS_BIN" latest
  run_phase after-kms-upgrade

  log "starting strict direct-WireGuard availability probe"
  rm -f "$WORK_DIR/network-probe.ready" "$WORK_DIR/network-probe.stop"
  compose run --rm --no-deps runner /suite/scripts/network-probe.sh \
    >"$WORK_DIR/network-probe.log" 2>&1 &
  probe_pid=$!
  for _ in $(seq 1 120); do
    if [[ -e "$WORK_DIR/network-probe.ready" ]]; then
      break
    fi
    kill -0 "$probe_pid" 2>/dev/null || {
      cat "$WORK_DIR/network-probe.log" >&2
      die "network probe exited during warmup"
    }
    sleep 1
  done
  [[ -e "$WORK_DIR/network-probe.ready" ]] || die "network probe did not become ready"

  log "upgrading Gateway in place while CVM traffic remains active"
  compose stop -t 30 gateway
  DSTACK_E2E_GATEWAY_IMAGE="$LATEST_RUNTIME_IMAGE" DSTACK_E2E_GATEWAY_BIN="$LATEST_GATEWAY_BIN" \
    compose up -d --no-deps --force-recreate gateway
  wait_http gateway "https://127.0.0.1:${GATEWAY_RPC_HOST_PORT}/prpc/Info?json"
  container_version gateway "$LATEST_GATEWAY_BIN" latest
  sleep 3
  touch "$WORK_DIR/network-probe.stop"
  if ! wait "$probe_pid"; then
    cat "$WORK_DIR/network-probe.log" >&2
    die "CVM WireGuard data plane was interrupted during Gateway upgrade"
  fi
  probe_pid=""
  cat "$WORK_DIR/network-probe.log"
  run_phase after-gateway-upgrade

  log "upgrade E2E success"
  log "artifacts: $WORK_DIR"
}

main "$@"
