#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
REPO_DIR=$(cd -- "$SCRIPT_DIR/../.." && pwd)
STATE_DIR="$SCRIPT_DIR/state"
ENV_FILE=${DSTACK_E2E_ENV_FILE:-$SCRIPT_DIR/.env}

# Phases are the unit a run can be limited to. Each one is self-contained: it
# deploys what it needs and asserts on it, so a change that only touches one
# area does not have to pay for the whole suite.
#
#   upgrade  KMS/Gateway 0.5.8 -> current rolling upgrade (the full suite)
#   certbot  current-only KMS + two-node Gateway; ACME account registration,
#            CAA reconciliation, and account rotation
PHASE=${DSTACK_E2E_PHASE:-upgrade}
while (( $# )); do
  case "$1" in
    --phase) PHASE=${2:?--phase needs a value}; shift 2 ;;
    --phase=*) PHASE=${1#--phase=}; shift ;;
    -h|--help)
      sed -n '/^# Phases are/,/^PHASE=/p' "${BASH_SOURCE[0]}" | sed 's/^# \?//;$d'
      exit 0 ;;
    *) echo "ERROR: unknown argument $1" >&2; exit 1 ;;
  esac
done
case "$PHASE" in
  upgrade|certbot) ;;
  *) echo "ERROR: unknown phase $PHASE (expected upgrade or certbot)" >&2; exit 1 ;;
esac
export DSTACK_E2E_PHASE="$PHASE"

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

OLD_KMS_IMAGE=$(setting DSTACK_E2E_OLD_KMS_IMAGE \
  dstacktee/dstack-kms:0.5.8@sha256:9650dcb47dad0065470f432f00e78e012912214ef1a5b1d7272918817e61a26d)
OLD_GATEWAY_IMAGE=$(setting DSTACK_E2E_OLD_GATEWAY_IMAGE \
  dstacktee/dstack-gateway:0.5.8@sha256:6eb1dc1a5000f37cc5b0322d3fdb71e7f2e31859b5e3a611634919278cee2411)
APP_IMAGE=$(setting DSTACK_E2E_APP_IMAGE nginx:alpine)
KEEP_STACK=$(setting DSTACK_E2E_KEEP_STACK true)
CLEAN_STATE=$(setting DSTACK_E2E_UPGRADE_CLEAN_STATE true)
SKIP_BUILD=$(setting DSTACK_E2E_SKIP_CURRENT_BUILD false)
# dstack's build metadata deliberately embeds a 20-hex abbreviated revision.
CURRENT_REV=$(git -C "$REPO_DIR" rev-parse --short=20 HEAD)
CURRENT_VERSION=$(sed -n 's/^version = "\([^"]*\)"/\1/p' \
  "$REPO_DIR/dstack/Cargo.toml" | head -n1)
[[ -n "$CURRENT_VERSION" ]] || {
  echo "ERROR: could not read current workspace version" >&2
  exit 1
}

COMPOSE=(docker compose -f "$SCRIPT_DIR/compose.yml")
if [[ -f "$ENV_FILE" ]]; then
  COMPOSE=(docker compose --env-file "$ENV_FILE" -f "$SCRIPT_DIR/compose.yml")
fi

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
compose() { "${COMPOSE[@]}" "$@"; }

need_bin() {
  [[ -x "$1" ]] || die "missing executable $1"
}

pull_released_image() {
  local image=$1 component=$2
  log "pulling released $component image from Docker Hub: $image"
  docker pull "$image" || die "cannot pull released $component image $image"
}

reset_state() {
  log "resetting Compose stack and E2E state"
  compose down --remove-orphans >/dev/null 2>&1 || true
  docker run --rm -v "$STATE_DIR:/state" alpine:3.22 sh -c \
    'find /state -mindepth 1 ! -name .gitkeep -exec rm -rf {} +'
}

build_current_binaries() {
  if [[ "$SKIP_BUILD" == true ]]; then
    log "using prebuilt current musl KMS/Gateway binaries"
  else
    log "building current KMS/Gateway as production-style static musl binaries"
    cargo build --manifest-path "$REPO_DIR/dstack/Cargo.toml" \
      --release --target x86_64-unknown-linux-musl \
      -p dstack-kms -p dstack-gateway
  fi
  need_bin "$REPO_DIR/dstack/target/x86_64-unknown-linux-musl/release/dstack-kms"
  need_bin "$REPO_DIR/dstack/target/x86_64-unknown-linux-musl/release/dstack-gateway"
}

prepare_container_artifacts() {
  local artifact_dir="$STATE_DIR/artifacts/images"
  local context_dir="$STATE_DIR/image-build"
  local rev current_kms_image current_gateway_image
  local old_kms_id old_gateway_id current_kms_id current_gateway_id app_id
  rev=$(git -C "$REPO_DIR" rev-parse --short=16 HEAD)
  current_kms_image="dstack-e2e-kms-current:${rev}"
  current_gateway_image="dstack-e2e-gateway-current:${rev}"
  mkdir -p "$artifact_dir" "$context_dir/kms" "$context_dir/gateway"

  cp "$REPO_DIR/dstack/target/x86_64-unknown-linux-musl/release/dstack-kms" \
    "$context_dir/kms/dstack-kms"
  cat > "$context_dir/kms/Dockerfile" <<EOF
ARG BASE
FROM \${BASE}
COPY dstack-kms /usr/local/bin/dstack-kms
RUN chmod 0755 /usr/local/bin/dstack-kms
EOF
  docker build --build-arg "BASE=$OLD_KMS_IMAGE" -t "$current_kms_image" "$context_dir/kms"

  cp "$REPO_DIR/dstack/target/x86_64-unknown-linux-musl/release/dstack-gateway" \
    "$context_dir/gateway/dstack-gateway"
  cp "$REPO_DIR/dstack/gateway/dstack-app/builder/entrypoint.sh" \
    "$context_dir/gateway/entrypoint.sh"
  cat > "$context_dir/gateway/Dockerfile" <<EOF
ARG BASE
FROM \${BASE}
COPY dstack-gateway /usr/local/bin/dstack-gateway
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod 0755 /usr/local/bin/dstack-gateway /app/entrypoint.sh
EOF
  docker build --build-arg "BASE=$OLD_GATEWAY_IMAGE" -t "$current_gateway_image" "$context_dir/gateway"

  old_kms_id=$(docker image inspect -f '{{.Id}}' "$OLD_KMS_IMAGE")
  old_gateway_id=$(docker image inspect -f '{{.Id}}' "$OLD_GATEWAY_IMAGE")
  current_kms_id=$(docker image inspect -f '{{.Id}}' "$current_kms_image")
  current_gateway_id=$(docker image inspect -f '{{.Id}}' "$current_gateway_image")
  app_id=$(docker image inspect -f '{{.Id}}' "$APP_IMAGE" 2>/dev/null || echo "")

  log "saving content-addressed images for import inside CVMs"
  docker save -o "$artifact_dir/kms-current.tar" "$current_kms_image"
  docker save -o "$artifact_dir/gateway-current.tar" "$current_gateway_image"
  # The released images are still the base layers the current binaries are
  # built on, so they are pulled either way; only the upgrade phase boots them.
  if [[ "$PHASE" == upgrade ]]; then
    docker save -o "$artifact_dir/kms-0.5.8.tar" "$OLD_KMS_IMAGE"
    docker save -o "$artifact_dir/gateway-0.5.8.tar" "$OLD_GATEWAY_IMAGE"
    docker save -o "$artifact_dir/app.tar" "$APP_IMAGE"
  fi

  cat > "$STATE_DIR/artifacts/images.env" <<EOF
OLD_KMS_IMAGE=$OLD_KMS_IMAGE
OLD_KMS_IMAGE_ID=$old_kms_id
OLD_GATEWAY_IMAGE=$OLD_GATEWAY_IMAGE
OLD_GATEWAY_IMAGE_ID=$old_gateway_id
CURRENT_KMS_IMAGE=$current_kms_image
CURRENT_KMS_IMAGE_ID=$current_kms_id
CURRENT_GATEWAY_IMAGE=$current_gateway_image
CURRENT_GATEWAY_IMAGE_ID=$current_gateway_id
APP_IMAGE=$APP_IMAGE
APP_IMAGE_ID=$app_id
EOF

  docker run --rm --entrypoint dstack-kms "$OLD_KMS_IMAGE" --version \
    | tee "$STATE_DIR/work/kms-old.version.txt"
  docker run --rm --entrypoint dstack-kms "$current_kms_image" --version \
    | tee "$STATE_DIR/work/kms-current.version.txt"
  docker run --rm --entrypoint dstack-gateway "$OLD_GATEWAY_IMAGE" --version \
    | tee "$STATE_DIR/work/gateway-old.version.txt"
  docker run --rm --entrypoint dstack-gateway "$current_gateway_image" --version \
    | tee "$STATE_DIR/work/gateway-current.version.txt"

  grep -E '^dstack-kms v0\.5\.8 \(git:' "$STATE_DIR/work/kms-old.version.txt" >/dev/null \
    || die "$OLD_KMS_IMAGE is not KMS 0.5.8"
  grep -E '^dstack-gateway v0\.5\.8 \(git:' "$STATE_DIR/work/gateway-old.version.txt" >/dev/null \
    || die "$OLD_GATEWAY_IMAGE is not Gateway 0.5.8"
  grep -E "^dstack-kms v${CURRENT_VERSION//./\\.} \\(git:" \
    "$STATE_DIR/work/kms-current.version.txt" >/dev/null \
    || die "locally built KMS is not current v$CURRENT_VERSION"
  grep -E "^dstack-gateway v${CURRENT_VERSION//./\\.} \\(git:" \
    "$STATE_DIR/work/gateway-current.version.txt" >/dev/null \
    || die "locally built Gateway is not current v$CURRENT_VERSION"
  grep -F "$CURRENT_REV" "$STATE_DIR/work/kms-current.version.txt" >/dev/null \
    || die "KMS binary was not built from current revision $CURRENT_REV"
  grep -F "$CURRENT_REV" "$STATE_DIR/work/gateway-current.version.txt" >/dev/null \
    || die "Gateway binary was not built from current revision $CURRENT_REV"
}

wait_local_key_provider() {
  local port deadline status
  port=$(setting DSTACK_E2E_KEY_PROVIDER_PORT 13443)
  deadline=$((SECONDS + 120))
  log "waiting for production SGX Local-Key-Provider on 127.0.0.1:${port}"
  while (( SECONDS < deadline )); do
    status=$(compose ps --format json local-keyprovider 2>/dev/null \
      | jq -rs 'map(select(.Service == "local-keyprovider"))[0].Health // ""' 2>/dev/null \
      || true)
    if [[ "$status" == healthy ]]; then
      log "Local-Key-Provider enclave is healthy"
      return 0
    fi
    sleep 2
  done
  compose logs --tail=200 aesmd local-keyprovider >&2 || true
  die "Local-Key-Provider did not become healthy; fix SGX/DCAP/PCCS provisioning rather than disabling attestation"
}

on_exit() {
  local rc=$?
  if (( rc != 0 )); then
    log "E2E failed; recent infrastructure logs follow"
    compose logs --tail=250 auth artifacts vmm runner >&2 || true
  fi
  if [[ "$KEEP_STACK" != true ]]; then
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
  need_bin "$REPO_DIR/dstack/target/release/supervisor"

  pull_released_image "$OLD_KMS_IMAGE" kms
  pull_released_image "$OLD_GATEWAY_IMAGE" gateway
  if [[ "$PHASE" == upgrade ]]; then
    pull_released_image "$APP_IMAGE" application
  fi
  build_current_binaries
  [[ "$CLEAN_STATE" == true ]] && reset_state

  log "building E2E infrastructure"
  compose build init-config mock-cf-dns-api aesmd local-keyprovider
  compose run --rm init-config
  prepare_container_artifacts

  log "starting authorization, artifact, attestation, ACME and VMM infrastructure"
  compose up -d mock-cf-dns-api pebble aesmd local-keyprovider auth artifacts
  wait_local_key_provider
  compose up -d vmm

  log "running the $PHASE phase"
  # Keep the complete runner transcript in state/work even though the runner is
  # an ephemeral Compose container.  This is especially important for failures
  # during deployment, before a per-VM log file exists.
  compose run --rm --no-deps \
    -e DSTACK_E2E_PHASE="$PHASE" \
    -e DSTACK_E2E_CURRENT_VERSION="$CURRENT_VERSION" \
    -e DSTACK_E2E_CURRENT_REV="$CURRENT_REV" runner \
    2>&1 | tee "$STATE_DIR/work/runner.log"

  log "$PHASE E2E success"
  log "artifacts: $STATE_DIR/work"
}

main "$@"
