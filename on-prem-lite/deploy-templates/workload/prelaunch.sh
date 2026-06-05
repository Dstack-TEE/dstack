#!/bin/sh
# Runs in /dstack before docker compose up. It never edits docker-compose.yaml;
# the only app deployment file it writes is .env. In on-prem-lite there is no KMS,
# so the only runtime value resolved here is DSTACK_REGISTRY (where the lite
# launcher pulls itself and the encrypted workload image from).
set -eu

REGISTRY_RE='^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]+)?(/[a-z0-9._-]+)+$'

md() {
  curl -fs -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/$1" 2>/dev/null || true
}

find_user_config() {
  if [ -n "${PRELAUNCH_USER_CONFIG:-}" ] && [ -f "$PRELAUNCH_USER_CONFIG" ]; then
    printf '%s\n' "$PRELAUNCH_USER_CONFIG"
  elif [ -f ./user_config ]; then
    printf '%s\n' ./user_config
  elif [ -f /dstack/user_config ]; then
    printf '%s\n' /dstack/user_config
  elif [ -f /dstack/.host-shared/.user-config ]; then
    printf '%s\n' /dstack/.host-shared/.user-config
  fi
}

USER_CONFIG_FILE="$(find_user_config || true)"

json_lookup() {
  key="$1"
  [ -n "$USER_CONFIG_FILE" ] || return 0
  command -v jq >/dev/null 2>&1 || return 0
  jq -e . "$USER_CONFIG_FILE" >/dev/null 2>&1 || return 0
  jq -r --arg k "$key" 'if type == "object" and has($k) then .[$k] else empty end' \
    "$USER_CONFIG_FILE" 2>/dev/null || true
}

kv_lookup() {
  key="$1"
  [ -n "$USER_CONFIG_FILE" ] || return 0
  sed -n "s/^[[:space:]]*$key[[:space:]]*=[[:space:]]*//p" "$USER_CONFIG_FILE" \
    2>/dev/null | tail -n 1
}

config_lookup() {
  for key in "$@"; do
    value="$(json_lookup "$key")"
    [ -n "$value" ] || value="$(kv_lookup "$key")"
    if [ -n "$value" ]; then
      printf '%s\n' "$value"
      return 0
    fi
  done
  return 1
}

require_value() {
  name="$1"
  value="$2"
  if [ -z "$value" ]; then
    echo "prelaunch: missing $name" >&2
    exit 1
  fi
}

validate() {
  name="$1"
  value="$2"
  regex="$3"
  if ! printf '%s' "$value" | grep -Eq "$regex"; then
    echo "prelaunch: invalid $name" >&2
    exit 1
  fi
}

DSTACK_REGISTRY="$(config_lookup DSTACK_REGISTRY dstack_registry registry || true)"
if [ -z "$DSTACK_REGISTRY" ]; then
  PROJECT="$(config_lookup GCP_PROJECT PROJECT project || true)"
  [ -n "$PROJECT" ] || PROJECT="$(md project/project-id)"
  REGION="$(config_lookup GCP_REGION REGION region || true)"
  if [ -z "$REGION" ]; then
    ZONE="$(config_lookup GCP_ZONE ZONE zone || true)"
    [ -n "$ZONE" ] || ZONE="$(md instance/zone)"
    ZONE="${ZONE##*/}"
    REGION="${ZONE%-*}"
  fi
  AR_REPO="$(config_lookup AR_REPO DSTACK_AR_REPO ar_repo || true)"
  [ -n "$AR_REPO" ] || AR_REPO="$(md instance/attributes/ar-repo)"
  [ -n "$AR_REPO" ] || AR_REPO="dstack-private"
  require_value PROJECT "$PROJECT"
  require_value REGION "$REGION"
  DSTACK_REGISTRY="${REGION}-docker.pkg.dev/${PROJECT}/${AR_REPO}"
fi

require_value DSTACK_REGISTRY "$DSTACK_REGISTRY"
validate DSTACK_REGISTRY "$DSTACK_REGISTRY" "$REGISTRY_RE"

umask 077
tmp_env=".env.$$"
{
  printf 'DSTACK_REGISTRY=%s\n' "$DSTACK_REGISTRY"
} >"$tmp_env"
mv "$tmp_env" .env

if [ "${PRELAUNCH_SKIP_DOCKER_LOGIN:-}" != "1" ]; then
  AR_HOST="${DSTACK_REGISTRY%%/*}"
  TOKEN="$(md instance/service-accounts/default/token | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  require_value METADATA_ACCESS_TOKEN "$TOKEN"
  echo "$TOKEN" | docker login -u oauth2accesstoken --password-stdin "https://$AR_HOST"
fi
