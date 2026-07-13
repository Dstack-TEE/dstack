#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
WORK_DIR=${DSTACK_E2E_WORK_DIR:-$STATE_DIR/work}
# shellcheck disable=SC1091
source "$STATE_DIR/state.env"

ready="$WORK_DIR/network-probe.ready"
stop="$WORK_DIR/network-probe.stop"
result="$WORK_DIR/network-probe.result.json"
attempts=0
failures=0
failovers=0
cycle=0
started_ns=$(date +%s%N)

probe_endpoint() {
  local label=$1 instance=$2 port=$3 sni
  sni="${instance}-80.${BASE_DOMAIN}"
  curl -kfsS --connect-timeout 1 --max-time 2 \
    --connect-to "${sni}:${port}:127.0.0.1:${port}" \
    "https://${sni}:${port}/" 2>/dev/null \
    | grep -qi 'welcome to nginx'
}

probe_ha() {
  local label=$1 instance=$2 first second
  if (( cycle % 2 == 0 )); then
    first=$GATEWAY1_PROXY_HOST_PORT
    second=$GATEWAY2_PROXY_HOST_PORT
  else
    first=$GATEWAY2_PROXY_HOST_PORT
    second=$GATEWAY1_PROXY_HOST_PORT
  fi
  attempts=$((attempts + 1))
  if probe_endpoint "$label" "$instance" "$first"; then
    return 0
  fi
  if probe_endpoint "$label" "$instance" "$second"; then
    failovers=$((failovers + 1))
    return 0
  fi
  failures=$((failures + 1))
  printf '%(%FT%T%z)T route unavailable label=%s preferred=%s fallback=%s\n' \
    -1 "$label" "$first" "$second" >&2
  return 1
}

declare -a labels=(legacy lite)
declare -A instances
for label in "${labels[@]}"; do
  instances[$label]=$(jq -r '.instance_id // ""' "$WORK_DIR/${label}.info.json")
  [[ -n "${instances[$label]}" ]] || {
    echo "missing instance id for $label" >&2
    exit 1
  }
done

# Warm up against both physical Gateway nodes before declaring the HA probe live.
for label in "${labels[@]}"; do
  for port in "$GATEWAY1_PROXY_HOST_PORT" "$GATEWAY2_PROXY_HOST_PORT"; do
    probe_endpoint "$label" "${instances[$label]}" "$port" || {
      echo "warmup failed: $label via Gateway proxy port $port" >&2
      exit 1
    }
  done
done
touch "$ready"

while [[ ! -e "$stop" ]]; do
  cycle=$((cycle + 1))
  for label in "${labels[@]}"; do
    probe_ha "$label" "${instances[$label]}" || true
  done
  sleep 0.05
done

ended_ns=$(date +%s%N)
duration_ms=$(((ended_ns - started_ns) / 1000000))
jq -n \
  --argjson duration_ms "$duration_ms" \
  --argjson attempts "$attempts" \
  --argjson failures "$failures" \
  --argjson failovers "$failovers" \
  '{duration_ms:$duration_ms,attempts:$attempts,failures:$failures,successful_failovers:$failovers}' \
  | tee "$result"

(( failures == 0 ))
