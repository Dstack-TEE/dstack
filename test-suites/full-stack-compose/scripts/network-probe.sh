#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

STATE_DIR=${DSTACK_E2E_STATE_DIR:-/suite-state}
WORK_DIR=${DSTACK_E2E_WORK_DIR:-$STATE_DIR/work}
TARGETS=${DSTACK_E2E_NETWORK_TARGETS:-$WORK_DIR/network-targets.tsv}
READY=$WORK_DIR/network-probe.ready
STOP=$WORK_DIR/network-probe.stop
RESULT=$WORK_DIR/network-probe.result.json
FAILURES=$WORK_DIR/network-probe.failures.log
INTERVAL=${DSTACK_E2E_NETWORK_PROBE_INTERVAL:-0.05}
REQUEST_TIMEOUT=${DSTACK_E2E_NETWORK_PROBE_TIMEOUT:-1}
WARMUP_SUCCESSES=${DSTACK_E2E_NETWORK_PROBE_WARMUP:-20}

log() { printf '[%(%H:%M:%S)T] %s\n' -1 "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

[[ -s "$TARGETS" ]] || die "missing network targets: $TARGETS"
rm -f "$READY" "$STOP" "$RESULT" "$FAILURES"

probe_all() {
  local count=0 label ip body
  while IFS=$'\t' read -r label ip; do
    [[ -n "$label" && -n "$ip" ]] || continue
    body=$(curl -fsS --max-time "$REQUEST_TIMEOUT" "http://${ip}:80/" 2>&1) \
      && grep -qi 'welcome to nginx' <<<"$body" \
      || return 1
    count=$((count + 1))
  done < "$TARGETS"
  (( count > 0 ))
}

log "warming up direct CVM WireGuard probes"
successes=0
deadline=$((SECONDS + 120))
while (( successes < WARMUP_SUCCESSES )); do
  (( SECONDS < deadline )) || die "network probe warmup timed out"
  if probe_all; then
    successes=$((successes + 1))
  else
    successes=0
  fi
  sleep "$INTERVAL"
done

started_at=$(date +%s%3N)
printf 'ready\n' > "$READY"
log "probe ready; strict zero-failure window started"

attempts=0
failures=0
while [[ ! -e "$STOP" ]]; do
  attempts=$((attempts + 1))
  if ! probe_all; then
    failures=$((failures + 1))
    printf '%s\tattempt=%s\n' "$(date --iso-8601=ns)" "$attempts" >> "$FAILURES"
  fi
  sleep "$INTERVAL"
done

finished_at=$(date +%s%3N)
jq -n \
  --argjson started_at_ms "$started_at" \
  --argjson finished_at_ms "$finished_at" \
  --argjson attempts "$attempts" \
  --argjson failures "$failures" \
  '{started_at_ms:$started_at_ms, finished_at_ms:$finished_at_ms, duration_ms:($finished_at_ms-$started_at_ms), attempts:$attempts, failures:$failures}' \
  | tee "$RESULT"

(( attempts > 0 )) || die "network probe recorded no attempts"
(( failures == 0 )) || die "CVM WireGuard data plane had $failures failed probe cycle(s)"
log "zero-downtime CVM network assertion passed"
