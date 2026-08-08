#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-chrony-state
CONFIG=
for candidate in /etc/chrony/chrony.conf /etc/chrony.conf; do
  test -f "$candidate" && { CONFIG=$candidate; break; }
done
test -n "$CONFIG"
mkdir -p "$ROOT"
cp -a "$CONFIG" "$ROOT/chrony.conf"
BASE_HASH=$(sha256sum "$CONFIG" | cut -d' ' -f1)
cleanup() {
  set +e
  cp -a "$ROOT/chrony.conf" "$CONFIG" 2>/dev/null
  systemctl restart chrony.service 2>/dev/null
  rm -rf "$ROOT"
}
trap cleanup EXIT
systemctl is-active --quiet chrony.service
chronyc tracking >"$ROOT/tracking.before" 2>&1
chronyc sources -n >"$ROOT/sources.before" 2>&1
BASELINE_ACTIVE=true
systemctl stop chrony.service
if systemctl is-active --quiet chrony.service; then exit 1; fi
STOP_OBSERVED=true
cat >"$CONFIG" <<'EOF'
server 127.0.0.1 port 9 iburst maxsamples 1
makestep 1.0 3
EOF
systemctl start chrony.service
sleep 2
systemctl is-active --quiet chrony.service
chronyc sources -n >"$ROOT/sources.fault" 2>&1
chronyc tracking >"$ROOT/tracking.fault" 2>&1
if grep -Eqi '127\.0\.0\.1|\?\?\?' "$ROOT/sources.fault" || grep -Eqi 'Not synchronised|Stratum[[:space:]]*:[[:space:]]*0|Reference ID[[:space:]]*:[[:space:]]*00000000' "$ROOT/tracking.fault"; then
  UNREACHABLE=true
else
  UNREACHABLE=false
fi
systemctl restart chrony.service & A=$!
systemctl restart chrony.service & B=$!
wait "$A"; wait "$B"
systemctl is-active --quiet chrony.service
CONCURRENT=true
cp -a "$ROOT/chrony.conf" "$CONFIG"
systemctl restart chrony.service
sleep 2
systemctl is-active --quiet chrony.service
chronyc tracking >"$ROOT/tracking.after" 2>&1
RECOVERED=true
RESTORED_HASH=$(sha256sum "$CONFIG" | cut -d' ' -f1)
test "$BASE_HASH" = "$RESTORED_HASH"
CONFIG_RESTORED=true
printf '{"baseline_active":%s,"stop_observed":%s,"unreachable_source_observed":%s,"concurrent_restart":%s,"recovered_active":%s,"config_restored":%s,"cleanup":true}\n' "$BASELINE_ACTIVE" "$STOP_OBSERVED" "$UNREACHABLE" "$CONCURRENT" "$RECOVERED" "$CONFIG_RESTORED"
