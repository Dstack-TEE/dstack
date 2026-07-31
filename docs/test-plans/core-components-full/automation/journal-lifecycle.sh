#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-journal
DROPIN=/run/systemd/journald.conf.d/99-dstack-test.conf
TOKEN=${1:?sentinel token}
TOKEN_HASH=${2:?sentinel hash}
MARKER=${3:?run marker}
mkdir -p "$ROOT" "$(dirname "$DROPIN")"
cleanup() {
  set +e
  rm -f "$DROPIN"
  systemctl restart systemd-journald.service >/dev/null 2>&1
  rm -rf "$ROOT"
}
trap cleanup EXIT
systemctl is-active --quiet systemd-journald.service
BASE_BOOT=$(journalctl --list-boots --no-pager | wc -l)
BASE_USAGE=$(journalctl --disk-usage --no-pager | sed -n 's/.*take up \([^ ]*\).*/\1/p')
cat >"$DROPIN" <<'CONF'
[Journal]
RuntimeMaxUse=8M
RuntimeMaxFileSize=1M
RuntimeMaxFiles=4
ReadKMsg=no
CONF
systemctl restart systemd-journald.service
systemctl is-active --quiet systemd-journald.service
systemd-analyze cat-config systemd/journald.conf >"$ROOT/effective.conf"
grep -q '^RuntimeMaxUse=8M$' "$ROOT/effective.conf"
grep -q '^RuntimeMaxFileSize=1M$' "$ROOT/effective.conf"
BASELINE=true
# Emit only the hash and an explicit redaction marker; journald is a transport,
# not a secret scrubber, so producers own payload redaction.
printf 'application marker=%s sentinel_sha256=%s token=[REDACTED]\n' "$MARKER" "$TOKEN_HASH" | systemd-cat -t dstack-journal-app
logger -t dstack-journal-rpc "rpc marker=$MARKER status=ok sentinel_sha256=$TOKEN_HASH"
if docker run --rm nonexistent.invalid/dstack-journal-test:"$MARKER" true >"$ROOT/docker.out" 2>"$ROOT/docker.err"; then exit 31; fi
if systemctl start "dstack-journal-missing-$MARKER.service" >"$ROOT/failure.out" 2>"$ROOT/failure.err"; then exit 32; fi
# Duplicate/concurrent producer paths must remain queryable exactly once each.
logger -t dstack-journal-concurrent "marker=$MARKER worker=a" & A=$!
logger -t dstack-journal-concurrent "marker=$MARKER worker=b" & B=$!
wait "$A"; wait "$B"
systemctl restart systemd-journald.service
sleep 1
journalctl --sync
journalctl -t dstack-journal-app --no-pager -o cat >"$ROOT/app.log"
journalctl -t dstack-journal-rpc --no-pager -o cat >"$ROOT/rpc.log"
journalctl -t dstack-journal-concurrent --no-pager -o cat >"$ROOT/concurrent.log"
grep -Fq "marker=$MARKER" "$ROOT/app.log"
grep -Fq "marker=$MARKER" "$ROOT/rpc.log"
test "$(grep -Fc "marker=$MARKER worker=" "$ROOT/concurrent.log")" -eq 2
journalctl --rotate
# Bounded pressure: about 2 MiB, below the configured 8 MiB runtime ceiling.
PAYLOAD=$(head -c 2048 /dev/zero | tr '\0' x)
for i in $(seq 1 1024); do logger -t dstack-journal-pressure "marker=$MARKER row=$i $PAYLOAD"; done
journalctl --sync
journalctl --rotate
journalctl --vacuum-size=8M >"$ROOT/vacuum.out" 2>&1
ROTATION=true
if grep -R -Fq -- "$TOKEN" "$ROOT" /run/log/journal /var/log/journal 2>/dev/null; then exit 36; fi
REDACTED=true
# Journal files must not be readable by an unrelated unprivileged identity.
JOURNAL_FILE=$(find /run/log/journal /var/log/journal -type f -name '*.journal' -print -quit 2>/dev/null)
test -n "$JOURNAL_FILE"
if su -s /bin/sh nobody -c "head -c 1 '$JOURNAL_FILE' >/dev/null 2>&1"; then exit 33; fi
UNPRIVILEGED_DENIED=true
# Invalid maintenance input fails closed without changing service health.
if journalctl --vacuum-size=not-a-size >"$ROOT/invalid.out" 2>&1; then exit 34; fi
systemctl is-active --quiet systemd-journald.service
INVALID_CLOSED=true
# Controlled dependency outage and recovery.
systemctl stop systemd-journald.service
if systemctl is-active --quiet systemd-journald.service; then exit 35; fi
OUTAGE=true
systemctl start systemd-journald.service
systemctl is-active --quiet systemd-journald.service
logger -t dstack-journal-recovery "marker=$MARKER recovered=true sentinel_sha256=$TOKEN_HASH"
journalctl --sync
journalctl -t dstack-journal-recovery --no-pager -o cat | grep -Fq "marker=$MARKER recovered=true"
RECOVERED=true
AFTER_BOOT=$(journalctl --list-boots --no-pager | wc -l)
AFTER_USAGE=$(journalctl --disk-usage --no-pager | sed -n 's/.*take up \([^ ]*\).*/\1/p')
printf '{"baseline":%s,"rotation":%s,"redacted":%s,"unprivileged_denied":%s,"invalid_closed":%s,"outage":%s,"recovered":%s,"cleanup":true,"boot_rows_before":%s,"boot_rows_after":%s,"usage_before":"%s","usage_after":"%s"}\n' \
 "$BASELINE" "$ROTATION" "$REDACTED" "$UNPRIVILEGED_DENIED" "$INVALID_CLOSED" "$OUTAGE" "$RECOVERED" "$BASE_BOOT" "$AFTER_BOOT" "$BASE_USAGE" "$AFTER_USAGE"
