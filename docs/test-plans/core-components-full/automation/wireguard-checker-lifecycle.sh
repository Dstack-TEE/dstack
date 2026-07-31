#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
EXPECTED_SCRIPT_SHA=${1:?expected checker sha256}
CHECKER=${2:?checker path}
ROOT=/run/dstack-test-wireguard
NS=dstest-wg
IFACE=dstack-wg0
CONF=/etc/wireguard/dstack-wg0.conf
BACKUP=$ROOT/original.conf
checks=0
umask 077
had_config=false
check() { "$@"; checks=$((checks + 1)); }
# shellcheck disable=SC2317
cleanup() {
  set +e
  ip netns del "$NS" 2>/dev/null
  if $had_config; then install -m 0600 "$BACKUP" "$CONF"; else rm -f "$CONF"; fi
  rm -rf "/etc/netns/$NS" "$ROOT"
}
trap cleanup EXIT
mkdir -p "$ROOT" /etc/wireguard
if test -f "$CONF"; then had_config=true; cp -a "$CONF" "$BACKUP"; fi
check test "$(sha256sum "$CHECKER" | awk '{print $1}')" = "$EXPECTED_SCRIPT_SHA"
for binary in ip wg awk sha256sum; do check command -v "$binary" >/dev/null; done

# Build a real case-owned WireGuard topology in a network namespace. Private keys
# never leave the namespace setup files and are deleted by the EXIT trap.
check ip netns add "$NS"
check ip -n "$NS" link add "$IFACE" type wireguard
wg genkey >"$ROOT/private"
wg genkey >"$ROOT/peer-private"
wg pubkey <"$ROOT/peer-private" >"$ROOT/peer-public"
check ip netns exec "$NS" wg set "$IFACE" private-key "$ROOT/private" peer "$(cat "$ROOT/peer-public")" allowed-ips 10.253.0.2/32
check ip -n "$NS" address add 10.253.0.1/24 dev "$IFACE"
check ip -n "$NS" link set "$IFACE" up
check ip -n "$NS" link show "$IFACE"
check sh -c "ip -n '$NS' route show | grep -q '10.253.0.0/24'"
mkdir -p "/etc/netns/$NS"
printf 'nameserver 192.0.2.53\n' >"/etc/netns/$NS/resolv.conf"
check sh -c "ip netns exec '$NS' cat /etc/resolv.conf | grep -q '192.0.2.53'"
check sh -c "ip netns exec '$NS' wg show '$IFACE' latest-handshakes | grep -Eq '[[:space:]]0$'"

mkdir -p "$ROOT/fake" "$ROOT/work"
cat >"$ROOT/fake/date" <<'SH'
#!/bin/sh
file=${DSTACK_TEST_TIME_FILE:?}
value=$(/bin/head -n1 "$file")
/bin/sed -i '1d' "$file"
if test -z "$value"; then value=999999; fi
printf '%s\n' "$value"
SH
cat >"$ROOT/fake/sleep" <<'SH'
#!/bin/sh
count_file=${DSTACK_TEST_SLEEP_COUNT:?}
count=0; test -f "$count_file" && count=$(/bin/cat "$count_file")
count=$((count + 1)); printf '%s\n' "$count" >"$count_file"
if test "$count" -ge 8; then /bin/kill -TERM "$PPID" 2>/dev/null; exit 0; fi
/bin/sleep 0.03
SH
cat >"$ROOT/fake/wg" <<'SH'
#!/bin/sh
if test "${1:-}" = show && test "${3:-}" = latest-handshakes; then
  printf 'peer-fixture\t%s\n' "$(/bin/cat "${DSTACK_TEST_HANDSHAKE_FILE:?}")"
  exit 0
fi
exec /bin/wg "$@"
SH
cat >"$ROOT/fake/dstack-util" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>"${DSTACK_TEST_CALLS:?}"
if test "${DSTACK_TEST_FAIL_FORCE:-0}" = 1 && echo "$*" | /bin/grep -q -- --force; then
  printf 'injected refresh failure\n' >&2
  exit 71
fi
exit 0
SH
chmod +x "$ROOT/fake/"*
printf 'fixture\n' >"$CONF"

run_checker() {
  name=$1; times=$2; handshake=$3; fail_force=${4:-0}
  calls="$ROOT/$name.calls"; log="$ROOT/$name.log"; time_file="$ROOT/$name.times"; sleep_count="$ROOT/$name.sleeps"
  : >"$calls"
  : >"$sleep_count"
  # shellcheck disable=SC2086
  printf '%s
' $times >"$time_file"
  printf '%s
' "$handshake" >"$ROOT/$name.handshake"
  set +e
  DSTACK_WORK_DIR="$ROOT/work" DSTACK_TEST_TIME_FILE="$time_file" DSTACK_TEST_SLEEP_COUNT="$sleep_count" \
    DSTACK_TEST_HANDSHAKE_FILE="$ROOT/$name.handshake" DSTACK_TEST_CALLS="$calls" DSTACK_TEST_FAIL_FORCE="$fail_force" \
    PATH="$ROOT/fake:/bin:/usr/bin" /bin/sh "$CHECKER" >"$log" 2>&1
  set -e
}

run_checker no_handshake '1000 1010 1191 1192 1200 1201 1202 1203' 0 1
check test "$(grep -c 'gateway-refresh' "$ROOT/no_handshake.calls")" -ge 2
check test "$(grep -c -- '--force' "$ROOT/no_handshake.calls")" -ge 1
check grep -q 'dstack gateway refresh failed' "$ROOT/no_handshake.log"
run_checker stale_handshake '2000 2010 2011 2012 2013 2014 2015 2016' 1800
check test "$(grep -c -- '--force' "$ROOT/stale_handshake.calls")" -ge 1
run_checker fresh_handshake '3000 3010 3020 3030 3040 3050 3060 3070' 3005
check test "$(grep -c 'gateway-refresh' "$ROOT/fresh_handshake.calls")" -eq 1
check test "$(grep -c -- '--force' "$ROOT/fresh_handshake.calls")" -eq 0
run_checker recovery '4000 4010 4191 4192 4200 4201 4202 4203' 0
check test "$(grep -c -- '--force' "$ROOT/recovery.calls")" -ge 1
check grep -q 'dstack gateway refresh succeeded' "$ROOT/recovery.log"

# With wg absent from PATH, the checker remains a no-op even when config exists.
mkdir -p "$ROOT/no-wg"
for binary in date sleep dstack-util awk; do ln -s "$ROOT/fake/$binary" "$ROOT/no-wg/$binary" 2>/dev/null || true; done
: >"$ROOT/missing-wg.calls"; : >"$ROOT/missing-wg.sleeps"
printf '%s\n' 5000 5010 5020 5030 5040 5050 5060 5070 >"$ROOT/missing-wg.times"
set +e
DSTACK_TEST_TIME_FILE="$ROOT/missing-wg.times" DSTACK_TEST_SLEEP_COUNT="$ROOT/missing-wg.sleeps" \
 DSTACK_TEST_CALLS="$ROOT/missing-wg.calls" PATH="$ROOT/no-wg" /bin/sh "$CHECKER" >"$ROOT/missing-wg.log" 2>&1
set -e
check test ! -s "$ROOT/missing-wg.calls"

# Removing the trigger config resets the checker without touching the interface.
rm -f "$CONF"
: >"$ROOT/no-config.calls"; : >"$ROOT/no-config.sleeps"
printf '%s\n' 6000 6010 6020 6030 6040 6050 6060 6070 >"$ROOT/no-config.times"
set +e
DSTACK_TEST_TIME_FILE="$ROOT/no-config.times" DSTACK_TEST_SLEEP_COUNT="$ROOT/no-config.sleeps" \
 DSTACK_TEST_HANDSHAKE_FILE="$ROOT/fresh_handshake.handshake" DSTACK_TEST_CALLS="$ROOT/no-config.calls" \
 PATH="$ROOT/fake:/bin:/usr/bin" /bin/sh "$CHECKER" >"$ROOT/no-config.log" 2>&1
set -e
check test ! -s "$ROOT/no-config.calls"
check ip -n "$NS" link show "$IFACE"

printf '{"checks":%d,"real_interface":true,"address_route":true,"dns_observed":true,"no_handshake_observed":true,"periodic_refresh":true,"no_handshake_force":true,"stale_handshake_force":true,"fresh_handshake_not_forced":true,"refresh_failure_observed":true,"refresh_recovery":true,"missing_wg_noop":true,"missing_config_noop":true,"interface_isolated":true}\n' "$checks"
