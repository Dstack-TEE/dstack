#!/bin/bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Exercise the packaged gateway checker's startup contract against a real
# WireGuard interface.
#
# The checker's refresh timing (periodic interval, handshake staleness, retry
# backoff) used to be driven from this script through a PATH-injected clock,
# because the checker was a shell script with no other seam. It is now
# dstack-util's `gateway-checker` subcommand whose decision function is pure and
# unit tested, so re-deriving that matrix here would only restate slower,
# flakier copies of those tests. What unit tests cannot reach, and what this
# script covers instead, is the boundary between the process and systemd: which
# exit code the checker picks for each unrecoverable startup condition, and
# whether the shipped unit actually honours it.
UNIT=${1:?unit name}
EXPECTED_MISCONFIGURED_EXIT=${2:?expected misconfigured exit code}
ROOT=/run/dstack-test-gateway-checker
NS=dstest-wg
IFACE=dstack-wg0
checks=0
umask 077
check() { "$@"; checks=$((checks + 1)); }
# shellcheck disable=SC2317
cleanup() {
  set +e
  ip netns del "$NS" 2>/dev/null
  rm -rf "/etc/netns/$NS" "$ROOT"
}
trap cleanup EXIT
mkdir -p "$ROOT"
for binary in ip wg awk systemctl dstack-util; do check command -v "$binary" >/dev/null; done

# Build a real case-owned WireGuard topology in a network namespace. Private
# keys never leave the namespace setup files and are deleted by the EXIT trap.
# This never touches the guest's own /etc/wireguard or routing.
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
# A freshly created peer has never handshaked. The checker reads exactly this
# `wg show ... latest-handshakes` shape, so pin the zero baseline it parses.
check sh -c "ip netns exec '$NS' wg show '$IFACE' latest-handshakes | grep -Eq '[[:space:]]0$'"

# Synthesize the host-shared inputs the checker loads at startup. These are
# deliberately minimal and case-owned: the point is which startup condition the
# checker detects, not that it can reach a gateway.
work=$ROOT/work
mkdir -p "$work/.host-shared"
printf '{"vm_config":"{}","gateway_urls":[]}\n' >"$work/.host-shared/.sys-config.json"
printf '{"disk_crypt_key":"00","k256_key":"00","k256_signature":"00","gateway_app_id":"%s","ca_cert":"","key_provider":{"None":{"key":"test"}}}\n' \
  "" >"$work/.host-shared/.appkeys.json"
write_compose() {
  printf '{"manifest_version":2,"name":"dstack-test","runner":"docker-compose","docker_compose_file":"services: {}","gateway_enabled":%s}\n' \
    "$1" >"$work/.host-shared/app-compose.json"
}
run_checker() {
  set +e
  timeout 30 dstack-util gateway-checker --work-dir "$work" >"$ROOT/$1.log" 2>&1
  printf '%s' "$?" >"$ROOT/$1.rc"
  set -e
}

# An app that never enabled dstack-gateway has nothing to supervise. The
# checker must exit successfully rather than poll forever: the unit restarts on
# failure, so a non-zero exit here would respawn the checker every RestartSec
# for the life of every gateway-less CVM.
write_compose false
run_checker disabled
check test "$(cat "$ROOT/disabled.rc")" -eq 0
check grep -q 'not enabled' "$ROOT/disabled.log"

# A gateway-enabled app with no allowed gateway app id is a deployment mistake.
# Both this and the missing-URL case below are fixed for the lifetime of the VM,
# so the checker must report them with the dedicated exit code instead of
# retrying something that can never succeed.
write_compose true
run_checker no_app_id
check test "$(cat "$ROOT/no_app_id.rc")" -eq "$EXPECTED_MISCONFIGURED_EXIT"
check grep -q 'misconfigured' "$ROOT/no_app_id.log"
check grep -q 'not retrying' "$ROOT/no_app_id.log"

# Same contract for a configured app id with no gateway URL to reach.
printf '{"disk_crypt_key":"00","k256_key":"00","k256_signature":"00","gateway_app_id":"any","ca_cert":"","key_provider":{"None":{"key":"test"}}}\n' \
  >"$work/.host-shared/.appkeys.json"
run_checker no_urls
check test "$(cat "$ROOT/no_urls.rc")" -eq "$EXPECTED_MISCONFIGURED_EXIT"

# The exit codes above only mean anything if the shipped unit honours them.
# Read the properties from the running system rather than the repository, so a
# unit that failed to install is not mistaken for a correct one.
unit_props=$(systemctl show "$UNIT" \
  --property=Id,LoadState,Restart,RestartPreventExitStatus,ExecStart --no-pager)
printf '%s\n' "$unit_props" >"$ROOT/unit.properties"
check grep -q "^Id=$UNIT\$" "$ROOT/unit.properties"
check grep -q '^LoadState=loaded$' "$ROOT/unit.properties"
# Restart=always would respawn the exit-0 "gateway disabled" case forever.
check grep -q '^Restart=on-failure$' "$ROOT/unit.properties"
# Without this the misconfigured exit degrades into a RestartSec respawn loop,
# which is the exact failure the dedicated exit code exists to prevent.
check grep -q "RestartPreventExitStatus=.*\\b$EXPECTED_MISCONFIGURED_EXIT\\b" "$ROOT/unit.properties"
check grep -q 'gateway-checker' "$ROOT/unit.properties"

# The checker is a dstack-util subcommand now; the old shell script must be gone
# from the image, otherwise both could ship and disagree.
check test ! -e /bin/wg-checker.sh
check test ! -e /usr/bin/wg-checker.sh

# The guest's own gateway state was never touched by any of the above.
check ip -n "$NS" link show "$IFACE"

printf '{"checks":%d,"real_interface":true,"address_route":true,"dns_observed":true,"no_handshake_observed":true,"disabled_exits_zero":true,"missing_app_id_exit_code":true,"missing_urls_exit_code":true,"unit_restart_on_failure":true,"unit_prevents_restart":true,"unit_runs_subcommand":true,"legacy_script_absent":true,"interface_isolated":true}\n' "$checks"
