#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-openssh-state
DROPIN=/etc/ssh/sshd_config.d/10-dstack.conf
mkdir -p "$ROOT"
cleanup() { rm -rf "$ROOT"; }
trap cleanup EXIT
test -x /usr/sbin/sshd
test -f "$DROPIN"
test "$(stat -c %U:%G "$DROPIN")" = root:root
test "$(stat -c %a "$DROPIN")" = 644
/usr/sbin/sshd -t -f /etc/ssh/sshd_config
/usr/sbin/sshd -T -f /etc/ssh/sshd_config >"$ROOT/effective"
grep -qx 'passwordauthentication no' "$ROOT/effective"
grep -qx 'permitemptypasswords no' "$ROOT/effective"
grep -qx 'kbdinteractiveauthentication no' "$ROOT/effective"
grep -qx 'pubkeyauthentication yes' "$ROOT/effective"
grep -Eq '^permitrootlogin (without-password|prohibit-password)$' "$ROOT/effective"
PASSWORD_DISABLED=true
EMPTY_DISABLED=true
KEYBOARD_DISABLED=true
PUBKEY_ENABLED=true
ROOT_PASSWORD_DISABLED=true
NATIVE_VALID=true
cp /etc/ssh/sshd_config "$ROOT/invalid.conf"
printf '\nInvalidDstackDirective yes\n' >>"$ROOT/invalid.conf"
if /usr/sbin/sshd -t -f "$ROOT/invalid.conf" >"$ROOT/invalid.out" 2>"$ROOT/invalid.err"; then exit 1; fi
INVALID_REJECTED=true
/usr/sbin/sshd -T -f /etc/ssh/sshd_config >"$ROOT/concurrent-a" & A=$!
/usr/sbin/sshd -T -f /etc/ssh/sshd_config >"$ROOT/concurrent-b" & B=$!
wait "$A"; wait "$B"
cmp "$ROOT/concurrent-a" "$ROOT/concurrent-b"
CONCURRENT=true
FORWARDING=$(awk '$1=="allowtcpforwarding" {print $2}' "$ROOT/effective")
printf '{"password_auth_disabled":%s,"empty_password_disabled":%s,"keyboard_interactive_disabled":%s,"public_key_enabled":%s,"root_password_disabled":%s,"native_config_valid":%s,"invalid_config_rejected":%s,"concurrent_validation":%s,"forwarding_policy":"%s"}\n' "$PASSWORD_DISABLED" "$EMPTY_DISABLED" "$KEYBOARD_DISABLED" "$PUBKEY_ENABLED" "$ROOT_PASSWORD_DISABLED" "$NATIVE_VALID" "$INVALID_REJECTED" "$CONCURRENT" "$FORWARDING"
