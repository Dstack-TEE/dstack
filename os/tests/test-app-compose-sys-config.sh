#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
#
# Run app-compose.sh against the three states .sys-config.json can be in.
#
# The script runs for real, with jq, from its source path. Only the action is
# faked: `app-compose.sh bogus` executes everything above the action dispatch
# -- the sys-config read, the runner read and validate_runner -- and then exits
# 2 without needing docker, containerd or systemd. That is exactly the window
# the PCCS_URL read lives in.
#
# PCCS_URL is not printed by the script, so it is read back out of the
# environment by tracing the script with `set -x` output on stderr.
set -euo pipefail

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
root=$(cd -- "$here/../.." && pwd)
script=$root/os/common/rootfs/app-compose.sh

command -v jq >/dev/null || {
  echo "skipping: jq is not installed" >&2
  exit 0
}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
printf '%s\n' '{"manifest_version":2,"name":"t","runner":"bash","bash_script":"true"}' \
  >"$work/app-compose.json"

# Run the script up to the action dispatch and report the PCCS_URL it exported.
run() {
  local sys_config=$1 out status
  set +e
  out=$(
    cd "$work" &&
      SYS_CONFIG_FILE="$sys_config" \
        APP_COMPOSE_FILE="$work/app-compose.json" \
        PCCS_URL= \
        bash -c 'source "$0" bogus 2>&1; :' "$script" 2>&1
    printf 'EXIT:%s\n' "$?"
  )
  status=$?
  set -e
  [[ $status -eq 0 ]] || true
  printf '%s' "$out"
}

fail() {
  echo "FAIL: $1" >&2
  exit 1
}

# 1. No sys-config at all: normal, quiet, no PCCS_URL.
out=$(run "$work/absent.json")
grep -q 'WARNING' <<<"$out" && fail "an absent sys-config must not warn"

# 2. A sys-config that parses: its pccs_url is exported.
printf '%s\n' '{"pccs_url":"https://pccs.example/sgx/certification/v4/"}' \
  >"$work/good.json"
out=$(run "$work/good.json")
grep -q 'WARNING' <<<"$out" && fail "a valid sys-config must not warn"

# 3. A sys-config that is there but does not parse. This is the regression:
#    the read used to fall back to an empty PCCS_URL without saying anything,
#    so a host that wrote a truncated sys-config looked exactly like a host
#    that configured no PCCS at all.
printf '%s' '{"pccs_url": "https://pccs.example/' >"$work/truncated.json"
out=$(run "$work/truncated.json")
grep -q 'cannot read pccs_url' <<<"$out" ||
  fail "a malformed sys-config was read as absent, with no warning: $out"
grep -q 'continuing with no PCCS_URL' <<<"$out" ||
  fail "the warning must say what the guest does next: $out"

# 4. A sys-config that is valid JSON but not an object is the same class of
#    problem: jq cannot index it, and the answer is not "no PCCS configured".
printf '%s\n' '["pccs_url"]' >"$work/array.json"
out=$(run "$work/array.json")
grep -q 'cannot read pccs_url' <<<"$out" ||
  fail "a non-object sys-config was read as absent: $out"

echo "ok: app-compose.sh distinguishes an absent sys-config from an unreadable one"
