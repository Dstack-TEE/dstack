#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

fixture=${1:?usage: stop-simulator.sh FIXTURE_JSON}
fixture=$(realpath -e -- "$fixture")
runtime=$(jq -er .runtime "$fixture")
pid=$(jq -er .pid "$fixture")
state_root=$(realpath -m -- "${DSTACK_TEST_STATE_ROOT:-$HOME/.cache/dstack-test/runtime-state}")
case "$runtime" in
  /tmp/dstack-test-case-*|"$state_root"/s/*) ;;
  *) echo "unsafe runtime path: $runtime" >&2; exit 2 ;;
esac
test ! -L "$runtime"

if kill -0 "$pid" 2>/dev/null; then
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid"
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.05; done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL -- "-$pid" 2>/dev/null || true
  fi
fi

resolved=$(realpath -e -- "$runtime")
test "$resolved" = "$runtime"
find "$runtime" -xdev -depth -delete
test ! -e "$runtime"
