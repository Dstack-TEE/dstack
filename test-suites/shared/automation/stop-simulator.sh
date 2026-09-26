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

# start-simulator.sh runs the simulator under `setsid sg`, and sg forks: the
# recorded pid is the sg leader of a new process group and the simulator is its
# child. TERM ends sg at once while the simulator is still unlinking its own
# sockets and lock files, so wait for the whole group before deleting the
# runtime, or find races the simulator for the same entries.
alive() { kill -0 -- "-$pid" 2>/dev/null || kill -0 "$pid" 2>/dev/null; }
if alive; then
  kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do alive || break; sleep 0.05; done
  if alive; then
    kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    for _ in $(seq 1 100); do alive || break; sleep 0.05; done
  fi
fi

resolved=$(realpath -e -- "$runtime")
test "$resolved" = "$runtime"
find "$runtime" -xdev -depth -delete
test ! -e "$runtime"
