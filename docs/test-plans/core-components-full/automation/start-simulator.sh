#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

manifest=${1:?usage: start-simulator.sh RUNTIME_MANIFEST CASE_RUNTIME OUTPUT_JSON}
runtime=${2:?usage: start-simulator.sh RUNTIME_MANIFEST CASE_RUNTIME OUTPUT_JSON}
output=${3:?usage: start-simulator.sh RUNTIME_MANIFEST CASE_RUNTIME OUTPUT_JSON}

manifest=$(realpath -e -- "$manifest")
runtime=$(realpath -m -- "$runtime")
state_root=$(realpath -m -- "${DSTACK_TEST_STATE_ROOT:-$HOME/.cache/dstack-test/runtime-state}")
case "$runtime" in
  /tmp/dstack-test-case-*|"$state_root"/s/*) ;;
  *) echo "unsafe runtime path: $runtime" >&2; exit 2 ;;
esac
test ! -L "$runtime"
install -d -m 700 "$runtime"

simulator=$(jq -er '.prepared_binaries.dstack_simulator.path' "$manifest")
fixtures=$(jq -er '.simulator_fixtures' "$manifest")
test -x "$simulator"
for file in appkeys.json app-compose.json attestation.bin sys-config.json dstack.toml; do
  install -m 600 "$fixtures/$file" "$runtime/$file"
done

if [[ -n ${DSTACK_TEST_MOCK_ATTESTATION_SEED:-} ]]; then
  python3 - "$runtime/dstack.toml" "$DSTACK_TEST_MOCK_ATTESTATION_SEED" <<'PY'
from pathlib import Path
import re, sys
path, seed = Path(sys.argv[1]), sys.argv[2]
if re.fullmatch(r"[0-9a-f]{64}", seed) is None:
    raise SystemExit("DSTACK_TEST_MOCK_ATTESTATION_SEED must be 64 lowercase hex characters")
text = path.read_text()
marker = "patch_report_data = true"
if text.count(marker) != 1:
    raise SystemExit("simulator config has no unique patch_report_data marker")
path.write_text(text.replace(marker, marker + f'\nmock_attestation_seed = "{seed}"', 1))
PY
fi

# GuestApi.Shutdown must never power off the physical development host. Record
# the requested systemd action as a simulator side effect instead.
install -d -m 700 "$runtime/test-bin"
cat >"$runtime/test-bin/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DSTACK_TEST_SYSTEMCTL_LOG:?}"
exit 0
SH
chmod 700 "$runtime/test-bin/systemctl"
export DSTACK_TEST_SYSTEMCTL_LOG="$runtime/systemctl.log"
export PATH="$runtime/test-bin:$PATH"

pushd "$runtime" >/dev/null
if test -S /var/run/docker.sock; then
  docker_gid=$(stat -c %g /var/run/docker.sock)
  docker_group=$(getent group "$docker_gid" | cut -d: -f1)
  test -n "$docker_group"
  printf -v simulator_command 'exec env PATH=%q DSTACK_TEST_SYSTEMCTL_LOG=%q %q -c %q' \
    "$PATH" "$DSTACK_TEST_SYSTEMCTL_LOG" "$simulator" dstack.toml
  # A long-lived tmux/dashboard parent can retain a stale supplementary-group
  # list after the operator is added to the Docker group. `sg` re-resolves the
  # checked group membership without requiring a host/session restart.
  setsid sg "$docker_group" -c "$simulator_command" >simulator.log 2>&1 &
else
  setsid "$simulator" -c dstack.toml >simulator.log 2>&1 &
fi
pid=$!
printf '%s\n' "$pid" >simulator.pid
popd >/dev/null
for _ in $(seq 1 100); do
  test -S "$runtime/tappd.sock" && test -S "$runtime/dstack.sock" && \
    test -S "$runtime/external.sock" && test -S "$runtime/guest.sock" && break
  kill -0 "$pid" 2>/dev/null || { cat "$runtime/simulator.log" >&2; exit 3; }
  sleep 0.05
done
test -S "$runtime/tappd.sock" -a -S "$runtime/dstack.sock" \
  -a -S "$runtime/external.sock" -a -S "$runtime/guest.sock"

python3 - "$output" "$runtime" "$pid" "$simulator" <<'PY'
import json, os, pathlib, sys, tempfile
output, runtime, pid, simulator = sys.argv[1:]
r = pathlib.Path(runtime)
value = {
    "schema_version": "1.0",
    "pid": int(pid),
    "runtime": runtime,
    "binary": simulator,
    "log": str(r / "simulator.log"),
    "services": {
        "Tappd": {"socket": str(r / "tappd.sock"), "route": "/prpc/Tappd.<Method>"},
        "DstackGuest": {"socket": str(r / "dstack.sock"), "route": "/<Method>"},
        "Worker": {"socket": str(r / "external.sock"), "route": "/prpc/<Method>"},
        "GuestApi": {"socket": str(r / "guest.sock"), "route": "/api/<Method>"},
    },
}
p = pathlib.Path(output); p.parent.mkdir(parents=True, exist_ok=True)
with tempfile.NamedTemporaryFile("w", dir=p.parent, delete=False) as f:
    json.dump(value, f, indent=2); f.write("\n"); temporary=f.name
os.replace(temporary, p)
PY
printf 'simulator fixture ready: %s\n' "$output"
