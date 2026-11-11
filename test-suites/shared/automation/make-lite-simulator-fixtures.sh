#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
#
# Derive guest-simulator fixtures whose attestation takes the TDX lite path.
#
# The SDK simulator replays a captured legacy quote, which makes a verifier
# download its OS image. Here the candidate dstack-tee-simulator computes the
# quote measurements from the lite `tdx_measurement` document of the verifier
# fixture, the same way the verifier recomputes them, and the captured RTMR3
# events are replayed on top. The simulator runs in a private user and mount
# namespace because the TDX ABI paths under /sys are fixed.
set -euo pipefail

manifest=${1:?usage: make-lite-simulator-fixtures.sh RUNTIME_MANIFEST OUTPUT_DIR}
output=${2:?usage: make-lite-simulator-fixtures.sh RUNTIME_MANIFEST OUTPUT_DIR}

manifest=$(realpath -e -- "$manifest")
repo=$(jq -er '.repository' "$manifest")
fixtures=$(jq -er '.simulator_fixtures' "$manifest")
util=$(jq -er '.prepared_binaries.dstack_util.path' "$manifest")
tee_simulator=$(jq -er '.prepared_binaries.dstack_tee_simulator.path' "$manifest")
lite_sample="$repo/dstack/verifier/fixtures/tdx-lite-getquote.json"

install -d -m 700 "$output"
work=$(mktemp -d "$output/.lite.XXXXXX")
trap 'rm -rf "$work"' EXIT
for file in appkeys.json app-compose.json dstack.toml; do
  install -m 600 "$fixtures/$file" "$output/$file"
done
"$util" attest-json -i "$fixtures/attestation.bin" -o "$work/legacy.json"

python3 - "$lite_sample" "$fixtures/sys-config.json" "$work" <<'PY'
import json, pathlib, sys
sample, sys_config, work = sys.argv[1], sys.argv[2], pathlib.Path(sys.argv[3])
vm_config = json.loads(pathlib.Path(sample).read_text())["vm_config"]
image_hash = json.loads(vm_config)["os_image_hash"]
config = json.loads(pathlib.Path(sys_config).read_text())
config["vm_config"] = vm_config
(work / "shared").mkdir()
(work / "shared/.sys-config.json").write_text(json.dumps(config))
(work / "tee-simulator.json").write_text(
    json.dumps({"platform": "dstack-tdx", "mock_attestation_seed": "00" * 32, "vm_config": vm_config})
)
legacy = json.loads((work / "legacy.json").read_text())
events = [
    (e["event"], image_hash if e["event"] == "os-image-hash" else e["event_payload"])
    for e in legacy["tdx_quote"]["event_log"]
    if e["imr"] == 3
]
(work / "events.txt").write_text("".join(f"{name} {payload}\n" for name, payload in events))
PY

# The quote signature is irrelevant: the guest simulator re-signs every quote
# with the lease seed and keeps only the measurements and the event log.
unshare --user --map-root-user --mount --fork bash -euo pipefail -s -- \
  "$tee_simulator" "$util" "$work" <<'NS'
tee_simulator=$1 util=$2 work=$3
measurements=/sys/kernel/config/tsm/report/com.intel.dcap
mount -t tmpfs none /sys/kernel/config
mkdir -p /sys/kernel/config/tsm/report
mount -t tmpfs none /run
"$tee_simulator" --platform dstack-tdx --config "$work/tee-simulator.json" \
  --runtime-dir "$work/run" </dev/null >"$work/tee-simulator.log" 2>&1 &
simulator=$!
trap 'kill "$simulator"' EXIT
for _ in $(seq 1 100); do
  test -e "$measurements/outblob" && break
  sleep 0.05
done
test -e "$measurements/outblob" || { cat "$work/tee-simulator.log" >&2; exit 3; }
mkdir -p /run/log/dstack
printf 1 >/run/log/dstack/runtime_event_version
export DSTACK_HOST_SHARED_DIR="$work/shared"
export DSTACK_CCEL_FILE="$measurements/ccel"
export DCAP_TDX_RTMR_SYSFS_PATH="$measurements/measurements"
while read -r event payload; do
  "$util" extend --event "$event" --payload "$payload"
done <"$work/events.txt"
"$util" attest -o "$work/attestation.bin"
NS

install -m 600 "$work/attestation.bin" "$output/attestation.bin"
install -m 600 "$work/shared/.sys-config.json" "$output/sys-config.json"
