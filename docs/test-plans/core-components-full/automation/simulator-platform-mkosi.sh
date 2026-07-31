#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT=/run/dstack-test-platform
SIM=$ROOT/dstack-tee-simulator
SEED=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
PIDS=()
MOUNTS=()
STAGE=initialization
dump_failure() {
  local rc=$?
  echo "FAILED_STAGE=$STAGE rc=$rc" >&2
  for log in "$ROOT"/*.log; do
    test -f "$log" || continue
    echo "===== $log =====" >&2
    tail -200 "$log" >&2
  done
  exit "$rc"
}
trap dump_failure ERR
mkdir -p "$ROOT"
stop_one() {
  local pid=$1 mount=${2:-}
  set +e
  test -n "$mount" && fusermount3 -uz "$mount" 2>/dev/null
  kill "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
  set -e
}
reset_devices() {
  set +e
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null; done
  for mount in "${MOUNTS[@]}"; do fusermount3 -uz "$mount" 2>/dev/null; done
  test -s "$ROOT/runtime/swtpm.pid" && kill "$(cat "$ROOT/runtime/swtpm.pid")" 2>/dev/null
  rm -f /dev/tpm0 /dev/tpmrm0 /dev/nsm
  modprobe -r tpm_vtpm_proxy 2>/dev/null
  set -e
  PIDS=(); MOUNTS=()
  rm -rf "$ROOT/runtime" "$ROOT/mount" "$ROOT/dmi"
  mkdir -p "$ROOT/runtime" "$ROOT/mount" "$ROOT/dmi"
}
cleanup() { reset_devices; rm -rf "$ROOT"; }
trap cleanup EXIT
write_config() {
  jq -cn \
    --arg platform "$1" \
    --arg seed "${2:-$SEED}" \
    --arg mr '{"version":3,"app_id":"","compose_hash":"","key_provider":"none"}' \
    '{platform:$platform,mock_attestation_seed:$seed,collateral_base_url:"http://127.0.0.1:18088",mr_config:$mr,vm_config:"{}"}' \
    >"$ROOT/config.json"
}
start_fuse() {
  local platform=$1 mount=$2 seed=${3:-$SEED}
  mkdir -p "$mount" "$ROOT/runtime-$platform" "$ROOT/dmi-$platform"
  write_config "$platform" "$seed"
  "$SIM" --config "$ROOT/config.json" --mountpoint "$mount" --runtime-dir "$ROOT/runtime-$platform" --dmi-root "$ROOT/dmi-$platform" >"$ROOT/$platform.log" 2>&1 &
  local pid=$!; PIDS+=("$pid"); MOUNTS+=("$mount")
  for _ in $(seq 1 200); do
    mountpoint -q "$mount" && { echo "$pid"; return; }
    kill -0 "$pid" 2>/dev/null || { cat "$ROOT/$platform.log" >&2; return 1; }
    sleep .05
  done
  return 1
}
# Required config and failure atomicity.
STAGE=config-validation
if "$SIM" --config "$ROOT/missing.json" >"$ROOT/missing.log" 2>&1; then MISSING_RC=0; else MISSING_RC=$?; fi
printf '{broken' >"$ROOT/malformed.json"
if "$SIM" --config "$ROOT/malformed.json" >"$ROOT/malformed.log" 2>&1; then MALFORMED_RC=0; else MALFORMED_RC=$?; fi
mkdir -p "$ROOT/bad-mount"
printf '{"platform":"dstack-tdx","mock_attestation_seed":"00"}\n' >"$ROOT/bad.json"
if "$SIM" --config "$ROOT/bad.json" --mountpoint "$ROOT/bad-mount" --runtime-dir "$ROOT/bad-run" --dmi-root "$ROOT/bad-dmi" >"$ROOT/bad.log" 2>&1; then BAD_RC=0; else BAD_RC=$?; fi
test "$MISSING_RC" -ne 0
test "$MALFORMED_RC" -ne 0
test "$BAD_RC" -ne 0
mountpoint -q "$ROOT/bad-mount" && exit 1
# Explicit CLI override, duplicate mount rejection, concurrency, adjacent identity.
STAGE=selection-concurrency-isolation
printf '{"platform":"dstack-amd-sev-snp","mock_attestation_seed":"%s"}\n' "$SEED" >"$ROOT/config.json"
mkdir -p "$ROOT/primary" "$ROOT/run-primary" "$ROOT/dmi-primary"
"$SIM" --platform dstack-tdx --config "$ROOT/config.json" --mountpoint "$ROOT/primary" --runtime-dir "$ROOT/run-primary" --dmi-root "$ROOT/dmi-primary" >"$ROOT/primary.log" 2>&1 &
PRIMARY=$!; PIDS+=("$PRIMARY"); MOUNTS+=("$ROOT/primary")
for _ in $(seq 1 200); do mountpoint -q "$ROOT/primary" && break; sleep .05; done
mountpoint -q "$ROOT/primary"
test "$(cat "$ROOT/primary/com.intel.dcap/provider")" = tdx_guest
if "$SIM" --platform dstack-tdx --config "$ROOT/config.json" --mountpoint "$ROOT/primary" --runtime-dir "$ROOT/run-dup" --dmi-root "$ROOT/dmi-dup" >"$ROOT/duplicate.log" 2>&1; then DUPLICATE_RC=0; else DUPLICATE_RC=$?; fi
test "$DUPLICATE_RC" -ne 0
mountpoint -q "$ROOT/primary"
# shellcheck disable=SC2016
seq 1 32 | xargs -P8 -I{} sh -c 'test "$(cat "$1")" = tdx_guest' _ /run/dstack-test-platform/primary/com.intel.dcap/provider
printf '{"platform":"dstack-tdx","mock_attestation_seed":"%s"}\n' "$(printf 10%.0s $(seq 1 32))" >"$ROOT/adjacent.json"
mkdir -p "$ROOT/adjacent" "$ROOT/run-adjacent" "$ROOT/dmi-adjacent"
"$SIM" --config "$ROOT/adjacent.json" --mountpoint "$ROOT/adjacent" --runtime-dir "$ROOT/run-adjacent" --dmi-root "$ROOT/dmi-adjacent" >"$ROOT/adjacent.log" 2>&1 &
ADJACENT=$!; PIDS+=("$ADJACENT"); MOUNTS+=("$ROOT/adjacent")
for _ in $(seq 1 200); do mountpoint -q "$ROOT/adjacent" && break; sleep .05; done
mountpoint -q "$ROOT/adjacent"
stop_one "$PRIMARY" "$ROOT/primary"
mountpoint -q "$ROOT/adjacent"
stop_one "$ADJACENT" "$ROOT/adjacent"
PIDS=(); MOUNTS=()
# Every FUSE-backed TeeVariant.
STAGE=fuse-platform-matrix
for platform in dstack-tdx dstack-amd-sev-snp; do
  reset_devices
  pid=$(start_fuse "$platform" "$ROOT/mount")
  case "$platform" in
    dstack-tdx) test "$(cat "$ROOT/mount/com.intel.dcap/provider")" = tdx_guest ;;
    dstack-amd-sev-snp) test -e "$ROOT/mount/inblob" || test -e "$ROOT/mount/provider" ;;
  esac
  stop_one "$pid" "$ROOT/mount"
  PIDS=(); MOUNTS=()
done
# GCP TPM + TDX FUSE, dependency failure, and retry.
STAGE=gcp-tpm-initial-start
start_gcp() {
  reset_devices
  modprobe tpm_vtpm_proxy
  if test ! -e /dev/vtpmx && test -r /sys/class/misc/vtpmx/dev; then IFS=: read -r a b </sys/class/misc/vtpmx/dev; mknod /dev/vtpmx c "$a" "$b"; fi
  chmod 0666 /dev/vtpmx
  write_config dstack-gcp-tdx
  "$SIM" --config "$ROOT/config.json" --mountpoint "$ROOT/mount" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/gcp.log" 2>&1 &
  GCP_PID=$!; PIDS+=("$GCP_PID"); MOUNTS+=("$ROOT/mount")
  for _ in $(seq 1 300); do
    if mountpoint -q "$ROOT/mount" && test -e /dev/tpmrm0 && TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_nvreadpublic 0x01c10002 >/dev/null 2>&1; then return; fi
    kill -0 "$GCP_PID" 2>/dev/null || { cat "$ROOT/gcp.log" >&2; return 1; }
    sleep .05
  done
  return 1
}
start_gcp
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_pcrread sha256:0 >/dev/null
STAGE=gcp-tpm-fault-injection
kill "$(cat "$ROOT/runtime/swtpm.pid")"
if TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_pcrread sha256:0 >/dev/null 2>&1; then FAULT_RC=0; else FAULT_RC=$?; fi
test "$FAULT_RC" -ne 0
STAGE=gcp-tpm-retry
start_gcp
TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_pcrread sha256:0 >/dev/null
# Nitro Enclave CUSE ABI.
STAGE=nitro-enclave-cuse
reset_devices
write_config dstack-nitro-enclave
"$SIM" --config "$ROOT/config.json" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/nitro-enclave.log" 2>&1 &
NSM_PID=$!; PIDS+=("$NSM_PID")
for _ in $(seq 1 200); do
  if test ! -e /dev/nsm && test -r /sys/class/cuse/nsm/dev; then IFS=: read -r a b </sys/class/cuse/nsm/dev; mknod /dev/nsm c "$a" "$b"; fi
  test -e /dev/nsm && break
  kill -0 "$NSM_PID" 2>/dev/null || { cat "$ROOT/nitro-enclave.log" >&2; exit 1; }
  sleep .05
done
test -e /dev/nsm
# NitroTPM proxy ABI.
STAGE=nitro-tpm-proxy
reset_devices
modprobe tpm_vtpm_proxy
if test ! -e /dev/vtpmx && test -r /sys/class/misc/vtpmx/dev; then IFS=: read -r a b </sys/class/misc/vtpmx/dev; mknod /dev/vtpmx c "$a" "$b"; fi
chmod 0666 /dev/vtpmx
write_config dstack-aws-nitro-tpm
"$SIM" --config "$ROOT/config.json" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/nitro-tpm.log" 2>&1 &
NITRO_PID=$!; PIDS+=("$NITRO_PID")
for _ in $(seq 1 300); do
  test -e /dev/tpm0 && TPM2TOOLS_TCTI=device:/dev/tpm0 tpm2_pcrread sha384:4 >/dev/null 2>&1 && break
  kill -0 "$NITRO_PID" 2>/dev/null || { cat "$ROOT/nitro-tpm.log" >&2; find /sys/class/tpm /sys/class/tpmrm -maxdepth 6 -printf "TPM_SYSFS %y %p -> %l\n" 2>&1 | sort >&2; exit 1; }
  sleep .05
done
TPM2TOOLS_TCTI=device:/dev/tpm0 tpm2_pcrread sha384:4 >/dev/null
python3 - <<PY
import json
print(json.dumps({"missing_config_rc":$MISSING_RC,"malformed_config_rc":$MALFORMED_RC,"backend_failure_rc":$BAD_RC,"duplicate_rc":$DUPLICATE_RC,"concurrent_reads":32,"adjacent_isolated":True,"dependency_fault_rc":$FAULT_RC,"retry":True,"platforms":["dstack-tdx","dstack-gcp-tdx","dstack-amd-sev-snp","dstack-nitro-enclave","dstack-aws-nitro-tpm"]},sort_keys=True))
PY
