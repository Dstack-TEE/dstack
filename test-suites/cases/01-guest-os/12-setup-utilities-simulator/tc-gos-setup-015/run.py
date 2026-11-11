#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the TPM simulator proxy lifecycle inside a lease-owned mkosi VM."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time

CASE_ID = "tc-gos-setup-015"
REMOTE = r"""set -euo pipefail
ROOT=/run/dstack-test-tpm
SIM=$ROOT/dstack-tee-simulator
UTIL=$ROOT/dstack-util
SEED1=7171717171717171717171717171717171717171717171717171717171717171
SEED2=7272727272727272727272727272727272727272727272727272727272727272
mkdir -p "$ROOT"
cleanup() {
  set +e
  test -s "$ROOT/simulator.pid" && kill "$(cat "$ROOT/simulator.pid")" 2>/dev/null
  test -s "$ROOT/runtime/swtpm.pid" && kill "$(cat "$ROOT/runtime/swtpm.pid")" 2>/dev/null
  fusermount3 -uz "$ROOT/tsm" 2>/dev/null
  rm -f /dev/tpm0 /dev/tpmrm0
  modprobe -r tpm_vtpm_proxy 2>/dev/null
  pkill -f 'swtpm.*dstack-' 2>/dev/null
}
trap cleanup EXIT
reset_tpm() {
  set +e
  test -s "$ROOT/simulator.pid" && kill "$(cat "$ROOT/simulator.pid")" 2>/dev/null
  test -s "$ROOT/runtime/swtpm.pid" && kill "$(cat "$ROOT/runtime/swtpm.pid")" 2>/dev/null
  fusermount3 -uz "$ROOT/tsm" 2>/dev/null
  rm -f /dev/tpm0 /dev/tpmrm0
  modprobe -r tpm_vtpm_proxy 2>/dev/null
  pkill -f 'swtpm.*dstack-' 2>/dev/null
  set -e
  rm -rf "$ROOT/runtime" "$ROOT/tsm" "$ROOT/dmi"
  mkdir -p "$ROOT/runtime" "$ROOT/tsm" "$ROOT/dmi"
  modprobe tpm_vtpm_proxy
  if test ! -e /dev/vtpmx && test -r /sys/class/misc/vtpmx/dev; then
    IFS=: read -r major minor </sys/class/misc/vtpmx/dev
    mknod /dev/vtpmx c "$major" "$minor"
  fi
  chmod 0666 /dev/vtpmx
}
write_config() {
  local os_image_hash
  os_image_hash=$(sha256sum "$ROOT/sha256sum.txt" | cut -d' ' -f1)
  jq -cn \
    --arg platform "$1" \
    --arg seed "$2" \
    --arg os_image_hash "$os_image_hash" \
    --arg checksum "$(base64 -w0 "$ROOT/sha256sum.txt")" \
    --arg measurement "$(base64 -w0 "$ROOT/measurement.gcp.cbor")" \
    --arg event_log "$(base64 -w0 "$ROOT/tpm_eventlog.bin")" \
    '{platform:$platform,mock_attestation_seed:$seed,collateral_base_url:"http://127.0.0.1:18088",vm_config:({os_image_hash:$os_image_hash,gcp_measurement:{checksum_file:$checksum,measurement:$measurement}}|tojson),gcp_tpm_replay:{event_log:$event_log}}' \
    > "$ROOT/config.json"
}
start_gcp() {
  reset_tpm
  write_config dstack-gcp-tdx "$1"
  "$SIM" --config "$ROOT/config.json" --mountpoint "$ROOT/tsm" --runtime-dir "$ROOT/runtime" --dmi-root "$ROOT/dmi" >"$ROOT/simulator.log" 2>&1 &
  echo $! >"$ROOT/simulator.pid"
  for i in $(seq 1 200); do
    if test -e /dev/tpmrm0 \
      && TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_pcrread sha256:0 >/dev/null 2>&1 \
      && TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_nvreadpublic 0x01c10003 >/dev/null 2>&1 \
      && TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_nvreadpublic 0x01c10002 >/dev/null 2>&1 \
      && TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_nvread -C o 0x01c10002 -o /dev/null >/dev/null 2>&1; then
      return
    fi
    kill -0 "$(cat "$ROOT/simulator.pid")" 2>/dev/null || { cat "$ROOT/simulator.log" >&2; return 1; }
    sleep .05
  done
  cat "$ROOT/simulator.log" >&2
  return 1
}
export TPM2TOOLS_TCTI=device:/dev/tpmrm0
start_gcp "$SEED1"
tpm2_pcrread sha256:0 > "$ROOT/pcr-first.txt"
tpm2_getrandom 32 -o "$ROOT/random-first.bin"
set +e
echo "raw NV inventory:" >&2
tpm2_nvreadpublic -T device:/dev/tpm0 0x01c10003 >&2
RAW_NV_RC=$?
echo "resource-manager NV inventory:" >&2
tpm2_nvreadpublic -T device:/dev/tpmrm0 0x01c10003 >&2
RM_NV_RC=$?
set -e
test "$RM_NV_RC" -eq 0
"$UTIL" tpm-quote --key-algo ecc --data 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --output "$ROOT/quote-first.bin"
test -s "$ROOT/quote-first.bin"
tpm2_nvread -C o 0x01c10002 -o "$ROOT/ak-cert-first.der"
test -s "$ROOT/ak-cert-first.der"
# A short raw command must terminate or reject promptly; it may tear down the proxy.
set +e
timeout 3 python3 - <<'PYRAW'
import os
fd=os.open('/dev/tpm0', os.O_RDWR)
try: os.write(fd, b'bad')
finally: os.close(fd)
PYRAW
MALFORMED_RC=$?
timeout 3 python3 - <<'PYRAW'
import os
fd=os.open('/dev/tpm0', os.O_RDWR)
try: os.write(fd, b'X' * 65537)
finally: os.close(fd)
PYRAW
OVERSIZED_RC=$?
set -e
test "$MALFORMED_RC" -ne 124
test "$OVERSIZED_RC" -ne 124
# Reconnect after independent handle closure and issue bounded concurrent requests.
tpm2_pcrread sha256:0 >/dev/null
seq 1 16 | xargs -P8 -I{} sh -c 'TPM2TOOLS_TCTI=device:/dev/tpmrm0 tpm2_getrandom 8 >/dev/null'
# Kill the external swtpm dependency: requests fail closed, then a restart recovers.
kill "$(cat "$ROOT/runtime/swtpm.pid")"
for i in $(seq 1 50); do kill -0 "$(cat "$ROOT/runtime/swtpm.pid")" 2>/dev/null || break; sleep .02; done
set +e
timeout 3 tpm2_pcrread sha256:0 >"$ROOT/dependency-fault.log" 2>&1
FAULT_RC=$?
set -e
test "$FAULT_RC" -ne 0
test "$FAULT_RC" -ne 124
# Seed-derived fixture PCRs persist across a clean simulator restart; random output is ephemeral.
start_gcp "$SEED1"
tpm2_pcrread sha256:0 > "$ROOT/pcr-restarted.txt"
cmp "$ROOT/pcr-first.txt" "$ROOT/pcr-restarted.txt"
tpm2_getrandom 32 -o "$ROOT/random-restarted.bin"
! cmp -s "$ROOT/random-first.bin" "$ROOT/random-restarted.bin"
"$UTIL" tpm-quote --key-algo ecc --data 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff --output "$ROOT/quote-retry.bin"
test -s "$ROOT/quote-retry.bin"
# An adjacent simulator identity has a distinct seed-derived AK certificate.
start_gcp "$SEED2"
tpm2_nvread -C o 0x01c10002 -o "$ROOT/ak-cert-adjacent.der"
! cmp -s "$ROOT/ak-cert-first.der" "$ROOT/ak-cert-adjacent.der"
python3 - <<PYJSON
import hashlib,json,pathlib
r=pathlib.Path("$ROOT")
def digest(name): return hashlib.sha256((r/name).read_bytes()).hexdigest()
print(json.dumps({
 "startup":True,"pcr_read":True,"quote":True,"random":True,
 "malformed_returncode":$MALFORMED_RC,"oversized_returncode":$OVERSIZED_RC,
 "disconnect_reconnect":True,"persistent_restart":True,"ephemeral_restart":True,
 "dependency_fault_returncode":$FAULT_RC,"concurrent_requests":16,"retry":True,
 "adjacent_identity":True,"pcr_sha256":digest("pcr-first.txt"),
 "quote_sha256":digest("quote-first.bin"),"primary_ak_sha256":digest("ak-cert-first.der"),
 "adjacent_ak_sha256":digest("ak-cert-adjacent.der")
},sort_keys=True))
PYJSON
"""


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded host or guest command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def write_json(path: pathlib.Path, value: object) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    """Execute the complete case in the fixture-owned mkosi guest."""
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values") or {}
    ssh = [str(item) for item in values.get("ssh_argv") or []]
    image = str(values.get("image", ""))
    expected = str(
        (runtime.get("environment") or {}).get("DSTACK_TEST_NO_TEE_GUEST_IMAGE", "")
    )
    store = pathlib.Path(
        str((runtime.get("environment") or {}).get("DSTACK_TEST_IMAGE_STORE", ""))
    )
    evidence: dict[str, object] = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": image,
    }
    status = "FAIL"
    summary = "TPM lifecycle did not execute."
    started = time.monotonic()
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError(
                "fixture did not provide a destructive lease-owned SSH guest"
            )
        if image != expected:
            raise RuntimeError(
                f"fixture booted {image!r}, expected mkosi development image {expected!r}"
            )
        metadata = json.loads((store / image / "metadata.json").read_text())
        if metadata.get("builder") != "mkosi" or metadata.get("is_dev") is not True:
            raise RuntimeError(
                f"guest image is not mkosi development media: {metadata}"
            )
        evidence["mkosi"] = {
            "builder": metadata["builder"],
            "is_dev": metadata["is_dev"],
            "git_revision": metadata.get("git_revision"),
        }
        binaries = runtime.get("prepared_binaries") or {}
        for key, remote in (
            ("dstack_tee_simulator", "/run/dstack-test-tpm/dstack-tee-simulator"),
            ("dstack_util", "/run/dstack-test-tpm/dstack-util"),
        ):
            source = pathlib.Path(str(binaries[key]["path"]))
            uploaded = run(
                [
                    *ssh,
                    f"mkdir -p /run/dstack-test-tpm && install -m 0755 /dev/stdin {remote}",
                ],
                data=source.read_bytes(),
                timeout=180,
            )
            if uploaded.returncode:
                raise RuntimeError(
                    f"failed to install {key}: {uploaded.stderr.decode(errors='replace')[-500:]}"
                )
        image_dir = store / image
        for name in (
            "measurement.gcp.eventlog.bin",
            "measurement.gcp.cbor",
            "sha256sum.txt",
        ):
            source = image_dir / name
            remote_name = "tpm_eventlog.bin" if name.endswith("eventlog.bin") else name
            uploaded = run(
                [
                    *ssh,
                    f"install -m 0644 /dev/stdin /run/dstack-test-tpm/{remote_name}",
                ],
                data=source.read_bytes(),
                timeout=60,
            )
            if uploaded.returncode:
                raise RuntimeError(
                    f"failed to install GCP TPM replay fixture {name}: "
                    + uploaded.stderr.decode(errors="replace")[-500:]
                )
        completed = run([*ssh, "bash", "-s"], data=REMOTE.encode(), timeout=600)
        log = completed.stdout + completed.stderr
        (artifacts / "mkosi-tpm-lifecycle.log").write_bytes(log)
        if completed.returncode:
            raise RuntimeError(
                f"mkosi TPM lifecycle rc={completed.returncode}: {log.decode(errors='replace')[-1000:]}"
            )
        lines = [
            line
            for line in completed.stdout.decode().splitlines()
            if line.startswith("{")
        ]
        if not lines:
            raise RuntimeError("mkosi TPM lifecycle omitted its JSON evidence")
        matrix = json.loads(lines[-1])
        required = (
            "startup",
            "pcr_read",
            "quote",
            "random",
            "disconnect_reconnect",
            "persistent_restart",
            "ephemeral_restart",
            "retry",
            "adjacent_identity",
        )
        if (
            not all(matrix.get(name) is True for name in required)
            or matrix.get("concurrent_requests") != 16
        ):
            raise RuntimeError(f"incomplete TPM matrix: {matrix}")
        evidence["matrix"] = matrix
        status = "PASS"
        summary = "Complete TPM simulator command and recovery lifecycle passed inside the fixture-declared mkosi VM."
    except Exception as error:  # preserve the first behavioral failure
        summary = f"{type(error).__name__}: {error}"
    finally:
        if ssh:
            cleanup = run(
                [
                    *ssh,
                    "bash",
                    "-lc",
                    "test ! -s /run/dstack-test-tpm/simulator.pid || kill $(cat /run/dstack-test-tpm/simulator.pid) 2>/dev/null || true; test ! -s /run/dstack-test-tpm/runtime/swtpm.pid || kill $(cat /run/dstack-test-tpm/runtime/swtpm.pid) 2>/dev/null || true; fusermount3 -uz /run/dstack-test-tpm/tsm 2>/dev/null || true; rm -rf /run/dstack-test-tpm",
                ],
                timeout=30,
            )
            evidence["cleanup_returncode"] = cleanup.returncode
            if cleanup.returncode and status == "PASS":
                status, summary = (
                    "FAIL",
                    f"guest cleanup failed rc={cleanup.returncode}",
                )
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    evidence_path = artifacts / "tpm-proxy-lifecycle.json"
    write_json(evidence_path, evidence)
    artifact = {
        "path": "artifacts/tpm-proxy-lifecycle.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "mkosi TPM proxy lifecycle matrix",
        "description": "Guest image provenance, TPM operations, faults, concurrency, restart, identity, and cleanup evidence.",
    }
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    observed = (
        summary
        if status == "FAIL"
        else "The mkosi guest passed startup, PCR, quote, random, malformed/oversized bounded rejection, reconnect, concurrent access, dependency failure, deterministic PCR restart, ephemeral random restart, retry, adjacent AK isolation, and cleanup."
    )
    steps = [
        {"id": f"{CASE_ID}-step-{number:02d}", "status": status, "observed": observed}
        for number in range(1, 4)
    ]
    write_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "The simulator runs inside a lease-owned mkosi development VM; simulation does not assert physical TPM isolation.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
