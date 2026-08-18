#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify physical TDX and simulated cross-platform versioned attestation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CASE_IDS = {"tc-gos-attestatio-002", "tc-int-failure-se-008"}
VM_ID = re.compile(r"Created VM with ID:\s*([0-9a-f-]{36})", re.IGNORECASE)
SIMULATOR_SERVICES = (
    "dstack-tdx-lite",
    "gcp-tdx",
    "amd-sev-snp",
    "aws-nitro-enclave",
    "aws-nitro-tpm",
)

FULL_TDX_IMAGE_HASH = "14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67"


def run_as_kvin(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Launch Docker through kvin with temporary files on the home volume."""
    docker_tmp = "/home/kvin/.cache/dstack-test/docker-tmp"
    safe_command = f"mkdir -p {docker_tmp} && export TMPDIR={docker_tmp} && {command}"
    return subprocess.run(
        ["sudo", "su", "kvin", "-c", safe_command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def emit(step_id: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step and return its persistent form."""
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def post(
    url: str, body: dict[str, object], *, accepted: bool
) -> tuple[int, dict[str, object]]:
    """POST bounded JSON and require acceptance or structured rejection."""
    request = urllib.request.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            status = int(response.status)
            payload = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        status = int(error.code)
        raw = error.read()
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {"diagnostic_sha256": hashlib.sha256(raw).hexdigest()}
    if accepted and status != 200:
        raise RuntimeError(f"valid Attest request returned HTTP {status}: {payload}")
    if not accepted and status < 400:
        raise RuntimeError(f"invalid Attest request returned HTTP {status}")
    if not isinstance(payload, dict):
        raise RuntimeError("Attest returned non-object JSON")
    return status, payload


def capture_vm_command(
    argv: list[str], artifacts: Path, name: str, timeout: int = 30
) -> subprocess.CompletedProcess[str]:
    """Capture one bounded VMM diagnostic without masking the tested failure."""
    completed = subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )
    (artifacts / name).write_text(completed.stdout + completed.stderr)
    return completed


def wait_guest(
    cli: list[str], vm_id: str, port: int, artifacts: Path, timeout: int = 240
) -> None:
    """Poll the guest endpoint and persist VM state while it is still owned."""
    deadline = time.monotonic() + timeout
    observations: list[dict[str, object]] = []
    while time.monotonic() < deadline:
        info = subprocess.run(
            [*cli, "info", "--json", vm_id],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        observations.append(
            {
                "elapsed_seconds": round(
                    timeout - max(0, deadline - time.monotonic()), 3
                ),
                "returncode": info.returncode,
                "stdout": info.stdout,
                "stderr": info.stderr,
            }
        )
        (artifacts / "hardware-info-poll.json").write_text(
            json.dumps(observations, indent=2) + "\n"
        )
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3):
                return
        except urllib.error.HTTPError:
            return
        except (OSError, urllib.error.URLError):
            time.sleep(5)
    capture_vm_command([*cli, "info", "--json", vm_id], artifacts, "hardware-info.json")
    capture_vm_command(
        [*cli, "logs", "-n", "1000", vm_id],
        artifacts,
        "hardware-vm.log",
        60,
    )
    capture_vm_command([*cli, "lsvm"], artifacts, "hardware-lsvm.log")
    raise RuntimeError(
        f"guest port {port} did not become ready; VMM info and logs were captured"
    )


def append_vm(registry: Path, vm_id: str) -> None:
    """Register the VM immediately so provider cleanup owns it after failures."""
    value = json.loads(registry.read_text())
    if not isinstance(value, list):
        raise RuntimeError("fixture VM registry is not a list")
    value.append({"id": vm_id})
    registry.write_text(json.dumps(value, indent=2) + "\n")


def verify_legacy_tdx(
    runtime: dict[str, object], repository: Path, artifacts: Path
) -> dict[str, object]:
    """Verify the production legacy-TDX quote against its prepared full image."""
    environment = runtime.get("environment") or {}
    if not isinstance(environment, dict):
        raise RuntimeError("runtime environment is not an object")
    fixture = Path(str(environment["DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR"]))
    acpi_tables = Path(str(environment["DSTACK_TEST_ACPI_TABLES_BINARY"]))
    if (
        hashlib.sha256((fixture / "sha256sum.txt").read_bytes()).hexdigest()
        != FULL_TDX_IMAGE_HASH
    ):
        raise RuntimeError("prepared full-TDX image does not match its quote")
    workspace = artifacts.parent / "debug-workspace" / "legacy-tdx"
    cache = workspace / "cache"
    shutil.copytree(fixture, cache / "images" / FULL_TDX_IMAGE_HASH)
    request = workspace / "quote-report.json"
    shutil.copy2(
        repository / "dstack/verifier/shared/fixtures/quote-report.json", request
    )
    config = workspace / "verifier.toml"
    config.write_text(
        f'''address = "127.0.0.1"
port = 8080
image_cache_dir = "{cache}"
image_download_url = "http://127.0.0.1:1/{{OS_IMAGE_HASH}}.tar.gz"
image_download_timeout_secs = 1
'''
    )
    binary = Path(
        str((runtime.get("prepared_binaries") or {})["dstack_verifier"]["path"])
    )
    process_environment = os.environ.copy()
    process_environment["PATH"] = f"{acpi_tables.parent}:{process_environment['PATH']}"
    completed = subprocess.run(
        [str(binary), "--config", str(config), "--verify", str(request)],
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
        env=process_environment,
    )
    (artifacts / "dstack-tdx-legacy.log").write_text(
        completed.stdout + completed.stderr
    )
    response = json.loads(Path(f"{request}.verification.json").read_text())
    details = response.get("details") or {}
    passed = (
        completed.returncode == 0
        and response.get("is_valid") is True
        and all(
            details.get(field) is True
            for field in (
                "quote_verified",
                "event_log_verified",
                "os_image_hash_verified",
                "acpi_tables_verified",
            )
        )
    )
    row = {
        "service": "dstack-tdx-legacy",
        "returncode": completed.returncode,
        "verified": passed,
        "fixture": "production quote with hash-bound full image",
    }
    if not passed:
        raise RuntimeError(f"legacy TDX fixture failed: {row}")
    return row


def main() -> int:
    """Run hardware TDX, a production legacy fixture, and five simulations."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in CASE_IDS:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    values = manifest.get("values") or {}
    matrix = values.get("attestation_matrix") or []
    hardware = next(
        (
            row
            for row in matrix
            if row.get("name") == "tdx" and row.get("confirmation") == "hardware"
        ),
        None,
    )
    live_vmm = values.get("live_vmm") or {}
    repository = Path(str(runtime["repository"]))
    suite = repository / "dstack/tests/e2e/attestation"
    quoted_suite = shlex.quote(str(suite))
    steps: list[dict[str, str]] = []
    failure = ""
    status = "FAIL"
    started = time.monotonic()

    try:
        if not isinstance(hardware, dict):
            raise RuntimeError("fixture omitted its physical TDX row")
        deploy = subprocess.run(
            [str(item) for item in hardware["deploy_argv"]],
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
        )
        (artifacts / "hardware-deploy.log").write_text(deploy.stdout + deploy.stderr)
        if deploy.returncode:
            raise RuntimeError(
                f"physical TDX deploy failed with rc={deploy.returncode}"
            )
        match = VM_ID.search(deploy.stdout + deploy.stderr)
        if not match:
            raise RuntimeError("physical TDX deploy output omitted its VM ID")
        vm_id = match.group(1)
        append_vm(Path(str(live_vmm["created_vms_registry"])), vm_id)
        start_vm = subprocess.run(
            [*[str(item) for item in live_vmm["cli_argv"]], "start", vm_id],
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        (artifacts / "hardware-start.log").write_text(start_vm.stdout + start_vm.stderr)
        if start_vm.returncode:
            raise RuntimeError(
                f"physical TDX start failed with rc={start_vm.returncode}"
            )
        port = int(hardware["host_port"])
        wait_guest(
            [str(item) for item in live_vmm["cli_argv"]],
            vm_id,
            port,
            artifacts,
        )
        attest_url = f"http://127.0.0.1:{port}/Attest"
        report_data = hashlib.sha512(os.environ["DSTACK_TEST_RUN_ID"].encode()).digest()
        _, first = post(attest_url, {"report_data": report_data.hex()}, accepted=True)
        raw = bytes.fromhex(str(first["attestation"]))
        if report_data not in raw:
            raise RuntimeError(
                "physical TDX evidence omitted exact 64-byte report data"
            )
        decoder = Path(
            str((runtime.get("prepared_binaries") or {})["dstack_util"]["path"])
        )
        with tempfile.TemporaryDirectory(dir=artifacts) as temporary:
            binary = Path(temporary) / "attestation.bin"
            projection_path = Path(temporary) / "attestation.json"
            binary.write_bytes(raw)
            decoded = subprocess.run(
                [
                    str(decoder),
                    "attest-json",
                    "--input",
                    str(binary),
                    "--output",
                    str(projection_path),
                ],
                text=True,
                capture_output=True,
                timeout=120,
                check=False,
            )
            if decoded.returncode:
                raise RuntimeError(
                    f"attest-json failed with rc={decoded.returncode}: {decoded.stderr[-500:]}"
                )
            projection = json.loads(projection_path.read_text())
        if projection.get("mode") != "dstack-tdx":
            raise RuntimeError(f"physical TDX decoded as {projection.get('mode')}")
        config = json.loads(str(projection["config"]))
        if config.get("image") != str(live_vmm["candidate_image"]):
            raise RuntimeError("physical TDX config did not name the candidate image")
        if len(str(config.get("os_image_hash", ""))) != 64:
            raise RuntimeError("physical TDX config omitted its OS image hash")
        steps.append(
            emit(
                f"{case_id}-step-01",
                "PASS",
                "The fixture-declared physical candidate TDX guest started, returned versioned evidence bound to a distinct 64-byte challenge, and decoded as dstack-tdx with the candidate image and OS hash.",
            )
        )

        changed = bytes(byte ^ 0x5A for byte in report_data)
        _, second = post(attest_url, {"report_data": changed.hex()}, accepted=True)
        changed_raw = bytes.fromhex(str(second["attestation"]))
        if changed not in changed_raw or changed_raw == raw:
            raise RuntimeError(
                "changed report data did not change its authenticated evidence"
            )
        short = b"short-boundary"
        _, short_result = post(attest_url, {"report_data": short.hex()}, accepted=True)
        if short + bytes(64 - len(short)) not in bytes.fromhex(
            str(short_result["attestation"])
        ):
            raise RuntimeError("short report data was not right-padded in evidence")
        malformed_status, _ = post(
            attest_url, {"report_data": "not-hex"}, accepted=False
        )
        oversized_status, _ = post(
            attest_url, {"report_data": "aa" * 65}, accepted=False
        )
        _, recovered = post(
            attest_url, {"report_data": report_data.hex()}, accepted=True
        )
        recovered_raw = bytes.fromhex(str(recovered["attestation"]))
        if report_data not in recovered_raw:
            raise RuntimeError(
                "physical TDX evidence did not recover challenge binding"
            )
        (artifacts / "hardware-tdx.json").write_text(
            json.dumps(
                {
                    "vm_id": vm_id,
                    "mode": projection["mode"],
                    "image": config.get("image"),
                    "os_image_hash": config.get("os_image_hash"),
                    "attestation_sha256": hashlib.sha256(raw).hexdigest(),
                    "changed_attestation_sha256": hashlib.sha256(
                        changed_raw
                    ).hexdigest(),
                    "short_input_bytes": len(short),
                    "malformed_http": malformed_status,
                    "oversized_http": oversized_status,
                    "recovered_after_rejections": True,
                },
                indent=2,
            )
            + "\n"
        )

        build = run_as_kvin(f"cd {quoted_suite} && docker compose build", 1800)
        (artifacts / "compose-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(
                f"attestation image build failed with rc={build.returncode}"
            )
        simulated = [verify_legacy_tdx(runtime, repository, artifacts)]
        for service in SIMULATOR_SERVICES:
            completed = run_as_kvin(
                f"cd {quoted_suite} && docker compose run --rm {service}", 600
            )
            log = completed.stdout + completed.stderr
            (artifacts / f"{service}.log").write_text(log)
            row = {
                "service": service,
                "returncode": completed.returncode,
                "verified": '"is_valid": true' in completed.stdout,
                "development_root_accepted": '"development_root_accepted":true' in log,
                "production_root_rejected": '"production_root_rejected":true' in log,
            }
            simulated.append(row)
            if (
                completed.returncode
                or not row["verified"]
                or not row["development_root_accepted"]
                or not row["production_root_rejected"]
            ):
                raise RuntimeError(f"simulated platform row failed: {row}")
        (artifacts / "simulated-platforms.json").write_text(
            json.dumps(simulated, indent=2, sort_keys=True) + "\n"
        )
        steps.append(
            emit(
                f"{case_id}-step-02",
                "PASS",
                "The production legacy-TDX quote passed full-image and ACPI verification; TDX lite, GCP TDX, SEV-SNP, Nitro Enclave, and NitroTPM simulations were accepted by their exact development roots and rejected by built-in production roots.",
            )
        )
        steps.append(
            emit(
                f"{case_id}-step-03",
                "PASS",
                "Changed and short valid challenges succeeded, malformed hex and 65-byte input were rejected, the original physical challenge recovered successfully, and every VM/container was registered for bounded cleanup.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001 - preserve first tested failure
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{case_id}-step-{len(steps) + 1:02d}", "FAIL", failure))
    finally:
        down = run_as_kvin(
            f"cd {quoted_suite} && docker compose down --remove-orphans", 180
        )
        (artifacts / "compose-down.log").write_text(down.stdout + down.stderr)
        if down.returncode and status == "PASS":
            status = "FAIL"
            failure = f"compose cleanup failed with rc={down.returncode}"

    result: dict[str, object] = {
        "schema_version": "1.0",
        "case_id": case_id,
        "status": status,
        "summary": "Physical TDX, production legacy-TDX, and five simulated platform rows satisfied versioned decoding, challenge binding, boundary rejection, recovery, and cleanup contracts.",
        "steps": steps,
        "artifacts": [
            {
                "path": f"artifacts/{path.name}",
                "name": path.name,
                "description": "Case-scoped cross-platform attestation evidence.",
            }
            for path in sorted(artifacts.iterdir())
        ],
        "remarks": "The live TDX row confirms physical hardware evidence, and the legacy-TDX row verifies a production quote against its hash-bound full image. The five simulator rows confirm functional encoding and verification only, not vendor hardware signatures or physical isolation.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if failure:
        result["failure"] = failure
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
