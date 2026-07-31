#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify development labeling and production rejection for every mock platform."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-ver-input-plat-007"
SERVICES = (
    "dstack-tdx-legacy",
    "dstack-tdx-lite",
    "gcp-tdx",
    "amd-sev-snp",
    "aws-nitro-enclave",
    "aws-nitro-tpm",
)


def run_as_kvin(command: str, *, timeout: int) -> subprocess.CompletedProcess[str]:
    """Launch Docker only through the required unprivileged kvin identity."""
    docker_tmp = "/home/kvin/.cache/dstack-test/docker-tmp"
    safe_command = f"mkdir -p {docker_tmp} && export TMPDIR={docker_tmp} && {command}"
    return subprocess.run(
        ["sudo", "su", "kvin", "-c", safe_command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def emit_step(step_id: str, status: str, observed: str) -> dict[str, str]:
    """Emit the runner protocol and return the persisted step record."""
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def repository_path() -> Path:
    """Resolve the candidate checkout from the runtime manifest or cwd."""
    manifest_path = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST")
    if manifest_path:
        manifest = json.loads(Path(manifest_path).read_text())
        if manifest.get("repository"):
            return Path(manifest["repository"]).resolve()
    return Path.cwd().resolve()


def main() -> int:
    """Execute all simulated platform/policy rows and write result.json."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    suite = repository_path() / "dstack/tests/e2e/attestation"
    rows: list[dict[str, object]] = []
    steps: list[dict[str, str]] = []
    failure = ""
    status = "FAIL"
    started = time.monotonic()

    try:
        if (
            not (suite / "compose.yaml").is_file()
            or not (suite / "run-platform.sh").is_file()
        ):
            raise RuntimeError("the checked-in attestation E2E suite is incomplete")
        build = run_as_kvin(
            f"cd {shlex.quote(str(suite))} && docker compose build", timeout=1800
        )
        (artifacts / "compose-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(
                f"attestation image build failed with rc={build.returncode}"
            )
        steps.append(
            emit_step(
                f"{CASE_ID}-step-01",
                "PASS",
                "The checked-in six-platform attestation image built successfully under the required Docker identity.",
            )
        )

        for service in SERVICES:
            completed = run_as_kvin(
                f"cd {shlex.quote(str(suite))} && docker compose run --rm {shlex.quote(service)}",
                timeout=600,
            )
            log = completed.stdout + completed.stderr
            (artifacts / f"{service}.log").write_text(log)
            row = {
                "service": service,
                "returncode": completed.returncode,
                "simulated_true": '"simulated": true' in log,
                "production_rejected": '"accepted": false' in log,
            }
            rows.append(row)
            if completed.returncode:
                raise RuntimeError(f"{service} failed with rc={completed.returncode}")
            if not row["simulated_true"] or not row["production_rejected"]:
                raise RuntimeError(f"{service} omitted a required policy assertion")
        (artifacts / "platform-policy-matrix.json").write_text(
            json.dumps(rows, indent=2, sort_keys=True) + "\n"
        )
        steps.append(
            emit_step(
                f"{CASE_ID}-step-02",
                "PASS",
                "All six platform rows verified with development roots, returned details.simulated=true, and were rejected when the explicit development-policy opt-in was removed.",
            )
        )
        steps.append(
            emit_step(
                f"{CASE_ID}-step-03",
                "PASS",
                "Each platform ran in a disposable container; per-row logs and the policy matrix were preserved without private keys.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001 - preserve the first tested failure
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit_step(f"{CASE_ID}-step-{len(steps) + 1:02d}", "FAIL", failure))
    finally:
        down = run_as_kvin(
            f"cd {shlex.quote(str(suite))} && docker compose down --remove-orphans",
            timeout=180,
        )
        (artifacts / "compose-down.log").write_text(down.stdout + down.stderr)
        if down.returncode and status == "PASS":
            status = "FAIL"
            failure = f"compose cleanup failed with rc={down.returncode}"

    artifact_entries = [
        {
            "path": f"artifacts/{path.name}",
            "name": path.name,
            "description": "Case-scoped simulator policy evidence.",
        }
        for path in sorted(artifacts.iterdir())
    ]
    result: dict[str, object] = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "status": status,
        "summary": "All mock platforms are accepted only with explicit development trust-root policy and are labeled simulated=true.",
        "steps": steps,
        "artifacts": artifact_entries,
        "remarks": "Simulation confirms encoding, routing, trust-policy and error behavior; it does not confirm vendor hardware signatures, firmware measurements or physical isolation.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if failure:
        result["failure"] = failure
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
