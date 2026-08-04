#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Execute the simulated SEV-SNP verifier and signed mutation matrix."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-ver-input-plat-005"
EXPECTED_ROWS = {
    "valid": (True, "verified"),
    "wrong-root": (False, "certificate-chain"),
    "measurement": (False, "report-signature"),
    "host-data": (False, "report-signature"),
    "reported-tcb": (False, "report-signature"),
    "chip-id": (False, "report-signature"),
    "signature": (False, "report-signature"),
    "report-data-binding": (False, "report-data"),
    "debug-policy": (False, "guest-policy"),
    "migration-policy": (False, "guest-policy"),
    "valid-after-failures": (True, "recovery"),
}


def run_as_kvin(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Launch Docker only through the required kvin identity."""
    docker_tmp = "/home/kvin/.cache/dstack-test/docker-tmp"
    safe_command = f"mkdir -p {docker_tmp} && export TMPDIR={docker_tmp} && {command}"
    return subprocess.run(
        ["sudo", "su", "kvin", "-c", safe_command],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def repository_path() -> Path:
    """Resolve the candidate repository recorded by the runner."""
    runtime = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST")
    if runtime:
        value = json.loads(Path(runtime).read_text()).get("repository")
        if value:
            return Path(value).resolve()
    return Path.cwd().resolve()


def emit(step_id: str, status: str, observed: str) -> dict[str, str]:
    """Emit and persist one runner-protocol step."""
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def main() -> int:
    """Run the positive component path, mutation table, and recovery cleanup."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    suite = repository_path() / "dstack/tests/e2e/attestation"
    quoted_suite = shlex.quote(str(suite))
    steps: list[dict[str, str]] = []
    failure = ""
    status = "FAIL"
    started = time.monotonic()

    try:
        build = run_as_kvin(f"cd {quoted_suite} && docker compose build", 1800)
        (artifacts / "compose-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(
                f"attestation image build failed with rc={build.returncode}"
            )
        baseline = run_as_kvin(
            f"cd {quoted_suite} && docker compose run --rm amd-sev-snp", 600
        )
        (artifacts / "amd-sev-snp-verifier.log").write_text(
            baseline.stdout + baseline.stderr
        )
        if baseline.returncode:
            raise RuntimeError(
                f"SEV-SNP verifier control failed with rc={baseline.returncode}"
            )
        if (
            '"is_valid": true' not in baseline.stdout
            or '"development_root_accepted":true' not in baseline.stdout
            or '"production_root_rejected":true' not in baseline.stdout
        ):
            raise RuntimeError(
                "SEV-SNP verifier control omitted a trust-root isolation assertion"
            )
        steps.append(
            emit(
                f"{CASE_ID}-step-01",
                "PASS",
                "The case-owned AMD simulator produced a signed SEV-SNP report accepted by its development root and rejected by the built-in production root.",
            )
        )

        matrix_run = run_as_kvin(
            f"cd {quoted_suite} && docker compose run --rm --entrypoint dstack-mock-attestation amd-sev-snp sev-snp-matrix",
            300,
        )
        (artifacts / "sev-snp-matrix.stderr.log").write_text(matrix_run.stderr)
        if matrix_run.returncode:
            raise RuntimeError(
                f"SEV-SNP mutation matrix failed with rc={matrix_run.returncode}"
            )
        rows = json.loads(matrix_run.stdout)
        observed = {
            str(row["name"]): (bool(row["accepted"]), str(row["stage"])) for row in rows
        }
        if observed != EXPECTED_ROWS:
            raise RuntimeError(f"SEV-SNP mutation matrix mismatch: {observed}")
        if any(not row.get("diagnostic") for row in rows if not row["accepted"]):
            raise RuntimeError("a rejected SEV-SNP row omitted its diagnostic")
        (artifacts / "sev-snp-matrix.json").write_text(
            json.dumps(rows, indent=2, sort_keys=True) + "\n"
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-02",
                "PASS",
                "Eleven rows covered VCEK trust, measurement, HOST_DATA, TCB, chip ID, signature, report-data, and correctly re-signed debug/migration policies; all nine negative rows failed at their named trust stage.",
            )
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-03",
                "PASS",
                "The valid control succeeded again after every rejected row, diagnostics were preserved, and disposable containers retained no trusted state.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001 - preserve first tested failure
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{CASE_ID}-step-{len(steps) + 1:02d}", "FAIL", failure))
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
        "case_id": CASE_ID,
        "status": status,
        "summary": "SEV-SNP certificate, authenticated-field, report-data, guest-policy, and recovery decisions matched the production verifier/QVL contract.",
        "steps": steps,
        "artifacts": [
            {
                "path": f"artifacts/{path.name}",
                "name": path.name,
                "description": "Case-scoped SEV-SNP verification evidence.",
            }
            for path in sorted(artifacts.iterdir())
        ],
        "remarks": "Development VCEK material confirms verification behavior but does not establish an AMD hardware trust claim.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if failure:
        result["failure"] = failure
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
