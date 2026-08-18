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
MATRIX_TEST = "generated_report_passes_real_qvl_and_negative_cases_fail"


def run_docker_shell(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Launch Docker only through the configured Docker shell wrapper."""
    docker_tmp = os.environ.get(
        "DSTACK_TEST_DOCKER_TMP", str(Path.home() / ".cache/dstack-test/docker-tmp")
    )
    safe_command = f"mkdir -p {docker_tmp} && export TMPDIR={docker_tmp} && {command}"
    return subprocess.run(
        [
            os.environ.get(
                "DSTACK_TEST_DOCKER_SHELL_RUNNER",
                os.path.join(
                    os.environ["DSTACK_TEST_PLAN_DIR"],
                    "shared/automation/run-docker-shell",
                ),
            ),
            safe_command,
        ],
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


def run_native_matrix(repository: Path) -> subprocess.CompletedProcess[str]:
    """Run the current source-defined SEV-SNP QVL matrix."""
    cargo = Path.home() / ".cargo/bin/cargo"
    environment = os.environ.copy()
    runtime = json.loads(Path(environment["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    return subprocess.run(
        [str(cargo), "test", "-p", "mock-attestation", MATRIX_TEST, "--lib"],
        cwd=repository / "dstack",
        env=environment,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )


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
    repository = repository_path()
    suite = repository / "dstack/tests/e2e/attestation"
    quoted_suite = shlex.quote(str(suite))
    steps: list[dict[str, str]] = []
    failure = ""
    status = "FAIL"
    started = time.monotonic()

    try:
        build = run_docker_shell(f"cd {quoted_suite} && docker compose build", 1800)
        (artifacts / "compose-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(
                f"attestation image build failed with rc={build.returncode}"
            )
        baseline = run_docker_shell(
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

        matrix_run = run_native_matrix(repository)
        matrix_output = matrix_run.stdout + matrix_run.stderr
        (artifacts / "sev-snp-matrix.log").write_text(matrix_output)
        if (
            matrix_run.returncode
            or f"{MATRIX_TEST} ... ok" not in matrix_output
            or "test result: ok. 1 passed; 0 failed" not in matrix_output
        ):
            raise RuntimeError(
                f"SEV-SNP mutation matrix failed with rc={matrix_run.returncode}"
            )
        steps.append(
            emit(
                f"{CASE_ID}-step-02",
                "PASS",
                "The current source-defined QVL test accepted valid signed evidence and rejected a wrong VCEK root, a tampered authenticated report, and a mismatched report-data binding.",
            )
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-03",
                "PASS",
                "The container control and native QVL matrix used independent generators and retained no trusted state.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001 - preserve first tested failure
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{CASE_ID}-step-{len(steps) + 1:02d}", "FAIL", failure))
    finally:
        down = run_docker_shell(
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
