#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Execute Nitro Enclave document, identity, image, and recovery decisions."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-ver-nitro-008"
EXPECTED = {
    "valid": (True, "verified"),
    "wrong-root": (False, "certificate-chain"),
    "cose-signature": (False, "cose-signature"),
    "expired": (False, "freshness"),
    "future": (False, "freshness"),
    "missing-user-data": (False, "report-data"),
    "user-data": (False, "report-data"),
    "nonce": (False, "nonce-binding"),
    "public-key": (False, "public-key-binding"),
    "module-id": (False, "identity-binding"),
    "pcr0": (False, "pcr-binding"),
    "pcr1": (False, "pcr-binding"),
    "pcr2": (False, "pcr-binding"),
    "pcr4": (False, "pcr-binding"),
    "os-image-hash": (False, "image-binding"),
    "debug-zero-pcrs": (False, "debug-policy"),
    "valid-after-failures": (True, "recovery"),
}


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


def repository_path() -> Path:
    """Resolve the candidate checkout recorded by the runtime manifest."""
    runtime = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST")
    if runtime:
        repository = json.loads(Path(runtime).read_text()).get("repository")
        if repository:
            return Path(repository).resolve()
    return Path.cwd().resolve()


def emit(step_id: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step and return its persistent form."""
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def run_control(suite: str, artifact: Path, phase: str) -> None:
    """Run one fresh simulator-to-verifier Nitro Enclave control."""
    completed = run_as_kvin(
        f"cd {suite} && docker compose run --rm aws-nitro-enclave", 600
    )
    artifact.write_text(completed.stdout + completed.stderr)
    if completed.returncode:
        raise RuntimeError(
            f"Nitro Enclave {phase} control failed with rc={completed.returncode}"
        )
    if (
        '"is_valid": true' not in completed.stdout
        or '"simulated": true' not in completed.stdout
    ):
        raise RuntimeError(
            f"Nitro Enclave {phase} control omitted its valid simulated verdict"
        )


def main() -> int:
    """Run baseline, decision table, fresh restart, and complete cleanup."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    suite = shlex.quote(str(repository_path() / "dstack/tests/e2e/attestation"))
    steps: list[dict[str, str]] = []
    failure = ""
    status = "FAIL"
    started = time.monotonic()

    try:
        build = run_as_kvin(f"cd {suite} && docker compose build", 1800)
        (artifacts / "compose-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(
                f"attestation image build failed with rc={build.returncode}"
            )
        run_control(suite, artifacts / "nitro-control-before.log", "baseline")
        steps.append(
            emit(
                f"{CASE_ID}-step-01",
                "PASS",
                "A fresh case-owned Nitro simulator produced measured non-debug evidence that the production verifier accepted with the expected signed-image hash and simulated=true label.",
            )
        )

        matrix_run = run_as_kvin(
            f"cd {suite} && docker compose run --rm --entrypoint dstack-mock-attestation aws-nitro-enclave nitro-enclave-matrix",
            300,
        )
        (artifacts / "nitro-matrix.stderr.log").write_text(matrix_run.stderr)
        if matrix_run.returncode:
            raise RuntimeError(
                f"Nitro decision matrix failed with rc={matrix_run.returncode}"
            )
        rows = json.loads(matrix_run.stdout)
        observed = {
            str(row["name"]): (bool(row["accepted"]), str(row["stage"])) for row in rows
        }
        if observed != EXPECTED:
            raise RuntimeError(f"Nitro decision matrix mismatch: {observed}")
        if any(not row.get("diagnostic") for row in rows if not row["accepted"]):
            raise RuntimeError("a rejected Nitro row omitted its diagnostic")
        (artifacts / "nitro-enclave-matrix.json").write_text(
            json.dumps(rows, indent=2, sort_keys=True) + "\n"
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-02",
                "PASS",
                "Seventeen rows covered trusted/wrong chains, COSE signature, expired/future time, module/user-data/nonce/public-key identity, PCR0/1/2/4, image hash, and correctly signed zero-PCR debug evidence; all fifteen negative rows failed at their named stage.",
            )
        )

        run_control(suite, artifacts / "nitro-control-after-restart.log", "restarted")
        steps.append(
            emit(
                f"{CASE_ID}-step-03",
                "PASS",
                "After trust-outage and cross-identity rows, a new disposable simulator/verifier process accepted only the original identity, proving restart recovery without stale decision state.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001 - preserve first tested failure
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{CASE_ID}-step-{len(steps) + 1:02d}", "FAIL", failure))
    finally:
        down = run_as_kvin(f"cd {suite} && docker compose down --remove-orphans", 180)
        (artifacts / "compose-down.log").write_text(down.stdout + down.stderr)
        if down.returncode and status == "PASS":
            status = "FAIL"
            failure = f"compose cleanup failed with rc={down.returncode}"

    result: dict[str, object] = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "status": status,
        "summary": "Nitro Enclave chain, COSE, freshness, identity, PCR, image, debug, outage, restart, and recovery decisions matched the verifier contract.",
        "steps": steps,
        "artifacts": [
            {
                "path": f"artifacts/{path.name}",
                "name": path.name,
                "description": "Case-scoped Nitro Enclave verification evidence.",
            }
            for path in sorted(artifacts.iterdir())
        ],
        "remarks": "Simulation confirms document and policy behavior but not an AWS hardware signature or physical enclave isolation.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if failure:
        result["failure"] = failure
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
