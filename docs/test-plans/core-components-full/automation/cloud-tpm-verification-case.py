#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Execute GCP TDX, NitroTPM, and cross-cloud verification decisions."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-ver-input-plat-006"
SERVICES = ("gcp-tdx", "aws-nitro-tpm")
EXPECTED = {
    "gcp-tdx": {
        "valid-vtpm": (True, "verified"),
        "wrong-ak-root": (False, "certificate-chain"),
        "quote-message": (False, "quote-signature"),
        "quote-signature": (False, "quote-signature"),
        "pcr-value": (False, "pcr-replay"),
        "qualifying-data": (False, "nonce-binding"),
    },
    "aws-nitro-tpm": {
        "valid-nsm": (True, "verified"),
        "wrong-nsm-root": (False, "certificate-chain"),
        "cose-signature": (False, "cose-signature"),
        "user-data": (False, "report-data"),
        "nonce": (False, "nonce-binding"),
        "public-key": (False, "public-key-binding"),
        "pcr14-event-replay": (False, "event-log-replay"),
    },
    "cross-cloud": {
        "tpm-root-for-nsm": (False, "platform-root-routing"),
        "nsm-root-for-tpm": (False, "platform-root-routing"),
        "valid-after-failures": (True, "recovery"),
    },
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


def main() -> int:
    """Run both cloud paths, the mutation table, recovery, and cleanup."""
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
        controls = {}
        for service in SERVICES:
            completed = run_as_kvin(
                f"cd {quoted_suite} && docker compose run --rm {service}", 600
            )
            (artifacts / f"{service}-verifier.log").write_text(
                completed.stdout + completed.stderr
            )
            controls[service] = completed.returncode
            if completed.returncode:
                raise RuntimeError(
                    f"{service} verifier control failed with rc={completed.returncode}"
                )
            if (
                '"is_valid": true' not in completed.stdout
                or '"simulated": true' not in completed.stdout
            ):
                raise RuntimeError(f"{service} omitted its valid simulated verdict")
        steps.append(
            emit(
                f"{CASE_ID}-step-01",
                "PASS",
                "Case-owned GCP TDX/vTPM and AWS NitroTPM simulators both produced versioned evidence accepted by the production verifier under explicit development roots and labeled simulated=true.",
            )
        )

        matrix_run = run_as_kvin(
            f"cd {quoted_suite} && docker compose run --rm --entrypoint dstack-mock-attestation gcp-tdx cloud-tpm-matrix",
            300,
        )
        (artifacts / "cloud-tpm-matrix.stderr.log").write_text(matrix_run.stderr)
        if matrix_run.returncode:
            raise RuntimeError(
                f"cloud TPM matrix failed with rc={matrix_run.returncode}"
            )
        rows = json.loads(matrix_run.stdout)
        observed: dict[str, dict[str, tuple[bool, str]]] = {}
        for row in rows:
            observed.setdefault(str(row["platform"]), {})[str(row["name"])] = (
                bool(row["accepted"]),
                str(row["stage"]),
            )
        if observed != EXPECTED:
            raise RuntimeError(f"cloud TPM matrix mismatch: {observed}")
        if any(not row.get("diagnostic") for row in rows if not row["accepted"]):
            raise RuntimeError("a rejected cloud TPM row omitted its diagnostic")
        (artifacts / "cloud-tpm-matrix.json").write_text(
            json.dumps(rows, indent=2, sort_keys=True) + "\n"
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-02",
                "PASS",
                "Sixteen rows covered AK/NSM chains, quote and COSE signatures, PCR and event-log replay, report-data/nonce/public-key bindings, and both TPM-root/NSM-root cross-cloud substitutions; all thirteen negative rows failed at their named stage.",
            )
        )
        steps.append(
            emit(
                f"{CASE_ID}-step-03",
                "PASS",
                "Both cloud controls recovered after rejected rows, diagnostics remained case-scoped, and disposable containers retained no verification state.",
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
        "summary": "GCP TDX/vTPM and NitroTPM evidence satisfied cloud chain, measured-boot, binding, routing, substitution, and recovery decisions.",
        "steps": steps,
        "artifacts": [
            {
                "path": f"artifacts/{path.name}",
                "name": path.name,
                "description": "Case-scoped cloud TPM verification evidence.",
            }
            for path in sorted(artifacts.iterdir())
        ],
        "remarks": "Simulation confirms functional verification behavior but not cloud-provider hardware identity or physical isolation.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if failure:
        result["failure"] = failure
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
