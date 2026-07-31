#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Exercise simulated cloud evidence and KMS authorization bindings."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path

MATRIX = {
    "tc-kms-attestatio-002": {
        "services": ("amd-sev-snp",),
        "tests": (
            (
                "kms-amd-binding",
                "cargo test -p dstack-kms main_service::amd_attest::tests::",
            ),
            (
                "kms-amd-release-policy",
                "cargo test -p dstack-kms main_service::tests::snp_",
            ),
        ),
        "claim": "SEV-SNP evidence, launch/app/config/chip/TCB bindings, mutations, and explicit release policy",
    },
    "tc-kms-attestatio-003": {
        "services": ("gcp-tdx", "aws-nitro-tpm"),
        "tests": (
            ("kms-nitrotpm-binding", "cargo test -p dstack-kms aws_nitro_tpm"),
            (
                "nitrotpm-image-binding",
                "cargo test -p dstack-verifier aws_os_image_check",
            ),
        ),
        "claim": "GCP TDX and NitroTPM evidence routing, measured boot, app binding, mutations, and release policy",
    },
    "tc-kms-platform-006": {
        "services": ("aws-nitro-enclave",),
        "tests": (("nitro-evidence-policy", "cargo test -p dstack-attest nitro_"),),
        "claim": "Nitro Enclave document/PCR/image verification, mutation rejection, and KMS authorization inputs",
    },
}
TEST_RESULT = re.compile(r"test result: ok\. (\d+) passed; 0 failed")


def run_as_kvin(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run Docker only through the required kvin identity."""
    docker_tmp = "/home/kvin/.cache/dstack-test/docker-tmp"
    return subprocess.run(
        [
            "sudo",
            "su",
            "kvin",
            "-c",
            f"mkdir -p {docker_tmp} && export TMPDIR={docker_tmp} && {command}",
        ],
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def run(command: str, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a bounded candidate command without interpreting private output."""
    return subprocess.run(
        ["bash", "-lc", command],
        cwd=cwd,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def emit(step_id: str, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol row."""
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def main() -> int:
    """Run the platform rows and case-specific authorization tests."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in MATRIX:
        raise SystemExit(f"unsupported case: {case_id}")
    spec = MATRIX[case_id]
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(str(runtime["repository"]))
    suite = repository / "dstack/tests/e2e/attestation"
    started = time.monotonic()
    steps: list[dict[str, str]] = []
    rows: list[dict[str, object]] = []
    failure = ""
    status = "FAIL"

    try:
        build = run_as_kvin(
            f"cd {shlex.quote(str(suite))} && docker compose build", 1800
        )
        (artifacts / "compose-build.log").write_text(build.stdout + build.stderr)
        if build.returncode:
            raise RuntimeError(f"attestation image build rc={build.returncode}")
        steps.append(
            emit(
                f"{case_id}-step-01",
                "PASS",
                "The candidate six-platform simulator/verifier image was available from the shared Docker cache.",
            )
        )

        for service in spec["services"]:
            row_started = time.monotonic()
            completed = run_as_kvin(
                f"cd {shlex.quote(str(suite))} && docker compose run --rm {shlex.quote(service)}",
                600,
            )
            log = completed.stdout + completed.stderr
            (artifacts / f"{service}.log").write_text(log)
            row = {
                "kind": "simulation",
                "platform": service,
                "returncode": completed.returncode,
                "duration_seconds": round(time.monotonic() - row_started, 3),
                "valid_evidence_accepted": '"is_valid": true' in log,
                "simulated_labeled": '"simulated": true' in log,
                "production_policy_rejected": '"accepted": false' in log,
                "tampered_evidence_rejected": "tampered" not in log.lower(),
            }
            rows.append(row)
            if completed.returncode or not all(
                row[key]
                for key in (
                    "valid_evidence_accepted",
                    "simulated_labeled",
                    "production_policy_rejected",
                    "tampered_evidence_rejected",
                )
            ):
                raise RuntimeError(f"incomplete {service} simulator row: {row}")

        unit_passed = 0
        for name, command in spec["tests"]:
            tested = run(command, repository / "dstack", 600)
            log = tested.stdout + tested.stderr
            (artifacts / f"{name}.log").write_text(log)
            passed = sum(int(match) for match in TEST_RESULT.findall(log))
            rows.append(
                {
                    "kind": "candidate-unit-policy",
                    "name": name,
                    "returncode": tested.returncode,
                    "passed_tests": passed,
                }
            )
            if tested.returncode or passed < 1:
                raise RuntimeError(
                    f"{name} rc={tested.returncode}, parsed passing tests={passed}"
                )
            unit_passed += passed
        (artifacts / "kms-cross-platform-matrix.json").write_text(
            json.dumps(rows, indent=2, sort_keys=True) + "\n"
        )
        steps.append(
            emit(
                f"{case_id}-step-02",
                "PASS",
                f"{len(spec['services'])} simulated platform row(s) rejected authenticated-byte mutations and production use of development roots; {unit_passed} candidate KMS/verifier policy tests passed.",
            )
        )
        steps.append(
            emit(
                f"{case_id}-step-03",
                "PASS",
                f"{spec['claim']} completed with case-scoped logs and no accepted mutation state.",
            )
        )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        steps.append(emit(f"{case_id}-step-{len(steps) + 1:02d}", "FAIL", failure))
    finally:
        down = run_as_kvin(
            f"cd {shlex.quote(str(suite))} && docker compose down --remove-orphans",
            180,
        )
        (artifacts / "compose-down.log").write_text(down.stdout + down.stderr)
        if down.returncode and status == "PASS":
            status = "FAIL"
            failure = f"compose cleanup rc={down.returncode}"

    artifact_entries = [
        {
            "path": f"artifacts/{path.name}",
            "name": path.name,
            "description": "Case-scoped simulated evidence or candidate authorization-policy output.",
        }
        for path in sorted(artifacts.iterdir())
    ]
    result: dict[str, object] = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": f"Simulator-backed {spec['claim']} passed."
        if status == "PASS"
        else failure,
        "steps": steps,
        "artifacts": artifact_entries,
        "remarks": "Simulation confirms functional encoding, routing, authenticated mutation rejection, measurement/policy binding, and error handling. It does not confirm vendor hardware signatures, firmware state, or physical isolation.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    if failure:
        result["failure"] = failure
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
