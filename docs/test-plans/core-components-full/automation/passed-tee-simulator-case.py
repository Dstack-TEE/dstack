#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic native-test harness for simulated hardware ABIs."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASES = {
    "tc-gos-setup-014": {
        "filter": "sev_snp::tests",
        "passed": 3,
        "tests": (
            "sev_snp::tests::report_update_is_verified_and_failure_atomic ... ok",
            "sev_snp::tests::filesystem_aliases_and_permissions_are_bounded ... ok",
            "sev_snp::tests::malformed_certificate_chains_fail_closed ... ok",
        ),
        "summary": "SEV-SNP report, certificate, boundary, and failure-atomicity matrix passed.",
        "observed": (
            "Report-data updates produced QVL-verifiable signed evidence.",
            "Invalid offsets, buffer lengths, paths, permissions, and certificate chains failed closed.",
            "Repeated updates recovered and correlated report/certificate state remained atomic.",
        ),
    },
    "tc-gos-setup-016": {
        "filter": "nsm::tests",
        "passed": 2,
        "tests": (
            "nsm::tests::pcr_lifecycle_matches_nsm_semantics ... ok",
            "nsm::tests::attestation_binds_claims_and_current_pcrs ... ok",
        ),
        "summary": "Nitro NSM request, PCR state, failure, and attestation-binding matrix passed.",
        "observed": (
            "PCR describe, extend, lock, bounds, and input limits were exercised.",
            "Read-only, invalid-index, and oversized-input paths failed closed.",
            "Signed evidence bound user data, nonce, public key, and current PCR state.",
        ),
    },
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON artifact atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def main() -> int:
    """Run the source-defined simulator behavior matrix for this case."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise SystemExit(f"unsupported case: {case_id}")
    scenario = CASES[case_id]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    command = [
        cargo,
        "test",
        "--locked",
        "-p",
        "dstack-tee-simulator",
        scenario["filter"],
        "--",
        "--nocapture",
    ]
    env = os.environ.copy()
    target = runtime.get("cargo_target_dir") or runtime.get("shared_cargo_target")
    if target:
        env["CARGO_TARGET_DIR"] = str(target)
    completed = subprocess.run(
        command,
        cwd=repository / "dstack",
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
        check=False,
    )
    output = completed.stdout
    checks = {
        "command_passed": completed.returncode == 0,
        "expected_count_passed": (f"{scenario['passed']} passed; 0 failed" in output),
        "named_tests_executed": all(name in output for name in scenario["tests"]),
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {
        "command": command,
        "returncode": completed.returncode,
        "checks": checks,
        "output_bytes": len(output.encode()),
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_tail": output[-12000:],
    }
    artifact_name = f"{scenario['filter'].split('::')[0]}-abi.json"
    atomic_json(artifacts / artifact_name, evidence)
    step_status = "PASS" if status == "PASS" else "FAIL"
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": (
            scenario["summary"]
            if status == "PASS"
            else "TEE simulator native regression matrix failed; inspect the bounded artifact."
        ),
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": step_status,
                "observed": scenario["observed"][0],
            },
            {
                "id": f"{case_id}-step-02",
                "status": step_status,
                "observed": scenario["observed"][1],
            },
            {
                "id": f"{case_id}-step-03",
                "status": step_status,
                "observed": scenario["observed"][2],
            },
        ],
        "artifacts": [
            {
                "name": "TEE simulator ABI regression",
                "path": f"artifacts/{artifact_name}",
                "step_id": f"{case_id}-step-01",
                "description": "Bounded native-test output, digest, status, and named assertion checks.",
            }
        ],
        "remarks": "Runs candidate source-defined tests with the prepared shared Cargo target and no host device mutation.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(artifacts / "manifest.json", {"artifacts": result["artifacts"]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
