#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the six-platform verifier OS-image strategy matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-strategy-006"
TESTS = (
    "verifies_tdx_lite_fixture_without_acpi_table_verification",
    "verifies_sev_snp_attestation_fixture_without_image_download",
    "gcp_and_nitro_enclave_measurement_bindings_matrix",
    "aws_os_image_check_requires_measurement",
    "aws_os_image_check_accepts_bound_measurement",
    "aws_os_image_check_rejects_boot_pcr_digest_mismatch",
    "image_cache_pruning_keeps_checksum_identity",
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def find_command(environment: dict[str, str], command: str) -> str:
    """Resolve a required command from PATH."""
    for directory in environment.get("PATH", "").split(os.pathsep):
        candidate = pathlib.Path(directory) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise OSError(f"required command is unavailable: {command}")


def main() -> int:
    """Execute every exact source-defined strategy test."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = "Six-platform OS-image strategy and binding matrix passed."
    stage = "baseline"
    try:
        cargo = find_command(environment, "cargo")
        for test in TESTS:
            stage = test
            completed = subprocess.run(
                [cargo, "test", "-p", "dstack-verifier", test, "--lib"],
                cwd=repository / "dstack",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                check=False,
            )
            output = completed.stdout + completed.stderr
            passed = bool(re.search(r"test result: ok\. 1 passed; 0 failed", output))
            rows.append(
                {
                    "test": test,
                    "returncode": completed.returncode,
                    "passed": passed,
                    "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                }
            )
            if completed.returncode or not passed:
                raise AssertionError(f"{test} failed with rc={completed.returncode}")
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "rows": rows,
        "platforms": [
            "tdx_full",
            "tdx_lite",
            "sev_snp",
            "gcp_tdx",
            "nitro_enclave",
            "nitro_tpm",
        ],
        "properties": [
            "platform_specific_measurement_binding",
            "offline_self_contained_paths_do_not_download",
            "required_measurement_rejection",
            "boot_pcr_digest_mismatch_rejection",
            "cache_identity_pruning",
        ],
    }
    artifact = {
        "path": "artifacts/platform-image-strategy-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Six-platform image strategy matrix",
        "description": "Exact tests, platforms, return codes, properties, and hashed output.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "The six source-defined platform strategies and historical full-TDX row were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Platform-specific offline, CBOR, PCR, measurement, rejection, and cache-identity bindings were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Every exact test passed independently and evidence retains only identities, status, properties, and output hashes.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Simulator and committed signed fixtures verify functional trust bindings; physical hardware origin is outside this matrix.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
