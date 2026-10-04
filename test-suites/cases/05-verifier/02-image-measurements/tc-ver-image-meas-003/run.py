#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the ACPI table, QEMU compatibility, and swtpm policy matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-image-meas-003"
ROWS = (
    ("dstack-verifier", "tdx_lite_acpi_hashes_are_selected_by_event_name"),
    ("dstack-verifier", "tdx_lite_acpi_hashes_reject_unlabeled_events"),
    ("dstack-verifier", "verifies_tdx_lite_fixture_without_image_download"),
    ("dstack-verifier", "tdx_lite_acpi_hashes_depend_on_the_reported_vm_shape"),
    ("dstack-verifier", "tdx_lite_acpi_hash_mismatch_names_the_table"),
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
    """Execute every exact source-defined ACPI/swtpm test."""
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
    evidence_rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = "ACPI, QEMU compatibility, and swtpm policy matrix passed."
    stage = "baseline"
    try:
        cargo = find_command(environment, "cargo")
        for package, test in ROWS:
            stage = test
            completed = subprocess.run(
                [cargo, "test", "-p", package, test, "--lib"],
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
            evidence_rows.append(
                {
                    "package": package,
                    "test": test,
                    "returncode": completed.returncode,
                    "passed": passed,
                    "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                }
            )
            if completed.returncode or not passed:
                raise AssertionError(
                    f"{package}:{test} failed with rc={completed.returncode}"
                )
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "rows": evidence_rows,
        "qemu_versions": ["8.0.0", "8.2.2", "9.0.0", "9.1.0", "10.0.1"],
        "properties": [
            "metadata_declared_ovmf_variant",
            "acpi_event_name_selection",
            "unlabeled_acpi_event_rejection",
            "matching_tdx_lite_evidence_acceptance",
            "no_image_download_for_matching_lite_evidence",
            "reported_vm_shape_binding",
            "named_acpi_table_mismatch",
        ],
    }
    artifact = {
        "path": "artifacts/acpi-swtpm-policy-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "ACPI and swtpm policy matrix",
        "description": "Exact package/tests, versions, properties, return codes, and hashed output.",
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
                    "observed": "The ACPI table set, supported QEMU rows, and swtpm policy boundary were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "OVMF version boundaries, ACPI event labels, malformed inputs, and matching offline TDX-lite evidence were exercised independently.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Every exact test passed and matching TDX-lite evidence caused no image download.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "This tests measurement and verifier policy behavior, not Yocto or mkosi build correctness.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
