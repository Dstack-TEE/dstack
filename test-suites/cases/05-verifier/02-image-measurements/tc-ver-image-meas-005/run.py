#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the verifier measurement-cache correctness and concurrency matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-image-meas-005"
TESTS = (
    "measurement_cache_version_mismatch_is_ignored_and_replaced",
    "corrupt_measurement_cache_entry_is_ignored",
    "concurrent_measurement_cache_writes_are_atomic",
    # Only the measured VM shape keys an entry (PR #1334).
    "measurement_cache_key_ignores_unmeasured_fields",
    # The directory is capped, oldest entries first, sparing temporaries (PR #1369).
    "measurement_cache_evicts_the_oldest_entries_and_spares_temporaries",
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def main() -> int:
    """Execute the source-defined cache tests against the prepared target."""
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
    summary = "Measurement cache version rejection, corruption recovery, atomic concurrency, shape-only keying, and bounded eviction passed."
    stage = "baseline"
    try:
        cargo = shutil_which(environment, "cargo")
        for test in TESTS:
            stage = test
            completed = subprocess.run(
                [
                    cargo,
                    "test",
                    "-p",
                    "dstack-verifier",
                    test,
                    "--lib",
                ],
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

    observations = {
        "candidate_commit": runtime.get("candidate_commit"),
        "rows": rows,
        "row_count": len(rows),
        "all_passed": status == "PASS",
        "cache_key_inputs": ["vm_config"],
        "cache_key_excludes": [
            "image",
            "tdx_measurement",
            "gcp_measurement",
            "aws_measurement",
        ],
        "eviction": "oldest .json entries beyond the cap; temporaries spared",
        "entry_compatibility_guard": "embedded_measurement_cache_version",
        "recovery_inputs": ["malformed_json", "stale_embedded_version"],
        "concurrency_property": "one complete entry and no temporary files",
    }
    artifact = {
        "path": "artifacts/measurement-cache-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Measurement cache matrix",
        "description": "Exact source-defined test names, return codes, and hashed output for embedded-version rejection, recovery, and atomic writes.",
    }
    atomic_json(result_dir / artifact["path"], observations)
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
                    "observed": "The prepared candidate revision and isolated Cargo target were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Embedded-version rejection and replacement, corrupt-entry recovery, concurrent atomic writes, keying on the measured VM shape only, and oldest-first eviction were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Each exact test passed independently; evidence retains only test identities, return codes, and output hashes.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "This verifies cache behavior; it does not assess Yocto or mkosi build correctness.",
        },
    )
    return 0


def shutil_which(environment: dict[str, str], command: str) -> str:
    """Resolve a required command from the runtime-declared PATH."""
    for directory in environment.get("PATH", "").split(os.pathsep):
        candidate = pathlib.Path(directory) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise OSError(f"required command is unavailable: {command}")


if __name__ == "__main__":
    raise SystemExit(main())
