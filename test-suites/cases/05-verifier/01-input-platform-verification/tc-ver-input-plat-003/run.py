#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the current TDX V2 event-log preimage and replay suite."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-input-plat-003"
PACKAGE = "cc-eventlog"
REQUIRED_TESTS = (
    "runtime_events::tests::mixed_v1_v2_replay",
    "runtime_events::tests::v2_digest_is_canonical_json_hash",
    "tdx::tests::fill_preimage_v2_is_canonical_json",
    "tdx::tests::stripped_v2_runtime_event_preserves_digest_binding",
    "tdx::tests::validates_v2_digest_preimage_before_use",
    "tdx::tests::rejects_missing_or_malformed_v2_preimage",
    "tdx::tests::rejects_v2_preimage_digest_mismatch",
    "tdx::tests::rejects_noncanonical_v2_preimage_with_matching_digest",
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
    """Execute the exact source-defined download-security test."""
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
    row: dict[str, Any] = {"package": PACKAGE, "tests": REQUIRED_TESTS}
    status = "PASS"
    summary = (
        "TDX V2 event-log preimage validation and mixed-version replay suite passed."
    )
    try:
        completed = subprocess.run(
            [
                find_command(environment, "cargo"),
                "test",
                "-p",
                PACKAGE,
                "--lib",
                "--",
                "--nocapture",
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
        passed = bool(
            re.search(r"test result: ok\. \d+ passed; 0 failed", output)
        ) and all(f"{test} ... ok" in output for test in REQUIRED_TESTS)
        row.update(
            {
                "returncode": completed.returncode,
                "passed": passed,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            }
        )
        if completed.returncode or not passed:
            raise AssertionError(
                f"{PACKAGE} V2 event-log suite failed with rc={completed.returncode}"
            )
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = str(error)

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "row": row,
        "covered_behaviors": [
            "valid_v2_preimages",
            "mixed_v1_v2_replay",
            "canonical_v2_digest",
            "stripped_v2_digest_binding",
            "missing_preimage_rejection",
            "malformed_preimage_rejection",
            "digest_preimage_mismatch_rejection",
            "noncanonical_preimage_rejection",
        ],
    }
    artifact = {
        "path": "artifacts/tdx-v2-eventlog-rtmr3-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "TDX V2 event-log preimage matrix",
        "description": "Exact test identity, return code, covered behaviors, and hashed output.",
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
                    "observed": "The candidate source and prepared Cargo target were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Canonical V2 preimages, mixed-version replay, missing and malformed preimages, digest mismatches, and noncanonical inputs were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Evidence retains the exact test identity, return code, behavior list, and output hash.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "This source suite verifies V2 event encoding and replay inputs; only a real TDX platform can establish physical hardware origin.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
