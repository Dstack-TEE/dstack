#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the verifier image-download digest and extraction security matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-image-meas-001"
TEST = "image_download_digest_redirect_timeout_and_retry_matrix"


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
    row: dict[str, Any] = {"test": TEST}
    status = "PASS"
    summary = (
        "Image download digest, extraction, redirect, timeout, and retry matrix passed."
    )
    try:
        completed = subprocess.run(
            [
                find_command(environment, "cargo"),
                "test",
                "-p",
                "dstack-verifier",
                TEST,
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
        row.update(
            {
                "returncode": completed.returncode,
                "passed": passed,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            }
        )
        if completed.returncode or not passed:
            raise AssertionError(f"{TEST} failed with rc={completed.returncode}")
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = str(error)

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "row": row,
        "covered_behaviors": [
            "valid_hash_bound_archive",
            "wrong_digest",
            "truncated_archive",
            "symlink_traversal_rejection",
            "http_redirect",
            "download_timeout",
            "same_cache_retry",
            "unlisted_file_pruning",
            "failure_without_destination_promotion",
        ],
    }
    artifact = {
        "path": "artifacts/image-download-security-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Image download security matrix",
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
                    "observed": "Digest, archive, redirect, timeout, retry, pruning, and atomic-promotion behaviors were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Evidence retains the exact test identity, return code, behavior list, and output hash.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "This verifies verifier download behavior; it does not assess Yocto or mkosi build correctness.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
