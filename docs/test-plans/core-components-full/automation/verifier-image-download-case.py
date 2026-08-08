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
PACKAGE = "dstack-verifier"
REQUIRED_TESTS = (
    "verification::tests::image_archive_rejects_links_and_accepts_regular_files",
    "verification::tests::image_archive_accepts_dot_prefixed_members",
    "verification::tests::image_archive_reads_every_gzip_member",
    "verification::tests::image_cache_pruning_keeps_checksum_identity",
    "verification::tests::image_paths_must_be_confined_and_manifest_paths_must_be_flat",
    "verification::tests::corrupt_measurement_cache_entry_is_ignored",
    "verification::tests::concurrent_measurement_cache_writes_are_atomic",
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
        "Image archive extraction, path confinement, pruning, and cache-safety suite passed."
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
        passed = bool(re.search(r"test result: ok\. 24 passed; 0 failed", output)) and all(
            f"{test} ... ok" in output for test in REQUIRED_TESTS
        )
        row.update(
            {
                "returncode": completed.returncode,
                "passed": passed,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            }
        )
        if completed.returncode or not passed:
            raise AssertionError(
                f"{PACKAGE} image suite failed with rc={completed.returncode}"
            )
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = str(error)

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "row": row,
        "covered_behaviors": [
            "regular_archive_extraction",
            "symlink_traversal_rejection",
            "multi_member_gzip_extraction",
            "dot_prefixed_member_normalization",
            "unlisted_file_pruning",
            "manifest_path_confinement",
            "corrupt_cache_recovery",
            "concurrent_cache_write_atomicity",
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
                    "observed": "Archive extraction, link and path confinement, gzip members, pruning, corrupt-cache recovery, and concurrent cache writes were exercised.",
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
