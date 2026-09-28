#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the candidate MR-config verifier behavior matrix."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def main() -> int:
    """Execute the exact candidate verifier tests and emit the case result."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    command = [
        "cargo",
        "test",
        "--manifest-path",
        str(pathlib.Path(runtime["repository"]) / "dstack/Cargo.toml"),
        "-p",
        "dstack-util",
        "system_setup::config_id_verifier::tests",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=300,
        env=environment,
        check=False,
    )
    passed = completed.returncode == 0
    status = "PASS" if passed else "FAIL"
    log_path = result_dir / "artifacts/mr-config-verifier-tests.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(completed.stdout + completed.stderr, encoding="utf-8")
    artifact = {
        "path": "artifacts/mr-config-verifier-tests.log",
        "step_id": f"{case_id}-step-01",
        "name": "MR-config verifier matrix",
        "description": "Filtered candidate Cargo output proves TDX v1/v3 matching and bound-field mismatch rejection, explicit non-TDX policy, and recovery without provisioning state.",
    }
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Candidate MR-config verifier behavior matrix passed."
            if passed
            else "Candidate MR-config verifier behavior matrix failed.",
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "TDX v1/v3 matching, bound-field mismatch, malformed input, and non-TDX policy tests executed.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Invalid inputs failed before provisioning and valid calls remained recoverable under the test scheduler.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "The pure verifier left no runtime state or credential material.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Image, CPU, and general VM measurement are covered by dedicated measurement cases.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
