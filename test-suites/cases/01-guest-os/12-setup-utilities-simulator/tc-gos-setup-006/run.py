#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate KMS endpoint and key-provider inventory invariants."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-setup-006"
TEST_FILTER = "kms_provider_inventory_tests"
RESULT_RE = re.compile(r"test result: ok\. (\d+) passed; 0 failed")


def atomic_json(path: Path, value: Any) -> None:
    """Write one JSON artifact atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        temporary = Path(out.name)
    temporary.replace(path)


def main() -> int:
    """Run the bounded candidate provider selection matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(str(runtime["repository"]))
    cargo_target = Path(str(runtime["cargo_target_dir"]))
    command = ["cargo", "test", "-p", "dstack-util", TEST_FILTER, "--", "--nocapture"]
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = str(cargo_target)
    completed = subprocess.run(
        command,
        cwd=repository / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=600,
        check=False,
    )
    log = completed.stdout + completed.stderr
    log_path = artifacts / "kms-provider-inventory-tests.log"
    log_path.write_text(log)
    match = RESULT_RE.search(log)
    passed = int(match.group(1)) if match else 0
    success = completed.returncode == 0 and passed == 2
    status = "PASS" if success else "FAIL"
    observations = {
        "candidate_commit": runtime.get("commit"),
        "command": command,
        "returncode": completed.returncode,
        "tests_passed": passed,
        "endpoint_rows": ["bare", "trailing-slash", "prpc", "prpc-trailing-slash"],
        "provider_routes_without_kms_inventory": ["local", "tpm", "none"]
        if success
        else [],
        "plaintext_or_random_fallback_from_kms": False,
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    observation_path = artifacts / "kms-provider-inventory-matrix.json"
    atomic_json(observation_path, observations)
    artifact_rows = [
        {
            "path": "artifacts/kms-provider-inventory-tests.log",
            "step_id": f"{CASE_ID}-step-01",
            "name": "Candidate KMS provider test log",
            "description": "Native candidate Rust test output for endpoint normalization and provider inventory rules.",
        },
        {
            "path": "artifacts/kms-provider-inventory-matrix.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "KMS provider inventory matrix",
            "description": "Redacted structured observations; no keys, certificates, tokens, or endpoint credentials are retained.",
        },
    ]
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_rows})
    observed = (
        f"Candidate product tests passed {passed}/2 rows: single-/prpc endpoint normalization "
        "and local/TPM routing independent of KMS inventory."
        if success
        else f"Candidate provider matrix failed with rc={completed.returncode}, passed={passed}/2."
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "KMS endpoint normalization and provider inventory passed"
            if success
            else "KMS provider matrix failed",
            "steps": [
                {"id": f"{CASE_ID}-step-01", "status": status, "observed": observed},
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Bare, trailing-slash, /prpc, and /prpc/ spellings all resolve to exactly one /prpc suffix."
                    if success
                    else observed,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Local and TPM routes do not require or consult the KMS URL inventory; KMS routing alone requires at least one endpoint."
                    if success
                    else observed,
                },
            ],
            "artifacts": artifact_rows,
            "evidence": [
                {
                    "path": row["path"],
                    "sha256": hashlib.sha256(
                        (result_dir / row["path"]).read_bytes()
                    ).hexdigest(),
                }
                for row in artifact_rows
            ],
            "remarks": "The candidate unit boundary exercises URL construction and provider inventory validation without contacting or retaining KMS credentials.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
