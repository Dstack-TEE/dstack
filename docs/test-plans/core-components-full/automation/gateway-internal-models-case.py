#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the Gateway dashboard-model invariant matrix."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-gw-internal-007"
TEST_FILTER = "gateway_top_n_batch_007_cache_health_and_invalidation"
SUBJECT = "top-N cache health, ordering, invalidation, and model reconstruction"


def main() -> int:
    """Run the focused candidate test through the prepared shared Cargo target."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported Gateway internal-model case: {case_id}")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    command = [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "-p",
        "dstack-gateway",
        TEST_FILTER,
        "--",
        "--nocapture",
    ]
    process = subprocess.run(
        command,
        cwd=Path(runtime["repository"]) / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    output = process.stdout + process.stderr
    matches = [int(value) for value in re.findall(r"(\d+) passed; 0 failed", output)]
    passed_tests = max(matches, default=0)
    passed = process.returncode == 0 and passed_tests == 1
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "cargo_target_dir_shared": True,
        "case_id": case_id,
        "filter": TEST_FILTER,
        "passed_tests": passed_tests,
        "returncode": process.returncode,
        "test_binary_invocations": len(matches),
        "vm_started": False,
        "service_started": False,
    }
    if not passed:
        evidence["diagnostic_tail"] = output[-3000:]
    artifact = result_dir / "artifacts/gateway-internal-models.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        f"One focused candidate Gateway test passed for {SUBJECT}."
        if passed
        else f"The focused candidate Gateway test failed for {SUBJECT}."
    )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {
                "id": f"{case_id}-step-{number:02d}",
                "status": status,
                "observed": observed,
            }
            for number in range(1, 5)
        ],
        "evidence": [
            {
                "path": "artifacts/gateway-internal-models.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": (
            "The immutable Cargo target is shared across compatible cases while result evidence "
            "remains case-scoped. The tested model layer owns no persistent service state, so "
            "reconstruction is its restart boundary; no VM, listener, credential, or process was created."
        ),
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
