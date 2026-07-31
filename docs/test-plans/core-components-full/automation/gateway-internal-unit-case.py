#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute focused Gateway internal unit matrices through the shared Cargo target."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

CASES = {
    "tc-gw-internal-006": {
        "filter": "gateway_internal_batch_006",
        "minimum_tests": 1,
        "subject": "fail-closed port filtering, reported-policy parsing, PROXY protocol decisions, and bounded retry backoff",
    },
}


def main() -> int:
    """Run the case-selected focused matrix and emit bounded evidence."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise SystemExit(f"unsupported Gateway internal unit case: {case_id}")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    row = CASES[case_id]
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    process = subprocess.run(
        [
            "cargo", "test", "--locked", "--offline", "-p", "dstack-gateway",
            str(row["filter"]), "--", "--nocapture",
        ],
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
    passed = process.returncode == 0 and passed_tests >= int(row["minimum_tests"])
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "cargo_target_dir_shared": True,
        "case_id": case_id,
        "filter": row["filter"],
        "minimum_tests": row["minimum_tests"],
        "passed_tests": passed_tests,
        "returncode": process.returncode,
        "vm_started": False,
        "service_started": False,
    }
    if not passed:
        evidence["diagnostic_tail"] = output[-3000:]
    artifact = result_dir / "artifacts/gateway-internal-unit.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        f"{passed_tests} focused candidate test passed for {row['subject']}."
        if passed
        else f"Focused candidate tests failed for {row['subject']}."
    )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{case_id}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 5)
        ],
        "evidence": [{
            "path": "artifacts/gateway-internal-unit.json",
            "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        }],
        "remarks": (
            "Immutable Cargo artifacts are shared across compatible cases; evidence and the "
            "raw lease substrate remain case-scoped. No VM, listener, credential, or service was created."
        ),
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
