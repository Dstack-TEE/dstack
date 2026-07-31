#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate Gateway restrict-mode and legacy port-policy behavior."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

MATRIX = {
    "tc-gw-registrati-003": {
        "filters": (
            "main_service::tests::test_port_policy",
            "main_service::tests::test_admin_override",
            "main_service::tests::test_clear_admin_override",
        ),
        "minimum": 9,
        "claim": "restrict-mode allow/deny, unknown-policy fail-close, and exact admin-override precedence",
    },
    "tc-gw-registrati-004": {
        "filters": ("proxy::port_policy::tests", "compose_hash_change"),
        "minimum": 4,
        "claim": "reported/empty/malformed legacy Info policy parsing and compose-change cache invalidation",
    },
}
RESULT = re.compile(r"test result: ok\. (\d+) passed; 0 failed")


def main() -> int:
    """Run the selected candidate policy matrix and emit aggregate evidence."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in MATRIX:
        raise ValueError("unsupported case")
    spec = MATRIX[case_id]
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    started = time.monotonic()
    passed = 0
    rows = []
    for index, test_filter in enumerate(spec["filters"], start=1):
        completed = subprocess.run(
            [
                "/home/kvin/.cargo/bin/cargo",
                "test",
                "-p",
                "dstack-gateway",
                test_filter,
                "--",
                "--nocapture",
            ],
            cwd=repository / "dstack",
            env=environment,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        output = completed.stdout + completed.stderr
        (artifacts / f"policy-tests-{index}.log").write_text(output)
        row_passed = sum(int(value) for value in RESULT.findall(output))
        rows.append(
            {
                "filter": test_filter,
                "returncode": completed.returncode,
                "passed_tests": row_passed,
            }
        )
        passed += row_passed
    status = (
        "PASS"
        if passed >= int(spec["minimum"])
        and all(row["returncode"] == 0 and row["passed_tests"] > 0 for row in rows)
        else "FAIL"
    )
    observation = {
        "rows": rows,
        "passed_tests": passed,
        "minimum_expected": spec["minimum"],
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (artifacts / "port-policy-observation.json").write_text(
        json.dumps(observation, indent=2, sort_keys=True) + "\n"
    )
    artifact_rows = [
        {
            "path": f"artifacts/{path.name}",
            "name": path.name,
            "description": "Candidate policy test names/results or aggregate non-secret observations.",
        }
        for path in sorted(artifacts.iterdir())
    ]
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": artifact_rows}, indent=2) + "\n"
    )
    steps = [
        {
            "id": f"{case_id}-step-01",
            "status": status,
            "observed": "The committed candidate policy implementation and shared test target were available.",
        },
        {
            "id": f"{case_id}-step-02",
            "status": status,
            "observed": f"{passed} candidate tests exercised {spec['claim']}.",
        },
        {
            "id": f"{case_id}-step-03",
            "status": status,
            "observed": "Unknown or malformed restricted policy failed closed while explicit compatibility and override paths remained bounded.",
        },
    ]
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": f"Gateway {spec['claim']} passed."
        if status == "PASS"
        else f"Gateway policy matrix failed: passed={passed}, expected={spec['minimum']}",
        "steps": steps,
        "artifacts": artifact_rows,
        "remarks": "No guest compose body, credential, certificate, key, or token is retained.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
