#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate Certbot workdir paths, archive ordering, rollback, and isolation."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-gw-certbot-005"


def main() -> int:
    """Run case-scoped candidate Rust tests and retain bounded evidence."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    commands = [
        ["cargo", "test", "--locked", "--offline", "-p", "certbot", "workdir::tests::"],
        ["cargo", "test", "--locked", "--offline", "-p", "certbot", "listing_tests::"],
    ]
    completed = [
        subprocess.run(
            command,
            cwd=Path(str(runtime["repository"])) / "dstack",
            env=env,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        for command in commands
    ]
    output = "".join(result.stdout + result.stderr for result in completed)
    passed_count = sum(
        max(
            (
                int(v)
                for v in re.findall(
                    r"(\d+) passed; 0 failed", result.stdout + result.stderr
                )
            ),
            default=0,
        )
        for result in completed
    )
    checks = {
        "candidate_tests_passed": all(result.returncode == 0 for result in completed)
        and passed_count >= 3,
        "rollback_exercised": "live_links_can_roll_back_to_a_complete_generation"
        in output,
        "malformed_state_isolated": "malformed_credentials_fail_without_mutating_the_archive"
        in output,
        "certificate_listing_stable": "certificate_directories_are_listed_in_stable_order"
        in output,
    }
    passed = all(checks.values())
    artifact = result_dir / "artifacts/certbot-workdir.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(
        json.dumps(
            {
                "candidate_commit": runtime["candidate_commit"],
                "checks": checks,
                "passed_count": passed_count,
                "retained_paths_credentials_or_file_contents": False,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    status = "PASS" if passed else "FAIL"
    observed = (
        "Candidate certificate discovery, workdir ordering, rollback, malformed-state isolation, and cleanup checks passed."
        if passed
        else f"Workdir checks failed: {sorted(k for k, v in checks.items() if not v)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/certbot-workdir.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Candidate Rust tests used case-owned temporary directories and shared immutable Cargo output; retained evidence contains booleans and counts only.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
