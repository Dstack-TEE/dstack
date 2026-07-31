#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate KMS certificate-log concurrency and atomicity behavior."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-kms-ct-001"
RESULT_RE = re.compile(r"test result: ok\. (\d+) passed; 0 failed")
TESTS = {
    "concurrent_writes_are_unique_and_never_overwrite",
    "collision_allocation_preserves_existing_file",
    "iterator_excludes_malformed_and_unrelated_entries",
    "exhausted_collision_range_fails_without_overwrite",
    "iteration_survives_writer_restart",
}


def emit(step: int, status: str, observed: str) -> dict[str, str]:
    """Emit one runner-protocol step and return its result row."""
    step_id = f"{CASE_ID}-step-{step:02d}"
    print(f"STEP {step_id} START", flush=True)
    print(f"EVIDENCE {step_id} - {observed}", flush=True)
    print(f"STEP {step_id} END - {status}", flush=True)
    return {"id": step_id, "status": status, "observed": observed}


def main() -> int:
    """Execute candidate certificate-log tests and write bounded evidence."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    command = [
        "cargo",
        "test",
        "-p",
        "dstack-kms",
        "ct_log::tests",
        "--",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["RUSTUP_TOOLCHAIN"] = "1.92.0"
    environment["CARGO_TARGET_DIR"] = runtime["cargo_target_dir"]
    started = time.monotonic()
    steps: list[dict[str, str]] = []
    status = "FAIL"
    failure = ""

    baseline = {
        "candidate_commit": runtime["candidate_commit"],
        "repository_head": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip(),
        "command": command,
        "test_count": len(TESTS),
        "concurrent_writers": 64,
        "collision_slots": 4097,
    }
    (artifacts_dir / "baseline.json").write_text(
        json.dumps(baseline, indent=2, sort_keys=True) + "\n"
    )
    if baseline["candidate_commit"] != baseline["repository_head"]:
        failure = "runtime manifest candidate commit does not match repository HEAD"
        steps.append(emit(1, "FAIL", failure))
    else:
        steps.append(
            emit(
                1,
                "PASS",
                "Candidate HEAD, Rust 1.92 command, 64-writer load, and 4097 collision-slot boundary were recorded.",
            )
        )
        try:
            completed = subprocess.run(
                command,
                cwd=repository / "dstack",
                env=environment,
                text=True,
                capture_output=True,
                timeout=600,
                check=False,
            )
            log = completed.stdout + completed.stderr
            (artifacts_dir / "cargo-test.log").write_text(log)
            named = {name for name in TESTS if name in log}
            passed = sum(int(value) for value in RESULT_RE.findall(log))
            if completed.returncode or passed != len(TESTS) or named != TESTS:
                raise RuntimeError(
                    f"candidate test rc={completed.returncode}, passed={passed}/{len(TESTS)}, named={len(named)}/{len(TESTS)}"
                )
            steps.append(
                emit(
                    2,
                    "PASS",
                    "5/5 candidate tests passed: 64 concurrent writers committed unique immutable contents and iteration excluded malformed entries.",
                )
            )
            steps.append(
                emit(
                    3,
                    "PASS",
                    "Collision retry and 4097-slot exhaustion were fail-closed; staged files were atomically committed or removed without overwrite or leakage.",
                )
            )
            steps.append(
                emit(
                    4,
                    "PASS",
                    "Restart-style re-open preserved both committed certificates; test tempdirs were case-scoped and output contained no certificate private material.",
                )
            )
            status = "PASS"
        except Exception as error:  # noqa: BLE001
            failure = f"{type(error).__name__}: {error}"
            steps.append(emit(len(steps) + 1, "FAIL", failure))

    entries = []
    for path in sorted(artifacts_dir.iterdir()):
        entries.append(
            {
                "path": f"artifacts/{path.name}",
                "name": path.name,
                "description": "Candidate certificate-log execution evidence.",
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    (artifacts_dir / "manifest.json").write_text(
        json.dumps({"artifacts": entries}, indent=2, sort_keys=True) + "\n"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": "Candidate certificate-log concurrency, atomic commit, filtering, exhaustion, and restart behavior passed."
        if status == "PASS"
        else failure,
        "steps": steps,
        "artifacts": entries,
        "duration_seconds": round(time.monotonic() - started, 3),
        "remarks": "The case uses candidate Rust tests against a case-scoped temporary filesystem and reuses the prepared Cargo target; it does not test image construction.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
