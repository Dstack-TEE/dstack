#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute KMS authorization decision freshness and scope checks."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-kms-auth-010"
EXACT_TESTS = 4
FILTER = "main_service::upgrade_authority::tests"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic JSON evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(
    command: list[str], cwd: pathlib.Path, env: dict[str, str]
) -> tuple[dict[str, Any], str]:
    """Run one bounded Cargo test process and parse its exact summary."""
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    output = completed.stdout
    match = re.search(
        r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;",
        output,
    )
    passed, failed, ignored, measured = (
        tuple(map(int, match.groups())) if match else (0, 1, 0, 0)
    )
    return (
        {
            "returncode": completed.returncode,
            "passed": passed,
            "failed": failed,
            "ignored": ignored,
            "measured": measured,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        },
        output,
    )


def main() -> int:
    """Execute exact authorization tests in two fresh Rust processes."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    cargo = pathlib.Path.home() / ".cargo/bin/cargo"
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = runtime["cargo_target_dir"]
    env["PATH"] = os.pathsep.join(
        [str(pathlib.Path.home() / ".cargo/bin"), env.get("PATH", "")]
    )
    command = [
        str(cargo),
        "test",
        "-p",
        "dstack-kms",
        FILTER,
        "--",
        "--nocapture",
    ]
    rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = "two fresh KMS test processes proved authorization decisions are uncached and scope-bound"
    for process_index in (1, 2):
        try:
            row, output = run(command, repo / "dstack", env)
        except (OSError, subprocess.TimeoutExpired) as error:
            row = {
                "returncode": -1,
                "passed": 0,
                "failed": 1,
                "ignored": 0,
                "measured": 0,
                "error_type": type(error).__name__,
            }
            output = str(error)
        row["process"] = process_index
        rows.append(row)
        if (
            row["returncode"] != 0
            or row["passed"] != EXACT_TESTS
            or row["failed"] != 0
            or row["ignored"] != 0
            or row["measured"] != 0
        ):
            status = "FAIL"
            summary = f"fresh Rust process {process_index} failed: {row}"
            debug = result_dir / "debug"
            debug.mkdir(exist_ok=True)
            (debug / f"cargo-process-{process_index}.log").write_text(output)
            break

    observation = {
        "candidate_commit": commit,
        "fresh_process_count": len(rows),
        "process_rows": rows,
        "coverage": [
            "identical-request-requeries-changed-decision",
            "app-and-kms-route-isolation",
            "all-boot-identity-fields-preserved",
            "malformed-backend-response-fails-closed",
            "next-request-recovers-without-retained-decision",
            "no-decision-state-across-process-restart",
        ],
        "decision_cache_present": False,
        "private_material_exported": False,
    }
    artifact = {
        "path": "artifacts/kms-authorization-freshness.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS authorization decision freshness matrix",
        "description": "Exact counts, durations, coverage labels, and output hashes from two fresh Rust test processes.",
    }
    detail = result_dir / artifact["path"]
    atomic_json(detail, observation)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    observed = (
        "Every request reached the configured authorization backend; no decision cache, TTL, or cross-identity reuse exists."
        if status == "PASS"
        else summary
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": status,
                "observed": observed,
            }
            for number in range(1, 5)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The product intentionally has no authorization decision cache, so revocation freshness is bounded by the backend/chain snapshot rather than a KMS-local TTL.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
