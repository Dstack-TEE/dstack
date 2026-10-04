#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate Gateway inbound PROXY protocol parsing boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-gw-proxy-prot-001"
FILTER = "pp::tests"
MINIMUM_TESTS = 9
# PR #1278: header lengths around the fixed-buffer cutoff and a v1 header
# ending on a bare CR must return rather than abort the gateway.
REQUIRED_TESTS = (
    "pp::tests::representative_v2_header_lengths_do_not_abort",
    "pp::tests::a_v1_header_ending_on_a_bare_cr_does_not_abort",
)


def main() -> int:
    """Run the focused candidate protocol matrix and emit bounded evidence."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported Gateway proxy protocol case: {case_id}")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    process = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "dstack-gateway",
            FILTER,
            "--",
            "--nocapture",
        ],
        cwd=Path(runtime["repository"]) / "dstack",
        env=environment,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    output = process.stdout + process.stderr
    matches = [int(value) for value in re.findall(r"(\d+) passed; 0 failed", output)]
    passed_tests = max(matches, default=0)
    required_passed = all(f"test {name} ... ok" in output for name in REQUIRED_TESTS)
    passed = (
        process.returncode == 0 and passed_tests >= MINIMUM_TESTS and required_passed
    )
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "cargo_target_dir_shared": True,
        "filter": FILTER,
        "minimum_tests": MINIMUM_TESTS,
        "passed_tests": passed_tests,
        "required_tests_passed": required_passed,
        "returncode": process.returncode,
        "coverage": [
            "PROXY v1 IPv4 source and destination",
            "PROXY v2 IPv4 source and destination",
            "missing protocol prefix rejection",
            "unterminated v1 rejection",
            "oversized v2 rejection",
            "synthetic unspecified address display",
            "v2 source display",
            "v2 header lengths never reach the unchecked advance",
            "v1 header ending on a bare CR",
        ],
        "mutable_fixture_reused": False,
    }
    if not passed:
        evidence["diagnostic_tail"] = output[-3000:]
    artifact = result_dir / "artifacts/gateway-proxy-protocol-unit.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        f"{passed_tests} candidate inbound PROXY protocol tests passed."
        if passed
        else "Candidate inbound PROXY protocol matrix failed."
    )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{case_id}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/gateway-proxy-protocol-unit.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": (
            "The immutable Cargo target is shared with compatible cases; the raw lease and evidence "
            "remain case-scoped. No Gateway cluster, VM, listener, credential, or backend is needed."
        ),
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
