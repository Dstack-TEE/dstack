#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate Gateway SNI selection and atomic certificate reload."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-gw-certificat-006"
RESULT = re.compile(r"test result: ok\. (\d+) passed; 0 failed")


def main() -> int:
    """Run the candidate cert-store behavior matrix and emit bounded evidence."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    target = Path(runtime["cargo_target_dir"])
    started = time.monotonic()
    command = [
        "/home/kvin/.cargo/bin/cargo",
        "test",
        "-p",
        "dstack-gateway",
        "cert_store::tests",
        "--",
        "--nocapture",
    ]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(target)
    completed = subprocess.run(
        command,
        cwd=repository / "dstack",
        env=environment,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    output = completed.stdout + completed.stderr
    (artifacts / "cert-store-tests.log").write_text(output)
    passed = sum(int(value) for value in RESULT.findall(output))
    status = "PASS" if completed.returncode == 0 and passed >= 8 else "FAIL"
    rows = {
        "returncode": completed.returncode,
        "passed_tests": passed,
        "minimum_expected": 8,
        "duration_seconds": round(time.monotonic() - started, 3),
        "coverage": {
            "exact_precedes_wildcard": "exact_certificate_precedes_parent_wildcard"
            in output,
            "single_label_wildcard": "test_cert_store_wildcard" in output,
            "mismatched_key_rejected": "mismatched_key_update_retains_previous_certificate"
            in output,
            "expired_rejected": "expired_update_retains_previous_certificate" in output,
            "corrupt_rejected": "corrupt_update_retains_previous_certificate" in output,
            "atomic_concurrent_reload": "concurrent_reads_never_observe_empty_during_reload"
            in output,
        },
    }
    if not all(rows["coverage"].values()):
        status = "FAIL"
    observation = artifacts / "cert-store-observation.json"
    observation.write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    steps = [
        {
            "id": f"{CASE_ID}-step-01",
            "status": status,
            "observed": f"Candidate cert-store suite executed {passed} tests from the committed source and shared Cargo target.",
        },
        {
            "id": f"{CASE_ID}-step-02",
            "status": status,
            "observed": "Exact SNI precedence, one-label wildcard boundaries, corrupt/expired/mismatched rejection, and four-reader atomic reload were exercised.",
        },
        {
            "id": f"{CASE_ID}-step-03",
            "status": status,
            "observed": "Rejected updates retained the previous SNI-resolvable certificate and concurrent readers observed no empty store.",
        },
    ]
    artifact_rows = [
        {
            "path": "artifacts/cert-store-tests.log",
            "name": "Candidate cert-store test output",
            "description": "Bounded test names and aggregate results; generated certificate and private-key material is never printed.",
        },
        {
            "path": "artifacts/cert-store-observation.json",
            "name": "Certificate-store behavior matrix",
            "description": "Return code, counts, duration, and non-secret coverage booleans.",
        },
    ]
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": artifact_rows}, indent=2) + "\n"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": "Gateway certificate-store SNI precedence and atomic hot reload passed."
        if status == "PASS"
        else f"Gateway certificate-store matrix failed: rc={completed.returncode}, passed={passed}",
        "steps": steps,
        "artifacts": artifact_rows,
        "remarks": "No certificate body, private key, credential, or native secret response is retained.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
