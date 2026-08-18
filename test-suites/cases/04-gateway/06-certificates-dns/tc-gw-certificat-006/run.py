#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the current candidate Gateway wildcard SNI certificate store."""

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
    status = "PASS" if completed.returncode == 0 and passed == 6 else "FAIL"
    rows = {
        "returncode": completed.returncode,
        "passed_tests": passed,
        "expected_tests": 6,
        "duration_seconds": round(time.monotonic() - started, 3),
        "coverage": {
            "empty_store": "test_cert_store_basic" in output,
            "builder_and_lookup": "test_cert_store_builder" in output,
            "single_label_wildcard": "test_cert_store_wildcard" in output,
            "mismatched_key_rejected": "mismatched_key_update_retains_previous_certificate"
            in output,
            "unrelated_update_survives_expired_entry": "expired_certificate_does_not_block_another_domain_update"
            in output,
            "expired_update_rejected": "expired_update_retains_previous_certificate"
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
            "observed": "Empty-store, builder lookup, and one-label wildcard boundaries were exercised by the complete current six-test module.",
        },
        {
            "id": f"{CASE_ID}-step-03",
            "status": status,
            "observed": "Expired and mismatched updates retained valid state, while an expired entry did not block an unrelated domain update.",
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
        "summary": "Gateway wildcard certificate-store lookup and current hot-reload rejection behavior passed."
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
