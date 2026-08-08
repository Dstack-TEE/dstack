#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify that the removed KMS certificate-log surface stays absent."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import tomllib
from pathlib import Path

CASE_ID = "tc-kms-ct-001"
RESULT_RE = re.compile(r"test result: ok\. (\d+) passed; 0 failed")


def main() -> int:
    """Check the removed surface and execute the current KMS library tests."""
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    kms = repository / "dstack/kms"
    cargo = tomllib.loads((kms / "Cargo.toml").read_text())
    main_source = (kms / "src/main.rs").read_text()

    checks = {
        "candidate_head_exact": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        == subprocess.check_output(
            ["git", "rev-parse", str(runtime["candidate_commit"])],
            cwd=repository,
            text=True,
        ).strip(),
        "ct_log_source_absent": not (kms / "src/ct_log.rs").exists(),
        "ct_log_module_absent": re.search(
            r"^\s*(?://\s*)?mod\s+ct_log\s*;", main_source, re.MULTILINE
        )
        is None,
        "cert_log_configuration_absent": "cert_log_dir" not in "".join(
            path.read_text(errors="replace")
            for path in sorted((kms / "src").glob("**/*.rs"))
        ),
        "dead_chrono_dependency_absent": "chrono"
        not in cargo.get("dependencies", {}),
    }
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = runtime["cargo_target_dir"]
    completed = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "-p", "dstack-kms"],
        cwd=repository / "dstack",
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
        check=False,
    )
    (artifacts / "cargo-test.log").write_text(completed.stdout)
    passed_tests = max(
        (int(value) for value in RESULT_RE.findall(completed.stdout)), default=0
    )
    checks["kms_library_tests_pass"] = completed.returncode == 0 and passed_tests > 0
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "kms_library_tests_passed": passed_tests,
        "returncode": completed.returncode,
        "private_material_persisted": False,
    }
    evidence_path = artifacts / "removed-certificate-log-surface.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact_rows = [
        {
            "path": f"artifacts/{path.name}",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in (evidence_path, artifacts / "cargo-test.log")
    ]
    failed = sorted(name for name, passed in checks.items() if not passed)
    observed = (
        f"Removed certificate-log surface remained absent and {passed_tests} current KMS library tests passed."
        if status == "PASS"
        else f"Removed certificate-log regression checks failed: {failed}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{CASE_ID}-step-{step:02d}", "status": status, "observed": observed}
            for step in range(1, 4)
        ],
        "evidence": artifact_rows,
        "duration_seconds": round(time.monotonic() - started, 3),
        "remarks": "The removed module had no production call site. This regression prevents its unsafe file-writing and configuration surface from returning silently.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
