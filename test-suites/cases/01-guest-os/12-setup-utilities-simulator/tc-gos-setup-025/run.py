#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Run focused streaming-encryption regression tests."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-gos-setup-025"
REQUIRED = (
    "crypto::tests::test_stream_roundtrip",
    "crypto::tests::test_stream_rejects_tampering_and_truncation",
    "tests::decrypt_auto_detects_stream_and_falls_back_to_legacy",
    "tests::env_encrypt_public_key_requires_the_trusted_signer",
)


def main() -> int:
    """Execute the candidate dstack-util test boundary."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    completed = subprocess.run(
        ["cargo", "test", "--locked", "--offline", "-p", "dstack-util"],
        cwd=Path(str(runtime["repository"])) / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=600,
        check=False,
    )
    output = completed.stdout + completed.stderr
    checks = {name: f"test {name} ... ok" in output for name in REQUIRED}
    passed = completed.returncode == 0 and all(checks.values())
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence = artifacts / "stream-encryption-tests.json"
    evidence.write_text(
        json.dumps({"candidate_commit": runtime.get("candidate_commit"), "checks": checks}, indent=2) + "\n"
    )
    status = "PASS" if passed else "FAIL"
    observed = (
        "Streaming round-trip, malformed-frame rejection, legacy fallback, and trusted-signer tests passed."
        if passed
        else f"Streaming encryption checks failed: {sorted(k for k, value in checks.items() if not value)}"
    )
    result = {
        "schema_version": "1.0", "case_id": CASE_ID, "provisional": False,
        "status": status, "summary": observed,
        "steps": [{"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed} for n in range(1, 4)],
        "evidence": [{"path": "artifacts/stream-encryption-tests.json", "sha256": hashlib.sha256(evidence.read_bytes()).hexdigest()}],
        "remarks": "No plaintext, key, or ciphertext is retained.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
