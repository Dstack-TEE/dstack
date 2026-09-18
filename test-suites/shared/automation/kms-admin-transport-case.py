#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise all compatible KMS admin-token transports and rejection rows."""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path

CASE_ID = "tc-kms-keys-certs-007"


def call(url: str, headers: dict[str, str]) -> tuple[int, int]:
    """Call the empty idempotent admin operation with explicit headers."""
    request = urllib.request.Request(
        url,
        data=b"{}",
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    started = time.monotonic_ns()
    try:
        with urllib.request.urlopen(
            request, timeout=20, context=ssl._create_unverified_context()
        ) as response:
            response.read()
            status = int(response.status)
    except urllib.error.HTTPError as error:
        error.read()
        status = int(error.code)
    return status, (time.monotonic_ns() - started) // 1_000


def main() -> int:
    """Run compatible, mixed, missing, malformed, prefix, and redaction rows."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    kms = manifest["values"]["kms"]
    token = Path(kms["admin_auth_token_file"]).read_text().strip()
    if len(token) < 16:
        raise RuntimeError("case-owned admin token is unexpectedly short")
    url = f"{str(kms['admin_url']).rstrip('/')}/Admin.ClearImageCache"
    invalid = "x" * len(token)
    rows = {
        "bearer_valid": ({"Authorization": f"Bearer {token}"}, True),
        "x_token_valid": ({"X-Admin-Token": token}, True),
        "both_valid": (
            {"Authorization": f"Bearer {token}", "X-Admin-Token": token},
            True,
        ),
        "bearer_valid_x_invalid": (
            {"Authorization": f"Bearer {token}", "X-Admin-Token": invalid},
            True,
        ),
        "bearer_invalid_x_valid": (
            {"Authorization": f"Bearer {invalid}", "X-Admin-Token": token},
            True,
        ),
        "missing": ({}, False),
        "malformed_bearer": ({"Authorization": token}, False),
        "both_invalid": (
            {"Authorization": f"Bearer {invalid}", "X-Admin-Token": invalid},
            False,
        ),
        "prefix_only": ({"Authorization": f"Bearer {token[:-1]}"}, False),
    }
    evidence: dict[str, object] = {"rows": {}, "credential_persisted": False}
    status = "PASS"
    failure = ""
    try:
        for name, (headers, accepted) in rows.items():
            code, elapsed_us = call(url, headers)
            if accepted and code != 200:
                raise AssertionError(f"{name} returned {code}, expected 200")
            if not accepted and code not in (401, 403):
                raise AssertionError(f"{name} returned {code}, expected rejection")
            evidence["rows"][name] = {
                "status": code,
                "accepted": accepted,
                "elapsed_us": elapsed_us,
            }
        log = Path(kms["log"]).read_text(errors="replace")
        if token in log:
            raise AssertionError("KMS log disclosed the admin token")
        evidence["log_redaction"] = True
    except Exception as error:  # noqa: BLE001
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
    artifact_path = artifacts / "kms-admin-transport.json"
    artifact_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/kms-admin-transport.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS admin transport matrix",
        "description": "Sanitized status, compatibility, bounded timing, and redaction observations.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "9/9 admin transport rows passed without token disclosure"
        if status == "PASS"
        else failure
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Credentials were read only from the case-owned token file and never written to evidence.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
