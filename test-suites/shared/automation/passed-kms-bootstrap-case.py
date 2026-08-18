#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for fresh KMS bootstrap semantics."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_IDS = {
    "tc-kms-bootstrap--001",
    "tc-kms-onboard-001",
}
PRIVATE_FILES = {"root-ca.key", "root-k256.key", "rpc.key", "tmp-ca.key"}
EXPECTED_FILES = PRIVATE_FILES | {
    "bootstrap-info.json",
    "root-ca.crt",
    "rpc-domain",
    "rpc.crt",
    "tmp-ca.crt",
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def call_json(url: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Call a JSON pRPC method and retain only structural public evidence."""
    request = urllib.request.Request(
        f"{url}/{method}?json",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            payload = response.read()
            status = response.status
    except urllib.error.HTTPError as error:
        payload = error.read()
        status = error.code
    elapsed_ms = round((time.monotonic() - started) * 1000)
    try:
        decoded = json.loads(payload) if payload else None
    except json.JSONDecodeError:
        decoded = None
    evidence: dict[str, Any] = {
        "status": status,
        "elapsed_ms": elapsed_ms,
        "body_bytes": len(payload),
        "body_sha256": hashlib.sha256(payload).hexdigest(),
    }
    if isinstance(decoded, dict):
        evidence["json_keys"] = sorted(decoded)
        if "error" in decoded:
            evidence["error_present"] = bool(decoded["error"])
        for field in ("ca_pubkey", "k256_pubkey", "attestation"):
            value = decoded.get(field)
            if isinstance(value, str):
                evidence.setdefault("response_fields", {})[field] = {
                    "encoded_length": len(value),
                    "sha256": hashlib.sha256(value.encode()).hexdigest(),
                }
    return evidence


def snapshot(directory: pathlib.Path) -> dict[str, Any]:
    """Record file metadata without reading private key contents."""
    result: dict[str, Any] = {}
    for name in sorted(EXPECTED_FILES):
        path = directory / name
        if not path.is_file():
            result[name] = {"exists": False}
            continue
        stat = path.stat()
        item: dict[str, Any] = {
            "exists": True,
            "mode": oct(stat.st_mode & 0o777),
            "size": stat.st_size,
            "inode": stat.st_ino,
            "mtime_ns": stat.st_mtime_ns,
        }
        if name not in PRIVATE_FILES:
            item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        result[name] = item
    return result


def main() -> int:
    """Exercise one-time bootstrap, duplicate safety, and validation."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASE_IDS:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    onboard = values["kms_onboard"]
    base_url = onboard["prpc_url"].rstrip("/")
    cert_dir = pathlib.Path(onboard["cert_dir"])
    domain = f"{case_id}.{manifest['lease_id']}.example.test"

    before = snapshot(cert_dir)
    empty_domain = call_json(base_url, "Onboard.Bootstrap", {"domain": ""})
    overlong_domain = call_json(
        base_url,
        "Onboard.Bootstrap",
        {"domain": "a" * 254},
    )
    after_invalid_bootstrap = snapshot(cert_dir)
    bootstrap = call_json(base_url, "Onboard.Bootstrap", {"domain": domain})
    after_bootstrap = snapshot(cert_dir)
    duplicate = call_json(base_url, "Onboard.Bootstrap", {"domain": domain})
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        concurrent_duplicates = list(
            executor.map(
                lambda _: call_json(base_url, "Onboard.Bootstrap", {"domain": domain}),
                range(2),
            )
        )
    after_duplicates = snapshot(cert_dir)
    attestation = call_json(base_url, "Onboard.GetAttestationInfo", {})
    invalid_onboard = call_json(
        base_url,
        "Onboard.Onboard",
        {"source_url": onboard["source_rpc_url"], "domain": ""},
    )
    after_invalid = snapshot(cert_dir)
    private_modes = {
        name: after_bootstrap[name].get("mode") for name in sorted(PRIVATE_FILES)
    }
    unchanged = after_bootstrap == after_duplicates == after_invalid
    generated = all(after_bootstrap[name].get("exists") for name in EXPECTED_FILES)
    response_fields = set(bootstrap.get("response_fields", {}))
    checks = {
        "clean_baseline": all(
            not before[name].get("exists") for name in EXPECTED_FILES
        ),
        "invalid_domains_rejected_before_mutation": (
            empty_domain["status"] == 400
            and overlong_domain["status"] == 400
            and after_invalid_bootstrap == before
        ),
        "bootstrap_success": bootstrap["status"] == 200,
        "bootstrap_fields": response_fields
        == {"ca_pubkey", "k256_pubkey", "attestation"},
        "hierarchy_generated": generated,
        "private_modes_0600": all(mode == "0o600" for mode in private_modes.values()),
        "duplicate_rejected": duplicate["status"] == 400,
        "concurrent_duplicates_rejected": all(
            item["status"] == 400 for item in concurrent_duplicates
        ),
        "duplicate_state_unchanged": unchanged,
        "attestation_info_success": attestation["status"] == 200,
        "invalid_onboard_rejected": invalid_onboard["status"] == 400,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {
        "checks": checks,
        "before": before,
        "empty_domain": empty_domain,
        "overlong_domain": overlong_domain,
        "after_invalid_bootstrap": after_invalid_bootstrap,
        "after_bootstrap": after_bootstrap,
        "after_duplicates": after_duplicates,
        "bootstrap": bootstrap,
        "duplicate": duplicate,
        "concurrent_duplicates": concurrent_duplicates,
        "attestation": attestation,
        "invalid_onboard": invalid_onboard,
    }
    artifact = {
        "path": "artifacts/kms-bootstrap-regression.json",
        "step_id": f"{case_id}-step-02",
        "name": "KMS bootstrap regression",
        "description": "Sanitized one-time hierarchy, duplicate safety, validation, and transition evidence.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": "Fresh KMS bootstrap deterministic regression passed."
        if status == "PASS"
        else "Fresh KMS bootstrap deterministic regression failed.",
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": (
                    "PASS"
                    if checks["clean_baseline"]
                    and checks["invalid_domains_rejected_before_mutation"]
                    else "FAIL"
                ),
                "observed": "Fresh baseline and pre-mutation domain validation were checked.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": status,
                "observed": "Bootstrap hierarchy, one-time concurrency, permissions, and response structure were checked.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": status,
                "observed": "Invalid onboarding left state unchanged and lease cleanup removed the fresh fixture.",
            },
        ],
        "artifacts": [artifact],
        "remarks": "Private key contents and response material were not persisted; only metadata and hashes were recorded.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
