#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Audit KMS and Gateway failure surfaces for credential and secret disclosure."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-int-failure-se-005"
AUTOMATION = pathlib.Path(__file__).resolve().parent


def request(
    url: str, body: bytes | None = None, headers: dict[str, str] | None = None
) -> tuple[int, bytes]:
    """Issue one bounded HTTP request without retaining its body."""
    req = urllib.request.Request(
        url,
        data=body,
        headers=headers or {},
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(
            req, timeout=20, context=ssl._create_unverified_context()
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()
    except urllib.error.URLError:
        return 0, b""


def run_shared(script: str, case_id: str, manifest_path: str) -> dict[str, Any]:
    """Execute a proven component matrix in an isolated nested result directory."""
    with tempfile.TemporaryDirectory(prefix="dstack-redaction-shared-") as directory:
        env = {
            **os.environ,
            "DSTACK_TEST_CASE_ID": case_id,
            "DSTACK_TEST_RESULT_DIR": directory,
            "DSTACK_TEST_CASE_MANIFEST": manifest_path,
        }
        completed = subprocess.run(
            ["python3", str(AUTOMATION / script)],
            env=env,
            capture_output=True,
            text=True,
            timeout=240,
            check=False,
        )
        result_path = pathlib.Path(directory) / "result.json"
        result = json.loads(result_path.read_text()) if result_path.is_file() else {}
        if completed.returncode or result.get("status") != "PASS":
            summary = result.get("summary") or completed.stderr[-300:]
            raise AssertionError(f"{script} failed: {summary}")
        return {
            "status": "PASS",
            "summary_sha256": hashlib.sha256(
                str(result.get("summary", "")).encode()
            ).hexdigest(),
        }


def scan_bytes(paths: list[pathlib.Path], needles: dict[str, bytes]) -> dict[str, Any]:
    """Scan bounded case-owned files and return counts without file contents."""
    findings: dict[str, int] = {name: 0 for name in needles}
    files = 0
    for path in paths:
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 32 * 1024 * 1024:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        files += 1
        for name, value in needles.items():
            if value and value in data:
                findings[name] += 1
    return {
        "files_scanned": files,
        "matches": findings,
        "clean": not any(findings.values()),
    }


def main() -> int:
    """Run the combined credential, failure-surface, and recovery audit."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest_path = os.environ["DSTACK_TEST_CASE_MANIFEST"]
    manifest = json.loads(pathlib.Path(manifest_path).read_text())
    values = manifest["values"]
    kms, gateway = values["kms"], values["gateway"]
    lease = str(manifest.get("lease_id", "lease"))[-12:].replace("-", "")
    sentinels = {
        name: f"redact-{name}-{lease}-Q7m4V9".encode()
        for name in (
            "admin-token",
            "private-key",
            "encrypted-env",
            "disk-key",
            "dns-credential",
            "quote",
            "csr",
        )
    }
    evidence: dict[str, Any] = {"groups": {}, "native_material_persisted": False}
    status, failure = "FAIL", ""
    try:
        evidence["groups"]["kms_admin_transport"] = run_shared(
            "kms-admin-transport-case.py", "tc-kms-keys-certs-007", manifest_path
        )
        evidence["groups"]["gateway_dns_credentials"] = run_shared(
            "gateway-dns-credential-case.py", "tc-gw-certificat-003", manifest_path
        )
        evidence["groups"]["csr_quote_mutations"] = run_shared(
            "kms-sign-cert-case.py", "tc-kms-keys-certs-004", manifest_path
        )

        failure_rows: dict[str, dict[str, int | bool]] = {}
        endpoints = {
            "kms_admin": f"{str(kms['admin_url']).rstrip('/')}/Admin.ClearImageCache",
            "gateway_admin": f"{str(gateway['admin_url']).rstrip('/')}/Admin.ListDnsCredentials",
        }
        for endpoint_name, url in endpoints.items():
            for secret_name, secret in sentinels.items():
                body = b'{"invalid":"' + secret + b'","unterminated":'
                code, response = request(
                    url,
                    body,
                    {
                        "content-type": "application/json",
                        "authorization": "Bearer " + secret.decode(),
                    },
                )
                leaked = secret in response
                if code < 400 or leaked:
                    raise AssertionError(
                        f"{endpoint_name}/{secret_name} rejection was unsafe: status={code}, leaked={leaked}"
                    )
                failure_rows[f"{endpoint_name}_{secret_name}"] = {
                    "status": code,
                    "response_length": len(response),
                    "leaked": leaked,
                }
        evidence["groups"]["malformed_failure_rows"] = {
            "passed": len(failure_rows),
            "total": 14,
            "rows": failure_rows,
        }

        surface_rows: dict[str, dict[str, int | bool]] = {}
        urls = {
            "kms_metrics": kms["metrics_url"],
            "gateway_health": gateway["health_url"],
            "gateway_dashboard": gateway["dashboard_url"],
            "gateway_debug": gateway["debug_url"],
        }
        for name, url in urls.items():
            code, body = request(str(url))
            matches = sum(secret in body for secret in sentinels.values())
            if matches:
                raise AssertionError(f"{name} disclosed a run sentinel")
            surface_rows[name] = {
                "status": code,
                "length": len(body),
                "matches": matches,
            }
        evidence["groups"]["public_surfaces"] = surface_rows

        scan_paths = [pathlib.Path(kms["log"]), pathlib.Path(gateway["log"])]
        substrate = values["component_substrate"]
        for key in ("log_dir", "run_dir"):
            root = pathlib.Path(substrate[key])
            if root.exists():
                scan_paths.extend(path for path in root.rglob("*") if path.is_file())
        scan = scan_bytes(scan_paths, sentinels)
        if not scan["clean"]:
            raise AssertionError(
                "a component log/runtime surface retained a run sentinel"
            )
        evidence["groups"]["bounded_file_scan"] = scan
        gateway_token = (
            pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
        )
        evidence["groups"]["recovery"] = {
            "kms_metrics_status": request(str(kms["metrics_url"]))[0],
            "gateway_health_status": request(
                str(gateway["health_url"]),
                headers={"Authorization": f"Bearer {gateway_token}"},
            )[0],
        }
        if (
            evidence["groups"]["recovery"]["kms_metrics_status"] != 200
            or evidence["groups"]["recovery"]["gateway_health_status"] != 200
        ):
            raise AssertionError(
                "service health did not recover after rejection matrix"
            )
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        evidence["failure"] = failure

    evidence_path = artifacts / "secret-redaction-audit.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/secret-redaction-audit.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Combined secret redaction audit",
        "description": "Sanitized statuses, lengths, counts, hashes, and disclosure booleans; no native credential material.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "KMS and Gateway redaction audit passed across 3 shared matrices, 14 malformed failures, 4 public surfaces, bounded files, and recovery"
        if status == "PASS"
        else failure
    )
    steps = [
        {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
        for n in range(1, 4)
    ]
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": steps,
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "All generated sentinels and fixture credentials remained memory-only; evidence contains only bounded metadata.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
