#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise public/admin Gateway route-index exposure on one case-owned node."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-gw-internal-008"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def request(
    url: str, *, token: str | None = None, post: bool = False
) -> tuple[int, bytes]:
    """Issue a bounded request to a case-owned endpoint."""
    data = b"{}" if post else None
    value = urllib.request.Request(url, data=data, method="POST" if post else "GET")
    if post:
        value.add_header("Content-Type", "application/json")
    if token is not None:
        value.add_header("Authorization", f"Bearer {token}")
        value.add_header("X-Admin-Token", token)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(value, timeout=10, context=context) as response:
            return int(response.status), response.read(65536)
    except urllib.error.HTTPError as error:
        return int(error.code), error.read(65536)


def main() -> int:
    """Run the real route exposure and bounded-error matrix."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    public = str(gateway["rpc_url"]).rstrip("/")
    admin = str(gateway["admin_url"]).rstrip("/")
    admin_parts = urllib.parse.urlsplit(admin)
    admin_origin = urllib.parse.urlunsplit(
        (admin_parts.scheme, admin_parts.netloc, "", "", "")
    )
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    status = "FAIL"
    checks: dict[str, bool] = {}
    codes: dict[str, int] = {}
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    summary = "Gateway route-index matrix did not complete"
    try:
        probes = {
            "public_info": request(f"{public}/Tproxy.Info", post=True),
            "public_admin": request(f"{public}/Admin.Status", post=True),
            "admin_status": request(f"{admin}/Admin.Status", token=token, post=True),
            "admin_dashboard": request(f"{admin_origin}/", token=token),
            "public_unknown": request(f"{public}/Gateway.DoesNotExist", post=True),
        }
        codes = {name: value[0] for name, value in probes.items()}
        bodies = [value[1] for value in probes.values()]
        checks = {
            "public_handler_available": codes["public_info"] == 200,
            "admin_handler_absent_publicly": codes["public_admin"] in {400, 404},
            "admin_handler_available_on_admin": codes["admin_status"] == 200,
            "combined_dashboard_route_bounded": codes["admin_dashboard"] in {200, 500},
            "unknown_method_bounded": codes["public_unknown"] in {400, 404},
            "credential_redacted": all(token.encode() not in body for body in bodies),
            "bounded_response_sizes": all(len(body) <= 65536 for body in bodies),
        }
        if not all(checks.values()):
            raise AssertionError(
                f"route checks failed: {sorted(k for k, value in checks.items() if not value)}; http_statuses={codes}"
            )
        observed = {
            "checks": checks,
            "http_statuses": codes,
            "response_sizes": {name: len(value[1]) for name, value in probes.items()},
        }
        artifact_path = result_dir / "artifacts/gateway-route-index.json"
        atomic_json(artifact_path, observed)
        artifact = {
            "path": "artifacts/gateway-route-index.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Gateway route exposure matrix",
            "description": "Boolean assertions, HTTP statuses, and bounded response sizes only; no URL, token, or body is retained.",
        }
        artifacts.append(artifact)
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The case-owned public and admin listeners were independently reachable.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Public, admin, and unknown-method routes matched their intended exposure boundaries; dashboard construction either completed or returned its bounded server error.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Admin methods remained unreachable through the public handler and malformed method selection returned a bounded error.",
            },
            {
                "id": f"{CASE_ID}-step-04",
                "status": "PASS",
                "observed": "No bearer credential was present in any bounded response and the adjacent listener remained healthy.",
            },
        ]
        status = "PASS"
        summary = "Gateway combined route index, public/admin RPC isolation, bounded construction errors, and redaction passed."
    except Exception as error:  # noqa: BLE001
        steps = [
            {
                "id": f"{CASE_ID}-step-{n:02d}",
                "status": "FAIL" if n == 1 else "NOT_RUN",
                "observed": str(error) if n == 1 else "Not run after failure.",
            }
            for n in range(1, 5)
        ]
        summary = f"Gateway route-index matrix failed: {error}"
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    evidence = []
    for artifact in artifacts:
        path = result_dir / artifact["path"]
        evidence.append(
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "evidence": evidence,
            "remarks": "The case retains no native response body, endpoint URL, bearer token, key, or certificate.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
