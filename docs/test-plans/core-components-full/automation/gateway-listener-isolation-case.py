#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway admin authentication and listener isolation."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-gw-cluster-ad-005"


def load_support() -> Any:
    """Load bounded HTTP and artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_listener_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def get(url: str) -> tuple[int, bytes]:
    """Issue a bounded GET request."""
    request = urllib.request.Request(url, method="GET")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def post(url: str, token: str | None) -> tuple[int, bytes]:
    """Issue a bounded JSON POST to a case-owned TLS endpoint."""
    request = urllib.request.Request(url, data=b"{}", method="POST")
    request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=10, context=context) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def main() -> int:
    """Run authentication, namespace isolation, and availability checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    admin = str(gateway["admin_url"]).rstrip("/")
    public = str(gateway["rpc_url"]).rstrip("/")
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "Gateway listener isolation did not complete"
    try:
        auth_code, auth_body = post(f"{admin}/Admin.Status", token)
        absent_code, absent_body = post(f"{admin}/Admin.Status", None)
        wrong_code, wrong_body = post(f"{admin}/Admin.Status", "wrong-case-token")
        public_admin_code, public_admin_body = post(f"{public}/Admin.Status", None)
        public_info_code, public_info_body = post(f"{public}/Tproxy.Info", None)
        admin_public_code, admin_public_body = post(f"{admin}/Tproxy.Info", token)
        public_parts = urllib.parse.urlsplit(public)
        public_health = urllib.parse.urlunsplit(
            (public_parts.scheme, public_parts.netloc, "/health", "", "")
        )
        health_code, health_body = get(public_health)
        bodies = [
            auth_body,
            absent_body,
            wrong_body,
            public_admin_body,
            public_info_body,
            admin_public_body,
            health_body,
        ]
        checks = {
            "authorized_admin_succeeds": auth_code == 200,
            "missing_token_rejected": absent_code in {401, 403},
            "wrong_token_rejected": wrong_code in {401, 403},
            "admin_absent_on_public_listener": public_admin_code in {400, 404},
            "public_rpc_available": public_info_code == 200,
            "public_rpc_absent_on_admin_listener": admin_public_code in {400, 404},
            "public_health_available": health_code == 200,
            "credential_not_disclosed": all(token.encode() not in body for body in bodies),
        }
        if not all(checks.values()):
            raise AssertionError(
                f"listener checks failed: {sorted(k for k, value in checks.items() if not value)}; health_http={health_code}"
            )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The case-owned public and admin listeners were independently healthy.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Admin.Status accepted the configured bearer identity and rejected missing and incorrect identities.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Admin and public RPC namespaces were mutually unavailable on the opposite listener while the public health endpoint remained bounded and responsive.",
            },
        ]
        observation = {
            "checks": checks,
            "authorized_admin_http": auth_code,
            "missing_token_http": absent_code,
            "wrong_token_http": wrong_code,
            "admin_on_public_http": public_admin_code,
            "public_rpc_http": public_info_code,
            "public_on_admin_http": admin_public_code,
            "public_health_http": health_code,
        }
        path = result_dir / "artifacts/gateway-listener-isolation.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-listener-isolation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Listener isolation matrix",
                "description": "HTTP statuses and boolean assertions only; no bearer credential or response payload is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway admin authentication, namespace isolation, redaction, public RPC availability, and bounded health response passed."
    except Exception as error:  # noqa: BLE001
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append(
                {
                    "id": f"{CASE_ID}-step-{index:02d}",
                    "status": "FAIL" if index == failed else "NOT_RUN",
                    "observed": str(error) if index == failed else "Not run after failure.",
                }
            )
        summary = f"Gateway listener isolation failed: {error}"
    SUPPORT.atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    SUPPORT.atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "No bearer credential or native response body is retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
