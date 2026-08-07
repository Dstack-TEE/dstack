#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway debug service isolation and simulator state accuracy."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

CASE_ID = "tc-gw-cluster-ad-006"


def load_support() -> Any:
    """Load atomic artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_debug_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def post(url: str, value: dict[str, Any], token: str | None = None) -> tuple[int | None, dict[str, Any]]:
    """Issue a bounded JSON request to HTTP or case-owned TLS."""
    request = urllib.request.Request(url, data=json.dumps(value).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    if token is not None:
        request.add_header("Authorization", f"Bearer {token}")
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(request, timeout=5, context=context) as response:
            body = response.read()
            return int(response.status), json.loads(body) if body else {}
    except urllib.error.HTTPError as error:
        return int(error.code), {}
    except urllib.error.URLError:
        return None, {}


def listener_absent(url: str) -> bool:
    """Return true when the endpoint has no listening TCP socket."""
    parsed = urllib.parse.urlsplit(url)
    try:
        with socket.create_connection((parsed.hostname or "", parsed.port or 80), timeout=1):
            return False
    except OSError:
        return True


def main() -> int:
    """Verify debug-only behavior, production absence, and namespace isolation."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest["values"]
    debug_node = values["gateway_cluster"]["nodes"][0]
    production_node = values["gateway_production_node"]
    token = pathlib.Path(values["gateway_cluster"]["admin_auth_token_file"]).read_text().strip()
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "Gateway debug isolation did not complete"
    try:
        suffix = str(manifest["lease_id"])[-12:]
        app_id = f"debug-app-{suffix}"
        instance_id = f"debug-instance-{suffix}"
        public_key = base64.b64encode(os.urandom(32)).decode()
        debug = str(debug_node["debug_url"]).rstrip("/")
        public = str(debug_node["rpc_url"]).rstrip("/")
        admin = str(debug_node["admin_url"]).rstrip("/")
        prod_public = str(production_node["rpc_url"]).rstrip("/")
        prod_admin = str(production_node["admin_url"]).rstrip("/")
        prod_debug = str(production_node["debug_url"]).rstrip("/")

        register_code, _ = post(
            f"{debug}/Debug.RegisterCvm",
            {"app_id": app_id, "instance_id": instance_id, "client_public_key": public_key},
        )
        sync_code, sync = post(f"{debug}/Debug.GetSyncData", {})
        proxy_code, proxy = post(f"{debug}/Debug.GetProxyState", {})
        synced = [row for row in sync.get("instances", []) if row.get("instance_id") == instance_id]
        proxied = [row for row in proxy.get("instances", []) if row.get("instance_id") == instance_id]
        checks["debug_registration_and_state_accurate"] = (
            register_code == 200
            and sync_code == 200
            and proxy_code == 200
            and len(synced) == 1
            and len(proxied) == 1
            and synced[0].get("app_id") == app_id
            and proxied[0].get("app_id") == app_id
            and int(sync.get("my_node_id", 0)) == int(debug_node["node_id"])
        )

        public_debug_code, _ = post(f"{public}/Debug.GetSyncData", {})
        admin_debug_code, _ = post(f"{admin}/Debug.GetSyncData", {}, token)
        debug_admin_code, _ = post(f"{debug}/Admin.Status", {})
        checks["debug_namespace_isolated"] = (
            public_debug_code in {400, 404}
            and admin_debug_code in {400, 404}
            and debug_admin_code in {400, 404}
        )

        prod_info_code, _ = post(f"{prod_public}/Tproxy.Info", {})
        prod_admin_code, _ = post(f"{prod_admin}/Admin.Status", {}, token)
        checks["production_node_healthy"] = prod_info_code == 200 and prod_admin_code == 200
        checks["production_debug_listener_absent"] = listener_absent(prod_debug)

        if not all(checks.values()):
            raise AssertionError(
                f"debug isolation checks failed: {sorted(k for k, value in checks.items() if not value)}"
            )
        steps = [
            {"id": f"{CASE_ID}-step-01", "status": "PASS", "observed": "The simulator-only debug listener exposed the configured node identity and no pre-existing run-scoped object."},
            {"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": "Debug registration appeared exactly once in synchronized and proxy state, while debug methods were absent from public and admin namespaces."},
            {"id": f"{CASE_ID}-step-03", "status": "PASS", "observed": "A healthy production-configured cluster node exposed public/admin APIs with no debug TCP listener."},
        ]
        observation = {
            "checks": checks,
            "register_http": register_code,
            "sync_http": sync_code,
            "proxy_state_http": proxy_code,
            "synchronized_match_count": len(synced),
            "proxy_match_count": len(proxied),
            "public_debug_http": public_debug_code,
            "admin_debug_http": admin_debug_code,
            "debug_admin_http": debug_admin_code,
            "production_public_http": prod_info_code,
            "production_admin_http": prod_admin_code,
        }
        path = result_dir / "artifacts/gateway-debug-isolation.json"
        SUPPORT.atomic_json(path, observation)
        artifacts.append({"path": "artifacts/gateway-debug-isolation.json", "step_id": f"{CASE_ID}-step-02", "name": "Debug isolation matrix", "description": "HTTP statuses, counts, and boolean assertions only; no key, address, URL, credential, or response body is retained."})
        status = "PASS"
        summary = "Gateway simulator debug accuracy, listener namespace isolation, and production debug absence passed."
    except Exception as error:  # noqa: BLE001
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append({"id": f"{CASE_ID}-step-{index:02d}", "status": "FAIL" if index == failed else "NOT_RUN", "observed": str(error) if index == failed else "Not run after failure."})
        summary = f"Gateway debug isolation failed: {error}"
    SUPPORT.atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    SUPPORT.atomic_json(result_dir / "result.json", {"schema_version": "1.0", "case_id": CASE_ID, "provisional": False, "status": status, "summary": summary, "steps": steps, "artifacts": artifacts, "remarks": "No WireGuard key, allocated address, URL, bearer token, certificate, or native response body is retained."})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
