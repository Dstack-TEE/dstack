#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise attested Gateway CVM registration and identity collision handling."""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import pathlib
import ssl
import sys
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-gw-registrati-001"


def load_support() -> Any:
    """Load bounded Gateway HTTP and atomic artifact helpers."""
    path = pathlib.Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_registration_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def tls_rpc(
    url: str,
    value: dict[str, Any],
    identity: dict[str, str] | None,
) -> tuple[int, bytes]:
    """Call a case-owned self-signed Gateway endpoint with optional mTLS identity."""
    request = urllib.request.Request(
        url,
        data=json.dumps(value).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if identity is not None:
        context.load_cert_chain(identity["cert"], identity["key"])
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def decoded(body: bytes) -> dict[str, Any]:
    """Decode a JSON response without retaining its native bytes."""
    try:
        return json.loads(body) if body else {}
    except json.JSONDecodeError:
        return {}


def main() -> int:
    """Run registration, re-registration, policy, collision, and authorization paths."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    identity = gateway["registration_client"]
    app_id = str(gateway["registered_app_id"])
    instance_id = str(gateway["registered_instance_id"])
    rpc_base = str(gateway["rpc_url"]).rstrip("/")
    debug_base = str(gateway["debug_url"]).rstrip("/")
    admin_base = str(gateway["admin_url"]).rstrip("/")
    token = pathlib.Path(gateway["admin_auth_token_file"]).read_text().strip()
    steps: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    status = "FAIL"
    summary = "registration matrix did not complete"
    artifacts: list[dict[str, str]] = []

    try:
        sync_code, sync_body = SUPPORT.http_call(
            f"{debug_base}/Debug.GetSyncData", b"{}", "application/json", None
        )
        baseline_instances = decoded(sync_body).get("instances", [])
        baseline = next(
            (
                row
                for row in baseline_instances
                if row.get("instance_id") == instance_id
            ),
            None,
        )
        checks["attested_baseline"] = (
            sync_code == 200
            and baseline is not None
            and baseline.get("app_id") == app_id
            and bool(baseline.get("ip"))
        )
        if not checks["attested_baseline"]:
            raise AssertionError("attested fixture registration missing")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The lease-owned simulator identity completed mTLS registration and appeared once in Gateway state.",
            }
        )

        client_key = base64.b64encode(os.urandom(32)).decode()
        request = {
            "client_public_key": client_key,
            "port_policy": {
                "ports": [{"port": 443, "pp": True}],
                "restrict_mode": True,
            },
        }
        register_url = f"{rpc_base}/Gateway.RegisterCvm?json"
        first_code, first_body = tls_rpc(register_url, request, identity)
        repeat_code, repeat_body = tls_rpc(register_url, request, identity)
        first_ip = (decoded(first_body).get("wg") or {}).get("client_ip", "")
        repeat_ip = (decoded(repeat_body).get("wg") or {}).get("client_ip", "")
        policy_code, policy_body = SUPPORT.rpc(
            admin_base,
            token,
            "Admin.GetInstancePortPolicy",
            {"instance_id": instance_id},
        )
        policy = decoded(policy_body).get("effective") or {}
        checks["deterministic_reregistration"] = (
            first_code == 200
            and repeat_code == 200
            and bool(first_ip)
            and first_ip == repeat_ip == baseline["ip"]
            and policy_code == 200
            and bool(policy.get("restrict_mode", policy.get("restrictMode", False)))
            and len(policy.get("ports", [])) == 1
        )

        duplicate_key_code = SUPPORT.rpc(
            debug_base,
            "",
            "Debug.RegisterCvm",
            {
                "app_id": app_id,
                "instance_id": f"collision-{instance_id}",
                "client_public_key": client_key,
            },
        )[0]
        duplicate_instance_code = SUPPORT.rpc(
            debug_base,
            "",
            "Debug.RegisterCvm",
            {
                "app_id": f"different-{app_id}",
                "instance_id": instance_id,
                "client_public_key": base64.b64encode(os.urandom(32)).decode(),
            },
        )[0]
        unauthenticated_code = tls_rpc(register_url, request, None)[0]
        invalid_key_code = SUPPORT.rpc(
            debug_base,
            "",
            "Debug.RegisterCvm",
            {
                "app_id": app_id,
                "instance_id": f"invalid-{instance_id}",
                "client_public_key": "invalid",
            },
        )[0]
        checks["identity_collisions_rejected"] = (
            duplicate_key_code >= 400
            and duplicate_instance_code >= 400
            and unauthenticated_code >= 400
            and invalid_key_code >= 400
        )

        changed_request = {
            "client_public_key": client_key,
            "port_policy": {
                "ports": [{"port": 8443, "pp": False}],
                "restrict_mode": True,
            },
        }
        changed_code = tls_rpc(register_url, changed_request, identity)[0]
        changed_policy_code, changed_policy_body = SUPPORT.rpc(
            admin_base,
            token,
            "Admin.GetInstancePortPolicy",
            {"instance_id": instance_id},
        )
        changed_policy = decoded(changed_policy_body).get("effective") or {}
        checks["policy_update_without_duplicate"] = (
            changed_code == 200
            and changed_policy_code == 200
            and [row.get("port") for row in changed_policy.get("ports", [])] == [8443]
        )
        final_sync_code, final_sync_body = SUPPORT.http_call(
            f"{debug_base}/Debug.GetSyncData", b"{}", "application/json", None
        )
        final_instances = decoded(final_sync_body).get("instances", [])
        checks["single_instance_state"] = (
            final_sync_code == 200
            and sum(row.get("instance_id") == instance_id for row in final_instances)
            == 1
            and not any(
                str(row.get("instance_id", "")).startswith(("collision-", "invalid-"))
                for row in final_instances
            )
        )
        if not all(checks.values()):
            raise AssertionError(
                f"registration checks failed: {sorted(k for k, v in checks.items() if not v)}"
            )
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Re-registration retained one allocation, updated the reported port policy, and rejected duplicate key/instance and invalid key states.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Unauthenticated registration failed and final synchronized state retained exactly one attested instance.",
                },
            ]
        )
        observation = {
            "checks": checks,
            "baseline_instance_count": len(baseline_instances),
            "first_http": first_code,
            "repeat_http": repeat_code,
            "same_allocation": first_ip == repeat_ip == baseline["ip"],
            "duplicate_key_http": duplicate_key_code,
            "duplicate_instance_http": duplicate_instance_code,
            "unauthenticated_http": unauthenticated_code,
            "invalid_key_http": invalid_key_code,
            "changed_policy_http": changed_code,
            "final_instance_count": len(final_instances),
        }
        artifact_path = result_dir / "artifacts/gateway-registration-observation.json"
        SUPPORT.atomic_json(artifact_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-registration-observation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Registration lifecycle assertions",
                "description": "Status codes, counts, and allocation-equality booleans only; no identity certificate, key, token, or WireGuard key is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway attested registration, deterministic re-registration, collision rejection, policy update, authorization, and state isolation passed."
    except Exception as error:  # noqa: BLE001
        summary = f"Gateway registration matrix failed: {error}"
        failed = len(steps) + 1
        for index in range(failed, 4):
            steps.append(
                {
                    "id": f"{CASE_ID}-step-{index:02d}",
                    "status": "FAIL" if index == failed else "NOT_RUN",
                    "observed": str(error)
                    if index == failed
                    else "Not run after failure.",
                }
            )
    SUPPORT.atomic_json(
        result_dir / "artifacts/manifest.json", {"artifacts": artifacts}
    )
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
            "remarks": "No identity certificate, private key, admin token, WireGuard key, or native attestation response is retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
