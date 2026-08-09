#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway WireGuard address allocation and recycle lifecycle."""

from __future__ import annotations

import base64
import concurrent.futures
import importlib.util
import ipaddress
import json
import os
import pathlib
import sys
import time
from typing import Any

CASE_ID = "tc-gw-registrati-002"


def load_support() -> Any:
    """Load the registration HTTP helpers."""
    path = pathlib.Path(__file__).with_name("gateway-registration-case.py")
    spec = importlib.util.spec_from_file_location("gateway_allocation_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load registration support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def register(
    debug_base: str, app: str, instance: str, key: str
) -> tuple[int, str, bool]:
    """Register one debug identity and classify the pRPC application result."""
    code, body = SUPPORT.SUPPORT.rpc(
        debug_base,
        "",
        "Debug.RegisterCvm",
        {"app_id": app, "instance_id": instance, "client_public_key": key},
    )
    value = SUPPORT.decoded(body)
    client_ip = str((value.get("wg") or {}).get("client_ip", ""))
    application_error = bool(value.get("error")) or not client_ip
    return code, client_ip, application_error


def main() -> int:
    """Run concurrent allocation, idempotence, expiry, and recycle paths."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    debug_base = str(gateway["debug_url"]).rstrip("/")
    lease = str(manifest.get("lease_id", "lease"))[-10:].replace("-", "")
    prefix = f"alloc-{lease}"
    steps: list[dict[str, str]] = []
    checks: dict[str, bool] = {}
    artifacts: list[dict[str, str]] = []
    status = "FAIL"
    summary = "allocation lifecycle did not complete"

    try:
        baseline_code, baseline_body = SUPPORT.SUPPORT.http_call(
            f"{debug_base}/Debug.GetSyncData", b"{}", "application/json", None
        )
        baseline_instances = SUPPORT.decoded(baseline_body).get("instances", [])
        checks["baseline_healthy"] = baseline_code == 200
        if not checks["baseline_healthy"]:
            raise AssertionError("debug baseline unavailable")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The lease-owned Gateway allocation state was queryable before run-scoped registrations.",
            }
        )

        count = 32
        first_rows = [
            (
                f"{prefix}-app",
                f"{prefix}-instance-{index:02d}",
                base64.b64encode(os.urandom(32)).decode(),
            )
            for index in range(count)
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            first_results = list(
                executor.map(lambda row: register(debug_base, *row), first_rows)
            )
        first_ips = [
            ip for code, ip, application_error in first_results
            if code == 200 and not application_error
        ]
        checks["concurrent_unique_allocation"] = (
            len(first_ips) == count
            and len(set(first_ips)) == count
            and all(ipaddress.ip_address(ip).version == 4 for ip in first_ips)
        )
        repeat_code, repeat_ip, repeat_error = register(debug_base, *first_rows[0])
        duplicate_code, _, duplicate_error = register(
            debug_base,
            first_rows[0][0],
            f"{prefix}-duplicate-key",
            first_rows[0][2],
        )
        checks["idempotent_and_collision_safe"] = (
            repeat_code == 200
            and not repeat_error
            and repeat_ip == first_results[0][1]
            and (duplicate_code >= 400 or duplicate_error)
        )

        recycle_deadline = time.monotonic() + 12
        remaining = set(row[1] for row in first_rows)
        while time.monotonic() < recycle_deadline:
            sync_code, sync_body = SUPPORT.SUPPORT.http_call(
                f"{debug_base}/Debug.GetSyncData", b"{}", "application/json", None
            )
            instances = SUPPORT.decoded(sync_body).get("instances", [])
            present = {str(row.get("instance_id", "")) for row in instances}
            remaining &= present
            if sync_code == 200 and not remaining:
                break
            time.sleep(0.25)
        checks["stale_instances_recycled"] = not remaining

        second_rows = [
            (
                f"{prefix}-app-new",
                f"{prefix}-new-{index:02d}",
                base64.b64encode(os.urandom(32)).decode(),
            )
            for index in range(16)
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            second_results = list(
                executor.map(lambda row: register(debug_base, *row), second_rows)
            )
        second_ips = [
            ip for code, ip, application_error in second_results
            if code == 200 and not application_error
        ]
        checks["recycled_addresses_not_concurrently_reused"] = (
            len(second_ips) == len(second_rows)
            and len(set(second_ips)) == len(second_ips)
            and bool(set(second_ips) & set(first_ips))
        )
        if not all(checks.values()):
            raise AssertionError(
                f"allocation checks failed: {sorted(k for k, v in checks.items() if not v)}"
            )
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Thirty-two concurrent registrations received unique IPv4 allocations; re-registration was stable and duplicate keys were rejected.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Bounded stale expiry removed all run-scoped instances and recycled addresses were reassigned uniquely without concurrent duplication.",
                },
            ]
        )
        observation = {
            "checks": checks,
            "baseline_instance_count": len(baseline_instances),
            "first_registration_count": len(first_ips),
            "first_unique_ip_count": len(set(first_ips)),
            "repeat_http": repeat_code,
            "repeat_ip_stable": repeat_ip == first_results[0][1],
            "duplicate_key_http": duplicate_code,
            "duplicate_key_application_error": duplicate_error,
            "remaining_after_recycle": len(remaining),
            "second_registration_count": len(second_ips),
            "second_unique_ip_count": len(set(second_ips)),
            "reused_address_count": len(set(second_ips) & set(first_ips)),
        }
        artifact_path = result_dir / "artifacts/gateway-allocation-observation.json"
        SUPPORT.SUPPORT.atomic_json(artifact_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-allocation-observation.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "WireGuard allocation lifecycle",
                "description": "Counts, statuses, and equality booleans only; no WireGuard public key or allocated address is retained.",
            }
        )
        status = "PASS"
        summary = "Gateway concurrent WireGuard allocation, deterministic re-registration, collision rejection, stale expiry, and safe address recycle passed."
    except Exception as error:  # noqa: BLE001
        summary = f"Gateway allocation matrix failed: {error}"
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
    SUPPORT.SUPPORT.atomic_json(
        result_dir / "artifacts/manifest.json", {"artifacts": artifacts}
    )
    SUPPORT.SUPPORT.atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "No WireGuard key, allocated address, credential, certificate, or token is retained.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
