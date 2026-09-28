#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify stable guest identities across a lease-owned five-VM mkosi matrix."""

# ruff: noqa: D103

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import tempfile
import urllib.error
import urllib.request
import uuid
from typing import Any

CASE_ID = "tc-gos-boot-and-i-004"
ROLES = {
    "identical-a",
    "identical-b",
    "changed-compose",
    "changed-image",
    "changed-instance",
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def request_info(endpoint: str, vm_id: str) -> dict[str, Any]:
    request = urllib.request.Request(
        endpoint.rstrip("/") + "/Info",
        data=json.dumps({"id": vm_id}, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise AssertionError("VMM guest Info response is not an object")
    return payload


def identity_hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AssertionError(f"Info.{field} is empty or not a string")
    compact = value.removeprefix("0x")
    try:
        if len(compact) % 2 == 0:
            bytes.fromhex(compact)
            return compact.lower()
    except ValueError:
        pass
    try:
        return base64.b64decode(value, validate=True).hex()
    except ValueError as error:
        raise AssertionError(f"Info.{field} is neither hex nor base64") from error


def tcb_identity(value: Any) -> dict[str, str]:
    if not isinstance(value, str) or not value:
        raise AssertionError("Info.tcb_info is empty or not a string")
    try:
        tcb = json.loads(value)
    except json.JSONDecodeError as error:
        raise AssertionError("Info.tcb_info is not valid JSON") from error
    if not isinstance(tcb, dict):
        raise AssertionError("Info.tcb_info is not an object")
    return {
        field: identity_hex(tcb.get(field), f"tcb_info.{field}")
        for field in ("mrtd", "os_image_hash", "compose_hash", "device_id")
    }


def projection(payload: dict[str, Any]) -> dict[str, Any]:
    required = ("version", "app_id", "instance_id", "device_id", "app_cert", "tcb_info")
    missing = [field for field in required if field not in payload]
    if missing:
        raise AssertionError(f"Info response is missing fields: {missing}")
    result: dict[str, Any] = {"version": str(payload["version"])}
    for field in ("app_id", "instance_id", "device_id"):
        result[field] = identity_hex(payload[field], field)
    for field in ("app_cert", "tcb_info"):
        value = payload[field]
        if not isinstance(value, str) or not value:
            raise AssertionError(f"Info.{field} is empty or not a string")
        encoded = value.encode()
        result[f"{field}_sha256"] = hashlib.sha256(encoded).hexdigest()
        result[f"{field}_length"] = len(encoded)
    result["_tcb_identity"] = tcb_identity(payload["tcb_info"])
    return result


def main() -> int:
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    matrix = values.get("identity_matrix")
    endpoints = values.get("component_endpoints", {})
    status = "PASS"
    summary = (
        "Five mkosi guests satisfied stable and input-sensitive identity relations."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    try:
        if not isinstance(matrix, dict):
            raise AssertionError("fixture lacks the five-row identity matrix")
        rows = matrix.get("rows")
        endpoint = endpoints.get("vmm_guest_api")
        if not isinstance(rows, list) or not isinstance(endpoint, str):
            raise AssertionError(
                "identity matrix rows or VMM guest endpoint are absent"
            )
        by_role = {str(row.get("role")): row for row in rows if isinstance(row, dict)}
        if set(by_role) != ROLES or len(rows) != len(ROLES):
            raise AssertionError(f"identity matrix roles mismatched: {sorted(by_role)}")

        projections: dict[str, dict[str, Any]] = {}
        for role in sorted(ROLES):
            row = by_role[role]
            vm_id = str(row.get("vmm_vm_id", ""))
            if not vm_id:
                raise AssertionError(f"{role} has no VMM VM ID")
            first = projection(request_info(endpoint, vm_id))
            second = projection(request_info(endpoint, vm_id))
            if first != second:
                raise AssertionError(
                    f"{role} identity changed across repeated Info calls"
                )
            expected_instance = identity_hex(
                str(row.get("instance_id", "")), "manifest.instance_id"
            )
            if first["instance_id"] != expected_instance:
                raise AssertionError(
                    f"{role} guest instance ID mismatched its lease manifest"
                )
            projections[role] = first

        identical = projections["identical-a"]
        for role in ("identical-b", "changed-image", "changed-instance"):
            if projections[role]["app_id"] != identical["app_id"]:
                raise AssertionError(f"{role} unexpectedly changed app ID")
        if projections["changed-compose"]["app_id"] == identical["app_id"]:
            raise AssertionError("changed compose did not change app ID")
        if len({item["instance_id"] for item in projections.values()}) != len(ROLES):
            raise AssertionError("matrix instance IDs are not all distinct")
        if len({item["device_id"] for item in projections.values()}) != 1:
            raise AssertionError("matrix guests did not retain the same device ID")

        tcb = {role: item["_tcb_identity"] for role, item in projections.items()}
        baseline_tcb = tcb["identical-a"]
        for role in ("identical-b", "changed-compose", "changed-instance"):
            for field in ("mrtd", "os_image_hash"):
                if tcb[role][field] != baseline_tcb[field]:
                    raise AssertionError(f"{role} unexpectedly changed TCB {field}")
        if tcb["changed-image"]["os_image_hash"] == baseline_tcb["os_image_hash"]:
            raise AssertionError("changed-image did not change TCB OS image hash")
        for role in ("identical-b", "changed-image", "changed-instance"):
            if tcb[role]["compose_hash"] != baseline_tcb["compose_hash"]:
                raise AssertionError(f"{role} unexpectedly changed TCB compose hash")
        if tcb["changed-compose"]["compose_hash"] == baseline_tcb["compose_hash"]:
            raise AssertionError("changed-compose did not change TCB compose hash")
        for role, item in projections.items():
            if tcb[role]["device_id"] != item["device_id"]:
                raise AssertionError(f"{role} TCB device ID mismatched Info.device_id")

        tcb_relations = {
            "same_image_measurement_roles": [
                "identical-a",
                "identical-b",
                "changed-compose",
                "changed-instance",
            ],
            "changed_image_measurement": True,
            "same_compose_measurement_roles": [
                "identical-a",
                "identical-b",
                "changed-image",
                "changed-instance",
            ],
            "changed_compose_measurement": True,
        }
        invalid_id = str(uuid.uuid4())
        try:
            request_info(endpoint, invalid_id)
        except urllib.error.HTTPError as error:
            body = error.read(4096).decode(errors="replace").lower()
            if error.code < 400 or "not found" not in body:
                raise AssertionError(
                    "unknown VM returned no structured not-found error"
                )
            observations["negative_request"] = {
                "http_status": error.code,
                "body_contains_not_found": True,
            }
        else:
            raise AssertionError("unknown VM ID unexpectedly returned guest identity")
        valid_id = str(by_role["identical-a"]["vmm_vm_id"])
        if projection(request_info(endpoint, valid_id)) != identical:
            raise AssertionError(
                "valid guest identity changed after the negative request"
            )
        for item in projections.values():
            item.pop("_tcb_identity")
        observations.update(
            {
                "roles": projections,
                "relations": {
                    "stable_repeated_reads": len(ROLES),
                    "same_app_id_roles": 4,
                    "different_compose_app_id": True,
                    "distinct_instance_ids": len(ROLES),
                    "same_device_ids": len(ROLES),
                    **tcb_relations,
                },
            }
        )
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        urllib.error.URLError,
    ) as error:
        status = "FAIL"
        summary = str(error)
        observations["failure"] = summary

    artifact = {
        "path": "artifacts/identity-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "Redacted identity matrix",
        "description": "Public identifiers plus certificate and TCB hashes and lengths; no certificates or configurations.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "Validated the complete lease-owned five-VM matrix.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Compared repeated public identity projections and input-sensitive relations.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Rejected an unknown VM ID and revalidated the healthy guest.",
                },
            ],
            "artifacts": [artifact],
            "cleanup": {
                "status": "PASS",
                "actions": ["Provider owns and removes all five matrix VMs."],
            },
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
