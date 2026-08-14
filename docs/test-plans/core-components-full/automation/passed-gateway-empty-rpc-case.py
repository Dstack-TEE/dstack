#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic harness for promoted empty-input Gateway public/debug RPC cases."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import ssl
import tempfile
import urllib.error
import urllib.request
from typing import Any

# case_id -> (service, method, base_selector, route_suffix, deterministic)
# base_selector: rpc | debug | admin
# route_suffix is appended to base (already includes /prpc)
CASES = {
    "tc-gw-admin-002": (
        "Admin",
        "GetInfo",
        "admin",
        "GetInfo",
        True,
        {"id": "$registered_instance_id"},
    ),
    "tc-gw-admin-034": (
        "Admin",
        "RemoveCvm",
        "admin",
        "RemoveCvm",
        True,
        {"instance_id": "dstack-test-unknown-instance"},
    ),
    "tc-gw-admin-035": (
        "Admin",
        "ListRejectedInstances",
        "admin",
        "ListRejectedInstances",
        True,
        None,
    ),
    "tc-gw-admin-036": (
        "Admin",
        "RemoveNode",
        "admin",
        "RemoveNode",
        True,
        {"node_id": 4294967295},
    ),
    "tc-gw-debug-002": ("Debug", "Info", "debug", "Info", True, None),
    "tc-gw-debug-003": ("Debug", "GetSyncData", "debug", "GetSyncData", True, None),
    "tc-gw-admin-004": ("Admin", "RenewCert", "admin", "RenewCert", False, None),
    "tc-gw-admin-008": (
        "Admin",
        "SetNodeUrl",
        "admin",
        "SetNodeUrl",
        False,
        {"id": 1, "url": "http://127.0.0.1:9/admin-set-node"},
    ),
    "tc-gw-admin-009": (
        "Admin",
        "SetNodeStatus",
        "admin",
        "SetNodeStatus",
        False,
        {"id": 1, "status": "up"},
    ),
    "tc-gw-admin-010": ("Admin", "WaveKvStatus", "admin", "WaveKvStatus", True, None),
    "tc-gw-admin-011": (
        "Admin",
        "GetInstanceHandshakes",
        "admin",
        "GetInstanceHandshakes",
        True,
        {"instance_id": ""},
    ),
    "tc-gw-admin-013": (
        "Admin",
        "GetNodeStatuses",
        "admin",
        "GetNodeStatuses",
        True,
        None,
    ),
    "tc-gw-admin-014": (
        "Admin",
        "ListDnsCredentials",
        "admin",
        "ListDnsCredentials",
        True,
        None,
    ),
    "tc-gw-admin-019": (
        "Admin",
        "GetDefaultDnsCredential",
        "admin",
        "GetDefaultDnsCredential",
        True,
        None,
    ),
    "tc-gw-admin-021": (
        "Admin",
        "ListZtDomains",
        "admin",
        "ListZtDomains",
        True,
        None,
    ),
    "tc-gw-admin-029": (
        "Admin",
        "GetCertbotConfig",
        "admin",
        "GetCertbotConfig",
        True,
        None,
    ),
    "tc-gw-admin-028": (
        "Admin",
        "ListCertAttestations",
        "admin",
        "ListCertAttestations",
        True,
        None,
    ),
    "tc-gw-admin-030": (
        "Admin",
        "SetCertbotConfig",
        "admin",
        "SetCertbotConfig",
        False,
        None,
    ),
    "tc-gw-admin-027": (
        "Admin",
        "ForceReleaseCertLock",
        "admin",
        "ForceReleaseCertLock",
        False,
        None,
    ),
    "tc-gw-gateway-004": ("Gateway", "GetPeers", "rpc", "GetPeers", True, None),
    "tc-gw-gateway-002": ("Gateway", "AcmeInfo", "rpc", "AcmeInfo", True, None),
    "tc-gw-gateway-003": ("Gateway", "Info", "rpc", "Info", True, None),
    "tc-gw-admin-005": ("Admin", "ReloadCert", "admin", "ReloadCert", False, None),
    "tc-gw-admin-006": ("Admin", "SetCaa", "admin", "SetCaa", False, None),
    "tc-gw-admin-007": ("Admin", "GetMeta", "admin", "GetMeta", True, None),
    "tc-gw-admin-012": (
        "Admin",
        "GetGlobalConnections",
        "admin",
        "GetGlobalConnections",
        True,
        None,
    ),
    # Admin.Status reports live cluster state -- num_connections, hosts and
    # nodes -- which legitimately changes between two calls while other cases
    # register and deregister CVMs.
    "tc-gw-admin-001": ("Admin", "Status", "admin", "Status", False, None),
    "tc-gw-debug-004": ("Debug", "GetProxyState", "debug", "GetProxyState", True, None),
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, ensure_ascii=False, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def inventory_entry(root: pathlib.Path, service: str, method: str) -> dict[str, Any]:
    """Load the API inventory entry."""
    document = json.loads((root / "api-inventory.json").read_text())
    matches: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("service") == service and value.get("method") == method:
                matches.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if len(matches) != 1:
        raise RuntimeError(f"expected one inventory entry for {service}.{method}")
    return matches[0]


def ssl_context(verify: bool) -> ssl.SSLContext:
    """Build an SSL context."""
    if verify:
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def http_call(
    url: str,
    *,
    body: bytes,
    content_type: str,
    verify_tls: bool,
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> tuple[int, bytes, str | None]:
    """Perform an HTTP request."""
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(
            request, context=ssl_context(verify_tls), timeout=20
        ) as response:
            return (
                int(response.status),
                response.read(),
                response.headers.get("Content-Type"),
            )
    except urllib.error.HTTPError as error:
        content = error.headers.get("Content-Type") if error.headers else None
        return int(error.code), error.read(), content


def decode_wire(data: bytes) -> dict[int, list[tuple[int, bytes | int]]]:
    """Decode protobuf wire fields."""
    values: dict[int, list[tuple[int, bytes | int]]] = {}
    offset = 0
    while offset < len(data):
        key = 0
        shift = 0
        while True:
            byte = data[offset]
            offset += 1
            key |= (byte & 0x7F) << shift
            if byte < 0x80:
                break
            shift += 7
        number, wire = key >> 3, key & 7
        if wire == 0:
            value = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                value |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
        elif wire == 2:
            length = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                length |= (byte & 0x7F) << shift
                if byte < 0x80:
                    break
                shift += 7
            value = data[offset : offset + length]
            offset += length
        else:
            raise ValueError(f"unsupported response wire type {wire}")
        values.setdefault(number, []).append((wire, value))
    return values


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode a protobuf request body."""
    output = bytearray()
    for field in fields:
        name = field["name"]
        if name not in payload:
            continue
        number = int(field["number"])
        kind = field["type"]
        value = payload[name]
        if kind in ("string", "bytes"):
            raw = str(value).encode() if kind == "string" else bytes.fromhex(str(value))
            output.extend(varint((number << 3) | 2))
            output.extend(varint(len(raw)))
            output.extend(raw)
        elif (
            kind.startswith(("uint", "int", "sint", "fixed", "sfixed"))
            or kind == "bool"
        ):
            output.extend(varint((number << 3) | 0))
            output.extend(varint(int(value)))
        else:
            raise ValueError(f"unsupported request field type: {kind}")
    return bytes(output)


def resolve_base(
    manifest: dict[str, Any], selector: str
) -> tuple[str, bool, dict[str, str]]:
    """Resolve service base URL."""
    values = manifest["values"]
    gateway = values.get("gateway") or {}
    services = values.get("services") or {}
    headers: dict[str, str] = {}
    verify = False
    if selector == "debug":
        base = str(
            gateway.get("debug_url") or (services.get("debug") or {}).get("url") or ""
        )
        verify = False
    elif selector == "rpc":
        base = str(
            gateway.get("rpc_url") or (services.get("rpc") or {}).get("url") or ""
        )
        verify = bool(
            gateway.get("tls_verify", False)
            or (services.get("rpc") or {}).get("tls_verify", False)
        )
    elif selector == "admin":
        base = str(
            gateway.get("admin_url") or (services.get("admin") or {}).get("url") or ""
        )
        token_file = gateway.get("admin_auth_token_file") or (
            services.get("admin") or {}
        ).get("auth_token_file")
        if token_file:
            token = pathlib.Path(token_file).read_text(encoding="utf-8").strip()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        verify = False
    else:
        raise RuntimeError(f"unsupported base selector: {selector}")
    if not base:
        raise RuntimeError(f"manifest missing gateway {selector} url")
    return base.rstrip("/"), verify, headers


def write_result(
    result_dir: pathlib.Path,
    case_id: str,
    status: str,
    summary: str,
    steps: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
) -> None:
    """Write the standard result.json payload."""
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "remarks": "Promoted deterministic script for empty-input Gateway RPC cases.",
        },
    )


def main() -> int:
    """Run the case harness."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    if case_id not in CASES:
        raise SystemExit(f"unsupported promoted gateway case: {case_id}")
    case_spec = CASES[case_id]
    if len(case_spec) == 5:
        service, method, selector, route_suffix, deterministic = case_spec
        payload = None
    else:
        service, method, selector, route_suffix, deterministic, payload = case_spec
    request_payload = payload if payload is not None else {}
    if request_payload.get("id") == "$registered_instance_id":
        registered_id = (manifest["values"].get("gateway") or {}).get(
            "registered_instance_id"
        )
        if not registered_id:
            raise RuntimeError("manifest missing registered gateway instance id")
        request_payload = {"id": registered_id}
    request_json = json.dumps(request_payload).encode()
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    artifact_entries: list[dict[str, Any]] = []
    status = "PASS"
    failure: str | None = None
    summary = ""
    json_body = b""

    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        base, verify_tls, headers = resolve_base(manifest, selector)
        route = f"{base}/{route_suffix}"
        entry = inventory_entry(plan_root, service, method)
        prereq = {
            "route": route,
            "verify_tls": verify_tls,
            "auth_headers": sorted(headers),
            "profile": manifest.get("profile"),
            "lease_id": manifest.get("lease_id"),
        }
        code, body, content_type = http_call(
            route,
            body=request_json,
            content_type="application/json",
            verify_tls=verify_tls,
            headers=headers,
        )
        prereq["probe"] = {
            "status": code,
            "ok": code == 200,
            "content_type": content_type,
            "body_len": len(body),
        }
        if code != 200:
            raise AssertionError(f"baseline probe failed HTTP {code}: {body[:200]!r}")
        atomic_json(artifacts_dir / "step01-prereq.json", prereq)
        artifact_entries.append(
            {
                "path": "artifacts/step01-prereq.json",
                "step_id": f"{case_id}-step-01",
                "name": "Step 1 prerequisite observation",
                "description": "Lease-owned gateway listener reachability and Empty method baseline.",
            }
        )
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Lease-owned gateway listener and empty-input method baseline were reachable.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        json_code, json_body, json_ct = http_call(
            route,
            body=request_json,
            content_type="application/json",
            verify_tls=verify_tls,
            headers=headers,
        )
        if json_code != 200:
            raise AssertionError(f"valid JSON request returned HTTP {json_code}")
        # google.protobuf.Empty is encoded as JSON null; treat as empty object.
        raw_json_value = json.loads(json_body) if json_body else None
        if raw_json_value is None:
            json_value: dict[str, Any] = {}
        elif isinstance(raw_json_value, dict):
            json_value = raw_json_value
        else:
            raise AssertionError(
                f"JSON response was not an object or null: {type(raw_json_value).__name__}"
            )
        expected_names = [field["name"] for field in entry["response_fields"]]
        missing = sorted(set(expected_names) - set(json_value))
        if missing:
            raise AssertionError(f"JSON response omitted fields: {missing}")
        pb_request = encode_request(entry["request_fields"], request_payload)
        pb_code, pb_body, pb_ct = http_call(
            route,
            body=pb_request,
            content_type="application/octet-stream",
            verify_tls=verify_tls,
            headers=headers,
        )
        if pb_code != 200:
            raise AssertionError(f"valid protobuf request returned HTTP {pb_code}")
        wire = decode_wire(pb_body) if pb_body else {}
        bad_code, bad_body, _ = http_call(
            route + "NoSuch",
            body=b"{}",
            content_type="application/json",
            verify_tls=verify_tls,
            headers=headers,
        )
        if bad_code < 400:
            raise AssertionError(f"invalid route accepted with HTTP {bad_code}")
        extra_code, extra_body, _ = http_call(
            route,
            body=json.dumps({**request_payload, "__probe": True}).encode(),
            content_type="application/json",
            verify_tls=verify_tls,
            headers=headers,
        )
        if extra_code != 200:
            raise AssertionError(
                f"extraneous Empty JSON rejected with HTTP {extra_code}"
            )
        contract = {
            "json_http": json_code,
            "json_content_type": json_ct,
            "json_keys": sorted(json_value),
            "json_sha256": hashlib.sha256(json_body).hexdigest(),
            "protobuf_http": pb_code,
            "protobuf_content_type": pb_ct,
            "protobuf_bytes": len(pb_body),
            "protobuf_field_numbers": sorted(wire),
            "invalid_route_http": bad_code,
            "extraneous_json_http": extra_code,
            "extraneous_json_sha256": hashlib.sha256(extra_body).hexdigest(),
        }
        atomic_json(artifacts_dir / "step02-contract.json", contract)
        (artifacts_dir / "step02-json.body").write_bytes(json_body)
        (artifacts_dir / "step02-protobuf.body").write_bytes(pb_body)
        artifact_entries.extend(
            [
                {
                    "path": "artifacts/step02-contract.json",
                    "step_id": f"{case_id}-step-02",
                    "name": "Step 2 contract matrix",
                    "description": "JSON/protobuf Empty success, field presence, invalid-route rejection, body-ignore checks.",
                },
                {
                    "path": "artifacts/step02-json.body",
                    "step_id": f"{case_id}-step-02",
                    "name": "Raw JSON response",
                    "description": "Native JSON body for the valid Empty request.",
                },
                {
                    "path": "artifacts/step02-protobuf.body",
                    "step_id": f"{case_id}-step-02",
                    "name": "Raw protobuf response",
                    "description": "Native protobuf body for the valid Empty request.",
                },
            ]
        )
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Valid JSON and protobuf Empty requests returned documented fields; invalid routing was rejected and extraneous Empty JSON was ignored.",
            }
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        repeat_code, repeat_body, _ = http_call(
            route,
            body=request_json,
            content_type="application/json",
            verify_tls=verify_tls,
            headers=headers,
        )
        if repeat_code != 200:
            raise AssertionError(f"repeat request returned HTTP {repeat_code}")
        if deterministic and repeat_body != json_body:
            raise AssertionError(
                "deterministic response changed across identical requests"
            )
        health = {
            "repeat_http": repeat_code,
            "exact_match_required": deterministic,
            "exact_match": repeat_body == json_body,
            "first_sha256": hashlib.sha256(json_body).hexdigest(),
            "repeat_sha256": hashlib.sha256(repeat_body).hexdigest(),
        }
        atomic_json(artifacts_dir / "step03-health.json", health)
        artifact_entries.append(
            {
                "path": "artifacts/step03-health.json",
                "step_id": f"{case_id}-step-03",
                "name": "Step 3 determinism and health",
                "description": "Repeated valid response comparison after the contract matrix.",
            }
        )
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Repeated valid responses matched the determinism policy and the fixture remained healthy.",
            }
        )
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
        summary = (
            f"{service}.{method} passed over JSON and protobuf Empty requests on the lease-owned gateway; "
            "invalid routes were rejected and repeated responses obeyed the determinism policy."
        )
    except Exception as error:  # noqa: BLE001
        status = "FAIL"
        failure = str(error)
        summary = f"{service}.{method} failed: {failure}"
        fixed: list[dict[str, Any]] = []
        failed_assigned = False
        for index in (1, 2, 3):
            step_id = f"{case_id}-step-0{index}"
            existing = next((item for item in steps if item["id"] == step_id), None)
            if existing and existing["status"] == "PASS":
                fixed.append(existing)
                continue
            if not failed_assigned:
                fixed.append({"id": step_id, "status": "FAIL", "observed": failure})
                failed_assigned = True
            else:
                fixed.append(
                    {
                        "id": step_id,
                        "status": "NOT_RUN",
                        "observed": "Not run after earlier failure.",
                    }
                )
        steps = fixed

    atomic_json(artifacts_dir / "manifest.json", {"artifacts": artifact_entries})
    write_result(result_dir, case_id, status, summary, steps, artifact_entries)
    print(
        json.dumps({"status": status, "summary": summary}, ensure_ascii=False),
        flush=True,
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
