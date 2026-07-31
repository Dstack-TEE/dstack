#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic harness for promoted isolated-component KMS RPC cases."""

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

CASES = {
    # The response carries a timestamp and signatures over it, so identical
    # requests match byte for byte only within the same second.
    "tc-kms-kms-003": (
        "KMS",
        "GetAppEnvEncryptPubKey",
        "KMS.GetAppEnvEncryptPubKey",
        "kms",
        False,
        {"app_id": "00" * 20},
    ),
    "tc-kms-kms-004": ("KMS", "GetMeta", "KMS.GetMeta", "kms", True),
    "tc-kms-kms-005": ("KMS", "GetTempCaCert", "KMS.GetTempCaCert", "kms", True),
    "tc-kms-onboard-003": (
        "Onboard",
        "GetAttestationInfo",
        "GetAttestationInfo",
        "onboard",
        True,
    ),
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
    method: str = "POST",
    headers: dict[str, str] | None = None,
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
        content_type_header = (
            error.headers.get("Content-Type") if error.headers else None
        )
        return int(error.code), error.read(), content_type_header


def varint(value: int) -> bytes:
    """Encode an unsigned protobuf varint."""
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        output.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(output)


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode the payload as a protobuf request body."""
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


def structural_json(value: dict[str, Any]) -> dict[str, Any]:
    """Build a structural JSON summary."""
    output: dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, list):
            output[key] = {
                "type": "array",
                "length": len(item),
                "item_lengths": [len(str(v)) for v in item],
            }
        elif isinstance(item, dict):
            output[key] = {"type": "object", "keys": sorted(item)}
        elif isinstance(item, str):
            output[key] = {
                "type": "string",
                "length": len(item),
                "sha256": hashlib.sha256(item.encode()).hexdigest(),
            }
        else:
            output[key] = {"type": type(item).__name__, "value": item}
    return output


def resolve_base(manifest: dict[str, Any], selector: str) -> tuple[str, bool]:
    """Resolve service base URL."""
    values = manifest["values"]
    if selector == "kms":
        kms = values["kms"]
        base = str(
            kms.get("rpc_prpc_url") or (str(kms["rpc_url"]).rstrip("/") + "/prpc")
        )
        return base.rstrip("/"), bool(kms.get("tls_verify", False))
    if selector == "onboard":
        onboard = values["services"]["onboard"]
        return str(onboard["url"]).rstrip("/"), False
    raise RuntimeError(f"unsupported base selector: {selector}")


def write_result(
    result_dir: pathlib.Path,
    case_id: str,
    status: str,
    summary: str,
    steps: list[dict[str, Any]],
    artifacts: list[dict[str, Any]],
    remarks: str,
) -> None:
    """Write the standard result.json payload."""
    payload = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": steps,
        "artifacts": artifacts,
        "remarks": remarks,
    }
    atomic_json(result_dir / "result.json", payload)


def main() -> int:
    """Run the case harness."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    if case_id not in CASES:
        raise SystemExit(f"unsupported promoted KMS case: {case_id}")

    entry_spec = CASES[case_id]
    service, method, route_suffix, base_selector, deterministic = entry_spec[:5]
    request_payload: dict = dict(entry_spec[5]) if len(entry_spec) > 5 else {}
    request_json = json.dumps(request_payload).encode()
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    artifact_entries: list[dict[str, Any]] = []
    status = "PASS"
    failure: str | None = None
    summary = ""
    json_body = b""
    metrics_url = None
    verify_tls = False
    route = ""

    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        base, verify_tls = resolve_base(manifest, base_selector)
        route = f"{base}/{route_suffix}"
        entry = inventory_entry(plan_root, service, method)
        values = manifest["values"]
        if "kms" in values:
            metrics_url = values["kms"].get("metrics_url")
        prereq = {
            "route": route,
            "verify_tls": verify_tls,
            "metrics_url": metrics_url,
            "profile": manifest.get("profile"),
            "lease_id": manifest.get("lease_id"),
        }
        if metrics_url:
            code, body, _ = http_call(
                metrics_url,
                body=b"",
                content_type="text/plain",
                verify_tls=verify_tls,
                method="GET",
            )
            prereq["metrics"] = {"status": code, "ok": code == 200, "bytes": len(body)}
            if code != 200:
                raise AssertionError(f"metrics probe failed with HTTP {code}")
        code, body, content_type = http_call(
            route,
            body=request_json,
            content_type="application/json",
            verify_tls=verify_tls,
        )
        prereq["probe"] = {
            "status": code,
            "ok": code == 200,
            "content_type": content_type,
            "body_len": len(body),
        }
        if code != 200:
            raise AssertionError(
                f"baseline method probe failed with HTTP {code}: {body[:200]!r}"
            )
        atomic_json(artifacts_dir / "step01-prereq.json", prereq)
        artifact_entries.append(
            {
                "path": "artifacts/step01-prereq.json",
                "step_id": f"{case_id}-step-01",
                "name": "Step 1 prerequisite observation",
                "description": "Listener reachability, metrics probe, and method baseline for the lease-owned KMS fixture.",
            }
        )
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Lease-owned KMS/onboard fixture listener and metrics baseline were reachable.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        json_code, json_body, json_ct = http_call(
            route,
            body=request_json,
            content_type="application/json",
            verify_tls=verify_tls,
        )
        if json_code != 200:
            raise AssertionError(f"valid JSON request returned HTTP {json_code}")
        raw_json_value = json.loads(json_body)
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
        )
        if pb_code != 200:
            raise AssertionError(
                f"valid protobuf Empty request returned HTTP {pb_code}"
            )
        wire = decode_wire(pb_body)
        bad_code, bad_body, _ = http_call(
            route + "-invalid",
            body=b"{}",
            content_type="application/json",
            verify_tls=verify_tls,
        )
        if bad_code < 400:
            raise AssertionError(f"invalid route was accepted with HTTP {bad_code}")
        extra_code, extra_body, _ = http_call(
            route,
            body=json.dumps(
                {**request_payload, "__probe": True, "nested": {"x": 1}}
            ).encode(),
            content_type="application/json",
            verify_tls=verify_tls,
        )
        if extra_code != 200:
            raise AssertionError(
                f"extraneous Empty JSON body was rejected with HTTP {extra_code}"
            )
        contract = {
            "json_http": json_code,
            "json_content_type": json_ct,
            "json_fields": structural_json(json_value),
            "json_keys": sorted(json_value),
            "protobuf_http": pb_code,
            "protobuf_content_type": pb_ct,
            "protobuf_bytes": len(pb_body),
            "protobuf_field_numbers": sorted(wire),
            "invalid_route_http": bad_code,
            "invalid_route_body_len": len(bad_body),
            "extraneous_json_http": extra_code,
            "extraneous_json_sha256": hashlib.sha256(extra_body).hexdigest(),
            "json_sha256": hashlib.sha256(json_body).hexdigest(),
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
                    "description": "JSON/protobuf Empty success, field presence, invalid-route rejection, and body-ignore checks.",
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
        )
        if repeat_code != 200:
            raise AssertionError(f"repeat request returned HTTP {repeat_code}")
        if deterministic and repeat_body != json_body:
            raise AssertionError(
                "documented deterministic response changed across identical requests"
            )
        health = {
            "repeat_http": repeat_code,
            "exact_match_required": deterministic,
            "exact_match": repeat_body == json_body,
            "first_sha256": hashlib.sha256(json_body).hexdigest(),
            "repeat_sha256": hashlib.sha256(repeat_body).hexdigest(),
        }
        if metrics_url:
            m_code, m_body, _ = http_call(
                metrics_url,
                body=b"",
                content_type="text/plain",
                verify_tls=verify_tls,
                method="GET",
            )
            health["metrics"] = {
                "status": m_code,
                "ok": m_code == 200,
                "bytes": len(m_body),
            }
            if m_code != 200:
                raise AssertionError(f"post-matrix metrics failed with HTTP {m_code}")
        atomic_json(artifacts_dir / "step03-health.json", health)
        artifact_entries.append(
            {
                "path": "artifacts/step03-health.json",
                "step_id": f"{case_id}-step-03",
                "name": "Step 3 determinism and health",
                "description": "Repeated valid response comparison and post-matrix listener/metrics health.",
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
            f"{service}.{method} passed over JSON and protobuf Empty requests on the lease-owned fixture; "
            "invalid routes were rejected and repeated responses remained deterministic."
        )
    except Exception as error:  # noqa: BLE001 - case boundary
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
    write_result(
        result_dir,
        case_id,
        status,
        summary,
        steps,
        artifact_entries,
        remarks="Promoted deterministic script for isolated-component KMS Empty RPC cases.",
    )
    print(
        json.dumps({"status": status, "summary": summary}, ensure_ascii=False),
        flush=True,
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
