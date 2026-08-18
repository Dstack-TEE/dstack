#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for previously confirmed simulator RPC cases."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Any

CASES = {
    "tc-gos-tappd-001": (
        "Tappd",
        "DeriveKey",
        {
            "path": "regression/a",
            "subject": "localhost",
            "alt_names": ["localhost"],
            "usage_ra_tls": True,
            "usage_server_auth": True,
            "usage_client_auth": False,
            "random_seed": False,
        },
        False,
    ),
    "tc-gos-tappd-002": (
        "Tappd",
        "DeriveK256Key",
        {"path": "regression/a", "purpose": "regression", "algorithm": "k256"},
        True,
    ),
    "tc-gos-tappd-004": ("Tappd", "RawQuote", {"report_data": "11" * 64}, True),
    "tc-gos-tappd-006": ("Tappd", "Version", {}, True),
    "tc-gos-dstackguest-001": (
        "DstackGuest",
        "GetTlsKey",
        {
            "subject": "localhost",
            "alt_names": ["localhost"],
            "usage_ra_tls": True,
            "usage_server_auth": True,
            "usage_client_auth": False,
            "not_before": 0,
            "not_after": 4102444800,
            "with_app_info": True,
        },
        False,
    ),
    "tc-gos-dstackguest-002": (
        "DstackGuest",
        "GetKey",
        {"path": "regression/a", "purpose": "regression", "algorithm": "ed25519"},
        True,
    ),
    "tc-gos-dstackguest-003": (
        "DstackGuest",
        "GetQuote",
        {"report_data": "22" * 64},
        True,
    ),
    "tc-gos-dstackguest-004": (
        "DstackGuest",
        "Attest",
        {"report_data": "33" * 64},
        True,
    ),
    "tc-gos-dstackguest-005": ("DstackGuest", "Info", {}, True),
    "tc-gos-dstackguest-006": ("DstackGuest", "GpuInfo", {}, True),
    "tc-gos-dstackguest-007": (
        "DstackGuest",
        "Sign",
        {"algorithm": "ed25519", "data": "44" * 32},
        True,
    ),
    "tc-gos-dstackguest-009": ("DstackGuest", "Version", {}, True),
    "tc-gos-worker-001": ("Worker", "Info", {}, True),
    "tc-gos-worker-002": ("Worker", "Version", {}, True),
    "tc-gos-worker-003": (
        "Worker",
        "GetAttestationForAppKey",
        {"algorithm": "ed25519"},
        True,
    ),
    "tc-gos-guestapi-001": ("GuestApi", "Info", {}, True),
    "tc-gos-guestapi-002": ("GuestApi", "SysInfo", {}, False),
    "tc-gos-tappd-003": (
        "Tappd",
        "TdxQuote",
        {
            "report_data": "55555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555"
        },
        True,
    ),
    "tc-gos-tappd-005": ("Tappd", "Info", {}, True),
    "tc-gos-guestapi-003": ("GuestApi", "NetworkInfo", {}, False),
    "tc-gos-guestapi-004": ("GuestApi", "ListContainers", {}, False),
    "tc-gos-guestapi-005": ("GuestApi", "Shutdown", {}, False),
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


def varint(value: int) -> bytes:
    """Encode an integer as a protobuf varint."""
    output = bytearray()
    while value > 0x7F:
        output.append((value & 0x7F) | 0x80)
        value >>= 7
    output.append(value)
    return bytes(output)


def scalar_bytes(field: dict[str, Any], value: Any) -> tuple[int, bytes]:
    """Encode a scalar field value."""
    kind = field["type"]
    if kind in ("string", "bytes"):
        if kind == "bytes":
            raw = bytes.fromhex(str(value))
        else:
            raw = str(value).encode()
        return 2, varint(len(raw)) + raw
    if kind == "bool":
        return 0, varint(1 if value else 0)
    if kind.startswith(("uint", "int", "sint", "fixed", "sfixed")):
        return 0, varint(int(value))
    raise ValueError(f"unsupported request field type: {kind}")


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode a protobuf request body."""
    output = bytearray()
    for field in fields:
        if field["name"] not in payload:
            continue
        values = (
            payload[field["name"]]
            if field.get("repeated")
            else [payload[field["name"]]]
        )
        for value in values:
            wire, encoded = scalar_bytes(field, value)
            output.extend(varint((int(field["number"]) << 3) | wire))
            output.extend(encoded)
    return bytes(output)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a protobuf varint from a buffer."""
    value = shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
        shift += 7


def decode_wire(data: bytes) -> dict[int, list[tuple[int, bytes | int]]]:
    """Decode protobuf wire fields."""
    values: dict[int, list[tuple[int, bytes | int]]] = {}
    offset = 0
    while offset < len(data):
        key, offset = read_varint(data, offset)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = read_varint(data, offset)
        elif wire == 2:
            length, offset = read_varint(data, offset)
            value = data[offset : offset + length]
            offset += length
        else:
            raise ValueError(f"unsupported response wire type {wire}")
        values.setdefault(number, []).append((wire, value))
    return values


def call(socket: str, route: str, content_type: str, body: bytes) -> tuple[int, bytes]:
    """Call a unix-socket HTTP endpoint."""
    marker = b"\nDSTACK_HTTP_STATUS:"
    process = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--unix-socket",
            socket,
            "--request",
            "POST",
            "--header",
            f"Content-Type: {content_type}",
            "--data-binary",
            "@-",
            "--write-out",
            marker.decode() + "%{http_code}",
            "http://localhost" + route,
        ],
        input=body,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(process.stderr.decode(errors="replace")[-1000:])
    response, code = process.stdout.rsplit(marker, 1)
    return int(code), response


def inventory_entry(root: pathlib.Path, service: str, method: str) -> dict[str, Any]:
    """Load the API inventory entry."""
    document = json.loads((root / "catalog" / "api-inventory.json").read_text())
    matches = []

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


def structural_json(value: dict[str, Any]) -> dict[str, Any]:
    """Build a structural JSON summary."""
    output = {}
    for key, item in value.items():
        if isinstance(item, list):
            output[key] = {
                "type": "array",
                "length": len(item),
                "item_lengths": [len(str(v)) for v in item],
            }
        elif isinstance(item, str):
            output[key] = {
                "type": "string",
                "length": len(item),
                "sha256": hashlib.sha256(item.encode()).hexdigest(),
            }
        else:
            output[key] = {"type": type(item).__name__, "value": item}
    return output


def main() -> int:
    """Run the case harness."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    service, method, payload, deterministic = CASES[case_id]
    steps = []
    status = "PASS"
    failure = None
    matrix: dict[str, Any] = {
        "case_id": case_id,
        "environment": "SIMULATION",
        "service": service,
        "method": method,
    }
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        fixture = manifest["values"]
        service_fixture = fixture["services"][service]
        socket = service_fixture["socket"]
        route = service_fixture["route"].replace("<Method>", method)
        if not pathlib.Path(socket).is_socket():
            raise RuntimeError(f"fixture socket is not available: {socket}")
        entry = inventory_entry(plan_root, service, method)
        matrix["fixture"] = {
            "profile": manifest["profile"],
            "lease_id": manifest["lease_id"],
            "socket_available": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The lease-owned simulator socket and indexed RPC contract were available.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-01 - Proves that the isolated simulator listener and indexed method contract were ready.",
            flush=True,
        )
        print(json.dumps(matrix["fixture"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        json_code, json_body = call(
            socket, route, "application/json", json.dumps(payload).encode()
        )
        if json_code != 200:
            raise AssertionError(f"valid JSON request returned HTTP {json_code}")
        expected_names = [field["name"] for field in entry["response_fields"]]
        # Unit/Empty responses have an empty HTTP body. Retain compatibility
        # with JSON null while never accepting an empty body for a response
        # that declares fields.
        if not json_body:
            if expected_names:
                raise AssertionError("non-Empty JSON response had an empty body")
            json_value: dict[str, Any] = {}
        else:
            raw_json_value = json.loads(json_body)
            if raw_json_value is None:
                json_value = {}
            elif isinstance(raw_json_value, dict):
                json_value = raw_json_value
            else:
                raise AssertionError(
                    f"JSON response was not an object or null: {type(raw_json_value).__name__}"
                )
        missing = sorted(set(expected_names) - set(json_value))
        if missing:
            raise AssertionError(f"JSON response omitted fields: {missing}")
        binary_request = encode_request(entry["request_fields"], payload)
        protobuf_code, protobuf_body = call(
            socket, route, "application/octet-stream", binary_request
        )
        if protobuf_code != 200:
            raise AssertionError(
                f"valid protobuf request returned HTTP {protobuf_code}"
            )
        wire = decode_wire(protobuf_body)
        expected_numbers = {
            int(field["number"])
            for field in entry["response_fields"]
            if json_value.get(field["name"]) not in (None, "", 0, False, [])
        }
        if not expected_numbers.issubset(wire):
            raise AssertionError(
                f"protobuf response omitted fields: {sorted(expected_numbers - set(wire))}"
            )
        bad_route_code, bad_route_body = call(
            socket, route + "-invalid", "application/json", b"{}"
        )
        if bad_route_code < 400:
            raise AssertionError("invalid route was accepted")
        try:
            bad_route_value = json.loads(bad_route_body)
        except json.JSONDecodeError as error:
            raise AssertionError(
                "invalid route did not return structured JSON"
            ) from error
        if not isinstance(bad_route_value.get("error"), str):
            raise AssertionError("invalid route response omitted error")
        invalid_code = None
        if entry["request_fields"]:
            first = entry["request_fields"][0]
            wrong = {
                **payload,
                first["name"]: 123 if first["type"] in ("string", "bytes") else "wrong",
            }
            invalid_code, invalid_body = call(
                socket, route, "application/json", json.dumps(wrong).encode()
            )
            if invalid_code < 400:
                raise AssertionError(f"schema-invalid {first['name']} was accepted")
            if not isinstance(json.loads(invalid_body).get("error"), str):
                raise AssertionError("schema-invalid response omitted error")
        matrix["contract"] = {
            "json_http": json_code,
            "json_fields": structural_json(json_value),
            "protobuf_http": protobuf_code,
            "protobuf_bytes": len(protobuf_body),
            "protobuf_field_numbers": sorted(wire),
            "invalid_route_http": bad_route_code,
            "invalid_field_http": invalid_code,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Valid JSON and protobuf requests returned every indexed response field; invalid routing and schema input were rejected.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-02 - Proves JSON/protobuf field coverage and structured rejection of invalid input.",
            flush=True,
        )
        print(
            json.dumps(
                {
                    "json_http": json_code,
                    "json_fields": sorted(json_value),
                    "protobuf_http": protobuf_code,
                    "protobuf_fields": sorted(wire),
                    "invalid_route_http": bad_route_code,
                    "invalid_field_http": invalid_code,
                },
                sort_keys=True,
            ),
            flush=True,
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        repeat_code, repeat_body = call(
            socket, route, "application/json", json.dumps(payload).encode()
        )
        if repeat_code != 200:
            raise AssertionError(
                f"post-error valid request returned HTTP {repeat_code}"
            )
        if deterministic and repeat_body != json_body:
            raise AssertionError(
                "documented deterministic response changed across identical requests"
            )
        matrix["repeat"] = {
            "http": repeat_code,
            "exact_match_required": deterministic,
            "exact_match": repeat_body == json_body,
            "first_sha256": hashlib.sha256(json_body).hexdigest(),
            "repeat_sha256": hashlib.sha256(repeat_body).hexdigest(),
            "sensitive_response_persisted": False,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "The service remained available after invalid input and repeated behavior matched the documented determinism policy.",
            }
        )
        print(
            f"EVIDENCE {case_id}-step-03 - Proves post-error availability and repeat-call semantics without persisting response secrets.",
            flush=True,
        )
        print(json.dumps(matrix["repeat"], sort_keys=True), flush=True)
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        completed = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in completed:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})
        print(
            f"EVIDENCE {case_id}-step-{len(steps):02d} - Captures the first deterministic harness mismatch.",
            flush=True,
        )
        print(failure, file=sys.stderr, flush=True)

    matrix["status"] = status
    matrix["failure"] = failure
    matrix_path = artifacts / "rpc-regression-matrix.json"
    atomic_json(matrix_path, matrix)
    artifact = {
        "name": "RPC regression matrix",
        "path": "artifacts/rpc-regression-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Records structural JSON/protobuf coverage, invalid-input rejection, repeat semantics, and proves that no native secret response was persisted.",
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Deterministic simulator RPC regression passed."
            if status == "PASS"
            else failure,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "SIMULATION: this confirms RPC behavior, not physical TEE trust properties.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
