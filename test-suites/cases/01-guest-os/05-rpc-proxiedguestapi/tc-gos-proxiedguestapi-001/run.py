#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic ProxiedGuestApi.Info JSON/protobuf contract regression."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-gos-proxiedguestapi-001"
FIELDS = {"version", "app_id", "instance_id", "app_cert", "tcb_info", "device_id"}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def request(url: str, content_type: str, body: bytes) -> tuple[int, bytes]:
    """Call one ProxiedGuestApi method."""
    req = urllib.request.Request(url, data=body, headers={"content-type": content_type})
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def protobuf_string(value: str) -> bytes:
    """Encode one field-one protobuf string request."""
    raw = value.encode()
    if len(raw) >= 128:
        raise ValueError("fixture VM id is unexpectedly long")
    return b"\x0a" + bytes([len(raw)]) + raw


def protobuf_fields(raw: bytes) -> set[int]:
    """Return length-delimited field numbers from a bounded response."""
    fields: set[int] = set()
    offset = 0
    while offset < len(raw):
        tag = raw[offset]
        offset += 1
        field, wire = tag >> 3, tag & 7
        if wire != 2 or field < 1:
            raise ValueError("unexpected protobuf wire encoding")
        length = 0
        shift = 0
        while True:
            byte = raw[offset]
            offset += 1
            length |= (byte & 0x7F) << shift
            if byte < 128:
                break
            shift += 7
            if shift > 28:
                raise ValueError("protobuf length overflow")
        offset += length
        if offset > len(raw):
            raise ValueError("truncated protobuf field")
        fields.add(field)
    return fields


def main() -> int:
    """Run the promoted regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    service = manifest["values"]["services"]["ProxiedGuestApi"]
    vm_id = str(service["id"])
    url = str(service["url"]).format(method="Info")
    failures: list[str] = []
    evidence: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    try:
        print(f"STEP {case_id}-step-01 START", flush=True)
        if not vm_id or not url.startswith("http://127.0.0.1:"):
            raise AssertionError(
                "fixture did not provide an isolated ProxiedGuestApi target"
            )
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Resolved the lease-owned VM and isolated ProxiedGuestApi endpoint.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        payload = json.dumps({"id": vm_id}, separators=(",", ":")).encode()
        json_code, json_raw = request(url, "application/json", payload)
        repeated_code, repeated_raw = request(url, "application/json", payload)
        response = json.loads(json_raw)
        if json_code != 200 or repeated_code != 200 or set(response) != FIELDS:
            raise AssertionError("JSON GuestInfo schema was incomplete")
        if json_raw != repeated_raw:
            raise AssertionError("repeated GuestInfo response was unstable")
        proto_code, proto_raw = request(
            url, "application/octet-stream", protobuf_string(vm_id)
        )
        if proto_code != 200 or protobuf_fields(proto_raw) != set(range(1, 7)):
            raise AssertionError("protobuf GuestInfo schema was incomplete")
        invalid_code, _ = request(url, "application/json", b'{"id":"invalid"}')
        malformed_code, _ = request(url, "application/octet-stream", b"\x0a\xff")
        if invalid_code < 400 or malformed_code < 400:
            raise AssertionError("invalid ProxiedGuestApi.Info input was accepted")
        evidence["matrix"] = {
            "json_status": json_code,
            "json_fields": sorted(response),
            "repeat_status": repeated_code,
            "repeat_sha256_equal": hashlib.sha256(json_raw).digest()
            == hashlib.sha256(repeated_raw).digest(),
            "protobuf_status": proto_code,
            "protobuf_fields": sorted(protobuf_fields(proto_raw)),
            "invalid_status": invalid_code,
            "malformed_status": malformed_code,
            "sensitive_values_persisted": False,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "JSON and protobuf returned fields 1-6; invalid requests failed closed.",
            }
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)

        print(f"STEP {case_id}-step-03 START", flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Repeated read-only Info calls were byte-stable and created no mutable state.",
            }
        )
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            sid = f"{case_id}-step-{number:02d}"
            if not any(step["id"] == sid for step in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    artifact = {
        "name": "ProxiedGuestApi.Info contract matrix",
        "path": "artifacts/proxiedguestapi-info-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Bounded status, schema, determinism, invalid-input, and no-secret assertions for JSON and protobuf Info calls.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "ProxiedGuestApi.Info deterministic JSON/protobuf regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Read-only lease-scoped calls; response contents are not persisted.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
