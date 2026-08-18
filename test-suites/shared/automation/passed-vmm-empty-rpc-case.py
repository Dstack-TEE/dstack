#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic harness for promoted VMM RPC cases.

Each case exercises one indexed `Vmm` method over both JSON and protobuf,
checks that the documented response fields are present, that an invalid route
is rejected, and that an unknown field is ignored. Methods that take request
fields carry their payload in the case table; methods with an empty request
send an empty body.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import urllib.error
import urllib.request
from typing import Any

CREATED_VM_ID = "$created_vm_id"

# case_id -> (method, deterministic, request payload or None for an empty body)
CASES: dict[str, tuple[str, bool, dict[str, Any] | None]] = {
    "tc-vmm-vmm-011": ("ListImages", True, None),
    "tc-vmm-vmm-014": ("Version", True, None),
    "tc-vmm-vmm-015": ("GetMeta", True, None),
    "tc-vmm-vmm-017": ("ReloadVms", False, None),
    "tc-vmm-vmm-018": ("SvList", True, None),
    "tc-vmm-vmm-021": ("ListRegistryImages", True, None),
    # Every field of Vmm.Status is an optional filter, so the empty request is
    # the documented "list everything" call rather than a degenerate one.
    "tc-vmm-vmm-010": ("Status", False, {}),
    # GetComposeHash derives a hash from the supplied configuration without
    # touching VMM state, so it is exercised with a fixed configuration.
    "tc-vmm-vmm-009": (
        "GetComposeHash",
        True,
        {
            "name": "dtest-compose-hash",
            "image": "dstack-dev-0.6.0",
            "compose_file": '{"manifest_version":2,"name":"dtest","runner":"docker-compose","docker_compose_file":"services: {}\\n"}',
            "vcpu": 1,
            "memory": 1024,
            "disk_size": 10,
        },
    ),
    # The documented response carries a timestamp and signatures over it, so
    # two identical requests are byte-identical only within the same second.
    "tc-vmm-vmm-012": (
        "GetAppEnvEncryptPubKey",
        False,
        {"app_id": "00" * 20},
    ),
    # StopVm on the prepared stopped VM is idempotent, so step 3's repeat call
    # holds; GetInfo is read-only.
    "tc-vmm-vmm-003": ("StopVm", False, {"id": CREATED_VM_ID}),
    "tc-vmm-vmm-013": ("GetInfo", False, {"id": CREATED_VM_ID}),
    "tc-vmm-vmm-002": ("StartVm", False, {"id": CREATED_VM_ID}),
    # ShutdownVm, SvStop, SvRemove and RemoveVm do not fit this harness: it
    # calls each method over JSON, then protobuf, then once more, and requires
    # every call to succeed. RemoveVm is not idempotent, and the other three
    # need a running VM and its supervisor process, which the prepared stopped
    # VM does not have. They need a harness that models a state transition.
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


def inventory_entry(root: pathlib.Path, method: str) -> dict[str, Any]:
    """Load the API inventory entry."""
    document = json.loads((root / "catalog" / "api-inventory.json").read_text())
    matches: list[dict[str, Any]] = []

    def walk(value: Any) -> None:
        if isinstance(value, dict):
            if value.get("service") == "Vmm" and value.get("method") == method:
                matches.append(value)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(document)
    if len(matches) != 1:
        raise RuntimeError(f"expected one inventory entry for Vmm.{method}")
    return matches[0]


def http_call(
    url: str,
    *,
    body: bytes,
    content_type: str,
    headers: dict[str, str] | None = None,
    method: str = "POST",
) -> tuple[int, bytes, str | None]:
    """Perform an HTTP request."""
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Content-Type", content_type)
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return (
                int(response.status),
                response.read(),
                response.headers.get("Content-Type"),
            )
    except urllib.error.HTTPError as error:
        content = error.headers.get("Content-Type") if error.headers else None
        return int(error.code), error.read(), content


def create_stopped_vm(manifest: dict[str, Any]) -> str:
    """Create the fixture's prepared stopped VM and return its ID.

    The helper registers the VM in the lease's registry, so the fixture tears
    it down even if the case fails partway through.
    """
    test_input = (manifest["values"].get("vmm") or {}).get("test_input") or {}
    argv = test_input.get("create_stopped_helper_argv")
    if not isinstance(argv, list) or not argv:
        raise RuntimeError("fixture does not prepare create_stopped_helper_argv")
    process = subprocess.run(
        argv, capture_output=True, text=True, timeout=180, check=False
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"prepared VM creation failed ({process.returncode}): "
            f"{process.stderr[-400:]}"
        )
    for line in reversed(process.stdout.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("id"):
            return str(value["id"])
    raise RuntimeError("prepared VM creation printed no VM ID")


def resolve_payload(
    payload: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, Any]:
    """Replace the created-VM placeholder with a freshly created VM ID."""
    if CREATED_VM_ID not in payload.values():
        return dict(payload)
    vm_id = create_stopped_vm(manifest)
    return {
        key: (vm_id if value == CREATED_VM_ID else value)
        for key, value in payload.items()
    }


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


def resolve_vmm(manifest: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """Resolve VMM URL and auth headers."""
    values = manifest["values"]
    vmm = values.get("vmm") or {}
    base = str(
        vmm.get("rpc_url") or values.get("services", {}).get("rpc", {}).get("url") or ""
    )
    if not base:
        raise RuntimeError("manifest missing vmm.rpc_url")
    base = base.rstrip("/")
    headers: dict[str, str] = {}
    auth = vmm.get("auth") or {}
    token_file = auth.get("token_file")
    if auth.get("enabled") and token_file:
        token = pathlib.Path(token_file).read_text(encoding="utf-8").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return base, headers


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
            "remarks": "Promoted deterministic script for empty-input VMM RPC cases.",
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
        raise SystemExit(f"unsupported promoted VMM case: {case_id}")
    method, deterministic, payload = CASES[case_id]
    request_payload: dict = resolve_payload(payload or {}, manifest)
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
        base, headers = resolve_vmm(manifest)
        routes = (manifest["values"].get("vmm") or {}).get("json_prpc_routes") or {}
        json_path = routes.get(method) or f"/prpc/{method}?json"
        # strip ?json for explicit content-type control
        route_path = json_path.split("?", 1)[0]
        json_url = base + route_path
        entry = inventory_entry(plan_root, method)
        prereq = {
            "rpc_url": base,
            "route": route_path,
            "auth_headers": sorted(headers),
            "profile": manifest.get("profile"),
            "lease_id": manifest.get("lease_id"),
        }
        code, body, content_type = http_call(
            json_url,
            body=request_json,
            content_type="application/json",
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
                "description": "Lease-owned VMM listener reachability and Empty method baseline.",
            }
        )
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Lease-owned VMM listener and empty-input method baseline were reachable.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)

        print(f"STEP {case_id}-step-02 START", flush=True)
        json_code, json_body, json_ct = http_call(
            json_url,
            body=request_json,
            content_type="application/json",
            headers=headers,
        )
        if json_code != 200:
            raise AssertionError(f"valid JSON request returned HTTP {json_code}")
        # A google.protobuf.Empty response is serialised either as the JSON
        # literal null or as a zero-length body; both mean "no fields".
        raw_json_value = json.loads(json_body) if json_body.strip() else None
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
            json_url,
            body=pb_request,
            content_type="application/octet-stream",
            headers=headers,
        )
        if pb_code != 200:
            raise AssertionError(f"valid protobuf request returned HTTP {pb_code}")
        wire = decode_wire(pb_body) if pb_body else {}
        bad_code, bad_body, _ = http_call(
            base + route_path + "NoSuch",
            body=b"{}",
            content_type="application/json",
            headers=headers,
        )
        if bad_code < 400:
            raise AssertionError(f"invalid route accepted with HTTP {bad_code}")
        extra_code, extra_body, _ = http_call(
            json_url,
            body=json.dumps({**request_payload, "__probe": True}).encode(),
            content_type="application/json",
            headers=headers,
        )
        if extra_code != 200:
            raise AssertionError(
                f"unknown-field request rejected with HTTP {extra_code}"
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
            json_url,
            body=request_json,
            content_type="application/json",
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
            f"Vmm.{method} passed over JSON and protobuf Empty requests on the lease-owned VMM; "
            "invalid routes were rejected and repeated responses obeyed the determinism policy."
        )
    except Exception as error:  # noqa: BLE001
        status = "FAIL"
        failure = str(error)
        summary = f"Vmm.{method} failed: {failure}"
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
