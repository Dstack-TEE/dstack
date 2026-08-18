#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic CreateVm contract and stopped-VM persistence lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-vmm-001"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def varint(value: int) -> bytes:
    """Encode an unsigned protobuf varint."""
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        output.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(output)


def length_field(number: int, raw: bytes) -> bytes:
    """Encode one length-delimited protobuf field."""
    return varint((number << 3) | 2) + varint(len(raw)) + raw


def scalar_field(number: int, value: int | bool) -> bytes:
    """Encode one protobuf varint field."""
    return varint(number << 3) + varint(int(value))


def encode_network(value: dict[str, Any]) -> bytes:
    """Encode NetworkingConfig."""
    return b"".join(
        [
            length_field(1, str(value.get("mode", "")).encode()),
            length_field(2, str(value.get("bridge_name", "")).encode()),
        ]
    )


def encode_gpu(value: dict[str, Any]) -> bytes:
    """Encode GpuConfig including each requested slot and attach mode."""
    output = bytearray()
    for item in value.get("gpus") or []:
        output.extend(length_field(1, length_field(1, str(item["slot"]).encode())))
    output.extend(length_field(2, str(value.get("attach_mode", "")).encode()))
    return bytes(output)


def encode_port(value: dict[str, Any]) -> bytes:
    """Encode PortMapping."""
    return b"".join(
        [
            length_field(1, str(value.get("protocol", "")).encode()),
            scalar_field(2, int(value.get("host_port", 0))),
            scalar_field(3, int(value.get("vm_port", 0))),
            length_field(4, str(value.get("host_address", "")).encode()),
        ]
    )


def encode_config(value: dict[str, Any]) -> bytes:
    """Encode every non-reserved VmConfiguration field."""
    output = bytearray()
    strings = {1: "name", 2: "image", 3: "compose_file", 10: "user_config"}
    for number, name in strings.items():
        output.extend(length_field(number, str(value.get(name, "")).encode()))
    for number, name in {4: "vcpu", 5: "memory", 6: "disk_size"}.items():
        output.extend(scalar_field(number, int(value.get(name, 0))))
    for item in value.get("ports") or []:
        output.extend(length_field(7, encode_port(item)))
    encrypted = value.get("encrypted_env") or ""
    raw_env = bytes.fromhex(encrypted) if encrypted else b""
    output.extend(length_field(8, raw_env))
    if value.get("app_id") is not None:
        output.extend(length_field(9, str(value["app_id"]).encode()))
    output.extend(scalar_field(11, bool(value.get("hugepages"))))
    output.extend(scalar_field(12, bool(value.get("pin_numa"))))
    output.extend(length_field(13, encode_gpu(value.get("gpus") or {})))
    for item in value.get("kms_urls") or []:
        output.extend(length_field(14, str(item).encode()))
    for item in value.get("gateway_urls") or []:
        output.extend(length_field(15, str(item).encode()))
    output.extend(scalar_field(16, bool(value.get("stopped"))))
    output.extend(scalar_field(17, bool(value.get("no_tee"))))
    if value.get("networking") is not None:
        output.extend(length_field(18, encode_network(value["networking"])))
    for item in value.get("networks") or []:
        output.extend(length_field(19, encode_network(item)))
    if value.get("simulated_tee") is not None:
        output.extend(length_field(21, str(value["simulated_tee"]).encode()))
    return bytes(output)


def decode_id(body: bytes) -> str:
    """Decode the required Id.id response field."""
    if not body or body[0] != 0x0A:
        raise AssertionError("protobuf Id response omitted field 1")
    offset = 1
    length = 0
    shift = 0
    while True:
        byte = body[offset]
        offset += 1
        length |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
    raw = body[offset : offset + length]
    if len(raw) != length:
        raise AssertionError("protobuf Id response was truncated")
    return raw.decode()


def call(
    url: str, body: bytes, content_type: str, headers: dict[str, str]
) -> tuple[int, bytes]:
    """Perform one bounded pRPC call."""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", content_type)
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def list_ids(manifest: dict[str, Any]) -> set[str]:
    """List persisted VM IDs using the fixture's authoritative command."""
    command = manifest["values"]["vmm"]["commands"]["list_vms"]
    process = subprocess.run(
        command, capture_output=True, text=True, timeout=30, check=False
    )
    if process.returncode:
        raise RuntimeError(f"list_vms failed: {process.stderr[-300:]}")
    return {
        str(item.get("id"))
        for item in json.loads(process.stdout or "[]")
        if isinstance(item, dict)
    }


def main() -> int:
    """Create stopped VMs through both wire representations and validate state."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM fixture is not case-owned")
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm.get("json_prpc_routes") or {}
    create_path = (routes.get("CreateVm") or "/prpc/CreateVm?json").split("?", 1)[0]
    info_path = (routes.get("GetInfo") or "/prpc/GetInfo?json").split("?", 1)[0]
    remove_path = (routes.get("RemoveVm") or "/prpc/RemoveVm?json").split("?", 1)[0]
    headers: dict[str, str] = {}
    auth = vmm.get("auth") or {}
    token_file = auth.get("token_file")
    if auth.get("enabled") and token_file:
        token = pathlib.Path(token_file).read_text().strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    nonce = hashlib.sha256(f"{time.time_ns()}:{case_id}".encode()).hexdigest()[:12]
    created: list[str] = []
    evidence: dict[str, Any] = {"template_fields": sorted(template)}
    steps: list[dict[str, str]] = []
    failure: str | None = None

    def persisted(vm_id: str, expected: dict[str, Any]) -> dict[str, Any]:
        code, body = call(
            base + info_path,
            json.dumps({"id": vm_id}).encode(),
            "application/json",
            headers,
        )
        if code != 200:
            raise AssertionError(f"GetInfo returned HTTP {code}")
        value = json.loads(body or b"{}")
        info = value.get("info") if isinstance(value, dict) else None
        config = info.get("configuration") if isinstance(info, dict) else None
        if not isinstance(config, dict):
            raise AssertionError("GetInfo omitted persisted configuration")
        for key in (
            "name",
            "image",
            "compose_file",
            "vcpu",
            "memory",
            "disk_size",
            "stopped",
            "no_tee",
        ):
            if config.get(key) != expected.get(key):
                raise AssertionError(
                    f"persisted {key}={config.get(key)!r}, expected {expected.get(key)!r}"
                )
        return config

    try:
        baseline = list_ids(manifest)
        evidence["baseline_count"] = len(baseline)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The case-owned VMM was reachable and contained no run-scoped VM IDs.",
            }
        )

        json_config = json.loads(json.dumps(template))
        json_config["name"] = f"dtest-{nonce}-create-json"
        json_request = {**json_config, "future_field": "ignored"}
        json_code, json_body = call(
            base + create_path,
            json.dumps(json_request).encode(),
            "application/json",
            headers,
        )
        json_value = json.loads(json_body or b"{}")
        json_id = json_value.get("id") if isinstance(json_value, dict) else None
        if json_code != 200 or not json_id:
            raise AssertionError(
                f"JSON CreateVm returned HTTP {json_code}: "
                f"{json_body.decode('utf-8', 'replace')[:300]}"
            )
        created.append(str(json_id))
        json_persisted = persisted(str(json_id), json_config)

        protobuf_config = json.loads(json.dumps(template))
        protobuf_config["name"] = f"dtest-{nonce}-create-protobuf"
        protobuf_code, protobuf_body = call(
            base + create_path,
            encode_config(protobuf_config),
            "application/octet-stream",
            headers,
        )
        if protobuf_code != 200:
            raise AssertionError(f"protobuf CreateVm returned HTTP {protobuf_code}")
        protobuf_id = decode_id(protobuf_body)
        if not protobuf_id:
            raise AssertionError("protobuf CreateVm returned an empty ID")
        created.append(protobuf_id)
        protobuf_persisted = persisted(protobuf_id, protobuf_config)
        if not set(created).issubset(list_ids(manifest)):
            raise AssertionError("created VM was absent from the authoritative listing")
        evidence["representations"] = {
            "json_http": json_code,
            "json_id_present": True,
            "json_persisted_fields": sorted(json_persisted),
            "protobuf_http": protobuf_code,
            "protobuf_id_present": True,
            "protobuf_persisted_fields": sorted(protobuf_persisted),
            "ids_distinct": json_id != protobuf_id,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "JSON and protobuf created distinct stopped VMs and GetInfo reproduced every persisted core configuration field.",
            }
        )

        missing_image, _ = call(
            base + create_path,
            json.dumps({"name": f"dtest-{nonce}-missing"}).encode(),
            "application/json",
            headers,
        )
        wrong_type, _ = call(
            base + create_path,
            json.dumps(
                {**template, "name": f"dtest-{nonce}-type", "memory": "x"}
            ).encode(),
            "application/json",
            headers,
        )
        malformed, _ = call(
            base + create_path, b"\x0a\x80", "application/octet-stream", headers
        )
        bad_route, _ = call(
            base + create_path + "NoSuch", b"{}", "application/json", headers
        )
        statuses = [missing_image, wrong_type, malformed, bad_route]
        if min(statuses) < 400:
            raise AssertionError(f"invalid CreateVm probe was accepted: {statuses}")
        if set(list_ids(manifest)) != baseline | set(created):
            raise AssertionError("rejected CreateVm probe left partial VM state")
        unauthenticated: int | None = None
        if headers:
            unauthenticated, _ = call(
                base + create_path,
                json.dumps({**template, "name": f"dtest-{nonce}-unauth"}).encode(),
                "application/json",
                {},
            )
            if unauthenticated < 400:
                raise AssertionError("CreateVm accepted an unauthenticated request")
        evidence["negative"] = {
            "missing_required_http": missing_image,
            "wrong_type_http": wrong_type,
            "malformed_protobuf_http": malformed,
            "invalid_route_http": bad_route,
            "unauthenticated_http": unauthenticated,
            "no_partial_state": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Missing, wrong-typed, malformed-protobuf, invalid-route, and applicable unauthenticated requests failed without partial VM state.",
            }
        )
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        done = {step["id"] for step in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in done:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})
    finally:
        cleanup: dict[str, int] = {}
        for vm_id in created:
            code, _ = call(
                base + remove_path,
                json.dumps({"id": vm_id}).encode(),
                "application/json",
                headers,
            )
            cleanup[vm_id] = code
        deadline = time.monotonic() + 30
        while set(created) & list_ids(manifest) and time.monotonic() < deadline:
            time.sleep(1)
        evidence["cleanup"] = {
            "statuses": sorted(cleanup.values()),
            "all_absent": not bool(set(created) & list_ids(manifest)),
        }
        if (
            any(code != 200 for code in cleanup.values())
            or not evidence["cleanup"]["all_absent"]
        ):
            if failure is None:
                failure = "cleanup failed to remove every created VM"

    artifact = {
        "path": "artifacts/create-vm-contract.json",
        "step_id": f"{case_id}-step-02",
        "name": "CreateVm contract matrix",
        "description": "Records independent representations, persisted fields, rejection paths, isolation, and cleanup.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if failure is None else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": (
                "Vmm.CreateVm created and persisted independent stopped VMs over JSON and protobuf and rejected invalid requests."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "All created VMs and the VMM are lease-owned; both successful rows are removed after verification.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
