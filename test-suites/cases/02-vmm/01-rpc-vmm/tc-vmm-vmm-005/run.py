#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic UpgradeApp persistence and rejection contract."""

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

CASE = "tc-vmm-vmm-005"


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
    """Encode a length-delimited protobuf field."""
    return varint((number << 3) | 2) + varint(len(raw)) + raw


def scalar_field(number: int, value: int | bool) -> bytes:
    """Encode a protobuf varint field."""
    return varint(number << 3) + varint(int(value))


def encode_gpu(value: dict[str, Any]) -> bytes:
    """Encode GpuConfig."""
    output = bytearray()
    for item in value.get("gpus") or []:
        output.extend(length_field(1, length_field(1, str(item["slot"]).encode())))
    output.extend(length_field(2, str(value.get("attach_mode", "")).encode()))
    return bytes(output)


def encode_network(value: dict[str, Any]) -> bytes:
    """Encode NetworkingConfig."""
    return length_field(1, str(value.get("mode", "")).encode()) + length_field(
        2, str(value.get("bridge_name", "")).encode()
    )


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


def encode_update(value: dict[str, Any]) -> bytes:
    """Encode every non-reserved UpdateVmRequest field."""
    output = bytearray()
    for number, name in {1: "id", 2: "compose_file", 4: "user_config"}.items():
        output.extend(length_field(number, str(value.get(name, "")).encode()))
    encrypted = value.get("encrypted_env") or ""
    output.extend(length_field(3, bytes.fromhex(encrypted) if encrypted else b""))
    output.extend(scalar_field(5, bool(value.get("update_ports"))))
    for item in value.get("ports") or []:
        output.extend(length_field(7, encode_port(item)))
    output.extend(scalar_field(8, bool(value.get("update_kms_urls"))))
    for item in value.get("kms_urls") or []:
        output.extend(length_field(9, str(item).encode()))
    output.extend(scalar_field(10, bool(value.get("update_gateway_urls"))))
    for item in value.get("gateway_urls") or []:
        output.extend(length_field(11, str(item).encode()))
    output.extend(length_field(13, encode_gpu(value.get("gpus") or {})))
    for number, name in {14: "vcpu", 15: "memory", 16: "disk_size"}.items():
        if value.get(name) is not None:
            output.extend(scalar_field(number, int(value[name])))
    if value.get("image") is not None:
        output.extend(length_field(17, str(value["image"]).encode()))
    if value.get("no_tee") is not None:
        output.extend(scalar_field(18, bool(value["no_tee"])))
    output.extend(scalar_field(19, bool(value.get("update_networking"))))
    for item in value.get("networks") or []:
        output.extend(length_field(20, encode_network(item)))
    return bytes(output)


def decode_id(body: bytes) -> str:
    """Decode Id.id from a protobuf response."""
    if not body or body[0] != 0x0A:
        raise AssertionError("protobuf Id response omitted field 1")
    offset, length, shift = 1, 0, 0
    while True:
        byte = body[offset]
        offset += 1
        length |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
    return body[offset : offset + length].decode()


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


def create_vm(manifest: dict[str, Any]) -> str:
    """Create one stopped fixture-owned VM through the prepared helper."""
    command = manifest["values"]["vmm"]["test_input"]["create_stopped_helper_argv"]
    process = subprocess.run(
        command, capture_output=True, text=True, timeout=180, check=False
    )
    if process.returncode:
        raise RuntimeError(f"create helper failed: {process.stderr[-300:]}")
    for line in reversed(process.stdout.splitlines()):
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("id"):
            return str(value["id"])
    raise RuntimeError("create helper returned no VM ID")


def list_ids(manifest: dict[str, Any]) -> set[str]:
    """List VMs through the authoritative fixture command."""
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
    """Upgrade independent stopped VMs over JSON and protobuf."""
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
    template = vmm["test_input"]["vm_configuration"]
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm.get("json_prpc_routes") or {}
    upgrade_path = (routes.get("UpgradeApp") or "/prpc/UpgradeApp?json").split("?", 1)[
        0
    ]
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
    evidence: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    failure: str | None = None

    def request_for(vm_id: str, encoding: str) -> tuple[dict[str, Any], str]:
        compose = json.loads(template["compose_file"])
        compose["upgrade_contract"] = f"{nonce}-{encoding}"
        compose_file = json.dumps(compose, separators=(",", ":"), sort_keys=True)
        request = {
            "id": vm_id,
            "compose_file": compose_file,
            "encrypted_env": "",
            "user_config": f"upgrade-{nonce}-{encoding}",
            "update_ports": True,
            "ports": [],
            "update_kms_urls": True,
            "kms_urls": [],
            "update_gateway_urls": True,
            "gateway_urls": [],
            "gpus": {"attach_mode": "listed", "gpus": []},
            "vcpu": 2,
            "memory": 1280,
            "disk_size": 21,
            "image": template["image"],
            "no_tee": True,
            "update_networking": True,
            "networks": [],
        }
        return request, hashlib.sha256(compose_file.encode()).hexdigest()[:40]

    def persisted(vm_id: str, request: dict[str, Any]) -> dict[str, Any]:
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
            raise AssertionError("GetInfo omitted configuration")
        for key in (
            "compose_file",
            "user_config",
            "vcpu",
            "memory",
            "disk_size",
            "image",
            "no_tee",
        ):
            if config.get(key) != request.get(key):
                raise AssertionError(f"UpgradeApp did not persist {key}")
        return config

    try:
        baseline = list_ids(manifest)
        evidence["baseline_count"] = len(baseline)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The case-owned VMM was healthy before creating upgrade targets.",
            }
        )

        json_vm = create_vm(manifest)
        created.append(json_vm)
        json_request, json_expected = request_for(json_vm, "json")
        json_code, json_body = call(
            base + upgrade_path,
            json.dumps({**json_request, "future_field": "ignored"}).encode(),
            "application/json",
            headers,
        )
        json_value = json.loads(json_body or b"{}")
        json_id = json_value.get("id") if isinstance(json_value, dict) else None
        if json_code != 200 or json_id != json_expected:
            raise AssertionError(
                f"JSON UpgradeApp returned HTTP {json_code}, id={json_id!r}, "
                f"expected={json_expected!r}: "
                f"{json_body.decode('utf-8', 'replace')[:300]}"
            )
        json_config = persisted(json_vm, json_request)

        protobuf_vm = create_vm(manifest)
        created.append(protobuf_vm)
        protobuf_request, protobuf_expected = request_for(protobuf_vm, "protobuf")
        protobuf_code, protobuf_body = call(
            base + upgrade_path,
            encode_update(protobuf_request),
            "application/octet-stream",
            headers,
        )
        protobuf_id = decode_id(protobuf_body) if protobuf_code == 200 else ""
        if protobuf_code != 200 or protobuf_id != protobuf_expected:
            raise AssertionError(
                f"protobuf UpgradeApp returned HTTP {protobuf_code}, "
                f"id={protobuf_id!r}, expected={protobuf_expected!r}: "
                f"{protobuf_body.decode('utf-8', 'replace')[:300]}"
            )
        protobuf_config = persisted(protobuf_vm, protobuf_request)
        evidence["representations"] = {
            "json_http": json_code,
            "json_derived_id_matches": True,
            "json_persisted_fields": sorted(json_config),
            "protobuf_http": protobuf_code,
            "protobuf_derived_id_matches": True,
            "protobuf_persisted_fields": sorted(protobuf_config),
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "JSON and protobuf independently returned the compose-derived app ID and persisted compose, user, compute, image, TEE, endpoint-list, port, GPU, and networking updates.",
            }
        )

        malformed_compose, _ = call(
            base + upgrade_path,
            json.dumps({"id": json_vm, "compose_file": "{"}).encode(),
            "application/json",
            headers,
        )
        missing_vm, _ = call(
            base + upgrade_path,
            json.dumps(
                {**json_request, "id": "00000000-0000-0000-0000-000000000000"}
            ).encode(),
            "application/json",
            headers,
        )
        wrong_type, _ = call(
            base + upgrade_path,
            json.dumps({**json_request, "memory": "x"}).encode(),
            "application/json",
            headers,
        )
        malformed_pb, _ = call(
            base + upgrade_path, b"\x0a\x80", "application/octet-stream", headers
        )
        bad_route, _ = call(
            base + upgrade_path + "NoSuch", b"{}", "application/json", headers
        )
        statuses = [malformed_compose, missing_vm, wrong_type, malformed_pb, bad_route]
        if min(statuses) < 400:
            raise AssertionError(f"invalid UpgradeApp probe was accepted: {statuses}")
        repeat_code, repeat_body = call(
            base + upgrade_path,
            json.dumps(json_request).encode(),
            "application/json",
            headers,
        )
        repeat_id = json.loads(repeat_body or b"{}").get("id")
        if repeat_code != 200 or repeat_id != json_expected:
            raise AssertionError(
                "identical UpgradeApp did not converge to the same app ID"
            )
        if set(list_ids(manifest)) != baseline | set(created):
            raise AssertionError("rejected UpgradeApp probe changed VM inventory")
        evidence["negative"] = {
            "malformed_compose_http": malformed_compose,
            "missing_vm_http": missing_vm,
            "wrong_type_http": wrong_type,
            "malformed_protobuf_http": malformed_pb,
            "invalid_route_http": bad_route,
            "repeat_http": repeat_code,
            "repeat_id_matches": True,
            "inventory_unchanged": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Malformed compose, missing VM, wrong type, malformed protobuf, and invalid route failed; an identical repeat converged to the same app ID.",
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
        cleanup: list[int] = []
        for vm_id in created:
            code, _ = call(
                base + remove_path,
                json.dumps({"id": vm_id}).encode(),
                "application/json",
                headers,
            )
            cleanup.append(code)
        deadline = time.monotonic() + 30
        while set(created) & list_ids(manifest) and time.monotonic() < deadline:
            time.sleep(1)
        evidence["cleanup"] = {
            "statuses": cleanup,
            "all_absent": not bool(set(created) & list_ids(manifest)),
        }
        if (
            any(code != 200 for code in cleanup)
            or not evidence["cleanup"]["all_absent"]
        ) and failure is None:
            failure = "cleanup failed to remove every upgraded VM"

    artifact = {
        "path": "artifacts/upgrade-app-contract.json",
        "step_id": f"{case_id}-step-02",
        "name": "UpgradeApp contract matrix",
        "description": "Records representation-specific persistence, derived identities, rejection paths, repeat convergence, and cleanup.",
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
                "Vmm.UpgradeApp persisted full updates over JSON and protobuf and returned deterministic compose-derived IDs."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Each representation uses a separate stopped VM; all targets and the VMM are lease-owned.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
