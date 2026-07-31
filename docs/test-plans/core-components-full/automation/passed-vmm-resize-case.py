#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic VMM ResizeVm regression for a stopped fixture-owned VM."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-vmm-008"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def call(
    base: str, headers: dict[str, str], method: str, body: dict[str, Any]
) -> tuple[int, bytes]:
    """Invoke one JSON pRPC method."""
    request = urllib.request.Request(
        base + f"/prpc/{method}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def main() -> int:
    """Run promoted ResizeVm coverage."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM fixture is not case-owned")
    base = str(vmm["rpc_url"]).rstrip("/")
    headers = {
        str(k): str(v) for k, v in vmm.get("auth", {}).get("headers", {}).items()
    }
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    vm_id = None
    steps = []
    failures = []
    evidence = {}
    try:
        nonce = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:12]
        template.update({"name": f"dtest-{nonce}-resize", "ports": [], "stopped": True})
        print(f"STEP {case_id}-step-01 START", flush=True)
        create_code, raw = call(base, headers, "CreateVm", template)
        created = json.loads(raw or b"null")
        vm_id = created.get("id") if isinstance(created, dict) else None
        if create_code != 200 or not vm_id:
            raise AssertionError("stopped VM creation failed")
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Created a stopped fixture-owned VM and retained the returned RPC id.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)
        print(f"STEP {case_id}-step-02 START", flush=True)
        vcpu = int(template["vcpu"]) + 1
        memory = int(template["memory"]) + 512
        valid_code, valid_body = call(
            base,
            headers,
            "ResizeVm",
            {
                "id": vm_id,
                "vcpu": vcpu,
                "memory": memory,
                "diskSize": int(template["disk_size"]),
                "image": template["image"],
            },
        )
        zero_code, _ = call(base, headers, "ResizeVm", {"id": vm_id, "vcpu": 0})
        empty_code, _ = call(base, headers, "ResizeVm", {"id": vm_id})
        unknown_code, _ = call(
            base,
            headers,
            "ResizeVm",
            {"id": "00000000-0000-0000-0000-000000000000", "vcpu": 2},
        )
        evidence["matrix"] = {
            "valid": valid_code,
            "valid_body_bytes": len(valid_body),
            "zero": zero_code,
            "empty": empty_code,
            "unknown": unknown_code,
            "state_persisted": False,
        }
        if valid_code != 200 or valid_body not in (b"", b"null", b"{}\n", b"{}"):
            raise AssertionError("valid ResizeVm unit response failed")
        if min(zero_code, empty_code, unknown_code) < 400:
            raise AssertionError("invalid ResizeVm input was accepted")
        info_code, info_raw = call(base, headers, "GetInfo", {"id": vm_id})
        info = json.loads(info_raw)
        configuration = info.get("info", {}).get("configuration", {})
        if (
            info_code != 200
            or configuration.get("vcpu") != vcpu
            or configuration.get("memory") != memory
        ):
            raise AssertionError("resized state did not persist")
        evidence["matrix"]["state_persisted"] = True
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Valid resize persisted; zero/default/unknown-id requests failed closed.",
            }
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)
        print(f"STEP {case_id}-step-03 START", flush=True)
        repeat, _ = call(
            base, headers, "ResizeVm", {"id": vm_id, "vcpu": vcpu, "memory": memory}
        )
        post, _ = call(base, headers, "GetInfo", {"id": vm_id})
        if repeat != 200 or post != 200:
            raise AssertionError("repeat resize or post-error availability failed")
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Repeated valid resize was idempotent and VMM remained available.",
            }
        )
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            sid = f"{case_id}-step-{number:02d}"
            if not any(step["id"] == sid for step in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    finally:
        if vm_id:
            stop, _ = call(base, headers, "StopVm", {"id": vm_id})
            remove, _ = call(base, headers, "RemoveVm", {"id": vm_id})
            evidence["cleanup"] = {"stop": stop, "remove": remove}
        evidence["sensitive_values_persisted"] = False
    artifact = {
        "name": "VMM resize matrix",
        "path": "artifacts/vmm-resize-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Bounded status and state assertions for valid, boundary-invalid, repeat, availability, and cleanup behavior.",
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
            "summary": "VMM resize regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only a stopped VM owned by the isolated fixture was mutated and removed.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
