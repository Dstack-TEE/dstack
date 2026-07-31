#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# ruff: noqa: E731
# SPDX-License-Identifier: Apache-2.0
"""Deterministic VMM port-mapping conflict and update regression."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import socket
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE = "tc-vmm-compute-ne-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write JSON evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        tmp = pathlib.Path(f.name)
    tmp.replace(path)


def call(
    base: str, headers: dict[str, str], method: str, body: dict[str, Any]
) -> tuple[int, bytes]:
    """Invoke one JSON pRPC method."""
    req = urllib.request.Request(
        base + f"/prpc/{method}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def free_port(minimum: int) -> int:
    """Reserve and release a policy-eligible loopback port."""
    for _ in range(100):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if port >= minimum:
            return port
    raise RuntimeError("could not allocate eligible host port")


def main() -> int:
    """Execute the promoted case."""
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
    auth = vmm.get("auth", {})
    headers = {str(k): str(v) for k, v in auth.get("headers", {}).items()}
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    policy = vmm["test_input"]["port_mapping"]
    ports = []
    observations = {"operations": []}
    steps = []
    failures = []

    def create(name: str, maps: list[dict[str, Any]]) -> tuple[int, str | None]:
        cfg = json.loads(json.dumps(template))
        cfg.update({"name": name, "ports": maps, "stopped": True})
        code, raw = call(base, headers, "CreateVm", cfg)
        value = json.loads(raw or b"null") if raw else None
        vm_id = value.get("id") if isinstance(value, dict) else None
        error = None
        if code >= 400:
            try:
                error = str(json.loads(raw).get("error", ""))[:300]
            except Exception:
                error = "unparseable error response"
        observations["operations"].append(
            {
                "operation": "create",
                "status": code,
                "port_count": len(maps),
                "id_returned": bool(vm_id),
                "error": error,
            }
        )
        if vm_id:
            ports.append(vm_id)
        return code, vm_id

    try:
        minimum = int(policy["min"])
        p1, p2, p3 = (free_port(minimum) for _ in range(3))
        nonce = hashlib.sha256(f"{time.time_ns()}".encode()).hexdigest()[:12]
        tcp = lambda port, to: {
            "protocol": "tcp",
            "host_port": port,
            "vm_port": to,
            "host_address": "127.0.0.1",
        }
        udp = lambda port, to: {
            "protocol": "udp",
            "host_port": port,
            "vm_port": to,
            "host_address": "127.0.0.1",
        }
        print(f"STEP {case_id}-step-01 START", flush=True)
        code, primary = create(f"dtest-{nonce}-primary", [tcp(p1, 8080), udp(p2, 8081)])
        if code != 200 or not primary:
            raise AssertionError("valid TCP/UDP create failed")
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Case-owned VMM accepted valid stopped-VM TCP and UDP mappings.",
            }
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)
        print(f"STEP {case_id}-step-02 START", flush=True)
        duplicate, _ = create(f"dtest-{nonce}-dup", [tcp(p3, 9000), tcp(p3, 9001)])
        conflict, _ = create(f"dtest-{nonce}-conflict", [tcp(p1, 9100)])
        if duplicate < 400 or conflict < 400:
            raise AssertionError(
                "duplicate or existing-VM host-port conflict was accepted"
            )
        update_code, _ = call(
            base,
            headers,
            "UpdateVm",
            {"id": primary, "update_ports": True, "ports": [tcp(p3, 8088)]},
        )
        reset_code, _ = call(
            base,
            headers,
            "UpdateVm",
            {"id": primary, "update_ports": True, "ports": []},
        )
        if update_code != 200 or reset_code != 200:
            raise AssertionError("port replacement or reset failed")
        observations["operations"].append(
            {
                "operation": "conflict_matrix",
                "duplicate_status": duplicate,
                "existing_status": conflict,
                "update_status": update_code,
                "reset_status": reset_code,
            }
        )
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Duplicate and existing-VM conflicts were rejected; replacement and reset succeeded.",
            }
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)
        print(f"STEP {case_id}-step-03 START", flush=True)
        reuse, _ = create(f"dtest-{nonce}-reuse", [tcp(p1, 9200)])
        if reuse != 200:
            raise AssertionError("released host port was not reusable")
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Reset released mappings and the original host port was reusable.",
            }
        )
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
    except Exception as e:
        failures.append(f"{type(e).__name__}: {e}")
        for n in range(1, 4):
            sid = f"{case_id}-step-{n:02d}"
            if not any(x["id"] == sid for x in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    finally:
        cleanup = []
        for vm_id in reversed(ports):
            stop, _ = call(base, headers, "StopVm", {"id": vm_id})
            remove, _ = call(base, headers, "RemoveVm", {"id": vm_id})
            cleanup.append({"stop": stop, "remove": remove})
        observations["cleanup"] = cleanup
        observations["sensitive_values_persisted"] = False
    artifact = {
        "name": "VMM port mapping matrix",
        "path": "artifacts/vmm-port-mapping-matrix.json",
        "step_id": f"{case_id}-step-02",
        "description": "Records bounded statuses for valid mapping, duplicate/cross-VM conflict rejection, replacement, reset, reuse, and cleanup.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "VMM port mapping regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only stopped VMs owned by the isolated fixture were created and removed.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
