#!/usr/bin/env python3
# ruff: noqa: D103
# SPDX-License-Identifier: Apache-2.0
"""Verify stopped-VM CPU, memory, and materialized disk resize boundaries."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-vm-lifecyc-004"
_HELPER = pathlib.Path(__file__).with_name("vmm-shutdown-stop-case.py")
_SPEC = importlib.util.spec_from_file_location("vmm_lifecycle_helpers", _HELPER)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError("unable to load VMM lifecycle helpers")
_helpers = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_helpers)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def rpc(
    base: str, headers: dict[str, str], route: str, body: dict[str, Any]
) -> tuple[int, bytes]:
    request = urllib.request.Request(
        base + route.split("?", 1)[0],
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()


def configuration(
    base: str, headers: dict[str, str], routes: dict[str, str], vm_id: str
) -> dict[str, Any]:
    code, raw = rpc(base, headers, routes["GetInfo"], {"id": vm_id})
    value = json.loads(raw or b"{}")
    config = value.get("info", {}).get("configuration", {})
    if code != 200 or not isinstance(config, dict):
        raise AssertionError("GetInfo did not return VM configuration")
    return config


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    test_input = vmm["test_input"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM is not case-owned")
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    command = [str(x) for x in vmm["commands"]["list_vms"]]
    headers = {
        str(k): str(v) for k, v in vmm.get("auth", {}).get("headers", {}).items()
    }
    vm_id = None
    failures: list[str] = []
    steps: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    try:
        evidence["baseline_count"] = len(_helpers.listed(command))
        vm_id = _helpers.create(test_input, "materialized-resize")
        _helpers.wait_state(command, vm_id, "stopped")
        initial = configuration(base, headers, routes, vm_id)
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Created and immediately registered a stopped isolated VM; recorded its public initial resource configuration.",
            }
        )
        start, _ = rpc(base, headers, routes["StartVm"], {"id": vm_id})
        _helpers.wait_state(command, vm_id, "running")
        running_code, _ = rpc(
            base,
            headers,
            routes["ResizeVm"],
            {"id": vm_id, "vcpu": int(initial["vcpu"]) + 1},
        )
        stop, _ = rpc(base, headers, routes["StopVm"], {"id": vm_id})
        _helpers.wait_state(command, vm_id, "stopped")
        if start != 200 or stop != 200 or running_code < 400:
            raise AssertionError("materialization or running-VM rejection failed")
        target = {
            "vcpu": int(initial["vcpu"]) + 1,
            "memory": int(initial["memory"]) + 512,
            "disk_size": int(initial["disk_size"]) + 1,
        }
        grow_code, grow_raw = rpc(
            base, headers, routes["ResizeVm"], {"id": vm_id, **target}
        )
        grown = configuration(base, headers, routes, vm_id)
        if grow_code != 200 or grow_raw not in (b"", b"null", b"{}", b"{}\n"):
            raise AssertionError("valid stopped resize failed")
        evidence["growth_observed"] = {
            "target": target,
            "public": {key: grown.get(key) for key in ("vcpu", "memory", "disk_size")},
        }
        if (
            grown.get("vcpu") != target["vcpu"]
            or grown.get("memory") != target["memory"]
            or grown.get("disk_size") != target["disk_size"]
        ):
            raise AssertionError("valid resize did not persist all resources")
        before_invalid = dict(grown)
        shrink_code, _ = rpc(
            base,
            headers,
            routes["ResizeVm"],
            {"id": vm_id, "disk_size": int(initial["disk_size"])},
        )
        zero_code, _ = rpc(base, headers, routes["ResizeVm"], {"id": vm_id, "vcpu": 0})
        unknown_code, _ = rpc(
            base,
            headers,
            routes["ResizeVm"],
            {"id": "00000000-0000-0000-0000-000000000000", "vcpu": 2},
        )
        after_invalid = configuration(base, headers, routes, vm_id)
        if (
            min(shrink_code, zero_code, unknown_code) < 400
            or after_invalid != before_invalid
        ):
            raise AssertionError(
                "invalid resize was accepted or partially mutated state"
            )
        evidence["matrix"] = {
            "start": start,
            "running_resize": running_code,
            "stop": stop,
            "growth": grow_code,
            "shrink": shrink_code,
            "zero": zero_code,
            "unknown": unknown_code,
            "initial": initial,
            "grown": grown,
            "invalid_atomic": True,
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Started once to materialize the writable disk, rejected running resize, then persisted stopped CPU/memory/disk growth while shrink and invalid values failed atomically.",
            }
        )
        repeat_code, _ = rpc(base, headers, routes["ResizeVm"], {"id": vm_id, **target})
        if repeat_code != 200 or configuration(base, headers, routes, vm_id) != grown:
            raise AssertionError("repeat resize was not idempotent")
        evidence["repeat"] = repeat_code
        evidence["sensitive_values_persisted"] = False
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Repeated growth was idempotent, the public state stayed stable after rejected inputs, and the VMM remained available.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            step_id = f"{CASE_ID}-step-{number:02d}"
            if not any(x["id"] == step_id for x in steps):
                steps.append(
                    {"id": step_id, "status": "FAIL", "observed": failures[-1]}
                )
    finally:
        if vm_id:
            stop_code, _ = rpc(base, headers, routes["StopVm"], {"id": vm_id})
            remove_code, _ = rpc(base, headers, routes["RemoveVm"], {"id": vm_id})
            evidence["cleanup"] = {"stop": stop_code, "remove": remove_code}
    artifact = {
        "path": "artifacts/vmm-materialized-resize.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "VMM materialized resize matrix",
        "description": "Public-state and HTTP evidence for disk materialization, running rejection, stopped growth, shrink/invalid atomicity, repeat behavior, and cleanup.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "Materialized stopped-VM resize boundaries passed."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only an immediately registered VM owned by the isolated fixture was resized and removed.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
