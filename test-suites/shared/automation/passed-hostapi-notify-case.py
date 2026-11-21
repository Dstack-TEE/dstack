#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify guest-originated HostApi.Notify over the VM's assigned vsock CID."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import time
from typing import Any

CASE = "tc-vmm-hostapi-002"


def load_module(filename: str, name: str) -> Any:
    """Load an adjacent checked-in harness module."""
    path = pathlib.Path(__file__).with_name(filename)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {filename}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = pathlib.Path(handle.name)
    temporary.replace(path)


def listed_vm(vmm: dict[str, Any], vm_id: str) -> dict[str, Any] | None:
    """Return one VM from the fixture's authoritative public listing."""
    import subprocess

    process = subprocess.run(
        vmm["commands"]["list_vms"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(f"list_vms exited {process.returncode}")
    for item in json.loads(process.stdout or "[]"):
        if isinstance(item, dict) and str(item.get("id")) == vm_id:
            return item
    return None


def event_names(events: Any) -> list[str]:
    """Extract public event names without retaining payloads."""
    names: list[str] = []
    if not isinstance(events, list):
        return names
    for event in events:
        if isinstance(event, dict):
            value = event.get("event") or event.get("name") or event.get("kind")
            if value is not None:
                names.append(str(value))
        elif isinstance(event, str):
            names.append(event.split("=", 1)[0].split(":", 1)[0])
    return names


def main() -> int:
    """Boot a lease-owned guest, observe Notify effects, run negatives, clean up."""
    lifecycle = load_module("passed-vmm-lifecycle-case.py", "vmm_lifecycle_common")
    host_common = load_module("passed-hostapi-case.py", "host_api_common")
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    host_api = manifest["values"]["host_api"]
    if vmm.get("case_owned") is not True or host_api.get("case_owned") is not True:
        raise RuntimeError("VMM or Host API fixture is not case-owned")
    base, headers = lifecycle.resolve_vmm(manifest)
    routes = vmm["json_prpc_routes"]
    notify_route = host_api["json_prpc_routes"]["Notify"]

    created: list[str] = []
    evidence: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    failure: str | None = None

    def rpc(method: str, vm_id: str) -> tuple[int, bytes]:
        route = base + routes[method].split("?", 1)[0]
        return lifecycle.call(
            route,
            json.dumps({"id": vm_id}).encode(),
            "application/json",
            headers,
        )

    try:
        baseline = lifecycle.list_vm_ids(manifest)
        probe = host_common.vsock_call(plan_root, host_api, notify_route, "{}")
        if probe["status"] < 400:
            raise AssertionError("host-originated empty Notify unexpectedly succeeded")
        evidence["baseline"] = {
            "vm_count": len(baseline),
            "host_originated_empty_http": probe["status"],
            "transport": host_api.get("transport"),
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The private Host API was reachable and rejected a host-originated Notify with no VM CID.",
            }
        )

        vm_id = lifecycle.create_vm(manifest)
        created.append(vm_id)
        start_code, _ = rpc("StartVm", vm_id)
        if start_code != 200:
            raise AssertionError(f"StartVm returned HTTP {start_code}")
        lifecycle.await_boot(manifest, vm_id, timeout=300)
        item = listed_vm(vmm, vm_id)
        if item is None or item.get("boot_progress") != "done":
            raise AssertionError("started guest did not report boot_progress done")
        names = event_names(item.get("events"))
        normalized = [name.lower().replace("_", ".") for name in names]
        if not any("boot.progress" in name for name in normalized):
            raise AssertionError(f"public events omitted boot.progress: {names}")
        evidence["guest_notify"] = {
            "boot_progress": item.get("boot_progress"),
            "event_names": sorted(set(names)),
            "boot_progress_event_present": True,
            "vm_id_recorded": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "A lease-owned guest reached boot completion and exposed guest-originated boot.progress Notify events.",
            }
        )

        valid_shape = json.dumps({"event": "fixture.event", "payload": "{}"})
        host_originated = host_common.vsock_call(
            plan_root, host_api, notify_route, valid_shape
        )
        wrong_type = host_common.vsock_call(
            plan_root,
            host_api,
            notify_route,
            json.dumps({"event": 7, "payload": {}}),
        )
        unknown_route = host_common.vsock_call(
            plan_root,
            host_api,
            notify_route.replace("Notify", "NotifyNoSuch"),
            valid_shape,
        )
        if host_originated["status"] < 400 or wrong_type["status"] < 400:
            raise AssertionError("invalid-context or wrong-type Notify was accepted")
        if unknown_route["status"] < 400:
            raise AssertionError("unknown Host API route was accepted")
        repeat = listed_vm(vmm, vm_id)
        if repeat is None or repeat.get("boot_progress") != "done":
            raise AssertionError("guest state changed after negative Notify probes")
        evidence["negative"] = {
            "host_originated_valid_shape_http": host_originated["status"],
            "wrong_type_http": wrong_type["status"],
            "unknown_route_http": unknown_route["status"],
            "guest_state_unchanged": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Host-originated, wrong-typed, and unknown-route probes failed while guest state remained healthy.",
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
        cleanup: list[dict[str, int]] = []
        for vm_id in created:
            stop_code, _ = rpc("StopVm", vm_id)
            remove_code, _ = rpc("RemoveVm", vm_id)
            cleanup.append({"stop_http": stop_code, "remove_http": remove_code})
        deadline = time.monotonic() + 30
        remaining = set(created) & lifecycle.list_vm_ids(manifest)
        while remaining and time.monotonic() < deadline:
            time.sleep(1)
            remaining = set(created) & lifecycle.list_vm_ids(manifest)
        evidence["cleanup"] = {
            "statuses": cleanup,
            "all_absent": not remaining,
        }
        if (
            any(row["remove_http"] != 200 for row in cleanup) or remaining
        ) and failure is None:
            failure = "cleanup failed to remove every Notify guest"

    artifact = {
        "path": "artifacts/host-api-notify.json",
        "step_id": f"{case_id}-step-02",
        "name": "Guest-originated HostApi.Notify evidence",
        "description": "Records boot notification names, direct negative statuses, recovery, and cleanup without event payloads.",
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
                "A lease-owned guest exercised HostApi.Notify over its assigned vsock CID and negative probes were isolated."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "The positive row is guest-originated; direct host calls are used only as negative context probes.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
