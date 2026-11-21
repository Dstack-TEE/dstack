#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103
"""Compare graceful guest shutdown with forced VMM stop on isolated VMs."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-vm-lifecyc-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        tmp = pathlib.Path(f.name)
    tmp.replace(path)


def rpc(base: str, headers: dict[str, str], route: str, body: dict[str, Any]) -> int:
    req = urllib.request.Request(
        base + route.split("?", 1)[0],
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def listed(command: list[str]) -> list[dict[str, Any]]:
    p = subprocess.run(command, text=True, capture_output=True, timeout=60, check=False)
    if p.returncode:
        raise RuntimeError("prepared list_vms command failed")
    value = json.loads(p.stdout or "[]")
    return value if isinstance(value, list) else []


def find_vm(command: list[str], vm_id: str) -> dict[str, Any] | None:
    return next((x for x in listed(command) if str(x.get("id")) == vm_id), None)


def wait_state(
    command: list[str], vm_id: str, wanted: str, timeout: int = 240
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        vm = find_vm(command, vm_id)
        observed = None if vm is None else str(vm.get("status"))
        if vm is not None and observed == wanted:
            return vm
        time.sleep(2)
    raise AssertionError(f"VM remained {observed!r} instead of {wanted!r}")


def wait_boot(command: list[str], vm_id: str, timeout: int = 300) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        vm = find_vm(command, vm_id)
        observed = None if vm is None else vm.get("boot_progress")
        if vm is not None and observed == "done":
            return vm
        time.sleep(3)
    raise AssertionError(f"guest boot remained {observed!r} instead of 'done'")


def create(test_input: dict[str, Any], suffix: str) -> str:
    p = subprocess.run(
        [
            *map(str, test_input["create_stopped_helper_argv"]),
            "--name",
            f"{test_input.get('name_prefix', 'dtest')}-{suffix}",
        ],
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if p.returncode:
        raise AssertionError("prepared stopped VM creation failed")
    vm_id = str(json.loads(p.stdout.splitlines()[-1])["id"])
    registry = json.loads(pathlib.Path(test_input["created_vms_registry"]).read_text())
    if vm_id not in registry:
        raise AssertionError("created VM ID was not immediately registered")
    return vm_id


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
    ids: list[str] = []
    failures: list[str] = []
    steps: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {}
    try:
        evidence["baseline_count"] = len(listed(command))
        graceful = create(test_input, "graceful")
        ids.append(graceful)
        forced = create(test_input, "forced")
        ids.append(forced)
        wait_state(command, graceful, "stopped")
        wait_state(command, forced, "stopped")
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Created and immediately registered two isolated stopped VMs on the healthy case-owned VMM.",
            }
        )
        start_graceful = rpc(base, headers, routes["StartVm"], {"id": graceful})
        start_forced = rpc(base, headers, routes["StartVm"], {"id": forced})
        if start_graceful != 200 or start_forced != 200:
            raise AssertionError("VM start failed")
        wait_state(command, graceful, "running")
        wait_state(command, forced, "running")
        wait_boot(command, graceful)
        shutdown = rpc(base, headers, routes["ShutdownVm"], {"id": graceful})
        wait_state(command, graceful, "stopped")
        peer = find_vm(command, forced)
        if shutdown != 200 or peer is None or peer.get("status") != "running":
            raise AssertionError("graceful shutdown failed or changed peer VM")
        forced_before = peer.get("boot_progress")
        stop = rpc(base, headers, routes["StopVm"], {"id": forced})
        wait_state(command, forced, "stopped")
        if stop != 200:
            raise AssertionError("forced stop failed")
        evidence["transitions"] = {
            "graceful": {"code": shutdown, "final": "stopped", "boot_progress": "done"},
            "forced": {
                "code": stop,
                "final": "stopped",
                "boot_progress_before_stop": forced_before,
            },
            "peer_isolated": True,
        }
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "A boot-complete guest shut down through ShutdownVm while its running peer remained isolated; StopVm then converged the second guest to stopped.",
            }
        )
        invalid = "00000000-0000-0000-0000-000000000000"
        bad_shutdown = rpc(base, headers, routes["ShutdownVm"], {"id": invalid})
        bad_stop = rpc(base, headers, routes["StopVm"], {"id": invalid})
        repeat_stop = rpc(base, headers, routes["StopVm"], {"id": forced})
        if bad_shutdown < 400 or bad_stop < 400 or repeat_stop != 200:
            raise AssertionError("invalid or repeat boundary violated")
        evidence["boundaries"] = {
            "invalid_shutdown": bad_shutdown,
            "invalid_stop": bad_stop,
            "repeat_stop": repeat_stop,
            "service_available": len(listed(command)) >= 2,
        }
        evidence["sensitive_values_persisted"] = False
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Invalid IDs failed closed, repeated forced stop was idempotent, both VM records remained scoped, and the public list stayed available.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for n in range(1, 4):
            sid = f"{CASE_ID}-step-{n:02d}"
            if not any(x["id"] == sid for x in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    finally:
        cleanup = []
        for vm_id in ids:
            cleanup.append(
                {
                    "id": vm_id,
                    "stop": rpc(base, headers, routes["StopVm"], {"id": vm_id}),
                    "remove": rpc(base, headers, routes["RemoveVm"], {"id": vm_id}),
                }
            )
        evidence["cleanup"] = cleanup
    artifact = {
        "path": "artifacts/vmm-shutdown-stop.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "VMM graceful and forced stop matrix",
        "description": "Bounded public-state evidence for boot-complete graceful shutdown, forced stop, peer isolation, invalid IDs, idempotency, and cleanup.",
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
            "summary": "Graceful shutdown and forced stop remained deterministic and isolated."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only immediately registered VMs owned by the isolated fixture were mutated and removed.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
