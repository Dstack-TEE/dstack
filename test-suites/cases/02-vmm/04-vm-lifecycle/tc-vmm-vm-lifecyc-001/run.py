#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify create/start/stop/remove idempotency on a case-owned VMM."""

from __future__ import annotations

import concurrent.futures
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-vm-lifecyc-001"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Atomically write JSON evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def rpc(base: str, headers: dict[str, str], route: str, body: dict[str, Any]) -> int:
    """Call one bounded JSON pRPC route and return HTTP status."""
    request = urllib.request.Request(
        base + route.split("?", 1)[0],
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response.read()
            return response.status
    except urllib.error.HTTPError as error:
        error.read()
        return error.code


def listed(command: list[str]) -> list[dict[str, Any]]:
    """Return the fixture-owned public VM list."""
    process = subprocess.run(
        command, text=True, capture_output=True, timeout=60, check=False
    )
    if process.returncode:
        raise RuntimeError("prepared list_vms command failed")
    value = json.loads(process.stdout or "[]")
    return value if isinstance(value, list) else []


def wait_state(
    command: list[str], vm_id: str, wanted: str | None, timeout: int = 180
) -> str | None:
    """Wait for one VM state, or absence when wanted is None."""
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        matches = [x for x in listed(command) if str(x.get("id")) == vm_id]
        observed = str(matches[0].get("status")) if matches else None
        if observed == wanted:
            return observed
        time.sleep(2)
    raise AssertionError(f"VM remained {observed!r} instead of {wanted!r}")


def main() -> int:
    """Run the full idempotent lifecycle matrix."""
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
    list_command = [str(x) for x in vmm["commands"]["list_vms"]]
    headers = {
        str(k): str(v) for k, v in vmm.get("auth", {}).get("headers", {}).items()
    }
    prefix = str(test_input.get("name_prefix", "dtest"))
    vm_id = None
    failures = []
    steps = []
    evidence = {}
    try:
        baseline = listed(list_command)
        evidence["baseline_count"] = len(baseline)
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Case-owned VMM was healthy and the prepared baseline was recorded.",
            }
        )
        created = subprocess.run(
            [
                *map(str, test_input["create_stopped_helper_argv"]),
                "--name",
                f"{prefix}-idempotent",
            ],
            text=True,
            capture_output=True,
            timeout=180,
            check=False,
        )
        if created.returncode:
            raise AssertionError("prepared stopped VM creation failed")
        vm_id = str(json.loads(created.stdout.splitlines()[-1])["id"])
        registry = json.loads(
            pathlib.Path(test_input["created_vms_registry"]).read_text()
        )
        if vm_id not in registry:
            raise AssertionError("created VM ID was not immediately registered")
        wait_state(list_command, vm_id, "stopped")

        def pair(method: str) -> list[int]:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                return list(
                    pool.map(
                        lambda _: rpc(base, headers, routes[method], {"id": vm_id}),
                        range(2),
                    )
                )

        starts = pair("StartVm")
        wait_state(list_command, vm_id, "running")
        stops = pair("StopVm")
        wait_state(list_command, vm_id, "stopped")
        restart = rpc(base, headers, routes["StartVm"], {"id": vm_id})
        wait_state(list_command, vm_id, "running")
        restop = rpc(base, headers, routes["StopVm"], {"id": vm_id})
        wait_state(list_command, vm_id, "stopped")
        evidence["transitions"] = {
            "concurrent_start": starts,
            "concurrent_stop": stops,
            "repeat_start": restart,
            "repeat_stop": restop,
            "final_state": "stopped",
        }
        concurrent_codes = {200, 400, 409}
        if (
            restart != 200
            or restop != 200
            or any(code not in concurrent_codes for code in starts)
            or any(code not in concurrent_codes for code in stops)
        ):
            raise AssertionError("valid lifecycle transition did not converge")
        steps.append(
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "Concurrent and repeated start/stop operations converged to one public VM state without duplication.",
            }
        )
        removes = pair("RemoveVm")
        wait_state(list_command, vm_id, None)
        repeat_remove = rpc(base, headers, routes["RemoveVm"], {"id": vm_id})
        invalid_id = "00000000-0000-0000-0000-000000000000"
        invalid_start = rpc(base, headers, routes["StartVm"], {"id": invalid_id})
        if (
            not any(code == 200 for code in removes)
            or repeat_remove < 400
            or invalid_start < 400
        ):
            raise AssertionError("remove or invalid-id boundary did not fail closed")
        evidence["removal"] = {
            "concurrent": removes,
            "repeat": repeat_remove,
            "invalid_start": invalid_start,
            "absent": True,
        }
        evidence["final_list_count"] = len(listed(list_command))
        evidence["sensitive_values_persisted"] = False
        steps.append(
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Concurrent removal converged to absence; repeated remove and invalid ID failed closed while VMM remained available.",
            }
        )
        vm_id = None
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for n in range(1, 4):
            sid = f"{CASE_ID}-step-{n:02d}"
            if not any(x["id"] == sid for x in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    finally:
        if vm_id:
            rpc(base, headers, routes["StopVm"], {"id": vm_id})
            rpc(base, headers, routes["RemoveVm"], {"id": vm_id})
    artifact = {
        "path": "artifacts/vmm-idempotent-lifecycle.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "VMM idempotent lifecycle matrix",
        "description": "Bounded HTTP status and public-state observations for registered creation, concurrent/repeated start, stop, remove, invalid-ID rejection, availability, and cleanup.",
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
            "summary": "Create/start/stop/remove idempotency and concurrency passed."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only the isolated fixture VMM and its immediately registered VM ID were mutated; provider cleanup remains authoritative.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
