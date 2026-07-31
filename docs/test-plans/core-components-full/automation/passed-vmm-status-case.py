#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic VMM status filtering and brief projection regression."""

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

CASE = "tc-vmm-ui-observa-001"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def call(
    base: str, headers: dict[str, str], method: str, body: dict[str, Any]
) -> tuple[int, Any]:
    """Call one JSON pRPC method and decode bounded JSON."""
    request = urllib.request.Request(
        f"{base}/prpc/{method}",
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={"content-type": "application/json", **headers},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            return response.status, json.loads(raw or b"null")
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            decoded = json.loads(raw or b"null")
        except json.JSONDecodeError:
            decoded = {"body_bytes": len(raw)}
        return error.code, decoded


def await_vm(
    base: str,
    headers: dict[str, str],
    vm_id: str,
    predicate: Any,
    timeout: int = 300,
) -> dict[str, Any]:
    """Poll Status until one VM satisfies the requested lifecycle predicate."""
    deadline = time.monotonic() + timeout
    observed: dict[str, Any] = {}
    while time.monotonic() < deadline:
        code, value = call(base, headers, "Status", {"ids": [vm_id]})
        vms = value.get("vms", []) if code == 200 and isinstance(value, dict) else []
        if vms:
            observed = vms[0]
            if predicate(observed):
                return observed
        time.sleep(3)
    raise AssertionError(
        f"VM lifecycle condition timed out at status={observed.get('status')!r}, "
        f"boot_progress={observed.get('boot_progress')!r}"
    )


def main() -> int:
    """Run promoted VMM status coverage."""
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
        str(key): str(value)
        for key, value in vmm.get("auth", {}).get("headers", {}).items()
    }
    template = json.loads(json.dumps(vmm["test_input"]["vm_configuration"]))
    nonce = hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:12]
    name = f"dtest-{nonce}-status"
    template.update({"name": name, "ports": [], "stopped": True})
    vm_id: str | None = None
    failures: list[str] = []
    steps: list[dict[str, str]] = []
    evidence: dict[str, Any] = {}
    try:
        baseline_code, baseline = call(base, headers, "Status", {"keyword": name})
        if baseline_code != 200 or baseline.get("vms"):
            raise AssertionError("run-scoped baseline was not empty")
        create_code, created = call(base, headers, "CreateVm", template)
        vm_id = created.get("id") if isinstance(created, dict) else None
        if create_code != 200 or not vm_id:
            raise AssertionError("stopped VM creation failed")
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Status baseline was reachable and a stopped fixture-owned VM was created.",
            }
        )

        full_code, full = call(base, headers, "Status", {"ids": [vm_id]})
        brief_code, brief = call(
            base, headers, "Status", {"ids": [vm_id], "brief": True}
        )
        filter_code, filtered = call(
            base,
            headers,
            "Status",
            {"keyword": name, "status": "stopped", "page": 1, "page_size": 1},
        )
        full_vm = full.get("vms", [{}])[0]
        brief_vm = brief.get("vms", [{}])[0]
        filtered_ids = [item.get("id") for item in filtered.get("vms", [])]
        if (
            full_code != 200
            or full_vm.get("id") != vm_id
            or not isinstance(full_vm.get("configuration"), dict)
            or full_vm.get("status") != "stopped"
            or full_vm.get("configuration", {}).get("image") != template.get("image")
            or not isinstance(full_vm.get("events"), list)
            or not isinstance(full_vm.get("interfaces"), list)
        ):
            raise AssertionError("full stopped-status projection failed")
        if (
            brief_code != 200
            or brief_vm.get("id") != vm_id
            or brief_vm.get("configuration") is not None
        ):
            raise AssertionError("brief status exposed configuration")
        if filter_code != 200 or filtered_ids != [vm_id] or filtered.get("total") != 1:
            raise AssertionError("keyword/page filter failed")

        start_code, _ = call(base, headers, "StartVm", {"id": vm_id})
        if start_code != 200:
            raise AssertionError(f"StartVm returned HTTP {start_code}")
        running = await_vm(
            base,
            headers,
            vm_id,
            lambda vm: vm.get("status") == "running"
            and vm.get("boot_progress") == "done",
        )
        events = running.get("events")
        timestamps = [
            event.get("timestamp")
            for event in events
            if isinstance(event, dict) and isinstance(event.get("timestamp"), int)
        ]
        if (
            not isinstance(running.get("uptime"), str)
            or not running.get("uptime")
            or not isinstance(running.get("boot_error"), str)
            or not isinstance(running.get("interfaces"), list)
            or not isinstance(running.get("image_version"), str)
            or not running.get("image_version")
            or not isinstance(events, list)
            or not events
            or timestamps != sorted(timestamps)
        ):
            raise AssertionError("running status omitted or reordered runtime fields")
        stop_code, _ = call(base, headers, "StopVm", {"id": vm_id})
        if stop_code != 200:
            raise AssertionError(f"StopVm returned HTTP {stop_code}")
        stopped = await_vm(
            base, headers, vm_id, lambda vm: vm.get("status") == "stopped"
        )
        evidence["lifecycle"] = {
            "start_http": start_code,
            "running_status": running.get("status"),
            "boot_progress": running.get("boot_progress"),
            "event_count": len(events),
            "event_timestamps_ordered": True,
            "interfaces_count": len(running.get("interfaces", [])),
            "image_version_present": True,
            "stop_http": stop_code,
            "stopped_status": stopped.get("status"),
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "ID, keyword, pagination, brief/full projections, running telemetry, ordered events, and stopped lifecycle state matched.",
            }
        )

        invalid_code, _ = call(base, headers, "Status", {"page": "invalid"})
        repeat_code, repeat = call(
            base, headers, "Status", {"ids": [vm_id], "brief": True}
        )
        repeat_vms = repeat.get("vms", []) if isinstance(repeat, dict) else []
        evidence["step3_observation"] = {
            "invalid_http": invalid_code,
            "repeat_http": repeat_code,
            "repeat_vm_count": len(repeat_vms),
            "repeat_id_matches": bool(repeat_vms) and repeat_vms[0].get("id") == vm_id,
        }
        if (
            invalid_code < 400
            or repeat_code != 200
            or repeat.get("vms", [{}])[0].get("id") != vm_id
        ):
            raise AssertionError("invalid rejection or repeat availability failed")
        evidence["matrix"] = {
            "baseline": baseline_code,
            "create": create_code,
            "full": full_code,
            "brief": brief_code,
            "filter": filter_code,
            "invalid": invalid_code,
            "repeat": repeat_code,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "A wrong-typed page failed closed and repeated brief status remained available.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if not any(step["id"] == step_id for step in steps):
                steps.append(
                    {"id": step_id, "status": "FAIL", "observed": failures[-1]}
                )
    finally:
        if vm_id:
            cleanup_stop, _ = call(base, headers, "StopVm", {"id": vm_id})
            remove_code, _ = call(base, headers, "RemoveVm", {"id": vm_id})
            evidence["cleanup"] = {"stop": cleanup_stop, "remove": remove_code}
    artifact = {
        "path": "artifacts/vmm-status-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "VMM status matrix",
        "description": "Bounded codes and assertions for status filters, projections, invalid input, repeatability, and cleanup.",
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
            "summary": "VMM status observability regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only one stopped VM owned by the isolated fixture was created and removed.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
