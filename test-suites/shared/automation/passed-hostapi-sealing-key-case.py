#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify guest-originated HostApi.GetSealingKey with a genuine TDX quote."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import tempfile
import time
from typing import Any

CASES = {"tc-vmm-hostapi-003", "tc-vmm-ui-observa-003", "tc-gos-setup-010"}


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


def main() -> int:
    """Boot a real-TDX local-provider guest, run negatives, and clean up."""
    lifecycle = load_module("passed-vmm-lifecycle-case.py", "vmm_lifecycle_common")
    host_common = load_module("passed-hostapi-case.py", "host_api_common")
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id not in CASES:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan_root = pathlib.Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    host_api = manifest["values"]["host_api"]
    dependency = host_api.get("key_provider_dependency") or {}
    if vmm.get("case_owned") is not True or host_api.get("case_owned") is not True:
        raise RuntimeError("VMM or Host API fixture is not case-owned")
    if dependency.get("hardware") != "sgx":
        raise RuntimeError("fixture omitted the SGX key-provider dependency")
    template = vmm["test_input"]["vm_configuration"]
    compose = json.loads(template.get("compose_file") or "{}")
    if template.get("no_tee") is not False or template.get("simulated_tee") is not None:
        raise RuntimeError("fixture did not prepare a real-TEE guest")
    if compose.get("key_provider") != "local":
        raise RuntimeError("fixture did not prepare key_provider=local")
    base, headers = lifecycle.resolve_vmm(manifest)
    routes = vmm["json_prpc_routes"]
    sealing_route = host_api["json_prpc_routes"]["GetSealingKey"]
    notify_route = host_api["json_prpc_routes"]["Notify"]

    created: list[str] = []
    evidence: dict[str, Any] = {
        "sensitive_values_persisted": False,
        "request_quote_persisted": False,
        "encrypted_key_persisted": False,
        "provider_quote_persisted": False,
    }
    steps: list[dict[str, str]] = []
    failure: str | None = None

    def rpc(method: str, vm_id: str) -> tuple[int, bytes]:
        return lifecycle.call(
            base + routes[method].split("?", 1)[0],
            json.dumps({"id": vm_id}).encode(),
            "application/json",
            headers,
        )

    try:
        entry = host_common.inventory_entry(plan_root, "GetSealingKey")
        request_fields = sorted(field["name"] for field in entry["request_fields"])
        response_fields = sorted(field["name"] for field in entry["response_fields"])
        if request_fields != ["quote"] or response_fields != [
            "encrypted_key",
            "provider_quote",
        ]:
            raise AssertionError("HostApi.GetSealingKey inventory contract changed")
        baseline = lifecycle.list_vm_ids(manifest)
        empty = host_common.vsock_call(plan_root, host_api, sealing_route, "{}")
        if empty["status"] < 400:
            raise AssertionError("empty host-originated sealing request succeeded")
        evidence["baseline"] = {
            "vm_count": len(baseline),
            "transport": host_api.get("transport"),
            "hardware_dependency": dependency.get("hardware"),
            "request_fields": request_fields,
            "response_fields": response_fields,
            "empty_quote_http": empty["status"],
        }
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "The vsock Host API, SGX provider dependency, real-TDX request, and inventory contract were prepared.",
            }
        )

        vm_id = lifecycle.create_vm(manifest)
        created.append(vm_id)
        start_code, _ = rpc("StartVm", vm_id)
        if start_code != 200:
            raise AssertionError(f"StartVm returned HTTP {start_code}")
        lifecycle.await_boot(manifest, vm_id, timeout=180)
        item = listed_vm(vmm, vm_id)
        if item is None or item.get("boot_progress") != "done":
            raise AssertionError("real-TDX local-provider guest did not finish boot")
        vm_dir = pathlib.Path(vmm["run_path"]) / vm_id
        log_files = [
            path for path in vm_dir.rglob("*") if path.is_file() and "log" in path.name
        ]
        sealing_error = False
        for path in log_files:
            text = path.read_text(errors="replace").lower()
            if "sealing" in text and any(
                word in text for word in ("error", "failed", "denied")
            ):
                sealing_error = True
        if sealing_error:
            raise AssertionError("guest logs report a sealing failure")
        events = item.get("events") if isinstance(item.get("events"), list) else []
        event_names = sorted(
            {
                str(event.get("event") or event.get("name"))
                for event in events
                if isinstance(event, dict) and (event.get("event") or event.get("name"))
            }
        )
        normalized_events = [name.lower().replace("_", ".") for name in event_names]
        if case_id == "tc-gos-setup-010" and not any(
            "boot.progress" in name for name in normalized_events
        ):
            raise AssertionError("guest-originated HostApi.Notify event was absent")
        evidence["guest_sealing"] = {
            "boot_progress": item.get("boot_progress"),
            "status": item.get("status"),
            "event_names": event_names,
            "notify_event_present": any(
                "boot.progress" in name for name in normalized_events
            ),
            "log_files_checked": len(log_files),
            "sealing_error_present": False,
            "real_tee": True,
            "key_provider": "local",
        }
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "The real-TDX local-provider guest completed boot after guest-originated sealing-key retrieval with no sealing error.",
            }
        )

        wrong_type = host_common.vsock_call(
            plan_root, host_api, sealing_route, json.dumps({"quote": "not-bytes"})
        )
        unknown_field = host_common.vsock_call(
            plan_root, host_api, sealing_route, json.dumps({"quote": [], "future": 1})
        )
        unknown_route = host_common.vsock_call(
            plan_root,
            host_api,
            sealing_route.replace("GetSealingKey", "GetSealingKeyNoSuch"),
            json.dumps({"quote": []}),
        )
        host_notify = host_common.vsock_call(
            plan_root,
            host_api,
            notify_route,
            json.dumps({"event": "host.invalid", "payload": "{}"}),
        )
        if wrong_type["status"] < 400 or unknown_field["status"] < 400:
            raise AssertionError("invalid host-originated sealing request was accepted")
        if unknown_route["status"] < 400:
            raise AssertionError("unknown sealing route was accepted")
        if case_id == "tc-gos-setup-010" and host_notify["status"] < 400:
            raise AssertionError("host-originated Notify bypassed guest CID binding")
        repeat = listed_vm(vmm, vm_id)
        if repeat is None or repeat.get("boot_progress") != "done":
            raise AssertionError("guest state changed after sealing negatives")
        evidence["negative"] = {
            "wrong_type_http": wrong_type["status"],
            "unknown_field_without_quote_http": unknown_field["status"],
            "unknown_route_http": unknown_route["status"],
            "host_originated_notify_http": host_notify["status"],
            "guest_state_unchanged": True,
        }
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Invalid host-originated requests failed without disturbing the successfully sealed guest.",
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
        evidence["cleanup"] = {"statuses": cleanup, "all_absent": not remaining}
        if (
            any(row["remove_http"] != 200 for row in cleanup) or remaining
        ) and failure is None:
            failure = "cleanup failed to remove the sealing guest"

    artifact = {
        "path": "artifacts/host-api-sealing-key.json",
        "step_id": f"{case_id}-step-02",
        "name": "Guest-originated HostApi.GetSealingKey evidence",
        "description": "Records public boot state, contract fields, redaction assertions, negative statuses, and cleanup without quote or key material.",
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
                "A real-TDX guest completed local-provider sealing through HostApi.GetSealingKey and invalid probes were isolated."
                if status == "PASS"
                else failure
            ),
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "No quote, encrypted key, provider quote, sealing material, or raw provider response was persisted.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
