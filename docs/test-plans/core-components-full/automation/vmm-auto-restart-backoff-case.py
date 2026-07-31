#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise automatic restart, bounded backoff, reset, and fault recovery."""

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

CASE_ID = "tc-vmm-vm-lifecyc-006"
POLICY_ROWS = {
    "effective-config", "eligible-restart", "never-started-ineligible",
    "removing-ineligible", "exponential-backoff", "retry-limit-no-hot-loop",
    "decision-events", "healthy-reset-window", "manual-lifecycle-reset",
    "invalid-config-rejected", "adjacent-availability", "cleanup",
}
MARKER = "DSTACK_AUTO_RESTART_ROW "


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def rpc(base: str, headers: dict[str, str], route: str, body: dict[str, Any]) -> int:
    request = urllib.request.Request(
        base + route.split("?", 1)[0], data=json.dumps(body).encode(),
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
    process = subprocess.run(command, text=True, capture_output=True, timeout=60, check=False)
    if process.returncode:
        raise RuntimeError("prepared list_vms command failed")
    value = json.loads(process.stdout or "[]")
    return value if isinstance(value, list) else []


def status(command: list[str], vm_id: str) -> str | None:
    vm = next((item for item in listed(command) if str(item.get("id")) == vm_id), None)
    return None if vm is None else str(vm.get("status"))


def wait_status(command: list[str], vm_id: str, wanted: str | None, timeout: float = 30) -> None:
    deadline = time.monotonic() + timeout
    observed = None
    while time.monotonic() < deadline:
        observed = status(command, vm_id)
        if observed == wanted:
            return
        time.sleep(0.2)
    raise AssertionError(f"VM remained {observed!r} instead of {wanted!r}")


def create(test_input: dict[str, Any], suffix: str) -> str:
    process = subprocess.run(
        [*map(str, test_input["create_stopped_helper_argv"]), "--name", f'{test_input["name_prefix"]}-{suffix}'],
        text=True, capture_output=True, timeout=180, check=False,
    )
    if process.returncode:
        raise AssertionError("prepared stopped VM creation failed")
    vm_id = str(json.loads(process.stdout.splitlines()[-1])["id"])
    registry = json.loads(pathlib.Path(test_input["created_vms_registry"]).read_text())
    if vm_id not in registry:
        raise AssertionError("created VM was not registered for cleanup")
    return vm_id


def wait_log(log: pathlib.Path, needle: str, minimum: int, timeout: float = 15) -> int:
    deadline = time.monotonic() + timeout
    count = 0
    while time.monotonic() < deadline:
        count = log.read_text(errors="replace").count(needle)
        if count >= minimum:
            return count
        time.sleep(0.2)
    raise AssertionError(f"log count for {needle!r} remained {count}, expected {minimum}")


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    vmm = manifest["values"]["vmm"]
    test_input = vmm["test_input"]
    if vmm.get("case_owned") is not True:
        raise RuntimeError("VMM is not case-owned")
    policy = test_input.get("auto_restart_policy", {})
    expected_policy = {"interval": 1, "max_retries": 3, "initial_backoff": 1, "max_backoff": 2, "reset_window": 2}
    if policy != expected_policy:
        raise RuntimeError("fixture did not activate the bounded case policy")
    crash_qemu = [str(x) for x in vmm["commands"].get("crash_qemu", [])]
    if not crash_qemu:
        raise RuntimeError("case-owned QEMU fault control is absent")
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    list_command = [str(x) for x in vmm["commands"]["list_vms"]]
    headers = {str(k): str(v) for k, v in vmm.get("auth", {}).get("headers", {}).items()}
    log = pathlib.Path(vmm["log"])
    ids: list[str] = []
    failures: list[str] = []
    steps: list[dict[str, Any]] = []
    evidence: dict[str, Any] = {"policy": policy, "vm_started": 3, "image_build_tested": False}
    try:
        # Execute the production policy model matrix as a fast boundary oracle.
        target = os.environ.get("DSTACK_TEST_SHARED_CARGO_TARGET", runtime.get("cargo_target_dir"))
        policy_process = subprocess.run(
            ["cargo", "test", "--manifest-path", str(pathlib.Path(runtime["repository"]) / "dstack/Cargo.toml"),
             "-p", "dstack-vmm", "auto_restart_case_matrix", "--target-dir", str(target), "--", "--nocapture"],
            text=True, capture_output=True, timeout=180, check=False,
        )
        policy_output = policy_process.stdout + policy_process.stderr
        rows = {line.split(MARKER, 1)[1].strip() for line in policy_output.splitlines() if MARKER in line}
        if policy_process.returncode or rows != POLICY_ROWS:
            raise AssertionError("candidate policy boundary matrix did not match")
        evidence["policy_rows"] = sorted(rows)
        evidence["baseline_count"] = len(listed(list_command))
        eligible = create(test_input, "restart-eligible")
        ids.append(eligible)
        never_started = create(test_input, "never-started")
        ids.append(never_started)
        removing = create(test_input, "removing")
        ids.append(removing)
        wait_status(list_command, eligible, "stopped")
        if rpc(base, headers, routes["RemoveVm"], {"id": removing}) != 200:
            raise AssertionError("removing boundary setup failed")
        wait_status(list_command, removing, None)
        ids.remove(removing)
        steps.append({"id": f"{CASE_ID}-step-01", "status": "PASS", "observed": "The case-owned VMM exposed the exact 1/1/2-second, three-retry policy; eligible, never-started, and removing records were isolated."})

        if rpc(base, headers, routes["StartVm"], {"id": eligible}) != 200:
            raise AssertionError("eligible VM start failed")
        wait_status(list_command, eligible, "running")
        attempt_needle = "automatic restart attempt"
        reset_needle = "automatic restart retry budget reset"
        exhausted_needle = "automatic restart retry limit exhausted"
        initial_attempts = log.read_text(errors="replace").count(attempt_needle)
        initial_resets = log.read_text(errors="replace").count(reset_needle)
        initial_exhausted = log.read_text(errors="replace").count(exhausted_needle)

        def crash_and_restart(expected_attempt_count: int) -> None:
            process = subprocess.run([*crash_qemu, "--id", eligible], text=True, capture_output=True, timeout=30, check=False)
            if process.returncode:
                raise AssertionError("lease-owned QEMU crash injection failed")
            wait_log(log, attempt_needle, initial_attempts + expected_attempt_count)
            wait_status(list_command, eligible, "running")

        crash_and_restart(1)
        wait_log(log, reset_needle, initial_resets + 1, timeout=8)
        crash_and_restart(2)  # retry number is one again after healthy reset
        crash_and_restart(3)
        crash_and_restart(4)
        process = subprocess.run([*crash_qemu, "--id", eligible], text=True, capture_output=True, timeout=30, check=False)
        if process.returncode:
            raise AssertionError("final lease-owned QEMU crash injection failed")
        wait_log(log, exhausted_needle, initial_exhausted + 1)
        wait_status(list_command, eligible, "exited")
        time.sleep(3)
        if status(list_command, eligible) != "exited":
            raise AssertionError("retry-exhausted VM entered a hot restart loop")
        if status(list_command, never_started) != "stopped":
            raise AssertionError("never-started VM was incorrectly restarted")
        evidence["restart"] = {"automatic_attempt_events": 4, "healthy_reset_events": 1, "exhausted_events": 1, "final_status": "exited", "never_started_status": "stopped"}
        steps.append({"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": "Injected five QEMU exits: the eligible VM restarted with bounded backoff, reset after its healthy window, exhausted exactly three consecutive retries, and then remained exited without a hot loop; ineligible peers never restarted."})

        invalid = "00000000-0000-0000-0000-000000000000"
        invalid_start = rpc(base, headers, routes["StartVm"], {"id": invalid})
        if invalid_start < 400 or not isinstance(listed(list_command), list):
            raise AssertionError("invalid input or adjacent availability boundary failed")
        evidence["boundaries"] = {"invalid_start": invalid_start, "list_available": True, "decision_events_observed": True}
        steps.append({"id": f"{CASE_ID}-step-03", "status": "PASS", "observed": "Structured restart/reset/exhaustion events were observed; invalid VM input failed closed and the public list remained available."})
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        evidence["failure_diagnostics"] = {
            "vmm_log_tail": log.read_text(errors="replace")[-6000:] if log.is_file() else "",
            "vm_stderr_tails": {
                vm_id: (pathlib.Path(vmm["run_path"]) / vm_id / "stderr.log").read_text(errors="replace")[-3000:]
                for vm_id in ids
                if (pathlib.Path(vmm["run_path"]) / vm_id / "stderr.log").is_file()
            },
            "public_status": {vm_id: status(list_command, vm_id) for vm_id in ids},
        }
        for number in range(1, 4):
            step_id = f"{CASE_ID}-step-{number:02d}"
            if not any(step["id"] == step_id for step in steps):
                steps.append({"id": step_id, "status": "FAIL", "observed": failures[-1]})
    finally:
        cleanup = []
        for vm_id in ids:
            cleanup.append({"id": vm_id, "stop": rpc(base, headers, routes["StopVm"], {"id": vm_id}), "remove": rpc(base, headers, routes["RemoveVm"], {"id": vm_id})})
        evidence["cleanup"] = cleanup
    artifact = {"path": "artifacts/vmm-auto-restart-policy.json", "step_id": f"{CASE_ID}-step-02", "name": "Automatic restart fault matrix", "description": "Candidate policy rows plus case-owned VMM/QEMU crash, event, retry, recovery, isolation, availability, and cleanup observations."}
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status_value = "PASS" if not failures else "FAIL"
    atomic_json(result_dir / "result.json", {"schema_version": "1.0", "case_id": CASE_ID, "provisional": False, "status": status_value, "summary": "12/12 policy rows and the case-owned crash/restart lifecycle passed." if not failures else failures[0], "steps": steps, "artifacts": [artifact], "evidence": [{"path": artifact["path"], "sha256": hashlib.sha256((result_dir / artifact["path"]).read_bytes()).hexdigest()}], "remarks": "Only three immediately registered VMs and their case-owned Supervisor were mutated; no image was built and provider cleanup remains authoritative."})
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
