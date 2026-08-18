#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise VMM NUMA pinning, hugepage exhaustion, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-vmm-compute-ne-003"


def rpc(base: str, method: str, value: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Call one bounded JSON pRPC method."""
    request = urllib.request.Request(
        f"{base}/prpc/{method}?json",
        data=json.dumps(value).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            body = json.loads(response.read() or b"{}")
            return response.status, body if isinstance(body, dict) else {}
    except urllib.error.HTTPError as error:
        error.read()
        return error.code, {}


def wait_for(predicate, message: str, timeout: float = 90):
    """Wait for one bounded process-state observation."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.25)
    raise TimeoutError(message)


def process_alive(pid: int) -> bool:
    """Return whether a case-owned process still exists."""
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def current_pid(vm_dir: Path) -> int | None:
    """Read a live QEMU PID, ignoring absent and stale files."""
    path = vm_dir / "qemu.pid"
    if not path.is_file():
        return None
    try:
        pid = int(path.read_text())
    except (OSError, ValueError):
        return None
    return pid if process_alive(pid) else None


def create_vm(helper: list[str], name: str, memory: int) -> str:
    """Create one stopped hugepage VM through the prepared helper."""
    completed = subprocess.run(
        [
            *helper,
            "--name",
            name,
            "--vcpu",
            "2",
            "--memory",
            str(memory),
            "--hugepages",
            "--pin-numa",
        ],
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    if completed.returncode:
        raise RuntimeError(f"stopped VM creation failed: {completed.stderr[-500:]}")
    value = json.loads(completed.stdout)
    return str(value["id"])


def remove_vm(base: str, vm_id: str, vm_dir: Path) -> None:
    """Stop and remove one case-owned definition."""
    rpc(base, "StopVm", {"id": vm_id})
    code, _ = rpc(base, "RemoveVm", {"id": vm_id})
    if code != 200:
        raise RuntimeError(f"RemoveVm returned HTTP {code}")
    wait_for(lambda: not vm_dir.exists(), f"VM {vm_id} removal did not finish")


def start_success(base: str, vm_id: str, vm_dir: Path) -> tuple[int, str]:
    """Start a VM and return its live QEMU PID and command."""
    code, _ = rpc(base, "StartVm", {"id": vm_id})
    if code != 200:
        raise RuntimeError(f"StartVm returned HTTP {code}")
    pid = wait_for(lambda: current_pid(vm_dir), f"VM {vm_id} did not start", 120)
    launch_path = vm_dir / "launch.json"
    if launch_path.is_file():
        launch = json.loads(launch_path.read_text())
        qemu = launch["qemu"]
        command = " ".join([qemu["command"], *qemu["args"]])
    else:
        command = (
            Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()
        )
    return pid, command


def main() -> int:
    """Run successful placement, exhaustion, isolation, and recovery rows."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("wrong case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    host = values.get("host_capabilities", {})
    total = int(host.get("hugepages_2m_total") or 0)
    nodes = int(host.get("numa_nodes") or 0)
    vmm = values.get("vmm", {})
    test_input = vmm.get("test_input", {})
    helper = test_input.get("create_stopped_helper_argv")
    base = str(vmm.get("rpc_url", ""))
    run_path = Path(str(vmm.get("run_path", "")))
    evidence: dict[str, Any] = {
        "host": {"hugepages_2m_total": total, "numa_nodes": nodes},
        "matrix": {},
    }
    created: list[tuple[str, Path]] = []
    status = "FAIL"
    summary = "NUMA and hugepage lifecycle did not execute."
    try:
        if total < 512 or nodes < 1:
            raise RuntimeError(
                f"prerequisite preparation incomplete: hugepages={total}, numa_nodes={nodes}"
            )
        if not isinstance(helper, list) or not helper:
            raise RuntimeError("prepared stopped-VM helper is unavailable")

        suffix = hashlib.sha256(str(result_dir).encode()).hexdigest()[:8]
        success_id = create_vm(helper, f"numa-success-{suffix}", 1024)
        success_dir = run_path / success_id
        created.append((success_id, success_dir))
        success_pid, command = start_success(base, success_id, success_dir)
        evidence["placement_process"] = {
            "pid": success_pid,
            "supervised_executable": os.readlink(f"/proc/{success_pid}/exe"),
            "qemu_command": command,
        }
        placement = {
            "qemu_started": process_alive(success_pid),
            "taskset_node0": command.startswith("taskset -c "),
            "numa_node0": "node,nodeid=0" in command,
            "hugepage_backend": "mem-path=/dev/hugepages" in command,
            "host_node_bound": "host-nodes=0,policy=bind" in command,
            "one_gib_preallocated": "size=1G" in command and "prealloc=yes" in command,
        }
        evidence["matrix"]["placement"] = placement
        if not all(placement.values()):
            raise AssertionError(f"incomplete placement command: {placement}")
        remove_vm(base, success_id, success_dir)
        created.clear()

        oversized_memory = ((total * 2) // 1024 + 2) * 1024
        failure_id = create_vm(helper, f"numa-exhaust-{suffix}", oversized_memory)
        failure_dir = run_path / failure_id
        created.append((failure_id, failure_dir))
        start_code, _ = rpc(base, "StartVm", {"id": failure_id})
        time.sleep(2)
        failure_clean = current_pid(failure_dir) is None
        evidence["matrix"]["exhaustion"] = {
            "requested_memory_mib": oversized_memory,
            "start_returned": start_code,
            "qemu_not_running": failure_clean,
            "vmm_available": urllib.request.urlopen(base + "/", timeout=10).status
            == 200,
        }
        if not failure_clean:
            raise AssertionError("oversized hugepage VM remained running")
        remove_vm(base, failure_id, failure_dir)
        created.clear()

        recovery_id = create_vm(helper, f"numa-recovery-{suffix}", 1024)
        recovery_dir = run_path / recovery_id
        created.append((recovery_id, recovery_dir))
        recovery_pid, recovery_command = start_success(base, recovery_id, recovery_dir)
        evidence["matrix"]["recovery"] = {
            "qemu_started": process_alive(recovery_pid),
            "hugepage_backend": "mem-path=/dev/hugepages" in recovery_command,
        }
        if not all(evidence["matrix"]["recovery"].values()):
            raise AssertionError("small hugepage VM did not recover after exhaustion")
        remove_vm(base, recovery_id, recovery_dir)
        created.clear()
        status = "PASS"
        summary = "NUMA pinning, hugepage placement, exhaustion isolation, and recovery passed."
    except Exception as error:  # noqa: BLE001
        summary = f"{type(error).__name__}: {error}"
    finally:
        for vm_id, vm_dir in reversed(created):
            try:
                remove_vm(base, vm_id, vm_dir)
            except Exception:
                pass

    artifact = result_dir / "artifacts/numa-hugepage-lifecycle.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": status,
                "observed": summary,
            }
            for number in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/numa-hugepage-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The official tdxlab preparation script provisions the bounded 2 MiB hugepage pool before fixture inventory.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
