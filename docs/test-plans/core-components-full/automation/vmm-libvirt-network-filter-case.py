#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise current user, bridge, and multi-NIC VMM networking lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-vmm-compute-ne-001"


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run one bounded command."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )


def rpc(
    base: str, method: str, value: dict[str, Any], timeout: int = 60
) -> tuple[int, dict[str, Any]]:
    """Call one JSON pRPC method and preserve its public status and body."""
    request = urllib.request.Request(
        f"{base}/prpc/{method}?json",
        data=json.dumps(value).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = json.loads(response.read() or b"{}")
            return response.status, body if isinstance(body, dict) else {}
    except urllib.error.HTTPError as error:
        error.read()
        return error.code, {}


def start(argv: list[str], log: Path, cwd: Path) -> subprocess.Popen[str]:
    """Start one case-owned process group."""
    return subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=log.open("a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
    )


def stop(process: subprocess.Popen[str] | None) -> None:
    """Stop and reap one case-owned process group."""
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(15)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(5)


def wait_for(predicate, message: str, timeout: float = 90):
    """Wait for one bounded lifecycle observation."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.25)
    raise TimeoutError(message)


def process_command(pid: int) -> str:
    """Read the case-owned QEMU command without shell interpolation."""
    return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode()


def make_config(
    template: str,
    artifact_root: Path,
    runtime_root: Path,
    image_store: Path,
    supervisor: Path,
    port: int,
) -> Path:
    """Materialize current VMM configuration without obsolete netd fields."""
    replacements = {
        'temp_dir = "/tmp"': (
            f'temp_dir = "{runtime_root}/data"\nrun_path = "{runtime_root}/vms"'
        ),
        'address = "unix:./vmm.sock"': f'address = "127.0.0.1:{port}"',
        '# path = ""': f'path = "{image_store}"',
        'qemu_path = ""': 'qemu_path = "/usr/bin/qemu-system-x86_64"',
        'platform = "auto"': 'platform = "tdx"',
        'exe = "./supervisor"': f'exe = "{supervisor}"',
        'sock = "./run/supervisor.sock"': f'sock = "{runtime_root}/supervisor.sock"',
        'pid_file = "./run/supervisor.pid"': f'pid_file = "{runtime_root}/supervisor.pid"',
        'log_file = "./run/supervisor.log"': f'log_file = "{runtime_root}/supervisor.log"',
        'port = 10000': f"port = {port + 1000}",
        '[key_provider]\nenabled = true': '[key_provider]\nenabled = false',
    }
    text = template
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"VMM template is missing {old!r}")
        text = text.replace(old, new, 1)
    text += '\n[cvm.tee_simulator]\nmock_attestation_seed = "' + "12" * 32 + '"\n'
    path = artifact_root / "vmm.toml"
    path.write_text(text)
    return path


def create_request(image: str, name: str, *, stopped: bool, networks: list[dict]) -> dict:
    """Build one non-production simulator request."""
    compose = {
        "manifest_version": 1,
        "name": name,
        "runner": "none",
        "gateway_enabled": False,
        "public_logs": True,
        "public_sysinfo": True,
        "key_provider": "none",
        "kms_enabled": False,
    }
    return {
        "name": name,
        "image": image,
        "compose_file": json.dumps(compose),
        "vcpu": 1,
        "memory": 1024,
        "disk_size": 1,
        "stopped": stopped,
        "no_tee": True,
        "simulated_tee": "dstack-tdx",
        "networks": networks,
    }


def remove_vm(base: str, vm_id: str, vm_dir: Path) -> None:
    """Stop and remove one case-owned VM if it still exists."""
    rpc(base, "StopVm", {"id": vm_id})
    rpc(base, "RemoveVm", {"id": vm_id})
    wait_for(lambda: not vm_dir.exists(), f"VM {vm_id} removal did not finish")


def main() -> int:
    """Run public networking, restart, rejection, and cleanup coverage."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("wrong case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    binary = Path(runtime["prepared_binaries"]["dstack_vmm"]["path"])
    supervisor = binary.with_name("supervisor")
    image_store = Path(os.environ["DSTACK_TEST_IMAGE_STORE"])
    image = os.environ["DSTACK_TEST_NO_TEE_GUEST_IMAGE"]
    root = result_dir / "artifacts/network-lifecycle"
    root.mkdir(parents=True)
    runtime_key = hashlib.sha256(str(result_dir).encode()).hexdigest()[:12]
    runtime_root = Path(f"/tmp/dtnet-{runtime_key}")
    shutil.rmtree(runtime_root, ignore_errors=True)
    runtime_root.mkdir(mode=0o700)
    config = make_config(
        (repository / "dstack/vmm/vmm.toml").read_text(),
        root,
        runtime_root,
        image_store,
        supervisor,
        18481,
    )
    base = "http://127.0.0.1:18481"
    process: subprocess.Popen[str] | None = None
    created: list[tuple[str, Path]] = []
    evidence: dict[str, Any] = {
        "candidate_commit": runtime["candidate_commit"],
        "matrix": {},
    }
    status = "FAIL"
    summary = "Networking lifecycle did not execute."
    try:
        process = start([str(binary), "--config", str(config)], root / "vmm.log", root)
        wait_for(lambda: run(["curl", "-sf", base + "/"]).returncode == 0, "VMM did not listen")

        bridge_request = create_request(
            image,
            "bridge-matrix",
            stopped=True,
            networks=[
                {"mode": "bridge", "bridge_name": "virbr0"},
                {"mode": "bridge", "bridge_name": "virbr0"},
            ],
        )
        code, body = rpc(base, "CreateVm", bridge_request, 180)
        if code != 200 or not body.get("id"):
            raise RuntimeError(f"stopped bridge VM creation failed with HTTP {code}")
        bridge_id = str(body["id"])
        bridge_dir = runtime_root / "vms" / bridge_id
        created.append((bridge_id, bridge_dir))
        start_code, _ = rpc(base, "StartVm", {"id": bridge_id}, 180)
        if start_code != 200:
            raise RuntimeError(f"bridge VM start failed with HTTP {start_code}")
        manifest = wait_for(
            lambda: json.loads((bridge_dir / "vm-manifest.json").read_text())
            if (bridge_dir / "vm-manifest.json").is_file()
            else None,
            "bridge VM manifest missing",
        )
        bridge_pid = wait_for(
            lambda: int((bridge_dir / "qemu.pid").read_text())
            if (bridge_dir / "qemu.pid").is_file()
            else None,
            "bridge VM did not start",
            120,
        )
        launch_text = process_command(bridge_pid)
        macs = re.findall(r"mac=([0-9a-f:]{17})", launch_text, re.IGNORECASE)
        evidence["matrix"]["bridge_launch"] = {
            "nic_count": len(manifest["networks"]),
            "distinct_macs": len(set(macs)) == 2,
            "bridge_netdevs": launch_text.count("bridge,id=net") == 2,
            "qemu_started": True,
        }
        stop_code, _ = rpc(base, "StopVm", {"id": bridge_id}, 60)
        if stop_code != 200:
            raise RuntimeError(f"bridge VM stop failed with HTTP {stop_code}")
        wait_for(
            lambda: not (bridge_dir / "qemu.pid").exists(),
            "bridge VM did not stop",
        )

        user_request = create_request(
            image,
            "user-matrix",
            stopped=False,
            networks=[{"mode": "user"}, {"mode": "user"}],
        )
        code, body = rpc(base, "CreateVm", user_request, 180)
        if code != 200 or not body.get("id"):
            raise RuntimeError(f"user VM creation failed with HTTP {code}")
        user_id = str(body["id"])
        user_dir = runtime_root / "vms" / user_id
        created.append((user_id, user_dir))
        old_pid = wait_for(
            lambda: int((user_dir / "qemu.pid").read_text())
            if (user_dir / "qemu.pid").is_file()
            else None,
            "user VM did not start",
            120,
        )
        user_text = process_command(old_pid)
        evidence["matrix"]["user_launch"] = {
            "user_netdevs": user_text.count("user,id=net") == 2,
            "qemu_started": True,
        }

        stop(process)
        process = start([str(binary), "--config", str(config)], root / "vmm-restart.log", root)
        wait_for(lambda: run(["curl", "-sf", base + "/"]).returncode == 0, "VMM restart failed")
        preserved_pid = int((user_dir / "qemu.pid").read_text())
        evidence["matrix"]["vmm_restart"] = {"qemu_pid_preserved": preserved_pid == old_pid}

        os.kill(old_pid, signal.SIGKILL)
        new_pid = wait_for(
            lambda: int((user_dir / "qemu.pid").read_text())
            if (user_dir / "qemu.pid").is_file()
            and int((user_dir / "qemu.pid").read_text()) != old_pid
            else None,
            "automatic restart did not replace QEMU",
            120,
        )
        evidence["matrix"]["qemu_restart"] = {"pid_replaced": new_pid != old_pid}

        invalid = create_request(
            image,
            "invalid-network",
            stopped=True,
            networks=[{"mode": "user", "bridge_name": "virbr0"}],
        )
        invalid_code, _ = rpc(base, "CreateVm", invalid, 60)
        evidence["matrix"]["invalid_rejection"] = {
            "rejected": invalid_code >= 400,
            "vmm_available": run(["curl", "-sf", base + "/"]).returncode == 0,
        }

        for vm_id, vm_dir in reversed(created):
            remove_vm(base, vm_id, vm_dir)
        created.clear()
        checks = [value for value in evidence["matrix"].values() for value in value.values()]
        if not checks or not all(checks):
            raise AssertionError(f"incomplete networking matrix: {evidence['matrix']}")
        status = "PASS"
        summary = "User and bridge multi-NIC launches, rejection, restart, persistence, and cleanup passed."
    except Exception as error:  # noqa: BLE001
        summary = f"{type(error).__name__}: {error}"
    finally:
        if process is not None:
            for vm_id, vm_dir in reversed(created):
                try:
                    remove_vm(base, vm_id, vm_dir)
                except Exception:
                    pass
        stop(process)
        shutil.rmtree(runtime_root, ignore_errors=True)

    artifact = result_dir / "artifacts/vmm-network-lifecycle.json"
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = summary
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{number:02d}", "status": status, "observed": observed}
            for number in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/vmm-network-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "TEE simulation validates VMM/QEMU/network lifecycle only; physical TEE attestation is out of scope.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
