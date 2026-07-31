#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Provide run-scoped physical-TDX and cross-platform simulator interfaces."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

STATE_ROOT = Path(
    os.environ.get("DSTACK_TEST_STATE_ROOT", "").strip()
    or str(Path.home() / ".cache/dstack-test/runtime-state")
)
ROOT = STATE_ROOT / "hardware-pool"


def fail(message: str) -> None:
    """Terminate the provider request with a diagnostic."""
    print(message, file=sys.stderr)
    raise SystemExit(1)


def request() -> dict[str, Any]:
    """Read one fixture protocol request from standard input."""
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        fail("provider request must be an object")
    return value


def endpoint_ready(host: str, port: int) -> bool:
    """Return whether a TCP endpoint accepts connections."""
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


def probe_gpu_inventory() -> dict[str, Any]:
    """Return a bounded inventory proving whether NVIDIA GPUs are available."""
    command = shutil.which("nvidia-smi")
    if command is None:
        return {
            "available": False,
            "count": 0,
            "probe": "nvidia-smi -L",
            "devices": [],
            "error": "nvidia-smi is not installed",
        }
    try:
        process = subprocess.run(
            [command, "-L"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "available": False,
            "count": 0,
            "probe": "nvidia-smi -L",
            "devices": [],
            "error": str(error),
        }
    devices = [line.strip() for line in process.stdout.splitlines() if line.strip()]
    return {
        "available": process.returncode == 0 and bool(devices),
        "count": len(devices) if process.returncode == 0 else 0,
        "probe": "nvidia-smi -L",
        "devices": devices if process.returncode == 0 else [],
        "error": None if process.returncode == 0 else process.stderr.strip()[-1000:],
    }


def find_port_block(count: int = 6) -> int:
    """Find a consecutive run-scoped host-port block."""
    for base in range(18101, 18995 - count):
        sockets = []
        try:
            for port in range(base, base + count):
                sock = socket.socket()
                sock.bind(("127.0.0.1", port))
                sockets.append(sock)
            return base
        except OSError:
            pass
        finally:
            for sock in sockets:
                sock.close()
    fail("no consecutive host-port block is available for attestation fixtures")


def write_compose_files(workspace: Path) -> tuple[Path, Path, Path, Path]:
    """Write proxy workloads for hardware and simulator key-provider modes."""
    proxy = """import http.server,http.client,socket,socketserver
class C(http.client.HTTPConnection):
 def connect(self):
  self.sock=socket.socket(socket.AF_UNIX); self.sock.connect('/run/dstack.sock')
class H(http.server.BaseHTTPRequestHandler):
 def relay(self):
  n=int(self.headers.get('content-length','0')); c=C('dstack')
  c.request(self.command,self.path,self.rfile.read(n),{'Content-Type':'application/json'})
  r=c.getresponse(); b=r.read(); self.send_response(r.status); self.end_headers(); self.wfile.write(b)
 do_GET=relay; do_POST=relay
socketserver.TCPServer.allow_reuse_address=True
socketserver.TCPServer(('',8000),H).serve_forever()
"""
    workload = workspace / "dstack-guest-proxy.yml"
    workload.write_text(
        "services:\n  dstack-guest-proxy:\n    image: python:3.12-alpine\n"
        "    network_mode: host\n"
        "    command:\n      - python3\n      - -c\n      - |\n"
        + "".join(f"        {line}\n" for line in proxy.splitlines())
        + "    volumes:\n      - /run/dstack.sock:/run/dstack.sock\n",
        encoding="utf-8",
    )
    common = {
        "manifest_version": 2,
        "name": "dstack-test-attestation-proxy",
        "runner": "docker-compose",
        "docker_compose_file": workload.read_text(),
        "gateway_enabled": False,
        "public_logs": True,
        "public_sysinfo": True,
        "public_tcbinfo": True,
        "key_provider_id": "",
        "allowed_envs": [],
        "no_instance_id": False,
        "secure_time": False,
        "kms_enabled": False,
        "storage_fs": "ext4",
    }
    hardware = workspace / "app-compose-hardware.json"
    simulator_none = workspace / "app-compose-simulator-none.json"
    simulator_tpm = workspace / "app-compose-simulator-tpm.json"
    hardware.write_text(json.dumps({**common, "key_provider": "none"}) + "\n")
    simulator_none.write_text(json.dumps({**common, "key_provider": "none"}) + "\n")
    simulator_tpm.write_text(json.dumps({**common, "key_provider": "tpm"}) + "\n")
    return workload, hardware, simulator_none, simulator_tpm


def prepare(value: dict[str, Any]) -> dict[str, Any]:
    """Prepare the cross-platform attestation matrix fixture."""
    lease = value.get("lease", {})
    requested = value.get("request", {})
    lease_id = str(lease.get("lease_id", ""))
    if not lease_id.startswith("lease-"):
        fail("lease identity is missing")
    runtime_path = Path(str(requested.get("_runtime_manifest", ""))).resolve()
    runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
    repository = Path(str(runtime["repository"])).resolve()
    workspace = ROOT / lease_id
    workspace.mkdir(parents=True, exist_ok=False)
    registry = workspace / "created-vms.json"
    registry.write_text("[]\n", encoding="utf-8")
    workload, hardware_compose, simulator_none, simulator_tpm = write_compose_files(
        workspace
    )
    port_base = find_port_block()
    vmm_url = os.environ.get("DSTACK_TEST_VMM_URL", "http://127.0.0.1:12100")
    cli = repository / "dstack/vmm/src/vmm-cli.py"
    mock_root = Path(
        os.environ.get(
            "DSTACK_TEST_MOCK_ROOTS", "/tmp/dstack-test-mock-attestation/roots"
        )
    ).resolve()
    mock_port = int(os.environ.get("DSTACK_TEST_MOCK_PORT", "18088"))
    if not endpoint_ready("127.0.0.1", mock_port):
        shutil.rmtree(workspace, ignore_errors=True)
        fail(f"mock collateral service is unavailable on 127.0.0.1:{mock_port}")
    matrix = [
        {
            "name": "tdx",
            "platform": "dstack-tdx",
            "confirmation": "hardware",
            "image_key": "candidate_image",
            "deploy_flags": ["--tee"],
        },
        {
            "name": "tdx-lite",
            "platform": "dstack-tdx",
            "confirmation": "simulation",
            "image_key": "development_image",
            "deploy_flags": ["--no-tee", "--simulated-tee", "dstack-tdx"],
        },
        {
            "name": "sev-snp",
            "platform": "dstack-amd-sev-snp",
            "confirmation": "simulation",
            "image_key": "development_image",
            "deploy_flags": ["--no-tee", "--simulated-tee", "dstack-amd-sev-snp"],
        },
        {
            "name": "gcp-tdx",
            "platform": "dstack-gcp-tdx",
            "confirmation": "simulation",
            "image_key": "development_image",
            "deploy_flags": ["--no-tee", "--simulated-tee", "dstack-gcp-tdx"],
        },
        {
            "name": "nitro-tpm",
            "platform": "dstack-aws-nitro-tpm",
            "confirmation": "simulation",
            "image_key": "development_image",
            "deploy_flags": ["--no-tee", "--simulated-tee", "dstack-aws-nitro-tpm"],
        },
        {
            "name": "nitro-enclave",
            "platform": "dstack-nitro-enclave",
            "confirmation": "simulation",
            "image_key": "development_image",
            "deploy_flags": ["--no-tee", "--simulated-tee", "dstack-nitro-enclave"],
        },
    ]
    for index, row in enumerate(matrix):
        row["app_id"] = hashlib.sha256(
            f"{lease_id}:{row['name']}".encode("utf-8")
        ).hexdigest()[:40]
        if row["confirmation"] == "hardware":
            row["compose"] = str(hardware_compose)
        elif row["platform"] in ("dstack-gcp-tdx", "dstack-aws-nitro-tpm"):
            row["compose"] = str(simulator_tpm)
        else:
            row["compose"] = str(simulator_none)
        row["host_port"] = port_base + index
        row["guest_port"] = 8000
        row["deployment_state"] = "not-started"
        row["deploy_argv"] = [
            sys.executable,
            str(cli),
            "--url",
            vmm_url,
            "deploy",
            "--name",
            f"dtest-{lease_id[-12:]}-{row['name']}",
            "--image",
            str(
                os.environ.get(
                    "DSTACK_TEST_GUEST_IMAGE"
                    if row["confirmation"] == "hardware"
                    else "DSTACK_TEST_NO_TEE_GUEST_IMAGE",
                    "dstack-0.6.0"
                    if row["confirmation"] == "hardware"
                    else "dstack-dev-0.6.0",
                )
            ),
            "--compose",
            row["compose"],
            "--app-id",
            row["app_id"],
            "--vcpu",
            "2",
            "--memory",
            "2G",
            "--port",
            f"tcp:127.0.0.1:{row['host_port']}:{row['guest_port']}",
            *row["deploy_flags"],
        ]
    values = {
        "attestation_matrix": matrix,
        "mock_attestation": {
            "public_roots": str(mock_root),
            "collateral_base_url_guest": f"http://10.0.2.2:{mock_port}",
            "collateral_base_url_host": f"http://127.0.0.1:{mock_port}",
            "development_only": True,
        },
        "live_vmm": {
            "url": vmm_url,
            "cli_argv": [sys.executable, str(cli), "--url", vmm_url],
            "candidate_image": os.environ.get(
                "DSTACK_TEST_GUEST_IMAGE", "dstack-0.6.0"
            ),
            "development_image": os.environ.get(
                "DSTACK_TEST_NO_TEE_GUEST_IMAGE", "dstack-dev-0.6.0"
            ),
            "name_prefix": f"dtest-{lease_id[-12:]}",
            "created_vms_registry": str(registry),
            "allowed_actions": ["deploy", "start", "stop", "remove"],
        },
        "canonical_compose": {
            "workload": str(workload),
            "hardware": str(hardware_compose),
            "simulator_none": str(simulator_none),
            "simulator_tpm": str(simulator_tpm),
            "simulator_policy": {
                "key_provider_by_platform": {
                    "dstack-gcp-tdx": "tpm",
                    "dstack-aws-nitro-tpm": "tpm",
                    "default": "none",
                },
                "kms_enabled": False,
                "gateway_enabled": False,
                "secure_time": False,
            },
        },
        "destructive_actions_allowed": True,
    }
    if str(lease.get("profile", "")) == "gpu-policy":
        values["gpu_inventory"] = probe_gpu_inventory()
    return {
        "values": values,
        "cleanup_handle": {
            "workspace": str(workspace),
            "registry": str(registry),
            "vmm_cli": str(cli),
            "vmm_url": vmm_url,
        },
    }


def verify(value: dict[str, Any]) -> dict[str, Any]:
    """Verify that all matrix rows and collateral are available."""
    values = value.get("prepared", {}).get("values", {})
    matrix = values.get("attestation_matrix", [])
    ok = (
        isinstance(matrix, list)
        and len(matrix) == 6
        and endpoint_ready(
            "127.0.0.1", int(os.environ.get("DSTACK_TEST_MOCK_PORT", "18088"))
        )
    )
    return {
        "ok": ok,
        "expected": {"matrix_rows": 6},
        "observed": {"matrix_rows": len(matrix) if isinstance(matrix, list) else 0},
        "error": None if ok else "cross-platform attestation interface is incomplete",
    }


def destroy(value: dict[str, Any]) -> dict[str, Any]:
    """Destroy every VM registered to the fixture lease."""
    errors = []
    for resource in value.get("resources", []):
        handle = resource.get("cleanup", {}).get("handle", {})
        workspace = Path(str(handle.get("workspace", ""))).resolve()
        registry = Path(str(handle.get("registry", ""))).resolve()
        if workspace.parent != ROOT or not workspace.name.startswith("lease-"):
            fail(f"refusing unsafe hardware-pool cleanup: {workspace}")
        if not workspace.exists():
            continue
        try:
            vm_ids = json.loads(registry.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            errors.append(f"invalid VM registry: {error}")
            vm_ids = []
        if isinstance(vm_ids, dict):
            vm_ids = vm_ids.get("created_vms", vm_ids.get("vms", []))
        cli = [
            sys.executable,
            str(handle.get("vmm_cli", "")),
            "--url",
            str(handle.get("vmm_url", "")),
        ]
        for item in reversed(vm_ids if isinstance(vm_ids, list) else []):
            vm_id = item.get("id", "") if isinstance(item, dict) else item
            if not vm_id:
                errors.append("VM registry entry has no ID")
                continue
            process = subprocess.run(
                [*cli, "remove", str(vm_id)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=180,
                check=False,
            )
            if process.returncode and "not found" not in process.stderr.lower():
                errors.append(process.stderr[-1000:])
        shutil.rmtree(workspace, ignore_errors=True)
    if errors:
        fail("; ".join(errors))
    return {"released": True}


def main() -> None:
    """Dispatch the fixture provider protocol operation."""
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify", "destroy"}:
        fail("usage: hardware-pool.py prepare|verify|destroy")
    value = request()
    result = {"prepare": prepare, "verify": verify, "destroy": destroy}[sys.argv[1]](
        value
    )
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
