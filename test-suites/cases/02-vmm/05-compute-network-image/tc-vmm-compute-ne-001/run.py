#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise current user, bridge, and multi-NIC VMM networking lifecycle.

Bridge NICs are built by netd, the privileged interface broker, on every node
(PR #1145/#1214/#1217); QEMU's bridge helper is no longer used. The case owns
its own netd instance on a private socket, started through `sudo -n`, and
tears it down after every VM it served is removed.
"""

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


def run(
    argv: list[str], timeout: int = 60, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run one bounded command."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False, env=env
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
        raw = error.read()
        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            body = {}
        return error.code, body if isinstance(body, dict) else {}


def start(
    argv: list[str], log: Path, cwd: Path, env: dict[str, str] | None = None
) -> subprocess.Popen[str]:
    """Start one case-owned process group."""
    return subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=log.open("a"),
        stderr=subprocess.STDOUT,
        start_new_session=True,
        text=True,
        env=env,
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


def stop_privileged(process: subprocess.Popen[str] | None) -> None:
    """Stop and reap the case-owned root netd process group."""
    if process is None or process.poll() is not None:
        return
    run(["sudo", "-n", "kill", "-TERM", "--", f"-{process.pid}"], timeout=10)
    try:
        process.wait(15)
    except subprocess.TimeoutExpired:
        run(["sudo", "-n", "kill", "-KILL", "--", f"-{process.pid}"], timeout=10)
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


def process_stopped(pid: int) -> bool:
    """Return whether the observed case-owned QEMU PID has exited."""
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


def link_exists(name: str) -> bool:
    """Return whether a host network interface exists."""
    return Path("/sys/class/net", name).exists()


def link_master(name: str) -> str | None:
    """Return the bridge a host interface is enslaved to."""
    master = Path("/sys/class/net", name, "master")
    return master.resolve().name if master.exists() else None


def make_config(
    template: str,
    artifact_root: Path,
    runtime_root: Path,
    image_store: Path,
    supervisor: Path,
    port: int,
    instance_id: str,
) -> Path:
    """Materialize current VMM and case-owned netd configuration."""
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
        "detached = false": "detached = true",
        "allowed_bridges = []": 'allowed_bridges = ["virbr0"]',
        "port = 10000": f"port = {port + 1000}",
        "[key_provider]\nenabled = true": "[key_provider]\nenabled = false",
        # The interface namespace netd records on every TAP it builds for this
        # VMM, so the case can attribute and count exactly its own interfaces.
        'instance_id = ""': f'instance_id = "{instance_id}"',
        # A private netd socket inside the 0700 case runtime directory. The
        # directory, not the socket mode, keeps other users out.
        'socket = "/run/dstack/netd.sock"': f'socket = "{runtime_root}/netd.sock"',
        "socket_mode = 0o660": "socket_mode = 0o666",
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


def create_request(
    image: str, name: str, *, stopped: bool, networks: list[dict]
) -> dict:
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


def netd_interfaces(binary: Path, config: Path, instance_id: str) -> list[dict]:
    """List the interfaces netd holds for this case's VMM instance."""
    listed = run(
        [
            str(binary),
            "--config",
            str(config),
            "netd",
            "list",
            "--instance",
            instance_id,
        ],
        timeout=30,
    )
    if listed.returncode:
        raise RuntimeError(f"netd list failed: {listed.stderr[-300:]}")
    rows = []
    for line in listed.stdout.splitlines()[1:]:
        fields = line.split()
        if not fields:
            break
        if len(fields) == 5:
            rows.append(
                {
                    "tap": fields[0],
                    "kind": fields[1],
                    "instance": fields[2],
                    "vm": fields[3],
                    "nic": fields[4],
                }
            )
    return rows


def discovered(cli: Path, env: dict[str, str]) -> list[dict]:
    """List VMM instances as `vmm-cli.py vmm ls --json` reports them."""
    listed = run(["python3", str(cli), "vmm", "ls", "--json"], timeout=30, env=env)
    if listed.returncode:
        raise RuntimeError(f"vmm ls failed: {listed.stderr[-300:]}")
    try:
        value = json.loads(listed.stdout)
    except json.JSONDecodeError:
        # "No running VMM instances found." is the empty answer.
        return []
    return value if isinstance(value, list) else []


def main() -> int:
    """Run public networking, netd, restart, rejection, and cleanup coverage."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("wrong case")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    binary = Path(runtime["prepared_binaries"]["dstack_vmm"]["path"])
    supervisor = binary.with_name("supervisor")
    cli = repository / "dstack/vmm/src/vmm-cli.py"
    image_store = Path(os.environ["DSTACK_TEST_IMAGE_STORE"])
    image = os.environ["DSTACK_TEST_NO_TEE_GUEST_IMAGE"]
    root = result_dir / "artifacts/network-lifecycle"
    root.mkdir(parents=True)
    runtime_key = hashlib.sha256(str(result_dir).encode()).hexdigest()[:12]
    runtime_root = Path(f"/tmp/dtnet-{runtime_key}")
    shutil.rmtree(runtime_root, ignore_errors=True)
    runtime_root.mkdir(mode=0o700)
    instance_id = f"dtnet-{runtime_key}"
    config = make_config(
        (repository / "dstack/vmm/vmm.toml").read_text(),
        root,
        runtime_root,
        image_store,
        supervisor,
        18481,
        instance_id,
    )
    # PR #1179: register this VMM under an XDG_RUNTIME_DIR outside /run/user,
    # which vmm-cli used to miss.
    xdg_dir = runtime_root / "xdg"
    xdg_dir.mkdir(mode=0o700)
    vmm_env = {**os.environ, "XDG_RUNTIME_DIR": str(xdg_dir)}
    cli_env_without_xdg = {
        key: value for key, value in os.environ.items() if key != "XDG_RUNTIME_DIR"
    }
    base = "http://127.0.0.1:18481"
    process: subprocess.Popen[str] | None = None
    netd: subprocess.Popen[str] | None = None
    created: list[tuple[str, Path]] = []
    evidence: dict[str, Any] = {
        "candidate_commit": runtime["candidate_commit"],
        "instance_id": instance_id,
        "matrix": {},
    }
    status = "FAIL"
    summary = "Networking lifecycle did not execute."
    try:
        process = start(
            [str(binary), "--config", str(config)], root / "vmm.log", root, vmm_env
        )
        wait_for(
            lambda: run(["curl", "-sf", base + "/"]).returncode == 0,
            "VMM did not listen",
        )
        # Other users' VMMs under /run/user are listed too; only registrations
        # carrying this case's config file are this case's.
        instances = [
            item
            for item in discovered(cli, vmm_env)
            if item.get("config_file") == str(config)
        ]
        foreign = discovered(cli, cli_env_without_xdg)
        evidence["matrix"]["cli_discovery"] = {
            "custom_xdg_lists_this_vmm": [item.get("pid") for item in instances]
            == [process.pid],
            "custom_xdg_address_matches": bool(instances)
            and instances[0].get("address") == "127.0.0.1:18481",
            "without_xdg_does_not_list_it": all(
                item.get("config_file") != str(config) for item in foreign
            ),
        }

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

        # Without netd a bridge NIC has no host interface, so the start must
        # fail closed with a diagnosis naming netd rather than fall back to
        # QEMU's bridge helper.
        no_netd_code, no_netd_body = rpc(base, "StartVm", {"id": bridge_id}, 180)
        no_netd_error = str(no_netd_body.get("error", ""))
        evidence["matrix"]["bridge_without_netd"] = {
            "rejected": no_netd_code >= 400,
            "error_names_netd": "run dstack-vmm netd" in no_netd_error,
            "qemu_not_started": not (bridge_dir / "qemu.pid").is_file(),
            "nothing_pending": not (bridge_dir / ".netd-pending").exists(),
            "vmm_available": run(["curl", "-sf", base + "/"]).returncode == 0,
        }
        evidence["bridge_without_netd_error"] = no_netd_error[-400:]

        netd = start(
            ["sudo", "-n", str(binary), "--config", str(config), "netd"],
            root / "netd.log",
            root,
        )
        wait_for(
            lambda: (runtime_root / "netd.sock").exists()
            and run(
                [str(binary), "--config", str(config), "netd", "list"], timeout=10
            ).returncode
            == 0,
            "case-owned netd did not serve its socket",
            60,
        )
        evidence["matrix"]["netd_started"] = {
            "no_interfaces_before_launch": netd_interfaces(binary, config, instance_id)
            == []
        }

        start_code, _ = rpc(base, "StartVm", {"id": bridge_id}, 180)
        if start_code != 200:
            raise RuntimeError(f"bridge VM start failed with HTTP {start_code}")
        manifest = wait_for(
            lambda: (
                json.loads((bridge_dir / "vm-manifest.json").read_text())
                if (bridge_dir / "vm-manifest.json").is_file()
                else None
            ),
            "bridge VM manifest missing",
        )
        bridge_pid = wait_for(
            lambda: (
                int((bridge_dir / "qemu.pid").read_text())
                if (bridge_dir / "qemu.pid").is_file()
                else None
            ),
            "bridge VM did not start",
            120,
        )
        launch_text = process_command(bridge_pid)
        macs = re.findall(r"mac=([0-9a-f:]{17})", launch_text, re.IGNORECASE)
        taps = re.findall(r"tap,id=net\d+,ifname=([^,\s]+)", launch_text)
        held = netd_interfaces(binary, config, instance_id)
        code, status_body = rpc(base, "Status", {"ids": [bridge_id]})
        status_vm = (status_body.get("vms") or [{}])[0]
        interfaces = status_vm.get("interfaces") or []
        evidence["bridge_launch_observation"] = {
            "taps": taps,
            "netd_rows": held,
            "status_interfaces": interfaces,
        }
        evidence["matrix"]["bridge_launch"] = {
            "nic_count": len(manifest["networks"]) == 2,
            "distinct_macs": len(set(macs)) == 2,
            "netd_tap_netdevs": len(set(taps)) == 2,
            "no_bridge_helper": "bridge,id=net" not in launch_text
            and "qemu-bridge-helper" not in launch_text,
            "vhost_off_by_node_default": launch_text.count("vhost=off") == 2,
            "taps_on_bridge": all(link_master(tap) == "virbr0" for tap in taps),
            "netd_holds_both": sorted(row["tap"] for row in held) == sorted(taps)
            and all(row["kind"] == "tap" and row["vm"] == bridge_id for row in held)
            and sorted(row["nic"] for row in held) == ["0", "1"],
            "cleanup_marked_pending": (bridge_dir / ".netd-pending").exists(),
            "status_running": code == 200 and status_vm.get("running") is True,
            "status_reports_data_plane": len(interfaces) == 2
            and all(
                item.get("backend") == "tap_bridge"
                and item.get("vhost") is False
                and item.get("queues") == 1
                for item in interfaces
            ),
            "qemu_started": True,
        }
        stop_code, _ = rpc(base, "StopVm", {"id": bridge_id}, 60)
        if stop_code != 200:
            raise RuntimeError(f"bridge VM stop failed with HTTP {stop_code}")
        wait_for(
            lambda: process_stopped(bridge_pid),
            "bridge VM did not stop",
        )
        released = wait_for(
            lambda: netd_interfaces(binary, config, instance_id) == [],
            "netd still holds the stopped bridge VM's interfaces",
            30,
        )
        evidence["matrix"]["bridge_stop_release"] = {
            "netd_holds_nothing": bool(released),
            "taps_deleted": bool(taps) and not any(link_exists(tap) for tap in taps),
            "pending_marker_cleared": not (bridge_dir / ".netd-pending").exists(),
        }

        user_request = create_request(
            image,
            "user-matrix",
            stopped=True,
            networks=[{"mode": "user"}, {"mode": "user"}],
        )
        code, body = rpc(base, "CreateVm", user_request, 180)
        if code != 200 or not body.get("id"):
            raise RuntimeError(f"user VM creation failed with HTTP {code}")
        user_id = str(body["id"])
        user_dir = runtime_root / "vms" / user_id
        created.append((user_id, user_dir))
        start_code, _ = rpc(base, "StartVm", {"id": user_id}, 180)
        if start_code != 200:
            raise RuntimeError(f"user VM start failed with HTTP {start_code}")
        old_pid = wait_for(
            lambda: (
                int((user_dir / "qemu.pid").read_text())
                if (user_dir / "qemu.pid").is_file()
                else None
            ),
            "user VM did not start",
            120,
        )
        user_text = process_command(old_pid)
        evidence["matrix"]["user_launch"] = {
            "user_netdevs": user_text.count("user,id=net") == 2,
            "no_netd_interfaces": netd_interfaces(binary, config, instance_id) == [],
            "qemu_started": True,
        }

        old_vmm_pid = process.pid
        stop(process)
        process = start(
            [str(binary), "--config", str(config)],
            root / "vmm-restart.log",
            root,
            vmm_env,
        )
        wait_for(
            lambda: run(["curl", "-sf", base + "/"]).returncode == 0,
            "VMM restart failed",
        )
        preserved_pid = int((user_dir / "qemu.pid").read_text())
        restarted_instances = [
            item
            for item in discovered(cli, vmm_env)
            if item.get("config_file") == str(config)
        ]
        evidence["matrix"]["vmm_restart"] = {
            "qemu_pid_preserved": preserved_pid == old_pid,
            "discovery_lists_only_the_new_vmm": [
                item.get("pid") for item in restarted_instances
            ]
            == [process.pid]
            and process.pid != old_vmm_pid,
        }

        try:
            os.kill(old_pid, signal.SIGKILL)
        except ProcessLookupError:
            # The supervisor may already have observed an early QEMU exit and
            # started its replacement before this deliberate restart trigger.
            pass
        new_pid = wait_for(
            lambda: (
                int((user_dir / "qemu.pid").read_text())
                if (user_dir / "qemu.pid").is_file()
                and int((user_dir / "qemu.pid").read_text()) != old_pid
                else None
            ),
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
        evidence["matrix"]["removal"] = {
            "netd_holds_nothing": netd_interfaces(binary, config, instance_id) == []
        }
        checks = [
            value for value in evidence["matrix"].values() for value in value.values()
        ]
        if not checks or not all(checks):
            raise AssertionError(f"incomplete networking matrix: {evidence['matrix']}")
        status = "PASS"
        summary = (
            "User and netd-built bridge multi-NIC launches, fail-closed start without "
            "netd, interface release on stop, CLI discovery, rejection, restart, "
            "persistence, and cleanup passed."
        )
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
        if netd is not None:
            try:
                leftovers = netd_interfaces(binary, config, instance_id)
            except Exception as error:  # noqa: BLE001
                leftovers = [{"error": str(error)[-200:]}]
            evidence["netd_leftovers_before_stop"] = leftovers
            for row in leftovers:
                if "tap" in row:
                    run(
                        [
                            str(binary),
                            "--config",
                            str(config),
                            "netd",
                            "remove-interface",
                            row["tap"],
                        ],
                        timeout=30,
                    )
        stop_privileged(netd)
        # `detached = true` keeps the case supervisor alive after the VMM
        # exits; stop it through its case-owned PID file.
        try:
            os.kill(int((runtime_root / "supervisor.pid").read_text()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
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
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": status,
                "observed": observed,
            }
            for number in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/vmm-network-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "TEE simulation validates VMM/QEMU/network lifecycle only; physical TEE attestation is out of scope. netd ran as a case-owned root process on a private socket and was stopped after cleanup.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
