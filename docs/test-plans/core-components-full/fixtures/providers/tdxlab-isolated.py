#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Lease-owned tdxlab guest provider for the core component test plan."""

from __future__ import annotations

# ruff: noqa: D103
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from image_provenance import require_image_backend
from vmm_fixture import (
    fail,
    link_image_store,
    reserve_ports,
    serialize_port_provisioning,
    start_component,
    terminate_pids,
    write_vmm_config,
)

STATE_ROOT = Path(
    os.environ.get("DSTACK_TEST_STATE_ROOT", "").strip()
    or str(Path.home() / ".cache/dstack-test/runtime-state")
)
PROVIDER_ROOT = STATE_ROOT / "tdxlab-fixtures"
RUN_LINK_ROOT = STATE_ROOT / "r"
# Guest disks and per-VM state live outside /tmp: the lab root filesystem is
# nearly full, while the home volume has terabytes free.
VM_DATA_ROOT = Path(
    os.environ.get("DSTACK_TEST_TDXLAB_VM_ROOT", "").strip()
    or str(Path.home() / ".cache/dstack-test-tdxlab-vms")
)
# Host ports forwarded into lease-owned guests. The lease-owned VMM only allows
# port mappings inside this block.
PORT_BLOCK_START = 19001
PORT_BLOCK_END = 19990
# Hardware-pool fixtures reserve guest-forwarded ports in 18101-18994.
# Admit both non-overlapping reservation blocks, not arbitrary host ports.
PORT_MAPPING_START = 18101
VM_ID_RE = re.compile(r"Created VM with ID:\s*([0-9a-f-]{36})")
# The guest images ship a world-writable `/` (mode 0777), so OpenSSH's default
# StrictModes refuses every authorized_keys file: its safe-path walk rejects any
# world-writable component up to and including the root directory. This sshd is
# fixture tooling installed by the pre-launch script, not part of the guest image
# under test, so relaxing the check only affects how a case reaches its own
# lease-owned guest. Report the image mode as a finding; do not rely on this to
# hide it.
SSHD_STRICT_MODES_RELAXATION = (
    "dstack_test_sshd_config=/dstack/persistent/ssh/sshd_config\n"
    'if [ -f "$dstack_test_sshd_config" ] &&'
    " ! grep -q '^StrictModes' \"$dstack_test_sshd_config\"; then\n"
    '  echo "StrictModes no" >> "$dstack_test_sshd_config"\n'
    "  systemctl restart sshd || true\n"
    "fi\n"
)
BOOTSTRAP_IMAGES = (
    "kvin/dstack-openssh-installer:latest",
    "ubuntu:latest",
    "dstack-test/tappd-bridge:v2",
    "dstacktee/dstack-verifier:0.5.4",
    "docker:27.5.1-dind",
    "busybox:1.37.0",
    "registry:2.8.3",
)
NESTED_WORKLOAD_IMAGE = "docker:27.5.1-dind"
NESTED_WORKLOAD_IMAGE_DIGEST = (
    "sha256:aa3df78ecf320f5fafdce71c659f1629e96e9de0968305fe1de670e0ca9176ce"
)
NESTED_WORKLOAD_IMAGE_ID = (
    "sha256:d2dc198f7d839eae26b5a9cb0e7cdc4e2c97d9cb4ea66dbeb0a4c0c7f0b165f8"
)
NESTED_PAYLOAD_IMAGE = "busybox:1.37.0"
NESTED_PAYLOAD_IMAGE_DIGEST = (
    "sha256:9532d8c39891ca2ecde4d30d7710e01fb739c87a8b9299685c63704296b16028"
)
NESTED_PAYLOAD_IMAGE_ID = (
    "sha256:db287cb6be81219cd18c1d82b70908f5d33eb028568b456f78eedff2ff2930e4"
)
INSTALLER_ARCHIVE = (
    Path.home()
    / ".cache/dstack-test/fixture-images/dstack-guest-bootstrap-images-v6.tar"
)


@serialize_port_provisioning
def start_bootstrap_server(state: Path) -> tuple[subprocess.Popen[str], str]:
    """Serve a host-cached installer image and public key to one guest lease."""
    INSTALLER_ARCHIVE.parent.mkdir(parents=True, exist_ok=True)
    bridge_image = "dstack-test/tappd-bridge:v2"
    inspected = subprocess.run(
        ["sudo", "su", "kvin", "-c", f"docker image inspect {bridge_image}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if inspected.returncode:
        source = Path(__file__).resolve().parent.parent / "images/tappd-bridge"
        context = STATE_ROOT / "tappd-bridge-build"
        shutil.rmtree(context, ignore_errors=True)
        context.mkdir(parents=True)
        shutil.copy2(source / "Dockerfile", context / "Dockerfile")
        compiled = subprocess.run(
            [
                "go",
                "build",
                "-o",
                str(context / "dstack-socket-bridge"),
                str(source / "bridge.go"),
            ],
            env={**os.environ, "CGO_ENABLED": "0"},
            capture_output=True,
            text=True,
            check=False,
        )
        if compiled.returncode:
            fail(f"failed to compile prepared Tappd bridge: {compiled.stderr[-500:]}")
        built = subprocess.run(
            [
                "sudo",
                "su",
                "kvin",
                "-c",
                f"docker build -t {bridge_image} {context}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if built.returncode:
            fail(f"failed to build prepared Tappd bridge image: {built.stderr[-500:]}")
    if not INSTALLER_ARCHIVE.is_file():
        temporary = INSTALLER_ARCHIVE.with_suffix(f".tmp-{os.getpid()}")
        command = f"docker save --output {temporary} {' '.join(BOOTSTRAP_IMAGES)}"
        exported = subprocess.run(
            ["sudo", "su", "kvin", "-c", command],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=180,
            check=False,
        )
        if exported.returncode:
            temporary.unlink(missing_ok=True)
            fail(
                f"failed to export prepared OpenSSH installer image: {exported.stderr[-500:]}"
            )
        temporary.replace(INSTALLER_ARCHIVE)
    public_key = Path(
        os.environ.get("DSTACK_TEST_SSH_PUBLIC_KEY_FILE", "").strip()
        or str(Path.home() / ".ssh/id_ed25519.pub")
    ).resolve()
    if not public_key.is_file():
        fail(f"fixture SSH public key is unavailable: {public_key}")
    bootstrap = state / "bootstrap"
    bootstrap.mkdir()
    (bootstrap / "installer.tar").symlink_to(INSTALLER_ARCHIVE)
    shutil.copyfile(public_key, bootstrap / "fixture.pub")
    port = reserve_ports(1)[0]
    process = start_component(
        [
            sys.executable,
            "-m",
            "http.server",
            str(port),
            "--bind",
            "127.0.0.1",
            "--directory",
            str(bootstrap),
        ],
        state / "bootstrap-http.log",
        port,
    )
    return process, f"http://10.0.2.2:{port}"


def run(
    command: list[str], *, timeout: int = 120, check: bool = True
) -> subprocess.CompletedProcess[str]:
    value = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and value.returncode != 0:
        stderr = value.stderr
        if len(stderr) > 4000:
            stderr = (
                stderr[:2000] + "\n... stderr middle omitted ...\n" + stderr[-2000:]
            )
        fail(f"command failed ({value.returncode}): {stderr}")
    return value


def endpoint_ready(host: str, port: int) -> bool:
    """Return whether a required host-side TCP endpoint accepts connections."""
    try:
        with socket.create_connection((host, port), timeout=3):
            return True
    except OSError:
        return False


PORT_RESERVATION_DIR = STATE_ROOT / "guest-ports"
# A marker is only reclaimed once its ports are free again, so this age
# only has to cover the gap between reserving a block and qemu binding it,
# which is seconds. Holding markers for ten minutes exhausted the 247
# available blocks after a few back-to-back sweeps.
PORT_RESERVATION_STALE_SECONDS = 60


def _bindable(base: int, count: int) -> bool:
    """Report whether every port in the block can currently be bound."""
    probes = []
    try:
        for port in range(base, base + count):
            item = socket.socket()
            item.bind(("127.0.0.1", port))
            probes.append(item)
    except OSError:
        return False
    finally:
        for item in probes:
            item.close()
    return True


def _reclaimable(marker: Path, base: int, count: int) -> bool:
    """Report whether a marker is left over from a lease that is gone."""
    try:
        age = time.time() - marker.stat().st_mtime
    except OSError:
        return False
    if age < PORT_RESERVATION_STALE_SECONDS:
        return False
    probes = []
    try:
        for port in range(base, base + count):
            item = socket.socket()
            item.bind(("127.0.0.1", port))
            probes.append(item)
    except OSError:
        return False
    finally:
        for item in probes:
            item.close()
    return True


def find_port_block(count: int = 4) -> int:
    """Reserve consecutive loopback ports for one lease-owned guest.

    Reserve every port in the block, not the block's base. Keying the marker on
    the base let two leases whose ranges overlapped both succeed: blocks
    starting at 19026, 19027 and 19028 all claimed port 19028, and qemu then
    refused to start with "Could not set up host forwarding rule", exiting a
    hundred milliseconds in with no console output.
    """
    PORT_RESERVATION_DIR.mkdir(parents=True, exist_ok=True)
    for base in range(PORT_BLOCK_START, PORT_BLOCK_END - count):
        claimed: list[Path] = []
        for port in range(base, base + count):
            marker = PORT_RESERVATION_DIR / f"{port}.reserved"
            if marker.exists() and _reclaimable(marker, port, 1):
                marker.unlink(missing_ok=True)
            try:
                handle = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            except OSError:
                break
            os.close(handle)
            claimed.append(marker)
        if len(claimed) == count and _bindable(base, count):
            return base
        for marker in claimed:
            marker.unlink(missing_ok=True)
    fail("no consecutive loopback port block is available")


def request() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as error:
        fail(f"invalid provider request: {error}")
    if not isinstance(value, dict):
        fail("provider request must be an object")
    return value


def config(value: dict[str, Any]) -> dict[str, Any]:
    """Resolve the candidate tree, guest image, and image store for a lease."""
    item = value.get("request", {})
    runtime_path = Path(str(item.get("_runtime_manifest", ""))).resolve()
    try:
        runtime = json.loads(runtime_path.read_text(encoding="utf-8"))
        repository = Path(runtime["repository"]).resolve()
    except (OSError, KeyError, json.JSONDecodeError) as error:
        fail(f"runtime manifest does not identify the repository: {error}")
    cli = repository / "dstack" / "vmm" / "src" / "vmm-cli.py"
    if not cli.is_file():
        fail(f"VMM CLI not found: {cli}")
    image = os.environ.get("DSTACK_TEST_GUEST_IMAGE", "dstack-0.6.0")
    image_store = os.environ.get("DSTACK_TEST_IMAGE_STORE", "").strip()
    if not image_store:
        fail("DSTACK_TEST_IMAGE_STORE is required for mkosi image provenance")
    try:
        image_provenance = require_image_backend(image_store, image)
    except RuntimeError as error:
        fail(str(error))
    return {
        "cli": cli,
        "image": image,
        "image_provenance": image_provenance,
        "image_store": Path(image_store).resolve(),
        "repository": repository,
        "runtime": runtime,
        "runtime_manifest": runtime_path,
    }


@serialize_port_provisioning
def start_vmm(
    state: Path,
    lease_id: str,
    settings: dict[str, Any],
    profile: str,
    simulator_seed: str = "",
    simulator_collateral_url: str = "http://10.0.2.2:18088",
    simulator_tdx_root_ca: str = "",
    extra_images: list[str] | None = None,
    allow_udp_port_mapping: bool = False,
) -> dict[str, Any]:
    """Start a VMM that only this lease owns.

    Cases must not depend on a shared lab VMM: its working directory, image
    store, and CID pool are outside the plan's control, so a host-side change
    silently breaks every guest fixture. Everything this VMM needs is derived
    from the runtime manifest and torn down with the lease.
    """
    binaries = settings["runtime"].get("prepared_binaries", {})
    binary = Path(str(binaries.get("dstack_vmm", {}).get("path", ""))).resolve()
    supervisor = Path(
        str(binaries.get("dstack_supervisor", {}).get("path", ""))
    ).resolve()
    source_config = settings["repository"] / "dstack/vmm/vmm.toml"
    if not binary.is_file() or not supervisor.is_file() or not source_config.is_file():
        fail("prepared VMM, supervisor, or candidate VMM config is unavailable")
    handle: dict[str, Any] = {"pids": [], "run_path_link": "", "vm_root": ""}
    try:
        for name in ("config", "data", "logs", "run"):
            (state / name).mkdir(parents=True, exist_ok=True)
        image_root = state / "data/images"
        image_root.mkdir()
        requested_images = [
            settings["image"],
            os.environ.get("DSTACK_TEST_NO_TEE_GUEST_IMAGE", "dstack-dev-0.6.0"),
            *(extra_images or []),
        ]
        link_image_store(
            settings["image_store"],
            image_root,
            list(dict.fromkeys(requested_images)),
        )
        vm_root = VM_DATA_ROOT / lease_id
        vm_root.mkdir(parents=True, exist_ok=False)
        handle["vm_root"] = str(vm_root)
        # QEMU unix socket paths are limited to 108 bytes, so the VMM run path
        # is reached through a short symlink rather than the lease workspace.
        RUN_LINK_ROOT.mkdir(parents=True, exist_ok=True)
        # Keep lease-owned Supervisor endpoints isolated from other users.
        RUN_LINK_ROOT.chmod(0o700)
        run_path_link = RUN_LINK_ROOT / f"dv-{lease_id[-12:]}"
        if run_path_link.exists() or run_path_link.is_symlink():
            fail(f"short VMM run-path link already exists: {run_path_link}")
        run_path_link.symlink_to(vm_root, target_is_directory=True)
        handle["run_path_link"] = str(run_path_link)
        supervisor_socket = RUN_LINK_ROOT / f"ds-{lease_id[-12:]}.sock"
        supervisor_lock = supervisor_socket.with_suffix(".lock")
        if supervisor_socket.exists() or supervisor_lock.exists():
            fail(f"short Supervisor endpoint already exists: {supervisor_socket}")
        handle["supervisor_socket"] = str(supervisor_socket)
        rpc_port, host_api_port = reserve_ports(2)
        config_path = state / "config/vmm.toml"
        if profile == "no-tee-guest-lifecycle" and not simulator_seed:
            simulator_seed = secrets.token_hex(32)
        write_vmm_config(
            source_config,
            config_path,
            state,
            run_path_link,
            image_root,
            supervisor,
            rpc_port,
            host_api_port,
            # Stride the CID pools by more than cid_pool_size so concurrent
            # lease-owned VMMs can never hand out the same guest CID.
            100_000 + rpc_port * 1000,
            enable_key_provider=True,
            enable_port_mapping=True,
            port_mapping_range=(
                f'    {{ protocol = "tcp", from = {PORT_MAPPING_START}, '
                f"to = {PORT_BLOCK_END} }},"
                + (
                    f'\n    {{ protocol = "udp", from = {PORT_MAPPING_START}, '
                    f"to = {PORT_BLOCK_END} }},"
                    if allow_udp_port_mapping
                    else ""
                )
            ),
            # Only the explicitly simulated profile may configure the TEE
            # simulator. Every other profile must produce real hardware TDX
            # quotes, so `[cvm.tee_simulator]` is never written for them.
            simulator_seed=simulator_seed,
            simulator_collateral_url=simulator_collateral_url,
            simulator_tdx_root_ca=simulator_tdx_root_ca,
            pccs_url=simulator_collateral_url if simulator_seed else "",
            # Supervisor uses an AF_UNIX socket whose pathname is limited to
            # SUN_LEN. Its security check also requires a real parent directory,
            # so place it beside (not beneath) the short QEMU symlink.
            supervisor_socket=supervisor_socket,
        )
        process = start_component(
            [str(binary), "--config", str(config_path)],
            state / "logs/vmm.log",
            rpc_port,
            cwd=state,
        )
        handle["pids"] = [process.pid]
        handle["url"] = f"http://127.0.0.1:{rpc_port}"
        handle["config"] = str(config_path)
        handle["log"] = str(state / "logs/vmm.log")
        handle["simulator_seed"] = simulator_seed
    except BaseException:
        release_vmm(handle, state)
        raise
    return handle


def release_vmm(handle: dict[str, Any], state: Path) -> None:
    """Stop a lease-owned VMM and delete the guest state it created."""
    pids = {int(pid) for pid in handle.get("pids", [])}
    supervisor_pid_file = state / "run/supervisor.pid"
    if supervisor_pid_file.is_file():
        try:
            pids.add(int(supervisor_pid_file.read_text(encoding="utf-8").strip()))
        except (OSError, ValueError):
            pass
    terminate_pids(pids)
    supervisor_socket_text = str(handle.get("supervisor_socket", ""))
    if supervisor_socket_text:
        supervisor_socket = Path(supervisor_socket_text)
        if (
            supervisor_socket.parent == RUN_LINK_ROOT
            and supervisor_socket.name.startswith("ds-")
            and supervisor_socket.suffix == ".sock"
        ):
            supervisor_socket.unlink(missing_ok=True)
            supervisor_socket.with_suffix(".lock").unlink(missing_ok=True)
    link_text = str(handle.get("run_path_link", ""))
    if link_text:
        link = Path(link_text)
        if (
            link.parent == RUN_LINK_ROOT
            and link.name.startswith("dv-")
            and link.is_symlink()
        ):
            link.unlink()
    vm_root_text = str(handle.get("vm_root", ""))
    if vm_root_text:
        vm_root = Path(vm_root_text)
        if vm_root.parent == VM_DATA_ROOT and vm_root.name.startswith("lease-"):
            shutil.rmtree(vm_root, ignore_errors=True)
    simulator_root = (STATE_ROOT / "s").resolve()
    for path_text in handle.get("extra_paths", []):
        path = Path(str(path_text)).resolve()
        if path.parent == simulator_root and path.name.startswith("lease-"):
            shutil.rmtree(path, ignore_errors=True)


def wait_removed(cli: list[str], vm_ids: list[str], timeout: int = 180) -> None:
    """Wait for background VM removal so no QEMU outlives its VMM."""
    deadline = time.monotonic() + timeout
    pending = list(vm_ids)
    while pending and time.monotonic() < deadline:
        listed = run([*cli, "lsvm", "--json"], timeout=30, check=False)
        if listed.returncode != 0:
            return
        try:
            rows = json.loads(listed.stdout)
        except json.JSONDecodeError:
            return
        known = {
            str(row.get("id"))
            for row in rows
            if isinstance(row, dict) and row.get("id") is not None
        }
        pending = [item for item in pending if item in known]
        if pending:
            time.sleep(2)


def compose_manifest(
    name: str,
    bootstrap_url: str,
    allowed_envs: list[str] | None = None,
    *,
    tpm_keys: bool = False,
    kms_enabled: bool = False,
    dependency_order: bool = False,
    boundary_role: str | None = None,
    storage_fs: str = "zfs",
) -> dict[str, Any]:
    compose = """services:
  dstack-agent:
    image: dstack-test/tappd-bridge:v2
    network_mode: host
    volumes:
      - /:/host/
      - /var/run/tappd.sock:/var/run/tappd.sock
      - /var/run/dstack.sock:/var/run/dstack.sock
    entrypoint:
      - /dstack-socket-bridge
      - 2000:/var/run/tappd.sock
      - 3000:/var/run/dstack.sock
  dstack-verifier:
    image: dstacktee/dstack-verifier:0.5.4
    ports:
      - "8080:8080"
    restart: unless-stopped
"""
    if dependency_order:
        compose = compose.replace(
            "    network_mode: host\n",
            "    network_mode: host\n"
            "    depends_on:\n"
            "      dstack-verifier:\n"
            "        condition: service_started\n",
            1,
        )
    if boundary_role == "normal":
        compose += """  boundary-target:
    image: ubuntu
    network_mode: none
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    pids_limit: 64
    mem_limit: 128m
    entrypoint: ["sleep", "infinity"]
"""
    elif boundary_role == "privileged":
        compose += """  boundary-target:
    image: ubuntu
    privileged: true
    network_mode: host
    pid: host
    volumes:
      - /:/guest-host:ro
      - /run/dstack.sock:/run/dstack.sock
    entrypoint: ["sleep", "infinity"]
"""
    return {
        "manifest_version": 2,
        "name": name,
        "runner": "docker-compose",
        "docker_compose_file": compose,
        "gateway_enabled": False,
        "public_logs": True,
        "public_sysinfo": True,
        "public_tcbinfo": True,
        "key_provider_id": "",
        "allowed_envs": allowed_envs or [],
        "no_instance_id": False,
        "secure_time": False,
        "key_provider": ("tpm" if tpm_keys else ("kms" if kms_enabled else "local")),
        "local_key_provider_enabled": not tpm_keys and not kms_enabled,
        "kms_enabled": kms_enabled,
        "storage_fs": storage_fs,
        "pre_launch_script": (
            f"curl --fail --silent --show-error --retry 3 {bootstrap_url}/installer.tar "
            "--output /run/dstack-openssh-installer.tar\n"
            f"curl --fail --silent --show-error --retry 3 {bootstrap_url}/fixture.pub "
            "--output /run/dstack-test-fixture.pub\n"
            "docker load --input /run/dstack-openssh-installer.tar\n"
            "docker run --rm --privileged --pid=host --net=host -v /:/host "
            '-e SSH_PUBKEY="$(cat /run/dstack-test-fixture.pub)" '
            f"{BOOTSTRAP_IMAGES[0]}\n" + SSHD_STRICT_MODES_RELAXATION
        ),
    }


def info(cli: list[str], vm_id: str) -> dict[str, Any]:
    process = run([*cli, "info", "--json", vm_id], timeout=30)
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        fail(f"VMM returned invalid VM info: {error}")
    if not isinstance(value, dict):
        fail("VMM returned non-object VM info")
    return value


FAILED_LEASE_EVIDENCE = STATE_ROOT / "failed-leases"


def preserve_failure_evidence(
    vmm_log: Path | None, vm_id: str, vm_root: Path | None = None
) -> str:
    """Copy the VMM log somewhere the workspace teardown cannot reach.

    The failure message is truncated by the lifecycle record, so a tail alone
    loses the beginning of the failure. Keep the whole log and report where it
    went.
    """
    if vmm_log is None or not vmm_log.is_file():
        return "<no vmm log>"
    # The VMM log only records that the guest exited. Why it exited is in the
    # supervisor log and the qemu output beside it, so keep the whole log
    # directory and the VM run directory.
    destination = FAILED_LEASE_EVIDENCE / vm_id
    try:
        destination.mkdir(parents=True, exist_ok=True)
        shutil.copytree(vmm_log.parent, destination / "logs", dirs_exist_ok=True)
        # qemu writes its own stderr under the VMM run path, which lives
        # outside the lease workspace; that file is the only place the reason
        # for an immediate exit appears.
        if vm_root is not None and vm_root.is_dir():
            shutil.copytree(vm_root, destination / "vm", dirs_exist_ok=True)
    except OSError as error:
        return f"<evidence not preserved: {error}>"
    return str(destination)


def vmm_log_tail(vmm_log: Path | None, limit: int = 4000) -> str:
    """Return the tail of the lease-owned VMM log for a failure diagnostic.

    The guest serial log is fetched through the VMM after the guest is already
    gone, so it comes back empty for a guest that died during startup. The
    VMM's own log records why it gave up, and the lease workspace holding it is
    deleted as soon as provisioning fails.
    """
    if vmm_log is None:
        return "<no vmm log path>"
    try:
        return vmm_log.read_text(encoding="utf-8", errors="replace")[-limit:]
    except OSError as error:
        return f"<vmm log unavailable: {error}>"


def wait_ready(
    cli: list[str],
    vm_id: str,
    timeout: int = 600,
    vmm_log: Path | None = None,
    vm_root: Path | None = None,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = info(cli, vm_id)
        if latest.get("boot_error"):
            fail(
                f"guest boot failed: {latest.get('boot_error')}\n"
                f"--- vmm log preserved at ---\n"
                f"{preserve_failure_evidence(vmm_log, vm_id, vm_root)}\n"
                f"--- vmm log tail ---\n{vmm_log_tail(vmm_log)}\n"
                f"--- guest serial log tail ---\n{guest_log_tail(cli, vm_id)}"
            )
        if latest.get("status") not in ("running", "starting"):
            fail(
                f"guest entered unexpected state: {latest.get('status')}\n"
                f"--- vmm status ---\n{json.dumps(latest, indent=2)[:1200]}\n"
                f"--- vmm log preserved at ---\n{preserve_failure_evidence(vmm_log, vm_id, vm_root)}\n"
                f"--- vmm log tail ---\n{vmm_log_tail(vmm_log)}\n"
                f"--- guest serial log tail ---\n{guest_log_tail(cli, vm_id)}"
            )
        if latest.get("boot_progress") == "done" and latest.get("instance_id"):
            return latest
        time.sleep(5)
    progress = latest.get("boot_progress")
    fail(
        f"guest readiness timed out; last progress: {progress}\n"
        f"--- vmm status ---\n{json.dumps(latest, indent=2)[:1200]}\n"
        f"--- vmm log preserved at ---\n"
        f"{preserve_failure_evidence(vmm_log, vm_id, vm_root)}\n"
        f"--- vmm log tail ---\n{vmm_log_tail(vmm_log)}\n"
        f"--- guest serial log tail ---\n{guest_log_tail(cli, vm_id)}"
    )


def wait_tappd_ready(port: int, timeout: int = 180) -> None:
    """Wait for the guest-side Tappd bridge, not only VM boot completion."""
    deadline = time.monotonic() + timeout
    last_error = "no request attempted"
    url = f"http://127.0.0.1:{port}/prpc/Info"
    while time.monotonic() < deadline:
        request = urllib.request.Request(
            url,
            data=b"{}",
            headers={"content-type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                value = json.load(response)
            if isinstance(value, dict) and value:
                return
            last_error = "Info returned empty or non-object JSON"
        except (ConnectionError, OSError, TimeoutError, urllib.error.URLError) as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(2)
    fail(f"guest Tappd bridge readiness timed out: {last_error}")


def guest_log_tail(cli: list[str], vm_id: str, limit: int = 4000) -> str:
    """Return the tail of the guest serial log for a failure diagnostic.

    A provisioning failure deletes the lease workspace, taking boot.log with
    it, so the only way the reason survives is inside the message itself.
    """
    try:
        logs = subprocess.run(
            [*cli, "logs", "-n", "2000", vm_id],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except Exception as error:  # noqa: BLE001 - diagnostics must never mask the real failure
        return f"<serial log unavailable: {error}>"
    return (logs.stdout or logs.stderr or "<empty>")[-limit:]


def wait_running(
    cli: list[str],
    vm_id: str,
    timeout: int = 30,
    vmm_log: Path | None = None,
    vm_root: Path | None = None,
) -> dict[str, Any]:
    """Wait only for VM creation when boot behavior is the action under test."""
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = info(cli, vm_id)
        if latest.get("status") == "running":
            return latest
        if latest.get("boot_error"):
            return latest
        time.sleep(2)
    fail(
        f"VM did not enter running state: {latest.get('status')}\n"
        f"--- vmm status ---\n{json.dumps(latest, indent=2)[:1200]}\n"
        f"--- vmm log preserved at ---\n{preserve_failure_evidence(vmm_log, vm_id, vm_root)}\n"
        f"--- vmm log tail ---\n{vmm_log_tail(vmm_log)}\n"
        f"--- guest serial log tail ---\n{guest_log_tail(cli, vm_id)}"
    )


def prepare(value: dict[str, Any]) -> dict[str, Any]:
    settings = config(value)
    image = settings["image"]
    request_value = value.get("request", {})
    profile = str(request_value.get("profile", "guest-readonly"))
    actions = request_value.get("actions_under_test", [])
    lease = value.get("lease", {})
    case_id = str(lease.get("case_id", ""))
    configuration_materialization = (
        isinstance(actions, list)
        and "System and user configuration materialization" in actions
    )
    identity_matrix_requested = (
        profile == "identity-matrix"
        and isinstance(actions, list)
        and "Stable app, instance, device, and compose identity" in actions
    )
    host_notification_requested = (
        isinstance(actions, list)
        and "Host notification boot and shutdown events" in actions
    )
    volume_persistence_requested = (
        isinstance(actions, list)
        and "Volume encryption and persistence semantics" in actions
    )
    data_disk_requested = (
        isinstance(actions, list)
        and "Data disk encryption filesystem repair and mount" in actions
    )
    key_derivation_requested = (
        isinstance(actions, list)
        and "Deterministic key derivation and purpose separation" in actions
    )
    local_provider_sealing_requested = (
        isinstance(actions, list)
        and "Local key provider sealing and identity isolation" in actions
    )
    compose_validation_requested = (
        isinstance(actions, list) and "Compose validation and startup" in actions
    )
    docker_boundary_requested = (
        isinstance(actions, list)
        and "Docker daemon and container privilege boundary" in actions
    )
    guest_hardening_requested = (
        isinstance(actions, list) and "Guest kernel and userspace hardening" in actions
    )
    sysbox_requested = (
        isinstance(actions, list)
        and "Sysbox runtime services and nested-container boundary" in actions
    )
    journal_lifecycle_requested = (
        isinstance(actions, list)
        and "Journal persistence rotation and redaction" in actions
    )
    stargz_lifecycle_requested = (
        isinstance(actions, list)
        and "Containerd stargz snapshotter integrity and fallback" in actions
    )
    dashboard_log_requested = (
        case_id == "tc-gos-observabil-001"
        or (
            isinstance(actions, list)
            and "Dashboard metrics and container log filtering" in actions
        )
    )
    config_entry_requested = (
        isinstance(actions, list)
        and "Guest-agent configuration precedence and compose deserialization"
        in actions
    )
    guest_agent_startup_requested = (
        isinstance(actions, list)
        and "Guest-agent startup modes and partial listener failure" in actions
    )
    systemd_graph_requested = (
        isinstance(actions, list)
        and "Systemd dependency and failure-action graph" in actions
    )
    host_shared_lifecycle_requested = (
        isinstance(actions, list) and "Host-shared mount and unmount command" in actions
    )
    wireguard_checker_requested = (
        isinstance(actions, list)
        and "WireGuard configuration and checker recovery" in actions
    )
    kms_cli_requested = (
        isinstance(actions, list)
        and "KMS GetKeys CLI transport and output safety" in actions
    )
    simulator_guest_requested = isinstance(actions, list) and any(
        action in actions
        for action in (
            "TPM simulator command proxy and lifecycle",
            "Simulator platform selection config and mount safety",
            "TDX event-log extend show and replay CLI",
            "Quote and quote-report CLI bindings",
            "RA CA and app key generation CLI",
            "vTPM attest quote and verify CLI suite",
            "Versioned attestation create inspect JSON and strip CLI",
            "KMS GetKeys CLI transport and output safety",
            "Chrony synchronization and clock recovery",
            "OpenSSH account and password-auth hardening",
        )
    )
    ssh_guest_requested = (
        simulator_guest_requested
        or configuration_materialization
        or sysbox_requested
        or journal_lifecycle_requested
        or stargz_lifecycle_requested
        or dashboard_log_requested
        or host_shared_lifecycle_requested
        or wireguard_checker_requested
    )
    deploy_mode: list[str] = []
    identity_alternate_image = ""
    if (
        profile in {"no-tee-guest-lifecycle", "identity-matrix"}
        or key_derivation_requested
    ):
        image = os.environ.get("DSTACK_TEST_NO_TEE_GUEST_IMAGE", "dstack-dev-0.6.0")
        deploy_mode = ["--no-tee", "--simulated-tee", "dstack-tdx"]
    elif not endpoint_ready("127.0.0.1", 3443):
        fail("local key provider is unavailable on 127.0.0.1:3443")
    if identity_matrix_requested:
        identity_alternate_image = os.environ.get(
            "DSTACK_TEST_IDENTITY_ALT_IMAGE", ""
        ).strip()
        if not identity_alternate_image:
            fail("DSTACK_TEST_IDENTITY_ALT_IMAGE is required for identity-matrix")
        if identity_alternate_image == image:
            fail("identity-matrix alternate image must differ from the base image")
        try:
            alternate_provenance = require_image_backend(
                settings["image_store"], identity_alternate_image
            )
        except RuntimeError as error:
            fail(f"identity-matrix alternate image is unavailable: {error}")
        if (
            alternate_provenance.get("git_revision")
            != settings["image_provenance"].get("git_revision")
        ):
            fail(
                "identity-matrix images must have the same source revision: "
                f"base={settings['image_provenance'].get('git_revision')!r}, "
                f"alternate={alternate_provenance.get('git_revision')!r}"
            )
    lease_id = str(lease.get("lease_id", ""))
    if not lease_id.startswith("lease-") or not case_id:
        fail("lease identity is missing")
    state = PROVIDER_ROOT / lease_id
    state.mkdir(parents=True, exist_ok=False)
    bootstrap_process, bootstrap_url = start_bootstrap_server(state)
    port_base = find_port_block(5)
    ssh_port, tappd_port, guest_port, verifier_port, dashboard_port = range(
        port_base, port_base + 5
    )
    name = ("dtest-" + case_id.lower().replace("_", "-") + "-" + lease_id[-12:])[:63]
    compose_path = state / "app-compose.json"
    marker_name = "DSTACK_TEST_CONFIG_MARKER"
    marker_value = hashlib.sha256(lease_id.encode()).hexdigest()
    allowed_envs = [marker_name] if configuration_materialization else []
    compose_value = compose_manifest(
        name,
        bootstrap_url,
        allowed_envs,
        tpm_keys=(
            profile == "no-tee-guest-lifecycle"
            and not simulator_guest_requested
            and not configuration_materialization
        ),
        kms_enabled=(
            configuration_materialization
            or identity_matrix_requested
            or key_derivation_requested
        ),
        dependency_order=compose_validation_requested,
        boundary_role=(
            "normal" if docker_boundary_requested or guest_hardening_requested else None
        ),
        storage_fs="ext4" if data_disk_requested else "zfs",
    )
    if simulator_guest_requested:
        compose_value["key_provider"] = "none"
        compose_value["local_key_provider_enabled"] = False
    compose_path.write_text(
        json.dumps(compose_value, separators=(",", ":")), encoding="utf-8"
    )
    deploy_inputs: list[str] = []
    case_kms: dict[str, Any] | None = None
    simulator_seed = secrets.token_hex(32) if identity_matrix_requested else ""
    if (
        configuration_materialization
        or identity_matrix_requested
        or kms_cli_requested
        or key_derivation_requested
    ):
        if (
            configuration_materialization
            or kms_cli_requested
            or key_derivation_requested
        ):
            simulator_seed = secrets.token_hex(32)
        collateral_port, kms_port, onboard_port, admin_port = reserve_ports(4)
        fixture_path = state / "case-kms.json"
        helper = settings["repository"] / (
            "docs/test-plans/core-components-full/automation/start-mkosi-kms-fixture.py"
        )
        completed = run(
            [
                str(helper),
                "--runtime-manifest",
                str(settings["runtime_manifest"]),
                "--state",
                str(state / "case-kms"),
                "--seed",
                simulator_seed,
                "--collateral-port",
                str(collateral_port),
                "--kms-port",
                str(kms_port),
                "--onboard-port",
                str(onboard_port),
                "--admin-port",
                str(admin_port),
                "--output",
                str(fixture_path),
            ],
            timeout=180,
            check=False,
        )
        if completed.returncode:
            terminate_pids({bootstrap_process.pid})
            shutil.rmtree(state, ignore_errors=True)
            fail(f"case-scoped KMS failed to start: {completed.stderr[-1000:]}")
        case_kms = json.loads(fixture_path.read_text(encoding="utf-8"))
    deploy_inputs = ["--kms-url", str(case_kms["guest_url"])] if case_kms else []
    user_config_path = state / "user-config.json"
    env_path = state / "encrypted-env-input"
    if configuration_materialization:
        user_config_path.write_text(
            json.dumps({"dstack_test_marker": lease_id}, separators=(",", ":")),
            encoding="utf-8",
        )
        env_path.write_text(f"{marker_name}={marker_value}\n", encoding="utf-8")
        deploy_inputs = [
            "--user-config",
            str(user_config_path),
            "--env-file",
            str(env_path),
            *deploy_inputs,
        ]
        if case_kms:
            deploy_inputs.extend(["--kms-encrypt-url", str(case_kms["controller_url"])])
        else:
            deploy_inputs.extend(
                [
                    "--kms-url",
                    os.environ.get(
                        "DSTACK_TEST_KMS_URL",
                        "https://kms.tdxlab.dstack.org:13001",
                    ),
                ]
            )
    try:
        vmm = start_vmm(
            state,
            lease_id,
            settings,
            profile,
            simulator_seed=simulator_seed,
            simulator_collateral_url=(
                str(case_kms["guest_collateral_url"])
                if case_kms
                else "http://10.0.2.2:18088"
            ),
            simulator_tdx_root_ca=(
                Path(str(case_kms["tdx_root_ca"])).read_text(encoding="utf-8")
                if case_kms
                else ""
            ),
            extra_images=(
                [identity_alternate_image] if identity_matrix_requested else None
            ),
        )
    except BaseException:
        terminate_pids(
            {bootstrap_process.pid}
            | {int(pid) for pid in (case_kms or {}).get("pids", [])}
        )
        shutil.rmtree(state, ignore_errors=True)
        raise
    vmm["pids"].append(bootstrap_process.pid)
    if case_kms:
        vmm["pids"].extend(int(pid) for pid in case_kms["pids"])
        vmm["extra_paths"] = [case_kms["simulator_runtime"]]
    vmm_url = str(vmm["url"])
    cli = [sys.executable, str(settings["cli"]), "--url", vmm_url]
    vmm_handle = {
        "pids": list(vmm["pids"]),
        "run_path_link": vmm["run_path_link"],
        "supervisor_socket": vmm["supervisor_socket"],
        "vm_root": vmm["vm_root"],
    }

    def abort() -> None:
        """Release everything this lease created before re-raising."""
        release_vmm(vmm, state)
        shutil.rmtree(state, ignore_errors=True)

    vm_id: str | None = None
    try:
        deploy = run(
            [
                *cli,
                "deploy",
                "--name",
                name,
                "--image",
                image,
                "--compose",
                str(compose_path),
                "--vcpu",
                "2",
                "--memory",
                "4G",
                "--disk",
                "20G",
                "--net",
                "user",
                "--port",
                f"tcp:127.0.0.1:{ssh_port}:22",
                "--port",
                f"tcp:127.0.0.1:{tappd_port}:2000",
                "--port",
                f"tcp:127.0.0.1:{guest_port}:3000",
                "--port",
                f"tcp:127.0.0.1:{verifier_port}:8080",
                "--port",
                f"tcp:127.0.0.1:{dashboard_port}:8090",
                *deploy_inputs,
                *deploy_mode,
            ],
            timeout=120,
        )
        match = VM_ID_RE.search(deploy.stdout)
        if not match:
            fail(f"could not parse VM ID from deploy output: {deploy.stdout[-1000:]}")
        vm_id = match.group(1)
        (state / "vm-id").write_text(vm_id + "\n", encoding="utf-8")
        initial_host_events: list[dict[str, Any]] = []
        if host_notification_requested:
            initial_value = info(cli, vm_id)
            events_value = initial_value.get("events", [])
            if isinstance(events_value, list):
                initial_host_events = [
                    event for event in events_value if isinstance(event, dict)
                ]
        observe_boot = profile == "no-tee-guest-lifecycle"
        vmm_log_path = state / "logs/vmm.log"
        vm_root_path = Path(str(vmm["vm_root"])) if vmm.get("vm_root") else None
        ready = (
            wait_running(cli, vm_id, vmm_log=vmm_log_path, vm_root=vm_root_path)
            if observe_boot
            else wait_ready(cli, vm_id, vmm_log=vmm_log_path, vm_root=vm_root_path)
        )
        if not observe_boot:
            wait_tappd_ready(tappd_port)
        if observe_boot:
            ssh_argv = [
                "ssh",
                "-p",
                str(ssh_port),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=15",
                "root@127.0.0.1",
            ]
            if ssh_guest_requested:
                deadline = time.monotonic() + 240
                latest_ssh = None
                while time.monotonic() < deadline:
                    latest_ssh = run([*ssh_argv, "true"], timeout=30, check=False)
                    if latest_ssh.returncode == 0:
                        break
                    latest_info = info(cli, vm_id)
                    if latest_info.get("boot_error"):
                        fail(
                            "mkosi guest reported boot_error before SSH became ready: "
                            f"{latest_info['boot_error']}"
                        )
                    time.sleep(3)
                if latest_ssh is None or latest_ssh.returncode != 0:
                    detail = latest_ssh.stderr[-1000:] if latest_ssh else "no attempt"
                    fail(
                        "mkosi development guest did not expose its lease-owned "
                        f"SSH interface: {detail}"
                    )
            logs = run([*cli, "logs", "-n", "10000", vm_id], timeout=60)
            serial_log = state / "boot.log"
            serial_log.write_text(logs.stdout, encoding="utf-8")
            values = {
                "vm_id": vm_id,
                "image": image,
                "serial_log": str(serial_log),
                # The snapshot above can be empty because this profile returns
                # as soon as QEMU is running.  Cases must refresh it while they
                # observe the behavior under test rather than treating the
                # initial snapshot as the complete boot log.
                "serial_log_refresh_argv": [*cli, "logs", "-n", "10000", vm_id],
                "vmm_cli_argv": cli,
                "vm_info_argv": [*cli, "info", "--json", vm_id],
                "list_vms_argv": [*cli, "lsvm", "--json"],
                "boot_observation": {
                    "status": ready.get("status"),
                    "boot_progress": ready.get("boot_progress"),
                    "boot_error": ready.get("boot_error", ""),
                },
                "destructive_actions_allowed": True,
            }
            if ssh_guest_requested:
                values.update(
                    {
                        "ssh_target": f"root@127.0.0.1:{ssh_port}",
                        "ssh_argv": ssh_argv,
                    }
                )
            if configuration_materialization:
                values["configuration_materialization"] = {
                    "user_config_marker": lease_id,
                    "environment_marker_name": marker_name,
                    "environment_marker_sha256": hashlib.sha256(
                        marker_value.encode()
                    ).hexdigest(),
                    "expected_host_share_inputs": [
                        "app-compose.json",
                        ".sys-config.json",
                        ".user-config",
                        ".encrypted-env",
                    ],
                }
            if kms_cli_requested and case_kms:
                values["case_kms"] = {
                    "guest_url": case_kms["guest_url"],
                    "kms_rpc_cert": case_kms["kms_rpc_cert"],
                }
            return {
                "values": values,
                "cleanup_handle": {
                    "vm_id": vm_id,
                    "state": str(state),
                    "cli": cli,
                    **vmm_handle,
                },
            }
        instance_id = str(ready["instance_id"])
        ssh_argv = [
            "ssh",
            "-p",
            str(ssh_port),
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=15",
            "root@127.0.0.1",
        ]
        # Verify the exact access path before exposing the fixture to a case.
        run([*ssh_argv, "true"], timeout=30)
        if sysbox_requested or stargz_lifecycle_requested or dashboard_log_requested:
            # The SSH installer intentionally prunes bootstrap-only images after
            # pre-launch. Reload the pinned workload corpus once access is ready
            # so image-dependent cases never rely on registry availability.
            loaded = run(
                [
                    *ssh_argv,
                    "docker load --input /run/dstack-openssh-installer.tar",
                ],
                timeout=180,
                check=False,
            )
            if loaded.returncode:
                fail(
                    f"failed to load pinned Sysbox workload corpus: {loaded.stderr[-500:]}"
                )
        logs = run([*cli, "logs", "-n", "10000", vm_id], timeout=60)
        serial_log = state / "boot.log"
        serial_log.write_text(logs.stdout, encoding="utf-8")
    except BaseException as error:
        if case_kms and vm_root_path is not None and vm_root_path.is_dir():
            public_evidence = vm_root_path / "public-kms-evidence"
            public_evidence.mkdir(exist_ok=True)
            for field in ("tdx_root_ca", "kms_rpc_cert"):
                source = Path(str(case_kms.get(field, "")))
                if source.is_file():
                    shutil.copy2(source, public_evidence / source.name)
        evidence = (
            preserve_failure_evidence(vmm_log_path, vm_id, vm_root_path)
            if vm_id is not None
            else "<guest was not created>"
        )
        if vm_id is not None:
            run([*cli, "remove", vm_id], timeout=180, check=False)
        abort()
        fail(f"{error}\nfailed guest evidence preserved at: {evidence}")
    values = {
        "vm_id": vm_id,
        "instance_id": instance_id,
        "image": image,
        "ssh_target": f"root@127.0.0.1:{ssh_port}",
        "ssh_argv": ssh_argv,
        "serial_log": str(serial_log),
        "vmm_cli_argv": cli,
        "vm_info_argv": [*cli, "info", "--json", vm_id],
        "list_vms_argv": [*cli, "lsvm", "--json"],
        "destructive_actions_allowed": True,
        "hardware_guests": [
            {
                "role": profile,
                "vm_id": vm_id,
                "instance_id": instance_id,
                "image_version": ready.get("image_version", "0.6.0"),
                "ssh_target": f"root@127.0.0.1:{ssh_port}",
                "ssh_argv": ssh_argv,
                "serial_log": str(serial_log),
                "destructive_actions_allowed": True,
            }
        ],
        "services": {
            "LocalKeyProvider": {
                "host": "127.0.0.1",
                "port": 3443,
                "protocol": "u32be-length-prefixed-json",
            },
            "Tappd": {"url": f"http://127.0.0.1:{tappd_port}/prpc/{{method}}"},
            "DstackGuest": {"url": f"http://127.0.0.1:{guest_port}/{{method}}"},
            "Verifier": {"url": f"http://127.0.0.1:{verifier_port}/{{method}}"},
            "Dashboard": {"url": f"http://127.0.0.1:{dashboard_port}"},
            "ProxiedGuestApi": {
                "url": f"{vmm_url.rstrip('/')}/guest/{{method}}",
                "id": vm_id,
            },
        },
    }
    if kms_cli_requested and case_kms:
        values["case_kms"] = {
            "guest_url": case_kms["guest_url"],
            "kms_rpc_cert": case_kms["kms_rpc_cert"],
        }
    if sysbox_requested:
        values["sysbox_lifecycle"] = {
            "nested_workload_image": NESTED_WORKLOAD_IMAGE,
            "nested_workload_image_digest": NESTED_WORKLOAD_IMAGE_DIGEST,
            "nested_workload_image_id": NESTED_WORKLOAD_IMAGE_ID,
            "nested_payload_image": NESTED_PAYLOAD_IMAGE,
            "nested_payload_image_digest": NESTED_PAYLOAD_IMAGE_DIGEST,
            "nested_payload_image_id": NESTED_PAYLOAD_IMAGE_ID,
            "service_units": [
                "sysbox-mgr.service",
                "sysbox-fs.service",
                "sysbox.service",
            ],
            "runtime_name": "sysbox-runc",
            "destructive_actions_allowed": True,
        }
    if stargz_lifecycle_requested:
        values["stargz_lifecycle"] = {
            "payload_image": NESTED_PAYLOAD_IMAGE,
            "payload_image_digest": NESTED_PAYLOAD_IMAGE_DIGEST,
            "payload_image_id": NESTED_PAYLOAD_IMAGE_ID,
            "registry_image": "registry:2.8.3",
            "registry_image_digest": "sha256:a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373",
            "registry_image_id": "sha256:26b2eb03618e749084668eaff68cff8f81dda12d06ac641be7a6398b82a6f25b",
            "snapshotter_unit": "containerd-stargz-grpc.service",
            "snapshotter_name": "stargz",
            "destructive_actions_allowed": True,
        }
    if profile == "network-lifecycle":
        values["socket_activation_lifecycle"] = {
            "service_unit": "dstack-guest-agent.service",
            "socket_unit": "dstack-guest-agent.socket",
            "dstack_socket": "/run/dstack.sock",
            "tappd_socket": "/run/tappd.sock",
            "external_port": 8090,
            "guest_api_vsock_port": 8000,
            "destructive_actions_allowed": True,
        }
        values["watchdog_lifecycle"] = {
            "service_unit": "dstack-guest-agent.service",
            "health_url": "http://127.0.0.1:8090/prpc/Worker.Version",
            "freeze_signal": "STOP",
            "destructive_actions_allowed": True,
        }
    if configuration_materialization:
        values["configuration_materialization"] = {
            "user_config_marker": lease_id,
            "environment_marker_name": marker_name,
            "environment_marker_sha256": hashlib.sha256(
                marker_value.encode()
            ).hexdigest(),
            "expected_host_share_inputs": [
                "app-compose.json",
                ".sys-config.json",
                ".user-config",
                ".encrypted-env",
            ],
        }
    if host_notification_requested:
        values["host_notify_recorder"] = {
            "vm_id": vm_id,
            "info_argv": [*cli, "info", "--json", str(vm_id)],
            "initial_events": initial_host_events,
            "event_field": "events",
            "destructive_actions_allowed": True,
        }
    if profile == "storage-lifecycle":
        values["storage_lifecycle"] = {
            "vm_id": vm_id,
            "stop_argv": [*cli, "stop", str(vm_id)],
            "start_argv": [*cli, "start", str(vm_id)],
            "info_argv": [*cli, "info", "--json", str(vm_id)],
            "persistent_marker_dir": "/dstack/persistent",
            "encrypted_device": "/dev/vdb1",
            "destructive_actions_allowed": True,
        }
    if identity_matrix_requested:
        matrix_vm_ids = [str(vm_id)]
        alternate_image = identity_alternate_image
        changed_compose_path = state / "changed-app-compose.json"
        changed_compose = json.loads(json.dumps(compose_value))
        changed_compose["public_sysinfo"] = not bool(
            changed_compose.get("public_sysinfo")
        )
        changed_compose_path.write_text(
            json.dumps(changed_compose, separators=(",", ":")), encoding="utf-8"
        )

        rows: list[dict[str, Any]] = [
            {
                "role": "identical-a",
                "vmm_vm_id": vm_id,
                "instance_id": instance_id,
                "image": image,
                "compose_sha256": hashlib.sha256(compose_path.read_bytes()).hexdigest(),
            }
        ]

        def deploy_matrix_row(role: str, row_image: str, row_compose: Path) -> None:
            row_name = (name + "-" + role)[:63]
            deployed = run(
                [
                    *cli,
                    "deploy",
                    "--name",
                    row_name,
                    "--image",
                    row_image,
                    "--compose",
                    str(row_compose),
                    "--vcpu",
                    "2",
                    "--memory",
                    "4G",
                    "--disk",
                    "20G",
                    "--net",
                    "user",
                    *deploy_mode,
                    *deploy_inputs,
                ],
                timeout=120,
            )
            match = VM_ID_RE.search(deployed.stdout)
            if not match:
                fail(f"could not parse matrix VM ID: {deployed.stdout[-1000:]}")
            row_vm_id = match.group(1)
            matrix_vm_ids.append(row_vm_id)
            try:
                row_ready = wait_ready(
                    cli,
                    row_vm_id,
                    vmm_log=Path(str(vmm["log"])),
                    vm_root=Path(str(vmm["vm_root"])),
                )
            except BaseException as error:
                fail(f"identity matrix row {role} failed: {error}")
            rows.append(
                {
                    "role": role,
                    "vmm_vm_id": row_vm_id,
                    "instance_id": str(row_ready["instance_id"]),
                    "image": row_image,
                    "compose_sha256": hashlib.sha256(
                        row_compose.read_bytes()
                    ).hexdigest(),
                }
            )

        try:
            deploy_matrix_row("identical-b", image, compose_path)
            deploy_matrix_row("changed-compose", image, changed_compose_path)
            deploy_matrix_row("changed-image", alternate_image, compose_path)
            deploy_matrix_row("changed-instance", image, compose_path)
        except BaseException:
            for matrix_vm_id in reversed(matrix_vm_ids):
                run([*cli, "remove", matrix_vm_id], timeout=180, check=False)
            abort()
            raise
        values["identity_matrix"] = {
            "rows": rows,
            "expected_relations": {
                "same_app_id_roles": [
                    "identical-a",
                    "identical-b",
                    "changed-image",
                    "changed-instance",
                ],
                "different_app_id_role": "changed-compose",
                "distinct_instance_id_roles": [row["role"] for row in rows],
                "same_device_id_roles": [row["role"] for row in rows],
            },
        }
        values["component_endpoints"] = {
            "vmm_guest_api": f"{vmm_url.rstrip('/')}/guest"
        }
        # Replace the single-VM cleanup handle after all matrix rows are owned.
        return {
            "values": values,
            "cleanup_handle": {
                "vm_id": vm_id,
                "vm_ids": matrix_vm_ids,
                "state": str(state),
                "cli": cli,
                **vmm_handle,
            },
        }
    if (
        volume_persistence_requested
        or key_derivation_requested
        or local_provider_sealing_requested
        or docker_boundary_requested
        or guest_hardening_requested
        or config_entry_requested
        or guest_agent_startup_requested
        or systemd_graph_requested
    ):
        peer_ssh_port = find_port_block(3)
        peer_tappd_port = peer_ssh_port + 1
        peer_guest_port = peer_ssh_port + 2
        peer_compose_path = state / "peer-app-compose.json"
        peer_compose = compose_manifest(
            name + "-peer",
            bootstrap_url,
            allowed_envs,
            kms_enabled=key_derivation_requested,
            boundary_role="privileged" if docker_boundary_requested else None,
        )
        peer_compose["public_sysinfo"] = not bool(peer_compose.get("public_sysinfo"))
        peer_compose_path.write_text(
            json.dumps(peer_compose, separators=(",", ":")), encoding="utf-8"
        )
        peer_vm_id: str | None = None
        try:
            deployed = run(
                [
                    *cli,
                    "deploy",
                    "--name",
                    (name + "-peer")[:63],
                    "--image",
                    image,
                    "--compose",
                    str(peer_compose_path),
                    "--vcpu",
                    "2",
                    "--memory",
                    "4G",
                    "--disk",
                    "20G",
                    "--net",
                    "user",
                    "--port",
                    f"tcp:127.0.0.1:{peer_ssh_port}:22",
                    "--port",
                    f"tcp:127.0.0.1:{peer_tappd_port}:2000",
                    "--port",
                    f"tcp:127.0.0.1:{peer_guest_port}:3000",
                    *deploy_inputs,
                    *deploy_mode,
                ],
                timeout=120,
            )
            match = VM_ID_RE.search(deployed.stdout)
            if not match:
                fail(f"could not parse volume peer VM ID: {deployed.stdout[-1000:]}")
            peer_vm_id = match.group(1)
            peer_ready = wait_ready(cli, peer_vm_id)
            peer_instance_id = str(peer_ready["instance_id"])
            peer_ssh_argv = [
                "ssh",
                "-p",
                str(peer_ssh_port),
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=15",
                "root@127.0.0.1",
            ]
            run([*peer_ssh_argv, "true"], timeout=30)
        except BaseException:
            if peer_vm_id:
                run([*cli, "remove", peer_vm_id], timeout=180, check=False)
            run([*cli, "remove", str(vm_id)], timeout=180, check=False)
            abort()
            raise
        peer_values = {
            "vm_id": peer_vm_id,
            "instance_id": peer_instance_id,
            "ssh_argv": peer_ssh_argv,
            "tappd_url": f"http://127.0.0.1:{peer_tappd_port}/prpc/{{method}}",
            "dstack_guest_url": f"http://127.0.0.1:{peer_guest_port}/{{method}}",
            "app_relation": "different-compose-and-app-id",
            "destructive_actions_allowed": True,
        }
        if volume_persistence_requested:
            values["volume_isolation_peer"] = peer_values
        if key_derivation_requested:
            values["key_derivation_peer"] = peer_values
        if local_provider_sealing_requested:
            values["local_provider_peer"] = peer_values
        if config_entry_requested:
            values["config_entry_peer"] = peer_values
        if guest_agent_startup_requested:
            values["guest_agent_startup_peer"] = peer_values
        if systemd_graph_requested:
            values["systemd_graph_peer"] = peer_values
        if guest_hardening_requested:
            values["guest_hardening_lifecycle"] = {
                "declared_policy": {
                    "net.netfilter.nf_conntrack_max": 2097152,
                    "password_authentication": False,
                    "root_password_login": False,
                },
                "primary": {
                    "vm_id": vm_id,
                    "instance_id": instance_id,
                    "ssh_argv": ssh_argv,
                },
                "adjacent": peer_values,
                "measured_readonly_paths": [
                    "/etc/ssh/sshd_config.d/10-dstack.conf",
                    "/etc/sysctl.d/99-dstack.conf",
                ],
                "destructive_actions_allowed": True,
            }
        if docker_boundary_requested:
            values["docker_boundary"] = {
                "normal": {
                    "vm_id": vm_id,
                    "instance_id": instance_id,
                    "ssh_argv": ssh_argv,
                    "compose_sha256": hashlib.sha256(
                        compose_path.read_bytes()
                    ).hexdigest(),
                    "role": "normal",
                },
                "privileged": {
                    **peer_values,
                    "compose_sha256": hashlib.sha256(
                        peer_compose_path.read_bytes()
                    ).hexdigest(),
                    "role": "privileged",
                },
                "expected_app_identity_relation": "different",
                "physical_host_access_allowed": False,
                "cross_guest_access_allowed": False,
            }
        return {
            "values": values,
            "cleanup_handle": {
                "vm_id": vm_id,
                "vm_ids": [vm_id, peer_vm_id],
                "state": str(state),
                "cli": cli,
                **vmm_handle,
            },
        }
    return {
        "values": values,
        "cleanup_handle": {
            "vm_id": vm_id,
            "state": str(state),
            "cli": cli,
            **vmm_handle,
        },
    }


def verify(value: dict[str, Any]) -> dict[str, Any]:
    prepared = value.get("prepared", {})
    values = prepared.get("values", {})
    vm_id = str(values.get("vm_id", ""))
    if not vm_id:
        return {"ok": False, "error": "prepared fixture has no VM ID"}
    # The VMM is lease-owned, so only the prepared fixture knows its endpoint.
    cli_value = values.get("vmm_cli_argv")
    if not isinstance(cli_value, list) or not all(
        isinstance(item, str) for item in cli_value
    ):
        return {"ok": False, "error": "prepared fixture has no VMM CLI command"}
    cli = [str(item) for item in cli_value]
    current = info(cli, vm_id)
    observe_boot = prepared.get("profile") == "no-tee-guest-lifecycle"
    ok = current.get("status") == "running" and (
        observe_boot or current.get("boot_progress") == "done"
    )
    return {
        "ok": ok,
        "expected": {
            "status": "running",
            "boot_progress": "under-test" if observe_boot else "done",
        },
        "observed": {
            "status": current.get("status"),
            "boot_progress": current.get("boot_progress"),
            "boot_error": current.get("boot_error", ""),
        },
        "error": None if ok else "lease-owned guest is not ready",
    }


def destroy(value: dict[str, Any]) -> dict[str, Any]:
    errors = []
    for resource in value.get("resources", []):
        handle = resource.get("cleanup", {}).get("handle", {})
        vm_id = str(handle.get("vm_id", ""))
        vm_ids_value = handle.get("vm_ids")
        vm_ids = (
            [str(item) for item in vm_ids_value]
            if isinstance(vm_ids_value, list)
            else ([vm_id] if vm_id else [])
        )
        state_text = str(handle.get("state", ""))
        if not state_text:
            errors.append("cleanup handle has no lease workspace")
            continue
        state = Path(state_text).resolve()
        if state.parent != PROVIDER_ROOT or not state.name.startswith("lease-"):
            errors.append(f"refusing unsafe lease workspace cleanup: {state}")
            continue
        cli = handle.get("cli")
        if isinstance(cli, list) and cli and all(isinstance(item, str) for item in cli):
            # Remove the guests while the lease-owned VMM still answers RPC,
            # then wait for its background teardown so no QEMU is orphaned.
            for owned_vm_id in reversed(vm_ids):
                removed = run([*cli, "remove", owned_vm_id], timeout=180, check=False)
                if (
                    removed.returncode != 0
                    and "not found" not in removed.stderr.lower()
                ):
                    errors.append(removed.stderr[-1000:])
            wait_removed(cli, vm_ids)
        else:
            errors.append("cleanup handle has no valid VMM CLI command")
        release_vmm(handle, state)
        shutil.rmtree(state, ignore_errors=True)
    if errors:
        fail("; ".join(errors))
    return {"released": True}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"prepare", "verify", "destroy"}:
        fail("usage: tdxlab-isolated.py prepare|verify|destroy")
    value = request()
    result = {"prepare": prepare, "verify": verify, "destroy": destroy}[sys.argv[1]](
        value
    )
    json.dump(result, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
