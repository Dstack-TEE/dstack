#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for fixture providers that own a dstack-vmm instance.

Both `isolated-component.py` and `tdxlab-isolated.py` provision a lease-owned
VMM from the candidate tree. Keeping the config rewriting, port reservation,
process supervision, and teardown primitives here prevents the two providers
from drifting apart.
"""

from __future__ import annotations

import fcntl
import functools
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_PORT_MAPPING_RANGE = (
    '    { protocol = "tcp", from = 20000, to = 65535 },\n'
    '    { protocol = "udp", from = 20000, to = 65535 },'
)

STATE_ROOT = Path(
    os.environ.get("DSTACK_TEST_STATE_ROOT", "").strip()
    or str(Path.home() / ".cache/dstack-test/runtime-state")
)
PROVISIONING_LOCK = STATE_ROOT / "port-provisioning.lock"


def serialize_port_provisioning(function):
    """Serialize the release-to-listen window across fixture providers."""

    @functools.wraps(function)
    def locked(*args, **kwargs):
        with PROVISIONING_LOCK.open("a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                return function(*args, **kwargs)
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    return locked


def fail(message: str) -> None:
    """Abort the provider with a diagnostic on stderr."""
    print(message, file=sys.stderr)
    raise SystemExit(1)


def reserve_ports(count: int = 16) -> list[int]:
    """Reserve loopback ports by holding them open until every one is bound."""
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            sockets.append(listener)
        return [int(listener.getsockname()[1]) for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


def wait_port(
    port: int,
    process: subprocess.Popen[str],
    timeout: float = 45,
    diagnostic_log: Path | None = None,
) -> None:
    """Wait until a started component listens, failing fast when it exits."""

    def failure(message: str) -> None:
        if diagnostic_log is not None:
            try:
                tail = diagnostic_log.read_text(encoding="utf-8", errors="replace")[
                    -4000:
                ]
            except OSError as error:
                tail = f"<log unavailable: {error}>"
            message = f"{message}\n--- component log tail ---\n{tail}"
        fail(message)

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            failure(f"component exited before listening on {port}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.25)
    failure(f"component did not listen on 127.0.0.1:{port}")


def start_component(
    command: list[str],
    log: Path,
    listen_port: int,
    env: dict[str, str] | None = None,
    cwd: Path | None = None,
) -> subprocess.Popen[str]:
    """Start a lease-owned component and wait for its listener."""
    stream = log.open("w", encoding="utf-8")
    process = subprocess.Popen(
        command,
        stdout=stream,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
        env={**os.environ, **(env or {})},
        cwd=cwd,
        umask=0o077,
    )
    wait_port(listen_port, process, diagnostic_log=log)
    return process


def link_image_store(
    source: Path, destination: Path, names: list[str] | None = None
) -> None:
    """Mirror guest images as symlinks so a lease may add its own entries."""
    if names is None:
        entries = [entry for entry in source.iterdir() if entry.is_dir()]
    else:
        entries = [source / name for name in dict.fromkeys(names)]
    for entry in entries:
        if not entry.is_dir():
            continue
        link = destination / entry.name
        if link.exists() or link.is_symlink():
            continue
        link.symlink_to(entry, target_is_directory=True)


def terminate_pids(pids: set[int], grace: float = 5) -> None:
    """Stop lease-owned processes, escalating to SIGKILL after a grace period."""
    live = {pid for pid in pids if isinstance(pid, int) and pid > 1}
    for pid in live:
        _kill(pid, "-TERM")
    deadline = time.monotonic() + grace
    while live and time.monotonic() < deadline:
        live = {pid for pid in live if Path(f"/proc/{pid}").exists()}
        if live:
            time.sleep(0.1)
    for pid in live:
        _kill(pid, "-KILL")


def _kill(pid: int, signal: str) -> None:
    """Signal a lease process group when the recorded PID is its leader."""
    try:
        process_group = os.getpgid(pid)
    except ProcessLookupError:
        return
    target = f"-{pid}" if process_group == pid else str(pid)
    subprocess.run(
        ["kill", signal, "--", target],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def write_vmm_config(
    source: Path,
    destination: Path,
    workspace: Path,
    vm_run_path: Path,
    image_store: Path,
    supervisor: Path,
    rpc_port: int,
    host_api_port: int,
    cid_start: int,
    image_registry: str = "",
    auth_token: str = "",
    kms_url: str = "",
    disable_auto_restart: bool = False,
    simulator_seed: str = "",
    enable_key_provider: bool = False,
    enable_port_mapping: bool = False,
    volumes_dir: str = "",
    log_max_bytes: int = 0,
    port_mapping_range: str = "",
    simulator_collateral_url: str = "http://10.0.2.2:18088",
    pccs_url: str = "",
    supervisor_socket: Path | None = None,
    auto_restart_policy: dict[str, int] | None = None,
) -> None:
    """Derive a lease-owned VMM config from the candidate `vmm.toml`.

    `simulator_seed` must stay empty for fixtures that assert real hardware
    attestation: it emits `[cvm.tee_simulator]`, which lets a deployment ask
    for software-mocked quotes.
    """
    supervisor_run_dir = workspace / "run"
    supervisor_run_dir.chmod(0o700)
    supervisor_socket = supervisor_socket or supervisor_run_dir / "supervisor.sock"
    text = source.read_text(encoding="utf-8")
    replacements = {
        'temp_dir = "/tmp"': (
            f'temp_dir = "{workspace / "data"}"\nrun_path = "{vm_run_path}"'
        ),
        'address = "unix:./vmm.sock"': f'address = "127.0.0.1:{rpc_port}"',
        '# path = ""': f'path = "{image_store}"',
        'registry = ""': f'registry = "{image_registry}"',
        'exe = "./supervisor"': f'exe = "{supervisor}"',
        'sock = "./run/supervisor.sock"': f'sock = "{supervisor_socket}"',
        'pid_file = "./run/supervisor.pid"': f'pid_file = "{workspace / "run/supervisor.pid"}"',
        'log_file = "./run/supervisor.log"': f'log_file = "{workspace / "logs/supervisor.log"}"',
        "port = 10000": f"port = {host_api_port}",
        "cid_start = 1000": f"cid_start = {cid_start}",
        'kms_url = "http://127.0.0.1:8081"': f'kms_url = "{kms_url}"',
        'pccs_url = ""': f'pccs_url = "{pccs_url}"',
        'volumes_dir = ""': f'volumes_dir = "{volumes_dir}"',
    }
    for old, new in replacements.items():
        if old not in text:
            fail(f"candidate VMM config is missing expected field: {old}")
        text = text.replace(old, new, 1)
    key_provider = "[key_provider]\nenabled = true"
    if key_provider not in text:
        fail("candidate VMM config is missing key_provider.enabled")
    if not enable_key_provider:
        text = text.replace(key_provider, "[key_provider]\nenabled = false", 1)
    if auth_token:
        auth_config = "[auth]\nenabled = false\ntokens = []"
        if auth_config not in text:
            fail("candidate VMM config is missing the default auth block")
        text = text.replace(
            auth_config,
            f'[auth]\nenabled = true\ntokens = ["{auth_token}"]',
            1,
        )
    if disable_auto_restart:
        auto_restart = "[cvm.auto_restart]\nenabled = true"
        if auto_restart not in text:
            fail("candidate VMM config is missing cvm.auto_restart.enabled")
        text = text.replace(auto_restart, "[cvm.auto_restart]\nenabled = false", 1)
    if auto_restart_policy:
        for field in (
            "interval",
            "max_retries",
            "initial_backoff",
            "max_backoff",
            "reset_window",
        ):
            old = f"{field} = "
            lines = text.splitlines()
            matches = [i for i, line in enumerate(lines) if line.startswith(old)]
            if len(matches) != 1:
                fail(f"candidate VMM config has no unique auto-restart field: {field}")
            lines[matches[0]] = f"{field} = {int(auto_restart_policy[field])}"
            text = "\n".join(lines) + "\n"
    if enable_port_mapping:
        port_mapping = """[cvm.port_mapping]
enabled = false
address = "127.0.0.1"
range = [
    { protocol = "tcp", from = 1, to = 20000 },
]"""
        if port_mapping not in text:
            fail("candidate VMM config is missing the default port mapping block")
        allowed = port_mapping_range or DEFAULT_PORT_MAPPING_RANGE
        text = text.replace(
            port_mapping,
            '[cvm.port_mapping]\nenabled = true\naddress = "127.0.0.1"\n'
            f"range = [\n{allowed}\n]",
            1,
        )
    if simulator_seed:
        text += (
            "\n[cvm.tee_simulator]\n"
            f'mock_attestation_seed = "{simulator_seed}"\n'
            f'collateral_base_url = "{simulator_collateral_url}"\n'
        )
    if log_max_bytes:
        # cvm.log is a sub-table, so the value has to be rewritten in place.
        # Appending to the [cvm] scalar block instead would either land the key
        # outside the table or swallow every [cvm] key that follows it.
        marker = 'max_bytes = "4M"'
        if marker not in text:
            fail("candidate VMM config is missing cvm.log.max_bytes")
        text = text.replace(marker, f"max_bytes = {log_max_bytes}", 1)
    destination.write_text(text, encoding="utf-8")
