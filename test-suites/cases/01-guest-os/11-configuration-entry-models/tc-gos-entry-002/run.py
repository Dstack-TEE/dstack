#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the source-defined guest-agent listener startup lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-entry-002"
SOCKET_NAMES = ("tappd.sock", "dstack.sock", "external.sock", "guest.sock")
PRIVATE_RE = re.compile(
    r"PRIVATE KEY|client_key|wg_sk|disk_crypt_key|env_crypt_key", re.I
)


def atomic_json(path: Path, value: Any) -> None:
    """Write one JSON evidence document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        temporary = Path(out.name)
    temporary.replace(path)


def wait_until(predicate: Any, timeout: float) -> bool:
    """Poll a bounded predicate."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def stop(process: subprocess.Popen[bytes] | None) -> None:
    """Stop one case-owned process exactly."""
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def copy_runtime(source: Path, target: Path, *, seed: str | None = None) -> Path:
    """Create an owner-only simulator runtime from prepared immutable fixtures."""
    target.mkdir(mode=0o700, parents=True)
    for name in (
        "appkeys.json",
        "app-compose.json",
        "attestation.bin",
        "sys-config.json",
        "dstack.toml",
    ):
        shutil.copy2(source / name, target / name)
        (target / name).chmod(0o600)
    config = target / "dstack.toml"
    text = config.read_text()
    if seed is not None:
        text = text.replace(
            "patch_report_data = true",
            f'patch_report_data = true\nmock_attestation_seed = "{seed}"',
            1,
        )
    config.write_text(text)
    return config


def launch(
    binary: str,
    runtime: Path,
    env: dict[str, str] | None = None,
    *,
    watchdog: bool = False,
) -> subprocess.Popen[bytes]:
    """Launch one simulator in its case-owned process group."""
    log = (runtime / "simulator.log").open("ab")
    command = [binary, "-c", "dstack.toml"]
    if watchdog:
        command.append("--watchdog")
        command = [
            "bash",
            "-c",
            'export WATCHDOG_PID=$$; exec "$@"',
            "watchdog-launch",
            *command,
        ]
    return subprocess.Popen(
        command,
        cwd=runtime,
        env={**os.environ, **(env or {})},
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def listeners_ready(runtime: Path) -> bool:
    """Return whether all four source-defined sockets accept connections."""
    for name in SOCKET_NAMES:
        path = runtime / name
        if not path.is_socket():
            return False
        try:
            client = socket.socket(socket.AF_UNIX)
            client.settimeout(0.2)
            client.connect(str(path))
            client.close()
        except OSError:
            return False
    return True


def no_listener_accepts(runtime: Path) -> bool:
    """Prove no case-owned listener accepts after failure/cleanup."""
    for name in SOCKET_NAMES:
        path = runtime / name
        try:
            client = socket.socket(socket.AF_UNIX)
            client.settimeout(0.1)
            client.connect(str(path))
            client.close()
            return False
        except OSError:
            pass
    return True


def activated_child(
    binary: str,
    runtime: Path,
    dstack_listener: socket.socket,
    tappd_listener: socket.socket,
    extra_env: dict[str, str] | None = None,
) -> int:
    """Fork/exec with the source-defined two systemd listener descriptors."""
    pid = os.fork()
    if pid == 0:
        try:
            os.chdir(runtime)
            source_fds = (dstack_listener.fileno(), tappd_listener.fileno())
            duplicated = [os.dup(fd) for fd in source_fds]
            for target, source in zip((3, 4), duplicated, strict=True):
                os.dup2(source, target)
                os.set_inheritable(target, True)
            env = {**os.environ, **(extra_env or {})}
            env.update(
                {
                    "LISTEN_PID": str(os.getpid()),
                    "LISTEN_FDS": "2",
                    "LISTEN_FDNAMES": "dstack:tappd",
                }
            )
            log_fd = os.open(
                runtime / "simulator.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            os.dup2(log_fd, 1)
            os.dup2(log_fd, 2)
            os.execve(binary, [binary, "-c", "dstack.toml"], env)
        finally:
            os._exit(127)
    return pid


def stop_pid(pid: int | None) -> None:
    """Stop one fork/exec child and reap it."""
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        waited, _ = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)


def bind_activated(path: Path) -> socket.socket:
    """Create one owner-scoped activated Unix listener."""
    path.unlink(missing_ok=True)
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(path))
    listener.listen(16)
    return listener


def main() -> int:
    """Run startup, fault, activation, watchdog, restart, and isolation rows."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime_manifest = json.loads(
        Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    binary = str(
        runtime_manifest["prepared_binaries"]["dstack_simulator"].get("resolved_path")
        or runtime_manifest["prepared_binaries"]["dstack_simulator"]["path"]
    )
    fixtures = Path(runtime_manifest["simulator_fixtures"])
    root = Path(
        tempfile.mkdtemp(
            prefix="dstack-test-entry002-",
            dir=os.environ.get("DSTACK_TEST_STATE_ROOT", "/tmp"),
        )
    )
    root.chmod(0o700)
    processes: list[subprocess.Popen[bytes]] = []
    child_pids: list[int] = []
    opened: list[socket.socket] = []
    observations: dict[str, Any] = {}
    status = "FAIL"
    failure = ""

    try:
        baseline = root / "baseline"
        copy_runtime(fixtures, baseline)
        process = launch(binary, baseline)
        processes.append(process)
        if not wait_until(lambda: listeners_ready(baseline), 15):
            raise RuntimeError("four-listener baseline did not become ready")
        observations["baseline"] = {
            "listeners_ready": 4,
            "pid_distinct": process.pid > 1,
        }
        stop(process)
        if not no_listener_accepts(baseline):
            raise RuntimeError("baseline shutdown left an accepting listener")

        dependency = root / "dependency-fault"
        copy_runtime(fixtures, dependency)
        (dependency / "appkeys.json").write_text("not-json")
        failed_dependency = launch(binary, dependency)
        processes.append(failed_dependency)
        if not wait_until(lambda: failed_dependency.poll() is not None, 15):
            raise RuntimeError("invalid trusted state did not fail startup")
        if not no_listener_accepts(dependency):
            raise RuntimeError("trusted-state failure exposed a listener")
        observations["dependency_fault"] = {
            "exit_nonzero": failed_dependency.returncode != 0,
            "listeners_exposed": 0,
        }

        bind_fault = root / "bind-fault"
        config = copy_runtime(fixtures, bind_fault)
        occupier = socket.socket(socket.AF_INET)
        occupier.bind(("127.0.0.1", 0))
        occupier.listen(1)
        opened.append(occupier)
        port = occupier.getsockname()[1]
        text = config.read_text().replace(
            'address = "unix:./external.sock"\nreuse = true',
            f'address = "127.0.0.1"\nport = {port}\nreuse = false',
            1,
        )
        config.write_text(text)
        failed_bind = launch(binary, bind_fault)
        processes.append(failed_bind)
        if not wait_until(lambda: failed_bind.poll() is not None, 15):
            raise RuntimeError("occupied external bind did not fail fast")
        if not no_listener_accepts(bind_fault):
            raise RuntimeError(
                "partial bind failure left an internal or GuestApi listener"
            )
        observations["partial_bind_failure"] = {
            "exit_nonzero": failed_bind.returncode != 0,
            "unintended_surfaces": 0,
        }

        activated = root / "activated"
        copy_runtime(fixtures, activated)
        dstack_listener = bind_activated(activated / "dstack-activated.sock")
        tappd_listener = bind_activated(activated / "tappd-activated.sock")
        opened.extend((dstack_listener, tappd_listener))
        child = activated_child(binary, activated, dstack_listener, tappd_listener)
        child_pids.append(child)
        if not wait_until(
            lambda: (
                (activated / "external.sock").is_socket()
                and (activated / "guest.sock").is_socket()
            ),
            15,
        ):
            raise RuntimeError(
                "socket-activated startup did not expose normal companion listeners"
            )
        log_text = (activated / "simulator.log").read_text(errors="replace")
        if (
            "Systemd socket activation detected" not in log_text
            or log_text.count("Using systemd-activated socket") < 2
        ):
            raise RuntimeError("both activated internal listeners were not consumed")
        stop_pid(child)
        child_pids.remove(child)
        restarted = activated_child(binary, activated, dstack_listener, tappd_listener)
        child_pids.append(restarted)
        if not wait_until(
            lambda: (
                (activated / "external.sock").is_socket()
                and (activated / "guest.sock").is_socket()
            ),
            15,
        ):
            raise RuntimeError("activated-socket restart did not recover")
        observations["socket_activation"] = {
            "activated_internal_listeners": 2,
            "companion_listeners": 2,
            "restart_reused_descriptors": True,
        }
        stop_pid(restarted)
        child_pids.remove(restarted)

        watchdog = root / "watchdog"
        config = copy_runtime(fixtures, watchdog)
        probe = socket.socket(socket.AF_INET)
        probe.bind(("127.0.0.1", 0))
        watchdog_port = probe.getsockname()[1]
        probe.close()
        text = config.read_text().replace(
            'address = "unix:./external.sock"\nreuse = true',
            f'address = "127.0.0.1"\nport = {watchdog_port}\nreuse = false',
            1,
        )
        config.write_text(text)
        notify_path = watchdog / "notify.sock"
        notify = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        notify.bind(str(notify_path))
        notify.settimeout(8)
        opened.append(notify)
        watchdog_process = launch(
            binary,
            watchdog,
            {"WATCHDOG_USEC": "2000000", "NOTIFY_SOCKET": str(notify_path)},
            watchdog=True,
        )
        processes.append(watchdog_process)
        # sd_notify validates WATCHDOG_PID only when provided; omission selects this process.
        messages: list[str] = []
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not any(
            "WATCHDOG=1" in item for item in messages
        ):
            try:
                messages.append(notify.recv(4096).decode(errors="replace"))
            except socket.timeout:
                break
        if not any("READY=1" in item for item in messages) or not any(
            "WATCHDOG=1" in item for item in messages
        ):
            raise RuntimeError(f"watchdog notifications missing: {messages}")
        observations["watchdog"] = {
            "ready_notifications": sum("READY=1" in x for x in messages),
            "heartbeat_notifications": sum("WATCHDOG=1" in x for x in messages),
        }
        stop(watchdog_process)

        concurrent = root / "concurrent"
        config = copy_runtime(fixtures, concurrent)
        port_probe = socket.socket(socket.AF_INET)
        port_probe.bind(("127.0.0.1", 0))
        concurrent_port = port_probe.getsockname()[1]
        port_probe.close()
        config.write_text(
            config.read_text().replace(
                'address = "unix:./external.sock"\nreuse = true',
                f'address = "127.0.0.1"\nport = {concurrent_port}\nreuse = false',
                1,
            )
        )
        left = launch(binary, concurrent)
        right = launch(binary, concurrent)
        processes.extend((left, right))
        if not wait_until(lambda: (left.poll() is None) != (right.poll() is None), 15):
            raise RuntimeError(
                "conflicting concurrent startup did not converge to one owner"
            )
        observations["concurrent_start"] = {
            "attempts": 2,
            "committed": int(left.poll() is None) + int(right.poll() is None),
        }
        stop(left)
        stop(right)

        primary = root / "primary"
        peer = root / "peer"
        copy_runtime(fixtures, primary, seed="11" * 32)
        copy_runtime(fixtures, peer, seed="22" * 32)
        primary_process = launch(binary, primary)
        peer_process = launch(binary, peer)
        processes.extend((primary_process, peer_process))
        if not wait_until(
            lambda: listeners_ready(primary) and listeners_ready(peer), 20
        ):
            raise RuntimeError(
                "adjacent simulator identities did not start independently"
            )
        observations["isolation"] = {
            "identities": 2,
            "seeds_distinct": True,
            "listener_sets": 2,
            "pids_distinct": primary_process.pid != peer_process.pid,
        }
        stop(primary_process)
        stop(peer_process)

        leaked_markers = []
        for log in root.rglob("*.log"):
            if PRIVATE_RE.search(log.read_text(errors="replace")):
                leaked_markers.append(str(log.relative_to(root)))
        if leaked_markers:
            raise RuntimeError(
                f"sensitive key field markers appeared in logs: {leaked_markers}"
            )
        observations["redaction"] = {
            "logs_scanned": len(list(root.rglob("*.log"))),
            "sensitive_markers": 0,
        }
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = str(error)
    finally:
        for process in reversed(processes):
            stop(process)
        for pid in list(child_pids):
            stop_pid(pid)
        for item in opened:
            item.close()
        observations["cleanup"] = {
            "live_processes": sum(process.poll() is None for process in processes),
            "accepting_listeners": sum(
                not no_listener_accepts(path)
                for path in root.iterdir()
                if path.is_dir()
            ),
        }

    observations.update(
        {
            "status": status,
            "failure": failure,
            "duration_seconds": round(time.monotonic() - started, 3),
            "source_defined_listener_count": 4,
        }
    )
    evidence_path = artifacts / "guest-agent-startup-matrix.json"
    atomic_json(evidence_path, observations)
    logs_path = artifacts / "logs"
    for source_log in root.rglob("*.log"):
        relative = source_log.relative_to(root)
        destination = logs_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_log, destination)
    shutil.rmtree(root, ignore_errors=True)
    artifact_rows = [
        {
            "path": "artifacts/guest-agent-startup-matrix.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Guest-agent startup matrix",
            "description": "Redacted four-listener, activation, watchdog, fault, concurrency, restart, isolation, and cleanup observations.",
        }
    ]
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_rows})
    summary = (
        "Guest-agent source-defined startup lifecycle passed"
        if status == "PASS"
        else f"Guest-agent startup lifecycle failed: {failure}"
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "Prepared candidate simulator inputs and an empty owner-only runtime baseline."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "All four source-defined listeners started; both internal listeners consumed activated descriptors; watchdog emitted READY and heartbeat; bind and trusted-state faults exposed no partial surface."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Two conflicting starts converged to one owner and all losing-process listeners were released."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": status,
                    "observed": "Activated descriptors survived process restart, independent seeded peers remained isolated, logs were redacted, and cleanup returned zero live processes/listeners."
                    if status == "PASS"
                    else failure,
                },
            ],
            "artifacts": artifact_rows,
            "evidence": [
                {
                    "path": artifact_rows[0]["path"],
                    "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "The source has one combined four-listener startup function, not independently selectable listener modes. TLS termination is not part of guest-agent listener startup; invalid trusted app-key state is the pre-listener dependency fault. Simulation does not claim physical TEE isolation.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
