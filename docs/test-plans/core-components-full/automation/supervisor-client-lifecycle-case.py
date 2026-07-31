#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise SupervisorClient full API, trusted UDS auto-start, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gos-setup-012"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write one JSON file atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def call(argv: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    """Run one bounded client invocation."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )


def parsed(process: subprocess.CompletedProcess[str]) -> Any:
    """Require successful JSON output."""
    if process.returncode:
        raise AssertionError(f"client failed with rc={process.returncode}")
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError("client emitted invalid JSON") from error


def wait_pid(path: pathlib.Path, timeout: float = 10) -> int:
    """Wait for an auto-started Supervisor PID file."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pid = int(path.read_text().strip())
        except (OSError, ValueError):
            time.sleep(0.05)
            continue
        if pathlib.Path(f"/proc/{pid}").exists():
            return pid
        time.sleep(0.05)
    raise AssertionError("auto-started Supervisor PID was not observed")


def wait_exit(pid: int, timeout: float = 10) -> None:
    """Wait for an owned PID to exit."""
    deadline = time.monotonic() + timeout
    while pathlib.Path(f"/proc/{pid}").exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if pathlib.Path(f"/proc/{pid}").exists():
        raise AssertionError("Supervisor did not exit after shutdown")


def main() -> int:
    """Run the complete Supervisor client matrix."""
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    substrate = manifest.get("values", {}).get("component_substrate")
    binaries = runtime.get("prepared_binaries", {})
    if not isinstance(substrate, dict) or not substrate.get("case_owned"):
        raise SystemExit("case-owned component substrate is required")
    client = pathlib.Path(str(binaries.get("supervisor_client", {}).get("path", "")))
    supervisor = pathlib.Path(
        str(binaries.get("dstack_supervisor", {}).get("path", ""))
    )
    if not client.is_file() or not supervisor.is_file():
        raise SystemExit("prepared Supervisor client/server binaries are required")
    state_root = pathlib.Path(
        str(runtime.get("environment", {}).get("DSTACK_TEST_STATE_ROOT", ""))
        or str(pathlib.Path.home() / ".cache/dstack-test/runtime-state")
    )
    lease_suffix = str(manifest["lease_id"])[-12:]
    run_dir = state_root / "su" / lease_suffix
    log_dir = pathlib.Path(str(substrate["log_dir"]))
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    run_dir.chmod(0o700)
    socket = run_dir / "s.sock"
    pid_file = run_dir / "supervisor.pid"
    log_file = log_dir / "supervisor-client-012.log"
    base = [str(client), "--base-url", f"unix:{socket}"]
    auto = [
        *base,
        "--auto-start",
        "--supervisor-path",
        str(supervisor),
        "--pid-file",
        str(pid_file),
        "--log-file",
        str(log_file),
        "--detached",
    ]
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    owned_pids: set[int] = set()
    status = "PASS"
    summary = "Supervisor client full API and trusted concurrent auto-start passed."
    try:
        unavailable = call([*base, "ping"])
        if unavailable.returncode == 0:
            raise AssertionError("dependency outage unexpectedly succeeded")
        starters = [
            subprocess.Popen(
                [*auto, "ping"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            for _ in range(8)
        ]
        starter_results = [
            process.communicate(timeout=20) + (process.returncode,)
            for process in starters
        ]
        observations["starter_results"] = [
            {"returncode": code, "stderr_tail": stderr[-800:]}
            for _, stderr, code in starter_results
        ]
        if any(code != 0 for _, _, code in starter_results):
            raise AssertionError("concurrent auto-start client failed")
        if any(json.loads(stdout) != "pong" for stdout, _, _ in starter_results):
            raise AssertionError("concurrent auto-start returned a non-pong response")
        pid = wait_pid(pid_file)
        owned_pids.add(pid)
        matching = []
        for proc in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
            try:
                argv = proc.read_bytes().split(b"\0")
            except OSError:
                continue
            if str(supervisor).encode() in argv and str(socket).encode() in argv:
                matching.append(int(proc.parent.name))
        if matching != [pid]:
            raise AssertionError("concurrent auto-start did not converge to one daemon")

        if parsed(call([*base, "ping"])) != "pong":
            raise AssertionError("ping response mismatch")
        deploy = parsed(
            call(
                [
                    *base,
                    "deploy",
                    "--id",
                    "child",
                    "--command",
                    "/bin/sh",
                    "--arg=-c",
                    "--arg=sleep 60",
                ]
            )
        )
        if deploy is not None:
            raise AssertionError("deploy response was not JSON null")
        listed = parsed(call([*base, "list"]))
        if not isinstance(listed, list) or len(listed) != 1:
            raise AssertionError("list did not contain the deployed child")
        info = parsed(call([*base, "info", "child"]))
        if not isinstance(info, dict):
            raise AssertionError("info response was not an object")
        if (
            call(
                [*base, "deploy", "--id", "child", "--command", "/bin/true"]
            ).returncode
            == 0
        ):
            raise AssertionError("duplicate deploy unexpectedly succeeded")
        parsed(call([*base, "stop", "child"]))
        parsed(call([*base, "start", "child"]))
        parsed(call([*base, "stop", "child"]))
        parsed(call([*base, "remove", "child"]))
        if parsed(call([*base, "info", "unknown-id"])) is not None:
            raise AssertionError("unknown process info was not JSON null")
        parsed(call([*base, "clear"]))
        parsed(call([*base, "shutdown"]))
        wait_exit(pid)
        owned_pids.discard(pid)

        socket.write_text("untrusted replacement")
        replacement_hash = hashlib.sha256(socket.read_bytes()).hexdigest()
        rejected = call([*auto, "ping"])
        if rejected.returncode == 0 or not socket.is_file():
            raise AssertionError("untrusted socket replacement was accepted or removed")
        if hashlib.sha256(socket.read_bytes()).hexdigest() != replacement_hash:
            raise AssertionError("untrusted socket replacement was modified")
        socket.unlink()
        if parsed(call([*auto, "ping"])) != "pong":
            raise AssertionError("auto-start recovery did not return pong")
        recovered_pid = wait_pid(pid_file)
        owned_pids.add(recovered_pid)
        parsed(call([*base, "shutdown"]))
        wait_exit(recovered_pid)
        owned_pids.discard(recovered_pid)
        observations.update(
            {
                "outage_failed_closed": True,
                "concurrent_clients": len(starters),
                "single_daemon_pid": True,
                "full_api": [
                    "deploy",
                    "list",
                    "info",
                    "stop",
                    "start",
                    "remove",
                    "clear",
                    "shutdown",
                ],
                "duplicate_rejected": True,
                "unknown_id_rejected": True,
                "replacement_rejected_and_preserved": True,
                "recovery_succeeded": True,
                "log_sha256": hashlib.sha256(log_file.read_bytes()).hexdigest()
                if log_file.is_file()
                else None,
            }
        )
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as error:
        status = "FAIL"
        summary = str(error)
    finally:
        for pid in owned_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        socket.unlink(missing_ok=True)
        socket.with_suffix(".lock").unlink(missing_ok=True)
        pid_file.unlink(missing_ok=True)
        try:
            run_dir.rmdir()
        except OSError:
            pass

    if log_file.is_file():
        observations["supervisor_log_tail"] = log_file.read_text(errors="replace")[
            -4000:
        ]

    artifact = {
        "path": "artifacts/supervisor-client-lifecycle.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Supervisor client lifecycle observations",
        "description": "Bounded auto-start, full API, concurrency, untrusted replacement, outage, recovery, and cleanup evidence.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
                for n in range(1, 4)
            ],
            "artifacts": [artifact],
            "remarks": "All sockets, processes, logs, and mutations are restricted to the case-owned raw substrate.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
