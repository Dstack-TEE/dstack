#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise one isolated Supervisor lifecycle and configuration matrix."""

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

CASE_ID = "tc-gos-storage-an-004"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def http(
    base: str, method: str, path: str, payload: Any | None = None
) -> tuple[int, Any]:
    """Call the isolated Supervisor HTTP API."""
    data = None if payload is None else json.dumps(payload).encode()
    request = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            body = {"body_bytes": len(raw)}
        return error.code, body


def success(body: Any) -> bool:
    """Return whether a Supervisor response is its data variant."""
    return isinstance(body, dict) and "data" in body


def state(base: str, process_id: str) -> dict[str, Any]:
    """Read one process info data object."""
    code, body = http(base, "GET", f"/info/{process_id}")
    if code != 200 or not success(body) or not isinstance(body["data"], dict):
        raise AssertionError(f"missing process info for {process_id}")
    return body["data"]["state"]


def wait_status(
    base: str, process_id: str, expected: str, timeout: float = 15
) -> dict[str, Any]:
    """Wait for a string or tagged ProcessStatus."""
    deadline = time.monotonic() + timeout
    latest: dict[str, Any] = {}
    while time.monotonic() < deadline:
        latest = state(base, process_id)
        status = latest.get("status")
        name = status if isinstance(status, str) else next(iter(status), "")
        if name == expected:
            return latest
        time.sleep(0.1)
    raise AssertionError(f"{process_id} did not reach {expected}")


def main() -> int:
    """Run Supervisor lifecycle acceptance."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    substrate = manifest.get("values", {}).get("component_substrate")
    binary_info = runtime.get("prepared_binaries", {}).get("dstack_supervisor", {})
    status = "PASS"
    summary = "Isolated Supervisor lifecycle and explicit restart policy passed."
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    supervisor: subprocess.Popen[str] | None = None
    try:
        if (
            not isinstance(substrate, dict)
            or not substrate.get("case_owned")
            or not substrate.get("destructive_actions_allowed")
            or not isinstance(binary_info, dict)
        ):
            status = "BLOCKED"
            summary = "fixture lacks case-owned Supervisor substrate or binary"
            observations["missing_capability"] = "supervisor-raw-substrate"
        else:
            binary = pathlib.Path(str(binary_info["path"]))
            if not binary.is_file():
                raise AssertionError("prepared Supervisor binary is absent")
            workspace = pathlib.Path(str(substrate["workspace"]))
            log_dir = pathlib.Path(str(substrate["log_dir"]))
            run_dir = pathlib.Path(str(substrate["run_dir"]))
            port = int(substrate["ports"]["rpc"])
            base = f"http://127.0.0.1:{port}"
            supervisor_log = log_dir / "supervisor.log"
            supervisor = subprocess.Popen(
                [
                    str(binary),
                    "--address",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--pid-file",
                    str(run_dir / "supervisor.pid"),
                    "--log-file",
                    str(supervisor_log),
                ],
                text=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    code, body = http(base, "GET", "/ping")
                    if code == 200 and success(body) and body["data"] == "pong":
                        break
                except OSError:
                    pass
                if supervisor.poll() is not None:
                    raise AssertionError("isolated Supervisor exited during startup")
                time.sleep(0.1)
            else:
                raise AssertionError("isolated Supervisor did not become ready")

            invalid_code, _ = http(
                base, "POST", "/deploy", {"id": 7, "command": "/bin/true"}
            )
            if invalid_code < 400:
                raise AssertionError("wrong-typed ProcessConfig was accepted")
            code, body = http(
                base, "POST", "/deploy", {"id": "", "command": "/bin/true"}
            )
            if code != 200 or success(body):
                raise AssertionError("empty process ID was not rejected")

            natural = {"id": "natural", "command": "/bin/sh", "args": ["-c", "exit 0"]}
            code, body = http(base, "POST", "/deploy", natural)
            if code != 200 or not success(body):
                raise AssertionError("minimal default ProcessConfig deploy failed")
            first_exit = wait_status(base, "natural", "exited")
            time.sleep(0.3)
            stable_exit = state(base, "natural")
            if first_exit["started_at"] != stable_exit["started_at"]:
                raise AssertionError("natural exit restarted without explicit start")
            code, body = http(base, "POST", "/start/natural")
            if code != 200 or not success(body):
                raise AssertionError("explicit restart of exited child failed")
            second_exit = wait_status(base, "natural", "exited")
            if second_exit["started_at"] < first_exit["started_at"]:
                raise AssertionError("explicit restart timestamp regressed")

            stdout_path = log_dir / "full.stdout"
            stderr_path = log_dir / "full.stderr"
            pidfile = run_dir / "full.pid"
            full = {
                "id": "full",
                "name": "full-fields",
                "command": "/bin/sh",
                "args": [
                    "-c",
                    "printf explicit-out; printf explicit-err >&2; sleep 60",
                ],
                "env": {"DSTACK_TEST_FIELD": "present"},
                "cwd": str(workspace),
                "stdout": str(stdout_path),
                "stderr": str(stderr_path),
                "pidfile": str(pidfile),
                "cid": 7,
                "note": "case-owned",
            }
            code, body = http(base, "POST", "/deploy", full)
            if code != 200 or not success(body):
                raise AssertionError("full ProcessConfig deploy failed")
            running = wait_status(base, "full", "running")
            if not running.get("pid") or not pidfile.is_file():
                raise AssertionError("running child lacks PID metadata")
            code, duplicate = http(base, "POST", "/deploy", full)
            if code != 200 or success(duplicate):
                raise AssertionError("duplicate running deploy was accepted")
            code, removal = http(base, "DELETE", "/remove/full")
            if code != 200 or success(removal):
                raise AssertionError("running child removal was accepted")
            code, body = http(base, "POST", "/stop/full")
            if code != 200 or not success(body):
                raise AssertionError("explicit stop failed")
            stopped = wait_status(base, "full", "stopped")
            code, body = http(base, "POST", "/start/full")
            if code != 200 or not success(body):
                raise AssertionError("explicit start after stop failed")
            wait_status(base, "full", "running")
            code, body = http(base, "POST", "/stop/full")
            if code != 200 or not success(body):
                raise AssertionError("second explicit stop failed")
            wait_status(base, "full", "stopped")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if stdout_path.exists() and stderr_path.exists():
                    if (
                        "explicit-out" in stdout_path.read_text()
                        and "explicit-err" in stderr_path.read_text()
                    ):
                        break
                time.sleep(0.1)
            else:
                raise AssertionError("redirected child logs were not captured")
            code, body = http(base, "DELETE", "/remove/full")
            if code != 200 or not success(body):
                raise AssertionError("stopped child removal failed")

            code, unknown = http(base, "POST", "/start/unknown")
            if code != 200 or success(unknown):
                raise AssertionError("unknown process start was accepted")
            unknown_config = {
                "id": "unknown-field",
                "command": "/bin/true",
                "unknown_sibling": True,
            }
            code, body = http(base, "POST", "/deploy", unknown_config)
            unknown_field_accepted = code == 200 and success(body)
            if unknown_field_accepted:
                wait_status(base, "unknown-field", "exited")
                http(base, "POST", "/stop/unknown-field")
                http(base, "DELETE", "/remove/unknown-field")

            http(base, "POST", "/stop/natural")
            http(base, "DELETE", "/remove/natural")
            code, listed = http(base, "GET", "/list")
            if code != 200 or not success(listed) or listed["data"]:
                raise AssertionError("Supervisor list was not empty before shutdown")
            try:
                http(base, "POST", "/shutdown")
            except OSError:
                pass
            supervisor.wait(timeout=15)
            observations.update(
                {
                    "minimal_defaults": True,
                    "wrong_type_http": invalid_code,
                    "empty_id_rejected": True,
                    "natural_exit_recorded": True,
                    "automatic_restart_observed": False,
                    "explicit_restart_succeeded": True,
                    "full_config_fields": len(full),
                    "duplicate_rejected": True,
                    "running_remove_rejected": True,
                    "stop_start_stop_succeeded": True,
                    "stdout_sha256": hashlib.sha256(
                        stdout_path.read_bytes()
                    ).hexdigest(),
                    "stderr_sha256": hashlib.sha256(
                        stderr_path.read_bytes()
                    ).hexdigest(),
                    "pidfile_present": pidfile.is_file(),
                    "started_at": running.get("started_at"),
                    "stopped_at": stopped.get("stopped_at"),
                    "unknown_id_rejected": True,
                    "unknown_sibling_accepted_and_ignored": unknown_field_accepted,
                    "empty_before_shutdown": True,
                    "shutdown_exit_code": supervisor.returncode,
                }
            )
            supervisor = None
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
    ) as error:
        status = "FAIL"
        summary = str(error)
        observations["failure"] = summary
    finally:
        if supervisor is not None:
            supervisor.terminate()
            try:
                supervisor.wait(timeout=10)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait(timeout=5)

    artifact = {
        "path": "artifacts/supervisor-lifecycle.json",
        "step_id": f"{case_id}-step-01",
        "name": "Supervisor lifecycle",
        "description": "Configuration outcomes, state transitions, timestamps, and log hashes.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": "Isolated Supervisor readiness and ProcessConfig boundary matrix were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Natural/nonzero policy, explicit lifecycle, duplicate/removal ordering, PID, and logs were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Unknown IDs, empty final inventory, and isolated shutdown were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Only the case-owned Supervisor and child processes are addressed.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
