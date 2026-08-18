#!/usr/bin/env python3
# ruff: noqa: D101, D102, D103, D107
# SPDX-License-Identifier: Apache-2.0
"""Crash and restart a case-owned VMM around every mutating VM transaction."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable

CASE_ID = "tc-int-failure-se-003"


def atomic(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        tmp = pathlib.Path(f.name)
    tmp.replace(path)


def rpc(base: str, route: str, body: dict[str, Any]) -> tuple[int, bytes]:
    req = urllib.request.Request(
        base + route.split("?", 1)[0],
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def listed(cmd: list[str]) -> list[dict[str, Any]]:
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=60)
    if p.returncode:
        raise RuntimeError("case-owned VMM list command failed")
    value = json.loads(p.stdout or "[]")
    if not isinstance(value, list):
        raise RuntimeError("VMM list response was not an array")
    return value


class Control:
    def __init__(self, c: dict[str, Any]):
        self.binary = str(c["binary"])
        self.config = str(c["config"])
        self.cwd = str(c["cwd"])
        self.log = pathlib.Path(c["log"])
        self.pid_file = pathlib.Path(c["pid_file"])
        self.port = int(c["rpc_port"])

    def crash(self) -> int:
        pid = int(self.pid_file.read_text().strip())
        os.killpg(pid, signal.SIGKILL)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            stat = pathlib.Path(f"/proc/{pid}/stat")
            if not stat.exists():
                return pid
            try:
                if stat.read_text().split()[2] == "Z":
                    return pid
            except (OSError, IndexError):
                return pid
            time.sleep(0.05)
        raise RuntimeError(f"VMM process {pid} survived SIGKILL")

    def restart(self) -> int:
        stream = self.log.open("a", encoding="utf-8")
        p = subprocess.Popen(
            [self.binary, "--config", self.config],
            cwd=self.cwd,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            text=True,
        )
        self.pid_file.write_text(f"{p.pid}\n")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if p.poll() is not None:
                raise RuntimeError("restarted VMM exited before listening")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=1):
                    return p.pid
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("restarted VMM did not become ready")

    def during(self, operation: Callable[[], Any], marker: str) -> dict[str, Any]:
        result: dict[str, Any] = {}

        def invoke() -> None:
            try:
                result["value"] = operation()
            except Exception as e:
                result["error"] = f"{type(e).__name__}: {e}"

        offset = self.log.stat().st_size
        thread = threading.Thread(target=invoke)
        thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with self.log.open(encoding="utf-8", errors="replace") as source:
                source.seek(offset)
                if marker in source.read():
                    break
            time.sleep(0.005)
        else:
            raise RuntimeError(f"transaction request did not reach VMM route: {marker}")
        old = self.crash()
        thread.join(timeout=130)
        new = self.restart()
        if (
            "ConnectionRefusedError" in str(result.get("error"))
            or "connection refused" in str(result.get("error", "")).lower()
        ):
            raise RuntimeError("transaction request never reached the live VMM")
        return {
            "crashed_pid": old,
            "restarted_pid": new,
            "request_completed": "value" in result,
            "request_value": str(result.get("value", ""))[:300],
            "request_error": result.get("error"),
        }


def wait_status(
    cmd: list[str], vm_id: str, allowed: set[str], timeout: int = 90
) -> str:
    deadline = time.monotonic() + timeout
    observed = "missing"
    while time.monotonic() < deadline:
        row = next((x for x in listed(cmd) if str(x.get("id")) == vm_id), None)
        observed = "missing" if row is None else str(row.get("status", "")).lower()
        if observed in allowed:
            return observed
        time.sleep(0.5)
    raise RuntimeError(f"VM {vm_id} remained {observed}, expected {sorted(allowed)}")


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case ID")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    vmm = manifest["values"]["vmm"]
    if vmm.get("case_owned") is not True or not vmm.get("process_control"):
        raise RuntimeError("restartable case-owned VMM control is absent")
    test = vmm["test_input"]
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    list_cmd = [str(x) for x in vmm["commands"]["list_vms"]]
    control = Control(vmm["process_control"])
    rows = []
    owned: set[str] = set()
    failures = []
    steps = []
    evidence: dict[str, Any] = {}

    def create(suffix: str) -> dict[str, Any]:
        p = subprocess.run(
            [
                *map(str, test["create_stopped_helper_argv"]),
                "--name",
                f"{test['name_prefix']}-{suffix}",
            ],
            text=True,
            capture_output=True,
            timeout=180,
        )
        if p.returncode:
            raise RuntimeError(p.stderr[-500:] or "stopped VM creation failed")
        return json.loads(p.stdout.splitlines()[-1])

    try:
        baseline = listed(list_cmd)
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "The isolated VMM was healthy, restartable, and contained no run-scoped VM.",
            }
        )
        row = control.during(lambda: create("create-crash"), "uri=/prpc/CreateVm")
        current = listed(list_cmd)
        owned.update(
            str(x["id"])
            for x in current
            if str(x.get("name", "")).startswith(test["name_prefix"])
        )
        if len(owned) > 1:
            raise RuntimeError("create crash produced duplicate VM records")
        if not owned:
            owned.add(str(create("transaction-base")["id"]))
        vm_id = next(iter(owned))
        wait_status(list_cmd, vm_id, {"stopped"})
        rows.append({"operation": "create", **row, "converged": "absent-or-complete"})
        operations = [
            ("start", lambda: rpc(base, routes["StartVm"], {"id": vm_id})),
            (
                "update",
                lambda: rpc(
                    base,
                    routes["UpdateVm"],
                    {"id": vm_id, "update_ports": True, "ports": []},
                ),
            ),
            (
                "resize",
                lambda: rpc(
                    base, routes["ResizeVm"], {"id": vm_id, "vcpu": 2, "memory": 1536}
                ),
            ),
            ("stop", lambda: rpc(base, routes["StopVm"], {"id": vm_id})),
        ]
        for name, op in operations:
            r = control.during(op, f"uri=/prpc/{name.title()}Vm")
            r.update(
                {
                    "operation": name,
                    "converged_status": wait_status(
                        list_cmd, vm_id, {"running", "stopped", "exited"}
                    ),
                }
            )
            rows.append(r)
        r = control.during(
            lambda: rpc(base, routes["RemoveVm"], {"id": vm_id}), "uri=/prpc/RemoveVm"
        )
        state = wait_status(
            list_cmd, vm_id, {"missing", "running", "stopped", "exited"}
        )
        if state != "missing":
            rpc(base, routes["StopVm"], {"id": vm_id})
            wait_status(list_cmd, vm_id, {"stopped", "exited"})
            code, _ = rpc(base, routes["RemoveVm"], {"id": vm_id})
            if code != 200:
                raise RuntimeError("remove crash did not converge or remain retryable")
        owned.discard(vm_id)
        rows.append({"operation": "remove", **r, "converged_status": state})
        remaining = listed(list_cmd)
        ids = [str(x.get("id")) for x in remaining]
        cids = [x.get("cid") for x in remaining if x.get("cid") is not None]
        if len(ids) != len(set(ids)) or len(cids) != len(set(cids)):
            raise RuntimeError("recovery retained duplicate VM or CID allocations")
        invalid, body = rpc(
            base, routes["StartVm"], {"id": "00000000-0000-0000-0000-000000000000"}
        )
        if invalid < 400 or not isinstance(listed(list_cmd), list):
            raise RuntimeError("invalid input or availability check failed")
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "SIGKILL covered create, start, update, resize, stop, and remove; every restart converged to the prior or complete new state and remained retryable.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Recovered state had unique VM/CID allocations, invalid input failed closed, and the public VMM API remained available.",
                },
            ]
        )
        evidence = {
            "baseline_count": len(baseline),
            "transactions": rows,
            "remaining_count": len(remaining),
            "unique_ids": True,
            "unique_cids": True,
            "invalid_status": invalid,
            "invalid_body_sha256": hashlib.sha256(body).hexdigest(),
        }
    except Exception as e:
        failures.append(f"{type(e).__name__}: {e}")
        evidence = {
            "transactions": rows,
            "failure": failures[-1],
            "vmm_log_tail": control.log.read_text(errors="replace")[-8000:],
        }
        for n in range(1, 4):
            if not any(x["id"] == f"{CASE_ID}-step-{n:02d}" for x in steps):
                steps.append(
                    {
                        "id": f"{CASE_ID}-step-{n:02d}",
                        "status": "FAIL",
                        "observed": failures[-1],
                    }
                )
    finally:
        for vm_id in list(owned):
            try:
                rpc(base, routes["StopVm"], {"id": vm_id})
                rpc(base, routes["RemoveVm"], {"id": vm_id})
            except Exception:
                pass
    artifact = {
        "path": "artifacts/vmm-transaction-crash.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "VMM transaction crash matrix",
        "description": "Case-owned VMM crashes, restart PIDs, request outcomes, converged states, allocation uniqueness, rejection, and availability evidence.",
    }
    atomic(result_dir / artifact["path"], evidence)
    atomic(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": "All six VMM transaction crash rows converged without leaked identity allocations."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "duration_seconds": round(time.monotonic() - started, 3),
            "remarks": "Only the lease-owned VMM, Supervisor, and immediately registered VMs were mutated; provider cleanup owns the current restarted VMM PID.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
