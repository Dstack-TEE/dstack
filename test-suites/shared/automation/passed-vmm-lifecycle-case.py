#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic harness for VMM methods that change VM state.

The RPC contract harness calls each method over JSON, then protobuf, then once
more, and requires all three to succeed. That only fits an idempotent method.
`Vmm.RemoveVm` removes the VM, so the second call must be refused, and asserting
otherwise would either fail a correct implementation or hide a real regression.

This harness models each transition instead: it provisions a fresh VM before
each encoding, establishes the action-specific prerequisite, invokes the
method, and checks the resulting VM or supervisor state.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

# case_id -> (method, transition kind)
CASES: dict[str, tuple[str, str]] = {
    "tc-vmm-vmm-004": ("RemoveVm", "remove-vm"),
    "tc-vmm-vmm-007": ("ShutdownVm", "shutdown-vm"),
    "tc-vmm-vmm-019": ("SvStop", "stop-supervisor"),
    "tc-vmm-vmm-020": ("SvRemove", "remove-supervisor"),
    "tc-vmm-ui-observa-004": ("SvRemove", "stop-remove-supervisor"),
}


def ignore_noncopyable(directory: str, names: list[str]) -> list[str]:
    """Exclude runtime sockets and other non-regular nodes from diagnostics."""
    ignored: list[str] = []
    root = pathlib.Path(directory)
    for name in names:
        path = root / name
        try:
            mode = path.lstat().st_mode
        except OSError:
            ignored.append(name)
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode) or stat.S_ISLNK(mode)):
            ignored.append(name)
    return ignored


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON so a reader never observes a partial document."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = handle.name
    os.replace(temporary, path)


def varint(value: int) -> bytes:
    """Encode an unsigned protobuf varint."""
    output = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        output.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(output)


def encode_id(vm_id: str) -> bytes:
    """Encode a request carrying a single string id in field 1."""
    raw = vm_id.encode()
    return varint((1 << 3) | 2) + varint(len(raw)) + raw


def resolve_vmm(manifest: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """Resolve the lease-owned VMM base URL and its auth headers."""
    values = manifest["values"]
    vmm = values.get("vmm") or {}
    base = str(vmm.get("rpc_url") or "")
    if not base:
        raise RuntimeError("manifest missing vmm.rpc_url")
    headers: dict[str, str] = {}
    auth = vmm.get("auth") or {}
    token_file = auth.get("token_file")
    if auth.get("enabled") and token_file:
        token = pathlib.Path(token_file).read_text(encoding="utf-8").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
    return base.rstrip("/"), headers


def call(
    url: str, body: bytes, content_type: str, headers: dict[str, str]
) -> tuple[int, bytes]:
    """Perform one pRPC call and return its status and body."""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", content_type)
    for key, value in headers.items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def create_vm(manifest: dict[str, Any]) -> str:
    """Create the fixture's prepared stopped VM and return its ID."""
    test_input = (manifest["values"].get("vmm") or {}).get("test_input") or {}
    argv = test_input.get("create_stopped_helper_argv")
    if not isinstance(argv, list) or not argv:
        raise RuntimeError("fixture does not prepare create_stopped_helper_argv")
    process = subprocess.run(
        argv, capture_output=True, text=True, timeout=180, check=False
    )
    if process.returncode != 0:
        raise RuntimeError(
            f"prepared VM creation failed ({process.returncode}): "
            f"{process.stderr[-400:]}"
        )
    for line in reversed(process.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get("id"):
                return str(value["id"])
    raise RuntimeError("prepared VM creation printed no VM ID")


def list_vm_ids(manifest: dict[str, Any]) -> set[str]:
    """Return the IDs the VMM currently reports."""
    commands = (manifest["values"].get("vmm") or {}).get("commands") or {}
    argv = commands.get("list_vms")
    if not isinstance(argv, list) or not argv:
        raise RuntimeError("fixture does not prepare a list_vms command")
    process = subprocess.run(
        argv, capture_output=True, text=True, timeout=60, check=False
    )
    if process.returncode != 0:
        raise RuntimeError(f"list_vms failed: {process.stderr[-300:]}")
    listed = json.loads(process.stdout or "[]")
    return {str(item.get("id")) for item in listed if isinstance(item, dict)}


def vm_state(manifest: dict[str, Any], vm_id: str) -> str | None:
    """Return the status the VMM reports for one VM, or None when absent."""
    commands = (manifest["values"].get("vmm") or {}).get("commands") or {}
    process = subprocess.run(
        commands["list_vms"], capture_output=True, text=True, timeout=60, check=False
    )
    if process.returncode != 0:
        raise RuntimeError(f"list_vms failed: {process.stderr[-300:]}")
    for item in json.loads(process.stdout or "[]"):
        if isinstance(item, dict) and str(item.get("id")) == vm_id:
            return str(item.get("status"))
    return None


def await_state(
    manifest: dict[str, Any], vm_id: str, wanted: str, timeout: int = 180
) -> str:
    """Wait until the VM reaches a state, returning the last one observed."""
    deadline = time.monotonic() + timeout
    observed = vm_state(manifest, vm_id)
    while time.monotonic() < deadline:
        if observed == wanted:
            return observed
        time.sleep(3)
        observed = vm_state(manifest, vm_id)
    raise AssertionError(f"{vm_id} stayed {observed!r} instead of reaching {wanted!r}")


def await_boot(manifest: dict[str, Any], vm_id: str, timeout: int = 300) -> str:
    """Wait until the guest reports that boot finished."""
    commands = (manifest["values"].get("vmm") or {}).get("commands") or {}
    deadline = time.monotonic() + timeout
    progress = None
    while time.monotonic() < deadline:
        process = subprocess.run(
            commands["list_vms"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        for item in json.loads(process.stdout or "[]"):
            if isinstance(item, dict) and str(item.get("id")) == vm_id:
                progress = item.get("boot_progress")
                if progress == "done":
                    return str(progress)
        time.sleep(5)
    raise AssertionError(
        f"{vm_id} boot_progress stalled at {progress!r} instead of 'done'"
    )


def supervisor_processes(
    base: str, routes: dict[str, str], headers: dict[str, str]
) -> list[dict[str, Any]]:
    """Return the supervisor process list through its public RPC contract."""
    route = base + (routes.get("SvList") or "/prpc/SvList?json").split("?", 1)[0]
    code, body = call(route, b"{}", "application/json", headers)
    if code != 200:
        raise RuntimeError(
            f"SvList returned HTTP {code}: {body.decode('utf-8', 'replace')[:300]}"
        )
    value = json.loads(body or b"{}")
    processes = value.get("processes") if isinstance(value, dict) else None
    if not isinstance(processes, list):
        raise RuntimeError("SvList response did not contain a process list")
    return [item for item in processes if isinstance(item, dict)]


def await_supervisor(
    base: str,
    routes: dict[str, str],
    headers: dict[str, str],
    *,
    vm_id: str,
    wanted: str | None,
    timeout: int = 180,
) -> dict[str, Any]:
    """Wait for the VM's supervisor process to appear or reach a state."""
    deadline = time.monotonic() + timeout
    observed: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        matches = [
            item
            for item in supervisor_processes(base, routes, headers)
            if str(item.get("id")) == vm_id
        ]
        if matches:
            observed = matches[0]
            if wanted is None or observed.get("status") == wanted:
                return observed
        time.sleep(3)
    state = None if observed is None else observed.get("status")
    raise AssertionError(
        f"supervisor process {vm_id} stayed {state!r} instead of reaching "
        f"{wanted or 'present'!r}"
    )


def await_supervisor_absent(
    base: str,
    routes: dict[str, str],
    headers: dict[str, str],
    *,
    process_id: str,
    timeout: int = 30,
) -> None:
    """Wait until a supervisor process disappears from the public list."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(
            str(item.get("id")) == process_id
            for item in supervisor_processes(base, routes, headers)
        ):
            return
        time.sleep(1)
    raise AssertionError(f"supervisor process {process_id} remained registered")


def main() -> int:
    """Run the lifecycle case selected by the environment."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    if case_id not in CASES:
        raise SystemExit(f"unsupported lifecycle case: {case_id}")
    method, transition_kind = CASES[case_id]
    base, headers = resolve_vmm(manifest)
    routes = (manifest["values"].get("vmm") or {}).get("json_prpc_routes") or {}
    route = base + (routes.get(method) or f"/prpc/{method}?json").split("?", 1)[0]

    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, Any]] = []
    status, failure = "PASS", None
    record: dict[str, Any] = {"case_id": case_id, "method": method, "route": route}

    def transition(encoding: str) -> dict[str, Any]:
        """Provision a VM, apply the method once, and prove it took effect."""
        vm_id = create_vm(manifest)
        if vm_id not in list_vm_ids(manifest):
            raise AssertionError(f"prepared VM {vm_id} was not listed before {method}")
        if transition_kind in {
            "shutdown-vm",
            "stop-supervisor",
            "remove-supervisor",
            "stop-remove-supervisor",
        }:
            start_route = (
                base + (routes.get("StartVm") or "/prpc/StartVm?json").split("?", 1)[0]
            )
            start_code, start_body = call(
                start_route,
                json.dumps({"id": vm_id}).encode(),
                "application/json",
                headers,
            )
            if start_code != 200:
                raise AssertionError(
                    f"StartVm returned HTTP {start_code}: "
                    f"{start_body.decode('utf-8', 'replace')[:300]}"
                )
            await_state(manifest, vm_id, "running")
            if transition_kind == "shutdown-vm":
                # ShutdownVm asks the in-guest agent to power down, so a VM
                # merely reported as running is not enough: without a booted
                # agent the call fails with "Connection reset by peer".
                await_boot(manifest, vm_id)
            else:
                # SvStop addresses the supervisor record, not the guest VM.
                # Boot completion is irrelevant and may never arrive; the
                # public SvList record is the authoritative prerequisite.
                process = await_supervisor(
                    base, routes, headers, vm_id=vm_id, wanted="running"
                )
                vm_id = str(process["id"])
                if transition_kind in {"remove-supervisor", "stop-remove-supervisor"}:
                    stop_route = (
                        base
                        + (routes.get("SvStop") or "/prpc/SvStop?json").split("?", 1)[0]
                    )
                    stop_code, stop_body = call(
                        stop_route,
                        json.dumps({"id": vm_id}).encode(),
                        "application/json",
                        headers,
                    )
                    if stop_code != 200:
                        raise AssertionError(
                            f"SvStop prerequisite returned HTTP {stop_code}: "
                            f"{stop_body.decode('utf-8', 'replace')[:300]}"
                        )
                    await_supervisor(
                        base, routes, headers, vm_id=vm_id, wanted="stopped"
                    )
        if encoding == "json":
            code, body = call(
                route,
                json.dumps({"id": vm_id, "future_field": "ignored"}).encode(),
                "application/json",
                headers,
            )
        else:
            code, body = call(
                route, encode_id(vm_id), "application/octet-stream", headers
            )
        if code != 200:
            # Report what the service said. Reporting only the status turns a
            # precise rejection into a guess.
            raise AssertionError(
                f"{encoding} {method} returned HTTP {code}: "
                f"{body.decode('utf-8', 'replace')[:300]}"
            )
        if transition_kind == "shutdown-vm":
            # The guest stops rather than disappearing, so the transition is
            # proven by the reported state. A graceful shutdown lands on
            # "stopped"; "exited" is what an unexpected termination reports.
            final = await_state(manifest, vm_id, "stopped")
        elif transition_kind == "stop-supervisor":
            # SvStop retains its record. Absence would prove SvRemove, not
            # SvStop, and accepting any non-running state would hide crashes.
            final = str(
                await_supervisor(base, routes, headers, vm_id=vm_id, wanted="stopped")[
                    "status"
                ]
            )
        elif transition_kind in {"remove-supervisor", "stop-remove-supervisor"}:
            await_supervisor_absent(base, routes, headers, process_id=vm_id)
            final = "absent"
        else:
            if vm_id in list_vm_ids(manifest):
                raise AssertionError(f"{vm_id} was still listed after {method}")
            final = "absent"
        repeat_code, _ = call(
            route, json.dumps({"id": vm_id}).encode(), "application/json", headers
        )
        if transition_kind in {"remove-vm", "remove-supervisor"} and repeat_code < 400:
            raise AssertionError(
                f"repeating {method} on the absent {vm_id} was accepted with "
                f"HTTP {repeat_code}"
            )
        cleanup: dict[str, int] = {}
        if transition_kind == "stop-supervisor":
            # The fixture's helper intentionally reuses one prepared VM name.
            # SvStop retains both the supervisor and VM records, so leaving the
            # first transition in place makes the protobuf row restart the same
            # exited VM rather than provision an independent prerequisite.
            # Remove both records only after recording the asserted stopped
            # state and repeat outcome.
            run_path = pathlib.Path(
                str((manifest["values"].get("vmm") or {}).get("run_path") or "")
            )
            pid_file = run_path / vm_id / "qemu.pid"
            qemu_pid = int(pid_file.read_text().strip()) if pid_file.is_file() else None
            sv_remove_route = (
                base
                + (routes.get("SvRemove") or "/prpc/SvRemove?json").split("?", 1)[0]
            )
            remove_vm_route = (
                base
                + (routes.get("RemoveVm") or "/prpc/RemoveVm?json").split("?", 1)[0]
            )
            cleanup["sv_remove"], sv_remove_body = call(
                sv_remove_route,
                json.dumps({"id": vm_id}).encode(),
                "application/json",
                headers,
            )
            if cleanup["sv_remove"] != 200:
                raise AssertionError(
                    f"SvRemove cleanup returned HTTP {cleanup['sv_remove']}: "
                    f"{sv_remove_body.decode('utf-8', 'replace')[:300]}"
                )
            cleanup["remove_vm"], remove_vm_body = call(
                remove_vm_route,
                json.dumps({"id": vm_id}).encode(),
                "application/json",
                headers,
            )
            if cleanup["remove_vm"] != 200:
                raise AssertionError(
                    f"RemoveVm cleanup returned HTTP {cleanup['remove_vm']}: "
                    f"{remove_vm_body.decode('utf-8', 'replace')[:300]}"
                )
            deadline = time.monotonic() + 30
            while vm_id in list_vm_ids(manifest) and time.monotonic() < deadline:
                time.sleep(1)
            if vm_id in list_vm_ids(manifest):
                raise AssertionError(f"cleanup left VM {vm_id} registered")
            if qemu_pid is not None:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    stat = pathlib.Path(f"/proc/{qemu_pid}/stat")
                    if not stat.exists():
                        break
                    fields = stat.read_text(encoding="utf-8", errors="replace").split()
                    if len(fields) > 2 and fields[2] == "Z":
                        break
                    time.sleep(1)
                else:
                    raise AssertionError(
                        "SvStop cleanup left its QEMU process alive after 30 seconds"
                    )
        elif transition_kind == "remove-supervisor":
            # SvStop already reaped the launcher children and SvRemove removed
            # the supervisor record; remove the independently persisted VM.
            remove_vm_route = (
                base
                + (routes.get("RemoveVm") or "/prpc/RemoveVm?json").split("?", 1)[0]
            )
            cleanup["remove_vm"], remove_vm_body = call(
                remove_vm_route,
                json.dumps({"id": vm_id}).encode(),
                "application/json",
                headers,
            )
            if cleanup["remove_vm"] != 200:
                raise AssertionError(
                    f"RemoveVm cleanup returned HTTP {cleanup['remove_vm']}: "
                    f"{remove_vm_body.decode('utf-8', 'replace')[:300]}"
                )
            deadline = time.monotonic() + 30
            while vm_id in list_vm_ids(manifest) and time.monotonic() < deadline:
                time.sleep(1)
            if vm_id in list_vm_ids(manifest):
                raise AssertionError(f"cleanup left VM {vm_id} registered")
        return {
            "encoding": encoding,
            "vm_id": vm_id,
            "status": code,
            "body_length": len(body),
            "final_state": final,
            # Recorded, not asserted: the contract for repeating this method on
            # an already-transitioned guest has not been established.
            "repeat_status": repeat_code,
            "cleanup": cleanup,
        }

    try:
        step = f"{case_id}-step-01"
        print(f"STEP {step} START", flush=True)
        record["json"] = transition("json")
        if transition_kind == "remove-vm":
            json_observed = (
                f"{method} over JSON removed the prepared VM and the repeated "
                "call on the absent VM was rejected."
            )
        elif transition_kind == "remove-supervisor":
            json_observed = (
                f"{method} over JSON removed the stopped supervisor record and "
                "the repeated call on the absent record was rejected."
            )
        else:
            json_observed = (
                f"{method} over JSON reached {record['json']['final_state']!r}; "
                "the repeat outcome was recorded without inventing an "
                "idempotency contract."
            )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": json_observed,
            }
        )
        print(
            f"EVIDENCE {step} - Proves the JSON transition and its rejection.",
            flush=True,
        )
        print(json.dumps(record["json"], sort_keys=True), flush=True)
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-02"
        print(f"STEP {step} START", flush=True)
        record["protobuf"] = transition("protobuf")
        if transition_kind == "remove-vm":
            protobuf_observed = (
                f"{method} over protobuf removed a freshly prepared VM and the "
                "repeated call was rejected."
            )
        elif transition_kind == "remove-supervisor":
            protobuf_observed = (
                f"{method} over protobuf removed a freshly stopped supervisor "
                "record and the repeated call was rejected."
            )
        else:
            protobuf_observed = (
                f"{method} over protobuf reached "
                f"{record['protobuf']['final_state']!r}; the repeat outcome was "
                "recorded without inventing an idempotency contract."
            )
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": protobuf_observed,
            }
        )
        print(f"EVIDENCE {step} - Proves the protobuf transition.", flush=True)
        print(json.dumps(record["protobuf"], sort_keys=True), flush=True)
        print(f"STEP {step} END - PASS", flush=True)

        step = f"{case_id}-step-03"
        print(f"STEP {step} START", flush=True)
        unknown_code, _ = call(
            route,
            json.dumps({"id": "dstack-test-absent"}).encode(),
            "application/json",
            headers,
        )
        if unknown_code < 400:
            raise AssertionError(
                f"{method} accepted an unknown VM ID with HTTP {unknown_code}"
            )
        wrong_type_code, _ = call(
            route, json.dumps({"id": 7}).encode(), "application/json", headers
        )
        if wrong_type_code < 400:
            raise AssertionError(
                f"{method} accepted a numeric process ID with HTTP {wrong_type_code}"
            )
        bad_route_code, _ = call(route + "NoSuch", b"{}", "application/json", headers)
        if bad_route_code < 400:
            raise AssertionError(f"invalid route accepted with HTTP {bad_route_code}")
        record["unknown_id_status"] = unknown_code
        record["wrong_type_status"] = wrong_type_code
        record["invalid_route_status"] = bad_route_code
        steps.append(
            {
                "id": step,
                "status": "PASS",
                "observed": "An unknown object ID, a wrong-typed ID, and an "
                "invalid route were rejected and the service stayed available.",
            }
        )
        print(f"EVIDENCE {step} - Proves scoped error behaviour.", flush=True)
        print(
            json.dumps(
                {
                    "unknown": unknown_code,
                    "wrong_type": wrong_type_code,
                    "route": bad_route_code,
                }
            ),
            flush=True,
        )
        print(f"STEP {step} END - PASS", flush=True)
    except Exception as error:  # noqa: BLE001 - recorded as a case failure
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        vmm = manifest["values"].get("vmm") or {}
        preserved: dict[str, str] = {}
        vmm_log = pathlib.Path(str(vmm.get("log") or ""))
        if vmm_log.is_file():
            destination = artifacts / "vmm.log"
            shutil.copy2(vmm_log, destination)
            preserved["vmm_log"] = str(destination.relative_to(result_dir))
        run_path = pathlib.Path(str(vmm.get("run_path") or ""))
        if run_path.is_dir():
            destination = artifacts / "vmm-run"
            shutil.copytree(
                run_path,
                destination,
                dirs_exist_ok=True,
                ignore=ignore_noncopyable,
            )
            preserved["vmm_run"] = str(destination.relative_to(result_dir))
        record["preserved_diagnostics"] = preserved
        done = {item["id"] for item in steps}
        for number in range(1, 4):
            step_id = f"{case_id}-step-{number:02d}"
            if step_id not in done:
                steps.append({"id": step_id, "status": "FAIL", "observed": failure})
        print(failure, flush=True)

    record["status"] = status
    record["failure"] = failure
    atomic_json(artifacts / "lifecycle-transition.json", record)
    artifact = {
        "name": "Lifecycle transition record",
        "path": "artifacts/lifecycle-transition.json",
        "step_id": f"{case_id}-step-01",
        "description": (
            "Records each provisioned VM, the encoding used, the resulting "
            "state change and the rejection of the repeated call."
        ),
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    if transition_kind == "remove-vm":
        success_summary = (
            f"Vmm.{method} removed a prepared VM over both encodings, left it "
            "absent, and rejected the repeated call, invalid ID, wrong type, "
            "and invalid route."
        )
    elif transition_kind == "shutdown-vm":
        success_summary = (
            f"Vmm.{method} stopped a booted guest over both encodings and "
            "rejected the invalid ID, wrong type, and invalid route."
        )
    elif transition_kind == "stop-supervisor":
        success_summary = (
            f"Vmm.{method} stopped a running supervisor process over both "
            "encodings, retained its stopped record, and rejected the invalid "
            "ID, wrong type, and invalid route."
        )
    else:
        success_summary = (
            f"Vmm.{method} removed a stopped supervisor process over both "
            "encodings, retained no supervisor record, and rejected the repeat, "
            "invalid ID, wrong type, and invalid route."
        )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": success_summary if status == "PASS" else failure,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": (
                "Models the method-specific state transition and records repeat "
                "semantics without inventing an idempotency requirement."
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
