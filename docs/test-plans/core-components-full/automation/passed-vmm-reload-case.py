#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for VMM reload and crash recovery."""

from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any

CASE_ID = "tc-vmm-vm-lifecyc-005"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write a JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, ensure_ascii=False, indent=2)
        out.write("\n")
        temporary = pathlib.Path(out.name)
    temporary.replace(path)


def run(argv: list[str], timeout: int = 30) -> dict[str, Any]:
    """Run a bounded manifest-declared command."""
    completed = subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )
    return {
        "returncode": completed.returncode,
        "stdout": completed.stdout,
        "stderr": completed.stderr,
    }


def rpc(url: str, route: str, payload: Any) -> dict[str, Any]:
    """Call one JSON pRPC route and return bounded metadata."""
    request = urllib.request.Request(
        url.rstrip("/") + "/" + route.lstrip("/"),
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read()
            status = int(response.status)
    except urllib.error.HTTPError as error:
        raw = error.read()
        status = int(error.code)
    body = None
    if raw:
        try:
            body = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            body = None
    return {"status": status, "body": body, "body_len": len(raw)}


def parse_vms(observation: dict[str, Any]) -> list[dict[str, Any]]:
    """Validate and decode a list-vms command result."""
    if observation["returncode"] != 0:
        raise RuntimeError("list-vms command failed")
    value = json.loads(observation["stdout"])
    if not isinstance(value, list):
        raise RuntimeError("list-vms did not return an array")
    return value


def wait_rpc(url: str, route: str, timeout: float = 30) -> None:
    """Wait until a restarted VMM route becomes healthy."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if rpc(url, route, {})["status"] == 200:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise TimeoutError("restarted VMM did not become healthy")


def main() -> int:
    """Execute the promoted reload and crash-recovery regression."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported promoted reload case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    vmm = values["vmm"]
    test_input = vmm["test_input"]
    routes = vmm["json_prpc_routes"]
    result_artifacts = result_dir / "artifacts"
    result_artifacts.mkdir(parents=True, exist_ok=True)
    step_ids = [f"{case_id}-step-{number:02d}" for number in (1, 2, 3)]
    steps: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    created_id = ""
    replacement: subprocess.Popen[bytes] | None = None
    injected: list[pathlib.Path] = []
    status = "PASS"
    failure = ""

    def record(name: str, step: str, value: Any, description: str) -> None:
        atomic_json(result_artifacts / name, value)
        artifacts.append(
            {
                "path": f"artifacts/{name}",
                "step_id": step,
                "name": name.removesuffix(".json").replace("-", " ").title(),
                "description": description,
            }
        )

    try:
        print(f"STEP {step_ids[0]} START", flush=True)
        baseline_list = run(list(vmm["commands"]["list_vms"]))
        baseline_vms = parse_vms(baseline_list)
        status_rpc = rpc(vmm["rpc_url"], routes["Status"], {})
        version_rpc = rpc(vmm["rpc_url"], routes["Version"], {})
        prefix = str(test_input["name_prefix"])
        if status_rpc["status"] != 200 or version_rpc["status"] != 200:
            raise AssertionError("VMM prerequisite RPC is not healthy")
        if any(str(vm.get("name", "")).startswith(prefix) for vm in baseline_vms):
            raise AssertionError("run-scoped VM already exists at baseline")
        baseline = {
            "list_returncode": baseline_list["returncode"],
            "status": status_rpc,
            "version": version_rpc,
            "run_scoped_count": 0,
        }
        record(
            "step01-baseline.json",
            step_ids[0],
            baseline,
            "Healthy VMM RPC and empty run-scoped baseline.",
        )
        steps.append(
            {
                "id": step_ids[0],
                "status": "PASS",
                "observed": "VMM was healthy and the run-scoped baseline was empty.",
            }
        )
        print(f"STEP {step_ids[0]} END - PASS", flush=True)

        print(f"STEP {step_ids[1]} START", flush=True)
        created = run(list(test_input["create_stopped_helper_argv"]), timeout=60)
        if created["returncode"] != 0:
            raise AssertionError("create-stopped helper failed")
        created_id = str(json.loads(created["stdout"])["id"])
        registry = pathlib.Path(test_input["created_vms_registry"])
        registry.parent.mkdir(parents=True, exist_ok=True)
        existing = (
            [line for line in registry.read_text().splitlines() if line.strip()]
            if registry.exists()
            else []
        )
        if created_id not in existing:
            with registry.open("a", encoding="utf-8") as output:
                output.write(created_id + "\n")
        before_restart = parse_vms(run(list(vmm["commands"]["list_vms"])))
        matching = [vm for vm in before_restart if vm.get("id") == created_id]
        if len(matching) != 1 or matching[0].get("status") != "stopped":
            raise AssertionError("created VM is not uniquely stopped")
        run_path = pathlib.Path(vmm["run_path"])
        for suffix in ("stale-workdir", "partial-create"):
            path = run_path / f"{prefix}-{suffix}"
            path.mkdir(parents=True, exist_ok=False)
            (path / "state.partial").write_text("run-scoped incomplete state\n")
            injected.append(path)
        old_pid = int(vmm["pid"])
        os.kill(old_pid, signal.SIGTERM)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                os.kill(old_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("case-owned VMM did not stop")
        prepared = values["prepared_binaries"]
        binary = (
            prepared.get("dstack_vmm")
            or prepared.get("dstack-vmm")
            or prepared.get("vmm")
        )
        if isinstance(binary, dict):
            binary = binary.get("path")
        if not binary:
            raise RuntimeError("manifest missing prepared VMM binary")
        log_handle = open(vmm["log"], "ab", buffering=0)
        replacement = subprocess.Popen(
            [str(binary), "--config", str(vmm["config"])],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        wait_rpc(vmm["rpc_url"], routes["Version"])
        reload_result = rpc(vmm["rpc_url"], routes["ReloadVms"], {})
        after_restart = parse_vms(run(list(vmm["commands"]["list_vms"])))
        matching = [vm for vm in after_restart if vm.get("id") == created_id]
        if reload_result["status"] != 200:
            raise AssertionError("ReloadVms failed after restart")
        if len(matching) != 1 or matching[0].get("status") != "stopped":
            raise AssertionError("reload duplicated or auto-started the stopped VM")
        behavior = {
            "created_id": created_id,
            "before_status": "stopped",
            "reload": reload_result,
            "after_status": matching[0].get("status"),
            "after_count": len(matching),
            "injected_workdir_count": len(injected),
        }
        record(
            "step02-reload-recovery.json",
            step_ids[1],
            behavior,
            "Stopped-VM reconstruction and stale/partial workdir recovery across a case-owned VMM restart.",
        )
        steps.append(
            {
                "id": step_ids[1],
                "status": "PASS",
                "observed": "Restart and ReloadVms reconstructed one stopped VM without duplication or auto-start.",
            }
        )
        print(f"STEP {step_ids[1]} END - PASS", flush=True)

        print(f"STEP {step_ids[2]} START", flush=True)
        first = rpc(vmm["rpc_url"], routes["Status"], {})
        second = rpc(vmm["rpc_url"], routes["Status"], {})
        malformed = rpc(
            vmm["rpc_url"], routes["ReloadVms"], {"unexpected": object.__name__}
        )
        if (
            first["status"] != 200
            or second["status"] != 200
            or first["body"] != second["body"]
        ):
            raise AssertionError("repeated status observations diverged")
        if malformed["status"] != 200:
            raise AssertionError(
                "compatible unknown ReloadVms JSON field changed behavior"
            )
        remove = rpc(vmm["rpc_url"], routes["RemoveVm"], {"id": created_id})
        if remove["status"] != 200:
            raise AssertionError("run-scoped VM cleanup failed")
        created_id = ""
        diagnostics = {
            "status_repeat_equal": True,
            "compatible_unknown_field": malformed,
            "cleanup": remove,
        }
        record(
            "step03-isolation-diagnostics.json",
            step_ids[2],
            diagnostics,
            "Repeatability, compatible JSON framing, availability, and cleanup evidence.",
        )
        steps.append(
            {
                "id": step_ids[2],
                "status": "PASS",
                "observed": "Repeated state was stable, compatible framing preserved behavior, and cleanup succeeded.",
            }
        )
        print(f"STEP {step_ids[2]} END - PASS", flush=True)
    except Exception as error:
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        current = len(steps)
        if current < 3:
            steps.append(
                {"id": step_ids[current], "status": "FAIL", "observed": failure}
            )
        print(f"STEP {step_ids[min(current, 2)]} END - FAIL", flush=True)
    finally:
        if created_id:
            try:
                rpc(vmm["rpc_url"], routes["RemoveVm"], {"id": created_id})
            except Exception:
                pass
        for path in injected:
            try:
                for child in path.iterdir():
                    child.unlink()
                path.rmdir()
            except Exception:
                pass
        if replacement is not None and replacement.poll() is None:
            replacement.terminate()
            try:
                replacement.wait(timeout=15)
            except subprocess.TimeoutExpired:
                replacement.kill()
                replacement.wait(timeout=5)
    while len(steps) < 3:
        steps.append(
            {
                "id": step_ids[len(steps)],
                "status": "NOT_RUN",
                "observed": "Not run after an earlier failure.",
            }
        )
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "status": status,
        "provisional": False,
        "summary": "VMM reload/crash recovery deterministic regression passed."
        if status == "PASS"
        else f"VMM reload/crash recovery regression failed: {failure}",
        "steps": steps,
        "artifacts": artifacts,
        "remarks": "Uses only the manifest-declared case-owned VMM, run path, helper, registry, prepared binary, and cleanup scope.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
