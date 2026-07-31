#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the case-owned Playwright VMM deployment and lifecycle workflow."""

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

CASE_ID = "tc-vmm-ui-observa-005"
EXPECTED_ROWS = {
    "healthy-ui", "unset-defaults", "semantic-form", "simulated-platform",
    "network-selection", "gpu-empty-state", "server-error-recovery",
    "keyboard-ui-submit", "created-observed", "ui-lifecycle",
    "ui-update-resize", "ui-log-view", "cross-session-isolation",
}


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True); output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def listed(command: list[str]) -> list[dict[str, Any]]:
    process = subprocess.run(command, text=True, capture_output=True, timeout=60, check=False)
    if process.returncode: raise RuntimeError("prepared list command failed")
    value = json.loads(process.stdout or "[]")
    return value if isinstance(value, list) else []


def rpc(base: str, route: str, vm_id: str) -> int:
    request = urllib.request.Request(base + route.split("?",1)[0], data=json.dumps({"id":vm_id}).encode(), headers={"content-type":"application/json"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            response.read(); return response.status
    except urllib.error.HTTPError as error:
        error.read(); return error.code


def main() -> int:
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID: raise RuntimeError("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest["values"]; vmm = values["vmm"]; fixture = values.get("vmm_web_ui_deployment", {})
    required = {"browser_session_argv","ui_url","health_probe_argv","semantic_form_rows","ui_submit_argv","created_vm_observer_argv","lifecycle_argv","server_error_row_argv","unset_default_observer_argv","keyboard_accessibility_argv","cross_session_probe_argv","cleanup_argv"}
    if fixture.get("destructive_actions_allowed") is not True or not required <= fixture.keys(): raise RuntimeError("complete browser controller absent")
    name = f'{vmm["test_input"]["name_prefix"]}-web-ui'
    output = result_dir / "artifacts/browser-workflow.json"; output.parent.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy(); env.update({"DSTACK_BROWSER_WORKFLOW":str(fixture["browser_workflow"]),"DSTACK_UI_URL":str(fixture["ui_url"]),"DSTACK_UI_VM_NAME":name,"DSTACK_UI_IMAGE":str(vmm["test_input"]["image"]),"DSTACK_UI_OUTPUT":str(output)})
    command = [str(x) for x in fixture["browser_session_argv"]]
    browser = subprocess.run(command, text=True, capture_output=True, timeout=240, check=False, env=env)
    evidence: dict[str,Any] = {"browser_returncode":browser.returncode,"browser_diagnostic_tail":(browser.stdout+browser.stderr)[-5000:],"vm_processes_started":1,"image_build_tested":False}
    failures: list[str] = []; steps: list[dict[str,Any]] = []; vm_id: str|None = None
    base = str(vmm["rpc_url"]).rstrip("/"); routes=vmm["json_prpc_routes"]; list_command=[str(x) for x in vmm["commands"]["list_vms"]]
    try:
        if browser.returncode or not output.is_file(): raise AssertionError("case-owned browser workflow failed")
        observed = json.loads(output.read_text()); rows={key for key,value in observed.get("rows",{}).items() if value is True}
        if rows != EXPECTED_ROWS: raise AssertionError(f"browser rows mismatch: missing={sorted(EXPECTED_ROWS-rows)}")
        matches=[item for item in listed(list_command) if str(item.get("name"))==name]
        if len(matches)!=1: raise AssertionError("UI-created VM was not uniquely observable by public list")
        vm=matches[0]; vm_id=str(vm["id"])
        registry=json.loads(pathlib.Path(vmm["test_input"]["created_vms_registry"]).read_text())
        # UI creation is not routed through the helper, so register it immediately for provider-safe cleanup.
        if vm_id not in registry:
            registry.append(vm_id); pathlib.Path(vmm["test_input"]["created_vms_registry"]).write_text(json.dumps(registry)+"\n")
        configuration=vm.get("configuration") or {}
        if configuration.get("disk_size") not in (21,"21") or configuration.get("user_config") != "ui-updated=true":
            raise AssertionError("UI update/resize was not reflected in public configuration")
        evidence.update({"rows":sorted(rows),"defaults":observed.get("defaults"),"alerts":observed.get("alerts"),"created_vm":{"id":vm_id,"status":vm.get("status"),"disk_size":configuration.get("disk_size"),"user_config":configuration.get("user_config")}})
        steps=[{"id":f"{CASE_ID}-step-01","status":"PASS","observed":"A fresh isolated Chromium context loaded the healthy case-owned VMM and observed exact deployment defaults."},{"id":f"{CASE_ID}-step-02","status":"PASS","observed":"The browser submitted the semantic form by keyboard, recovered from one controlled server error, created one VM, exercised UI stop/start/update/log actions, and public configuration reflected disk 21 plus user config."},{"id":f"{CASE_ID}-step-03","status":"PASS","observed":"A second browser context had no leaked form state, observed the same public VM by UUID, and the case remained available for cleanup."}]
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for number in range(1,4): steps.append({"id":f"{CASE_ID}-step-{number:02d}","status":"FAIL","observed":failures[-1]})
    finally:
        if vm_id:
            evidence["cleanup"]={"stop":rpc(base,routes["StopVm"],vm_id),"remove":rpc(base,routes["RemoveVm"],vm_id)}
    artifact={"path":"artifacts/browser-workflow.json","step_id":f"{CASE_ID}-step-02","name":"VMM web UI browser workflow","description":"Fresh-context defaults, semantic form, keyboard submission, server-error recovery, lifecycle, update, log, cross-session, public-state, and cleanup evidence."}
    # Preserve browser output as the named artifact and a separate controller summary.
    summary_path=result_dir/"artifacts/vmm-web-ui-summary.json"; atomic_json(summary_path,evidence)
    summary_artifact={"path":"artifacts/vmm-web-ui-summary.json","step_id":f"{CASE_ID}-step-03","name":"Web UI public-state summary","description":"Public UUID/configuration and cleanup correlation for the browser-created VM."}
    available_artifacts = [item for item in (artifact,summary_artifact) if (result_dir/item["path"]).is_file()]
    atomic_json(result_dir/"artifacts/manifest.json",{"artifacts":available_artifacts})
    status="PASS" if not failures else "FAIL"
    ev=[]
    for item in available_artifacts:
        path=result_dir/item["path"]
        ev.append({"path":item["path"],"sha256":hashlib.sha256(path.read_bytes()).hexdigest()})
    atomic_json(result_dir/"result.json",{"schema_version":"1.0","case_id":CASE_ID,"provisional":False,"status":status,"summary":"13/13 browser deployment rows passed." if not failures else failures[0],"steps":steps,"artifacts":available_artifacts,"evidence":ev,"remarks":"One VM was submitted through a fresh headless Chromium context; direct RPCs were used only for final bounded cleanup."})
    return 0 if not failures else 1


if __name__ == "__main__": raise SystemExit(main())
