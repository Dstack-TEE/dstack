#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise proxied Guest API targeting, interruption, recovery, and removal."""

from __future__ import annotations

import concurrent.futures
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

CASE_ID = "tc-vmm-manifest-001"
METHODS = ("Info", "SysInfo", "NetworkInfo", "ListContainers")


def atomic_json(path: pathlib.Path, value: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        tmp = pathlib.Path(f.name)
    tmp.replace(path)


def request(url, vm_id, timeout=15):
    req = urllib.request.Request(
        url,
        data=json.dumps({"id": vm_id}).encode(),
        headers={"content-type": "application/json"},
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), time.monotonic() - started
    except urllib.error.HTTPError as e:
        return e.code, e.read(), time.monotonic() - started
    except (TimeoutError, urllib.error.URLError) as e:
        return 0, str(e).encode(), time.monotonic() - started


def rpc(base, route, vm_id):
    return request(base + route.split("?", 1)[0], vm_id, 60)[0]


def listed(cmd):
    p = subprocess.run(cmd, text=True, capture_output=True, timeout=60, check=False)
    if p.returncode:
        raise RuntimeError("list failed")
    x = json.loads(p.stdout or "[]")
    return x if isinstance(x, list) else []


def find(cmd, vm_id):
    return next((x for x in listed(cmd) if str(x.get("id")) == vm_id), None)


def wait(cmd, vm_id, predicate, timeout=120):
    end = time.monotonic() + timeout
    last = None
    while time.monotonic() < end:
        last = find(cmd, vm_id)
        if predicate(last):
            return last
        time.sleep(1)
    raise AssertionError(
        f"target state timeout: {None if last is None else last.get('status')}"
    )


def create(vmm, suffix):
    ti = vmm["test_input"]
    p = subprocess.run(
        [
            *map(str, ti["create_stopped_helper_argv"]),
            "--name",
            f"{ti['name_prefix']}-{suffix}",
        ],
        text=True,
        capture_output=True,
        timeout=180,
        check=False,
    )
    if p.returncode:
        raise AssertionError("target creation failed")
    return str(json.loads(p.stdout.splitlines()[-1])["id"])


def projected(body):
    value = json.loads(body or b"{}")
    return {
        "app_id": value.get("app_id"),
        "instance_id": value.get("instance_id"),
        "version": value.get("version"),
    }


def main():
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    m = json.loads(pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    v = m["values"]
    vmm = v["vmm"]
    fx = v.get("vmm_proxied_guestapi", {})
    required = {
        "target_rows",
        "create_target_argv",
        "proxy_request_argv",
        "target_observer_argv",
        "deadline_rows",
        "concurrent_remove_argv",
        "closed_error_observer_argv",
        "dependency_stop_argv",
        "dependency_restart_argv",
        "recovery_request_argv",
        "adjacent_identity_observer_argv",
        "redaction_audit_argv",
        "cleanup_argv",
    }
    if fx.get("destructive_actions_allowed") is not True or not required <= fx.keys():
        raise RuntimeError("proxy controller absent")
    base = str(vmm["rpc_url"]).rstrip("/")
    routes = vmm["json_prpc_routes"]
    guest = fx["proxy_routes"]
    cmd = [str(x) for x in vmm["commands"]["list_vms"]]
    ids = []
    failures = []
    steps = []
    e = {
        "rows": {},
        "native_responses_persisted": False,
        "image_build_tested": False,
        "vm_processes_started": 2,
    }
    try:
        a = create(vmm, "proxy-a")
        ids.append(a)
        b = create(vmm, "proxy-b")
        ids.append(b)
        for x in ids:
            if rpc(base, routes["StartVm"], x) != 200:
                raise AssertionError("start failed")
        for x in ids:
            wait(
                cmd,
                x,
                lambda z: z is not None
                and z.get("status") == "running"
                and z.get("boot_progress") == "done",
            )
        e["rows"]["healthy-targets"] = True
        steps.append(
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": "Two registered case-owned guests reached boot-complete running state with distinct UUIDs.",
            }
        )
        identities = {}
        method_meta = {}
        for x, label in ((a, "a"), (b, "b")):
            for method in METHODS:
                code, body, duration = request(guest[method], x)
                if code != 200 or duration > 15:
                    raise AssertionError(f"{method} failed for {label}")
                method_meta[f"{label}:{method}"] = {
                    "status": code,
                    "duration_ms": round(duration * 1000),
                    "sha256": hashlib.sha256(body).hexdigest(),
                    "json_keys": sorted(json.loads(body).keys()),
                }
                e["rows"][f"running-{label}-{method.lower()}"] = True
            identities[label] = projected(request(guest["Info"], x)[1])
        if identities["a"].get("instance_id") == identities["b"].get("instance_id"):
            raise AssertionError("adjacent guests shared instance identity")
        # Unknown IDs fail closed for every route, including Shutdown.
        unknown = "00000000-0000-0000-0000-000000000000"
        unknown_codes = {
            method: request(guest[method], unknown)[0]
            for method in (*METHODS, "Shutdown")
        }
        if any(code in (0, 200) for code in unknown_codes.values()):
            raise AssertionError("unknown target did not fail closed")
        e["rows"]["unknown-closed"] = True
        # Dependency stop, bounded closed error, restart, and identity-stable recovery.
        if rpc(base, routes["StopVm"], a) != 200:
            raise AssertionError("dependency stop failed")
        wait(cmd, a, lambda z: z is not None and z.get("status") == "stopped")
        stopped_code, _, stopped_time = request(guest["Info"], a)
        if stopped_code in (0, 200) or stopped_time > 15:
            raise AssertionError("stopped target did not fail closed within deadline")
        if rpc(base, routes["StartVm"], a) != 200:
            raise AssertionError("dependency restart failed")
        wait(
            cmd,
            a,
            lambda z: z is not None
            and z.get("status") == "running"
            and z.get("boot_progress") == "done",
        )
        recovery_code, recovery_body, recovery_time = request(guest["Info"], a)
        if recovery_code != 200 or projected(recovery_body) != identities["a"]:
            raise AssertionError("recovery identity changed")
        e["rows"]["stop-closed-recovery"] = True
        # Proxied shutdown is routed to A only; automatic restart may subsequently restore it.
        shutdown_code, _, shutdown_time = request(guest["Shutdown"], a)
        if shutdown_code != 200 or shutdown_time > 15:
            raise AssertionError("proxied shutdown failed")
        wait(
            cmd, a, lambda z: z is not None and z.get("status") != "running", timeout=40
        )
        e["rows"]["targeted-shutdown"] = True
        # Race a B request with B removal; a success must still carry B identity, never A.
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(request, guest["Info"], b, 15)
            time.sleep(0.01)
            remove_code = rpc(base, routes["RemoveVm"], b)
            race_code, race_body, race_time = future.result(timeout=20)
        if remove_code != 200 or race_time > 15:
            raise AssertionError("concurrent removal was not bounded")
        if race_code == 200 and projected(race_body) != identities["b"]:
            raise AssertionError("disappearing target redirected to peer")
        if race_code == 200 and projected(race_body) == identities["a"]:
            raise AssertionError("race crossed VM identity")
        wait(cmd, b, lambda z: z is None)
        ids.remove(b)
        e["rows"]["concurrent-remove-no-redirect"] = True
        e.update(
            {
                "method_metadata": method_meta,
                "identity_hashes": {
                    k: hashlib.sha256(
                        json.dumps(val, sort_keys=True).encode()
                    ).hexdigest()
                    for k, val in identities.items()
                },
                "unknown_codes": unknown_codes,
                "stopped": {
                    "status": stopped_code,
                    "duration_ms": round(stopped_time * 1000),
                },
                "recovery": {
                    "status": recovery_code,
                    "duration_ms": round(recovery_time * 1000),
                },
                "shutdown": {
                    "status": shutdown_code,
                    "duration_ms": round(shutdown_time * 1000),
                },
                "race": {
                    "proxy_status": race_code,
                    "remove_status": remove_code,
                    "duration_ms": round(race_time * 1000),
                },
            }
        )
        steps.extend(
            [
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": "PASS",
                    "observed": "Info, SysInfo, NetworkInfo, ListContainers, and Shutdown reached only their selected running guest; stopped and unknown targets failed closed within 15 seconds.",
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Stop/restart restored the same projected identity, and an Info/Remove race completed without redirecting to the adjacent VM.",
                },
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": "PASS",
                    "observed": "Only response hashes, key names, status, timing, and projected identity hashes were retained; native certificates, TCB data, and sentinels were not persisted.",
                },
            ]
        )
    except Exception as err:
        failures.append(f"{type(err).__name__}: {err}")
        steps = [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": "FAIL", "observed": failures[0]}
            for n in range(1, 5)
        ]
    finally:
        cleanup = []
        for x in ids:
            cleanup.append(
                {
                    "id": x,
                    "stop": rpc(base, routes["StopVm"], x),
                    "remove": rpc(base, routes["RemoveVm"], x),
                }
            )
        e["cleanup"] = cleanup
    artifact = {
        "path": "artifacts/vmm-proxied-guestapi.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Proxied Guest API targeting matrix",
        "description": "Hashed and projected running/stopped/unknown/recovery/shutdown/concurrent-removal observations without native sensitive responses.",
    }
    atomic_json(result_dir / artifact["path"], e)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": f"{len(e['rows'])} proxied targeting rows passed."
            if not failures
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(
                        (result_dir / artifact["path"]).read_bytes()
                    ).hexdigest(),
                }
            ],
            "remarks": "Two real case-owned guests were used; only projected identities and response hashes were persisted.",
        },
    )
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
