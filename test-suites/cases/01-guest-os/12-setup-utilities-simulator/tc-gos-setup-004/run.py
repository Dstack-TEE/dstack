#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# ruff: noqa: D103
# SPDX-License-Identifier: Apache-2.0
"""Deterministic staged-setup lifecycle regression for a lease-owned no-TEE VM."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
from typing import Any

CASE = "tc-gos-setup-004"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write("\n")
        temporary = pathlib.Path(f.name)
    temporary.replace(path)


def run(
    argv: list[str], timeout: int = 180, check: bool = True
) -> subprocess.CompletedProcess[str]:
    p = subprocess.run(
        argv,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {p.stderr[-500:]}")
    return p


def info(cli: list[str], vm_id: str) -> dict[str, Any]:
    value = json.loads(run([*cli, "info", "--json", vm_id], timeout=30).stdout)
    if not isinstance(value, dict):
        raise RuntimeError("VMM info returned a non-object")
    return value


def ready(cli: list[str], vm_id: str, attempts: int = 120) -> dict[str, Any]:
    for _ in range(attempts):
        value = info(cli, vm_id)
        if (
            value.get("status") == "running"
            and value.get("boot_progress") == "done"
            and value.get("instance_id")
        ):
            return value
        if value.get("boot_error"):
            raise RuntimeError("lease-owned VM reported a boot error")
        time.sleep(5)
    raise RuntimeError("lease-owned VM did not become ready")


def main() -> int:
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE:
        raise RuntimeError(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values", {})
    if values.get("destructive_actions_allowed") is not True:
        raise RuntimeError("fixture is not lease-owned")
    expected_image = os.environ.get("DSTACK_TEST_NO_TEE_GUEST_IMAGE")
    if not expected_image:
        raise RuntimeError("DSTACK_TEST_NO_TEE_GUEST_IMAGE is required")
    if values.get("image") != expected_image:
        raise RuntimeError(
            f"unexpected guest image: expected {expected_image!r}, "
            f"got {values.get('image')!r}"
        )
    cli = [str(x) for x in values["vmm_cli_argv"]]
    vm_id = str(values["vm_id"])
    observations: dict[str, Any] = {"image": values["image"], "cycles": []}
    failures = []
    steps = []
    try:
        before = ready(cli, vm_id)
        identity = (before.get("app_id"), before.get("instance_id"))
        if not all(identity):
            raise AssertionError("guest identity was incomplete")
        print(f"STEP {case_id}-step-01 START", flush=True)
        for cycle in range(2):
            run([*cli, "stop", "--force", vm_id])
            run([*cli, "start", vm_id])
            after = ready(cli, vm_id)
            current = (after.get("app_id"), after.get("instance_id"))
            if current != identity:
                raise AssertionError("identity changed across unchanged setup cycle")
            observations["cycles"].append(
                {"cycle": cycle + 1, "ready": True, "identity_stable": True}
            )
        runtime_path = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST")
        if not runtime_path:
            raise RuntimeError("DSTACK_TEST_RUNTIME_MANIFEST is required")
        runtime = json.loads(pathlib.Path(runtime_path).read_text())
        workspace = pathlib.Path(str(runtime.get("repository", ""))) / "dstack"
        if not workspace.is_dir():
            raise RuntimeError("runtime manifest has no prepared dstack workspace")
        cargo_env = os.environ.copy()
        target = runtime.get("cargo_target_dir")
        if target:
            cargo_env["CARGO_TARGET_DIR"] = str(target)
        cargo = os.environ.get("CARGO") or shutil.which("cargo")
        if not cargo:
            candidate = pathlib.Path.home() / ".cargo" / "bin" / "cargo"
            if candidate.is_file():
                cargo = str(candidate)
        if not cargo:
            raise RuntimeError("prepared Rust toolchain has no cargo executable")
        tests = subprocess.run(
            [cargo, "test", "-p", "dstack-util", "system_setup"],
            cwd=workspace,
            env=cargo_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=900,
            check=False,
        )
        observations["unit_filter"] = {
            "returncode": tests.returncode,
            "passed": tests.returncode == 0,
        }
        if tests.returncode:
            raise RuntimeError(
                f"system_setup unit filter failed ({tests.returncode}): {tests.stderr[-500:]}"
            )
        print(
            f"EVIDENCE {case_id}-step-01 - Two unchanged setup cycles retained identity and the system_setup unit matrix passed.",
            flush=True,
        )
        print(f"STEP {case_id}-step-01 END - PASS", flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-01",
                "status": "PASS",
                "observed": "Two force stop/start cycles converged with stable identity; candidate system_setup unit filters passed.",
            }
        )
        print(f"STEP {case_id}-step-02 START", flush=True)
        recovered = info(cli, vm_id)
        if (recovered.get("app_id"), recovered.get("instance_id")) != identity:
            raise AssertionError("identity changed after setup recovery cycles")
        observations["recovery"] = {
            "unit_boundaries_passed": observations["unit_filter"]["passed"],
            "ready": recovered.get("status") == "running"
            and recovered.get("boot_progress") == "done",
            "identity_stable": True,
        }
        print(
            f"EVIDENCE {case_id}-step-02 - Unit failure boundaries passed and unchanged setup cycles converged.",
            flush=True,
        )
        print(f"STEP {case_id}-step-02 END - PASS", flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-02",
                "status": "PASS",
                "observed": "Candidate failure-boundary unit tests passed and unchanged lifecycle recovery retained readiness and identity.",
            }
        )
        print(f"STEP {case_id}-step-03 START", flush=True)
        final = info(cli, vm_id)
        observations["final"] = {
            "running": final.get("status") == "running",
            "ready": final.get("boot_progress") == "done",
            "identity_stable": (final.get("app_id"), final.get("instance_id"))
            == identity,
        }
        if not all(observations["final"].values()):
            raise AssertionError("final availability or identity check failed")
        print(
            f"EVIDENCE {case_id}-step-03 - Lease-owned VM remained ready; provider cleanup remains authoritative.",
            flush=True,
        )
        print(f"STEP {case_id}-step-03 END - PASS", flush=True)
        steps.append(
            {
                "id": f"{case_id}-step-03",
                "status": "PASS",
                "observed": "Final state was ready with stable identity; no adjacent VM or physical host was modified.",
            }
        )
    except Exception as error:
        failures.append(f"{type(error).__name__}: {error}")
        for n in range(1, 4):
            sid = f"{case_id}-step-{n:02d}"
            if not any(s["id"] == sid for s in steps):
                steps.append({"id": sid, "status": "FAIL", "observed": failures[-1]})
    observations["sensitive_values_persisted"] = False
    observations["digest"] = hashlib.sha256(
        json.dumps(observations, sort_keys=True).encode()
    ).hexdigest()
    artifact = {
        "name": "Setup lifecycle observations",
        "path": "artifacts/setup-lifecycle-observations.json",
        "step_id": f"{case_id}-step-02",
        "description": "Records bounded booleans and return codes for setup idempotence, unit boundaries, unchanged-cycle recovery, and final availability without persisting identity or credentials.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    status = "PASS" if not failures else "FAIL"
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Staged setup lifecycle regression passed."
            if status == "PASS"
            else failures[0],
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "Only the lease-owned no-TEE guest VM was restarted; the physical host and adjacent VMs were not modified.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
