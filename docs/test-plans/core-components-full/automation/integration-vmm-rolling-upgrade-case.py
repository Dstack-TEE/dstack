#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise a v0.5.11-to-candidate VMM upgrade around mixed Guest images."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import signal
import subprocess
import sys
import time
from typing import Any

CASE_ID = "tc-int-compatibil-002"
ACTION = "Rolling VMM upgrade with running mixed guests"


def support() -> Any:
    """Load the shared physical-TDX version matrix controller."""
    path = pathlib.Path(__file__).with_name("kms_upgrade_matrix_case.py")
    spec = importlib.util.spec_from_file_location("vmm_rolling_matrix", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load version matrix support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = support()


def terminate(pid: int) -> None:
    """Terminate one case-owned VMM process and wait for exit."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    os.kill(pid, signal.SIGKILL)


def handoff(process: subprocess.Popen[bytes]) -> None:
    """Stop only the old VMM daemon so supervised Guests keep running."""
    process.kill()
    process.wait(timeout=20)


def launch(
    binary: pathlib.Path, config: pathlib.Path, log: pathlib.Path
) -> subprocess.Popen[bytes]:
    """Launch one versioned VMM against the case-owned persisted state."""
    stream = log.open("ab", buffering=0)
    process = subprocess.Popen(
        [str(binary), "--config", str(config)],
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    return process


def wait_cli(cli: list[str], timeout: int = 60) -> list[dict[str, Any]]:
    """Wait for the active VMM to return a JSON inventory."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        completed = subprocess.run(
            [*cli, "lsvm", "--json"],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
        if completed.returncode == 0:
            try:
                value = json.loads(completed.stdout)
                if isinstance(value, list):
                    return value
            except json.JSONDecodeError:
                pass
        time.sleep(0.5)
    raise TimeoutError("versioned VMM did not expose its inventory")


def rpc_reload(url: str) -> int:
    """Invoke ReloadVms and return its HTTP status."""
    code, _ = SUPPORT.http(f"{url.rstrip('/')}/prpc/ReloadVms?json", b"{}", timeout=60)
    return int(code)


def main() -> int:
    """Build the pinned old VMM, switch versions, and verify mixed Guest state."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit(f"this harness only supports {CASE_ID}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime_path = pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"])
    values = manifest["values"]
    live = values["live_vmm"]
    version = values["version_matrix"]
    historical = {row["version"]: row for row in version["historical"]}
    old = historical["0.5.11"]
    old_source = pathlib.Path(old["source"])
    old_target = pathlib.Path(old["cargo_target_dir"])
    old_binary = old_target / "release/dstack-vmm"
    candidate_binary = pathlib.Path(
        version["candidate"]["prepared_binaries"]["dstack_vmm"]["path"]
    )
    config = pathlib.Path(live["config"])
    log = pathlib.Path(live["log"])
    cli = list(live["cli_argv"])
    initial_pid = int(live["pid"])
    active: subprocess.Popen[bytes] | None = None
    created: list[str] = []
    evidence: dict[str, Any] = {
        "action": ACTION,
        "guest_rows": [],
        "private_material_exported": False,
    }
    status, failure = "FAIL", ""
    try:
        build = subprocess.run(
            ["cargo", "build", "--release", "-p", "dstack-vmm"],
            cwd=old_source,
            env={**os.environ, "CARGO_TARGET_DIR": str(old_target)},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=900,
            check=False,
        )
        if build.returncode or not old_binary.is_file():
            raise AssertionError(
                f"pinned v0.5.11 VMM preparation failed; output_sha256={hashlib.sha256(build.stdout).hexdigest()}"
            )
        evidence["binaries"] = {
            "old_commit": old["commit"],
            "old_sha256": hashlib.sha256(old_binary.read_bytes()).hexdigest(),
            "candidate_commit": version["candidate"]["commit"],
            "candidate_sha256": hashlib.sha256(
                candidate_binary.read_bytes()
            ).hexdigest(),
            "different": hashlib.sha256(old_binary.read_bytes()).digest()
            != hashlib.sha256(candidate_binary.read_bytes()).digest(),
        }
        if not evidence["binaries"]["different"]:
            raise AssertionError("old and candidate VMM binaries are identical")

        terminate(initial_pid)
        active = launch(old_binary, config, log)
        wait_cli(cli)
        matrix = SUPPORT.MatrixRun(CASE_ID, result_dir, manifest, runtime_path)
        kms = matrix.deploy(
            "0.5.11",
            initialized=True,
            domain_override="10-0-2-2.sslip.io",
            legacy_vmm_wire=True,
        )
        created.append(kms["vm_id"])
        guests = []
        for label, image in (
            ("v0.5.8-running", version["guest_images"]["0.5.8"]),
            ("v0.5.11-stopped", version["guest_images"]["0.5.11"]),
        ):
            row = matrix.deploy_client(
                [kms],
                identity=label,
                kms_encrypt_row=kms,
                guest_image=image,
                legacy_vmm_wire=True,
            )
            created.append(row["vm_id"])
            guests.append((label, row))
        stopped_id = guests[1][1]["vm_id"]
        SUPPORT.run([*cli, "stop", stopped_id, "--force"], timeout=120)
        before = {guests[0][0]: matrix.client_observation(guests[0][1])}
        old_inventory = wait_cli(cli)

        handoff(active)
        active = launch(candidate_binary, config, log)
        wait_cli(cli)
        reload_status = rpc_reload(str(live["url"]))
        if reload_status != 200:
            raise AssertionError(f"candidate ReloadVms returned HTTP {reload_status}")
        inventory = wait_cli(cli)
        by_id = {str(row.get("id")): row for row in inventory}
        if any(vm_id not in by_id for vm_id in created):
            raise AssertionError("candidate inventory omitted a persisted old Guest VM")
        stopped_status = str(by_id[stopped_id].get("status", "")).lower()
        if stopped_status != "stopped":
            raise AssertionError(
                f"stopped Guest changed state across upgrade: {stopped_status}"
            )
        after = {guests[0][0]: matrix.client_observation(guests[0][1])}
        if before[guests[0][0]].get("public_key_sha256") != after[guests[0][0]].get(
            "public_key_sha256"
        ):
            raise AssertionError(
                "running old Guest identity changed across VMM upgrade"
            )

        candidate_row = matrix.deploy_client(
            [kms],
            identity="candidate-running",
            kms_encrypt_row=kms,
            guest_image=version["guest_images"]["0.6.0-candidate"],
        )
        created.append(candidate_row["vm_id"])
        guests.append(("candidate-running", candidate_row))
        candidate_observation = matrix.client_observation(candidate_row)
        if not candidate_observation.get("public_key_sha256"):
            raise AssertionError("candidate VMM did not serve the new Guest")
        SUPPORT.run([*cli, "start", stopped_id], timeout=120)
        stopped_observation = matrix.client_observation(guests[1][1], timeout=180)
        SUPPORT.run([*cli, "stop", stopped_id, "--force"], timeout=120)
        SUPPORT.run([*cli, "start", stopped_id], timeout=120)
        repeated = matrix.client_observation(guests[1][1], timeout=180)
        if stopped_observation.get("public_key_sha256") != repeated.get(
            "public_key_sha256"
        ):
            raise AssertionError(
                "stopped Guest identity changed after candidate lifecycle operations"
            )
        evidence.update(
            {
                "old_inventory_count": len(old_inventory),
                "candidate_inventory_count": len(inventory),
                "reload_http": reload_status,
                "running_identity_stable": 1,
                "candidate_guest_created_after_upgrade": True,
                "stopped_state_preserved": True,
                "candidate_start_stop_start": True,
                "stopped_identity_stable": True,
                "guest_rows": [
                    {
                        "label": label,
                        "vm_id_sha256": hashlib.sha256(
                            row["vm_id"].encode()
                        ).hexdigest(),
                        "image": image,
                    }
                    for (label, row), image in zip(
                        guests,
                        (
                            version["guest_images"]["0.5.8"],
                            version["guest_images"]["0.5.11"],
                            version["guest_images"]["0.6.0-candidate"],
                        ),
                        strict=True,
                    )
                ],
            }
        )
        for vm_id in reversed(created):
            SUPPORT.run([*cli, "remove", vm_id], timeout=120)
        created.clear()
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        evidence["failure"] = failure
    finally:
        if status == "PASS" and active is not None:
            terminate(active.pid)

    evidence_path = artifacts / "vmm-rolling-upgrade.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/vmm-rolling-upgrade.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "VMM rolling upgrade matrix",
        "description": "Version hashes, mixed Guest states, public identity stability, lifecycle compatibility, and cleanup metadata.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "Pinned v0.5.11 VMM upgraded to candidate around three mixed Guest generations with stable running services, stopped state, identity, reload, and lifecycle operations"
        if status == "PASS"
        else failure
    )
    result = {
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
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Historical compilation prepares the pinned executable; it is not a build-correctness assertion. Failure retains the active VMM and mixed Guest state for direct debugging.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
