#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Observe the no-TEE early host-share and simulator boot ordering."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gos-boot-and-i-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically to the requested result path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a bounded command and retain its output for diagnosis."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )


def main() -> int:
    """Observe early host-share ordering for the leased no-TEE guest."""
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
    values = manifest["values"]
    vm_id = str(values["vm_id"])
    info_argv = [*map(str, values["vmm_cli_argv"]), "info", "--json", vm_id]
    refresh_argv = [*map(str, values["serial_log_refresh_argv"])]
    serial_path = pathlib.Path(values["serial_log"])
    initial = values.get("boot_observation") or {}
    statuses: list[str] = [str(initial.get("boot_progress", ""))]
    serial = ""
    final: dict[str, Any] = {}
    status = "PASS"
    failure = ""
    try:
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            refreshed = run(refresh_argv, 30)
            if refreshed.returncode:
                raise AssertionError("failed to refresh lease guest serial log")
            temporary = serial_path.with_suffix(".refresh")
            temporary.write_text(refreshed.stdout, encoding="utf-8")
            temporary.replace(serial_path)
            serial = refreshed.stdout
            queried = run(info_argv, 30)
            if queried.returncode:
                raise AssertionError("failed to query lease VM boot state")
            final = json.loads(queried.stdout)
            progress = str(final.get("boot_progress", ""))
            if not statuses or statuses[-1] != progress:
                statuses.append(progress)
            if final.get("boot_error"):
                raise AssertionError(
                    f"no-TEE guest reported boot error: {final.get('boot_error')}"
                )
            if progress == "done":
                break
            time.sleep(2)
        else:
            raise AssertionError("no-TEE guest did not reach boot_progress=done")

        plain_serial = re.sub(r"\x1b\[[0-9;]*m", "", serial)
        mount_markers = [
            plain_serial.find("mounted host-shared via 9p"),
            plain_serial.find("mounted host-shared disk"),
        ]
        mount_index = min(index for index in mount_markers if index >= 0)
        ready_events = [
            match
            for match in re.finditer(r"[^\n]*simulator[^\n]*", plain_serial, re.I)
            if all(
                marker in match.group().lower()
                for marker in ["started", "dstack", "development", "tee", "abi"]
            )
        ]
        if not ready_events:
            raise AssertionError("serial log lacks simulator ready marker")
        if len(ready_events) != 1:
            raise AssertionError("simulator entered a duplicate/restart loop")
        if mount_index >= ready_events[0].start():
            raise AssertionError(
                "simulator became ready before early host share mounted"
            )
        if not final.get("instance_id") or not final.get("app_id"):
            raise AssertionError("ready no-TEE guest lacks stable identity")

        repository = pathlib.Path(runtime["repository"])
        unit = (
            repository
            / "os/yocto/layers/meta-dstack/recipes-core/dstack-tee-simulator/files/dstack-tee-simulator.service"
        ).read_text()
        required = [
            "Before=dstack-prepare.service",
            "test -f /run/dstack/tee-simulator-host-shared/.tee-simulator.json",
            "ExecStartPost=-/usr/bin/dstack-util host-shared unmount",
            "ExecStopPost=-/usr/bin/dstack-util host-shared unmount",
            "Restart=on-failure",
        ]
        missing = [marker for marker in required if marker not in unit]
        if missing:
            raise AssertionError(f"candidate early-share unit is missing {missing}")
        app_source = (repository / "dstack/vmm/src/app.rs").read_text()
        if "failed to remove stale TEE simulator config" not in app_source:
            raise AssertionError(
                "candidate does not remove invalid stale simulator config"
            )

        identity = f"{final['app_id']}:{final['instance_id']}"
        observations = {
            "candidate_commit": runtime.get("candidate_commit"),
            "initial_boot_progress": initial.get("boot_progress"),
            "boot_progress_sequence": statuses,
            "mount_before_ready": True,
            "simulator_ready_count": 1,
            "identity_sha256": hashlib.sha256(identity.encode()).hexdigest(),
            "serial_sha256": hashlib.sha256(serial.encode()).hexdigest(),
            "boot_error": False,
            "unit_cleanup_guards": len(required),
        }
    except (
        AssertionError,
        KeyError,
        OSError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        status = "FAIL"
        failure = str(error)
        plain_serial = re.sub(r"\x1b\[[0-9;]*m", "", serial)
        observations = {
            "candidate_commit": runtime.get("candidate_commit"),
            "boot_progress_sequence": statuses,
            "serial_bytes": len(serial.encode()),
            "serial_lines": len(serial.splitlines()),
            "serial_marker_counts": {
                marker: plain_serial.lower().count(marker)
                for marker in ["host-shared", "simulator", "starting", "started"]
            },
            "simulator_event_features": [
                {
                    marker: marker in line.lower()
                    for marker in [
                        "started",
                        "starting",
                        "failed",
                        "dstack",
                        "development",
                        "tee",
                        "abi",
                    ]
                }
                for line in plain_serial.splitlines()
                if "simulator" in line.lower()
            ],
            "serial_sha256": hashlib.sha256(serial.encode()).hexdigest(),
        }

    artifact = {
        "path": "artifacts/early-host-share.json",
        "step_id": f"{case_id}-step-01",
        "name": "Early host-share boot observations",
        "description": "Hashed serial and ordered boot observations without configuration contents.",
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    summary = (
        "No-TEE early host share mounted before one successful simulator startup."
        if status == "PASS"
        else failure
    )
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
                    "observed": "The lease VM baseline and early boot progress were polled without requiring ready-state provisioning.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Serial ordering proved read-only host-share mount preceded one simulator-ready event.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Ready identity, absence of boot error/restart loop, stale-config rejection, and unit unmount guards were checked.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The fixture manager owns removal of the lease VM; no physical host operation is issued.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
