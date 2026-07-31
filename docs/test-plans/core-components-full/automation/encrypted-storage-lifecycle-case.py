#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify lease-owned encrypted storage rejection and restart persistence."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gos-storage-an-001"


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


def run(argv: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a bounded command with retained output."""
    return subprocess.run(
        argv, text=True, capture_output=True, timeout=timeout, check=False
    )


def query(argv: list[str]) -> dict[str, Any]:
    """Read lease VM state."""
    completed = run(argv, 30)
    if completed.returncode:
        raise AssertionError("failed to query lease VM")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise AssertionError("lease VM query returned non-object")
    return value


def ssh(
    ssh_argv: list[str], script: str, timeout: int = 60
) -> subprocess.CompletedProcess[str]:
    """Run a bounded script inside the lease guest."""
    return subprocess.run(
        [*ssh_argv, "bash", "-s"],
        input=script,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def main() -> int:
    """Run encrypted storage lifecycle acceptance."""
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
    values = manifest.get("values", {})
    storage = values.get("storage_lifecycle")
    status = "PASS"
    summary = (
        "Encrypted lease storage rejected a wrong key and persisted across restart."
    )
    observations: dict[str, Any] = {"candidate_commit": runtime.get("candidate_commit")}
    marker_path = ""
    try:
        if (
            not isinstance(storage, dict)
            or not storage.get("destructive_actions_allowed")
            or not values.get("destructive_actions_allowed")
            or not isinstance(values.get("ssh_argv"), list)
        ):
            status = "BLOCKED"
            summary = (
                "fixture lacks destructive lease-owned storage lifecycle capability"
            )
            observations["missing_capability"] = "encrypted-storage-lifecycle"
        else:
            ssh_argv = [*map(str, values["ssh_argv"])]
            marker_dir = str(storage["persistent_marker_dir"])
            device = str(storage["encrypted_device"])
            marker_name = (
                "dstack-test-"
                + hashlib.sha256(os.environ["DSTACK_TEST_RUN_ID"].encode()).hexdigest()[
                    :20
                ]
            )
            marker_value = hashlib.sha256(
                (marker_name + "-persistent").encode()
            ).hexdigest()
            marker_path = marker_dir.rstrip("/") + "/" + marker_name
            probe = ssh(
                ssh_argv,
                f"""set -eu
test -d {marker_dir}
test -b {device}
cryptsetup isLuks {device}
source=$(findmnt -n -o SOURCE {marker_dir})
fstype=$(findmnt -n -o FSTYPE {marker_dir})
printf '%s\\n%s\\n' "$source" "$fstype"
if head -c 32 /dev/urandom | cryptsetup open --test-passphrase --key-file - {device}; then
    exit 42
fi
printf %s {marker_value} > {marker_path}
sync
""",
            )
            if probe.returncode == 42:
                raise AssertionError("wrong storage key was accepted")
            if probe.returncode:
                raise AssertionError("encrypted storage prerequisite probe failed")
            lines = probe.stdout.splitlines()
            if len(lines) != 2 or not all(lines):
                raise AssertionError("persistent mount metadata was incomplete")

            stopped = run([*map(str, storage["stop_argv"])], 180)
            if stopped.returncode:
                raise AssertionError("failed to stop lease VM")
            deadline = time.monotonic() + 90
            state = query([*map(str, storage["info_argv"])])
            while state.get("status") == "running" and time.monotonic() < deadline:
                time.sleep(1)
                state = query([*map(str, storage["info_argv"])])
            if state.get("status") == "running":
                raise AssertionError("lease VM did not stop")
            stopped_status = state.get("status")

            started = run([*map(str, storage["start_argv"])], 180)
            if started.returncode:
                raise AssertionError("failed to start lease VM")
            deadline = time.monotonic() + 180
            state = query([*map(str, storage["info_argv"])])
            while time.monotonic() < deadline:
                if (
                    state.get("status") == "running"
                    and state.get("boot_progress") == "done"
                ):
                    reachable = run([*ssh_argv, "true"], 20)
                    if reachable.returncode == 0:
                        break
                time.sleep(2)
                state = query([*map(str, storage["info_argv"])])
            else:
                raise AssertionError("restarted lease VM did not become ready")

            verified = ssh(
                ssh_argv,
                f"""set -eu
test "$(cat {marker_path})" = {marker_value}
cryptsetup isLuks {device}
rm -f {marker_path}
sync
""",
            )
            if verified.returncode:
                raise AssertionError(
                    "persistent marker or encryption check failed after restart"
                )
            marker_path = ""
            observations.update(
                {
                    "encrypted_device": device,
                    "luks_detected": True,
                    "wrong_key_rejected": True,
                    "persistent_mount_source": lines[0],
                    "persistent_filesystem": lines[1],
                    "marker_sha256": hashlib.sha256(marker_value.encode()).hexdigest(),
                    "stopped_status": stopped_status,
                    "restart_boot_progress": state.get("boot_progress"),
                    "ssh_reconnected": True,
                    "marker_persisted": True,
                    "marker_removed": True,
                }
            )
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
        if marker_path and isinstance(values.get("ssh_argv"), list):
            ssh([*map(str, values["ssh_argv"])], f"rm -f {marker_path}\n", 20)

    artifact = {
        "path": "artifacts/encrypted-storage-lifecycle.json",
        "step_id": f"{case_id}-step-01",
        "name": "Encrypted storage lifecycle",
        "description": "Redacted device, mount, wrong-key, restart, and marker-hash observations.",
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
                    "observed": "Lease storage, LUKS, mount, and wrong-key rejection were checked.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "A non-secret marker was written before lease VM stop and start.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Encryption, marker persistence, reconnect, and cleanup were verified.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Only the lease VM is stopped and started; the physical host is never rebooted.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
