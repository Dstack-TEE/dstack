#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise labeled-disk priority, 9p fallback, faults, recovery, and cleanup."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-platform-003"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 180
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def vm_ids(argv: list[str]) -> list[str]:
    """Return the stable VMM inventory identifiers."""
    completed = run(argv, timeout=30)
    if completed.returncode:
        raise RuntimeError("failed to observe adjacent VM inventory")
    value = json.loads(completed.stdout)
    rows = value if isinstance(value, list) else value.get("vms", [])
    return sorted(
        str(row.get("id")) for row in rows if isinstance(row, dict) and row.get("id")
    )


def main() -> int:
    """Run the host-shared source lifecycle."""
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values") or {}
    ssh = [str(value) for value in values.get("ssh_argv") or []]
    list_vms = [str(value) for value in values.get("list_vms_argv") or []]
    status = "PASS"
    summary = "Host-shared labeled-disk and 9p lifecycle passed."
    evidence: dict[str, Any] = {}
    try:
        if (
            not ssh
            or not list_vms
            or values.get("destructive_actions_allowed") is not True
        ):
            raise RuntimeError("fixture omitted lease-owned guest controls")
        before = vm_ids(list_vms)
        script = (
            pathlib.Path(str(runtime["repository"]))
            / "docs/test-plans/core-components-full/automation/host-shared-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-host-shared-lifecycle"],
            data=script.read_bytes(),
        )
        if installed.returncode:
            raise RuntimeError("failed to install host-shared lifecycle")
        executed = run([*ssh, "/run/dstack-test-host-shared-lifecycle"], timeout=240)
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / "host-shared-lifecycle.log").write_bytes(
            executed.stdout + executed.stderr
        )
        rows = [
            row
            for row in executed.stdout.decode(errors="replace").splitlines()
            if row.startswith("{")
        ]
        if executed.returncode or not rows:
            tail = (executed.stdout + executed.stderr).decode(errors="replace")[-2000:]
            raise RuntimeError(
                f"host-shared lifecycle rc={executed.returncode}: {tail}"
            )
        evidence = json.loads(rows[-1])
        required = (
            "disk_source",
            "disk_read_only",
            "invalid_disk_fallback_9p",
            "nine_p_content_hash_matched",
            "duplicate_unmount_rejected",
            "dependency_fault_rejected",
            "dependency_recovery",
            "invalid_target_rejected",
            "mount_count_restored",
        )
        if evidence.get("checks", 0) < 24 or not all(
            evidence.get(key) is True for key in required
        ):
            raise RuntimeError("host-shared evidence omitted a required row")
        after = vm_ids(list_vms)
        if before != after or str(values.get("vm_id")) not in after:
            raise RuntimeError("adjacent VM inventory changed")
        evidence["adjacent_vm_inventory_stable"] = True
        evidence["inventory_size"] = len(after)
    except (
        KeyError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        status = "FAIL"
        summary = f"{type(error).__name__}: {error}"
    artifact_entries = [
        {
            "path": "artifacts/host-shared-lifecycle.json",
            "step_id": f"{CASE_ID}-step-01",
            "name": "Host-shared lifecycle matrix",
            "description": "Boolean and count evidence for labeled-disk priority, read-only policy, 9p fallback, dependency faults, recovery, isolation, and cleanup.",
        },
        {
            "path": "artifacts/host-shared-lifecycle.log",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Host-shared native log",
            "description": "Native bounded lifecycle output; shared configuration content is represented only by an in-guest equality check.",
        },
    ]
    atomic_json(artifacts / "host-shared-lifecycle.json", evidence)
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_entries})
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "A DSTACKSHR loop disk took priority and mounted read-only."
                    if status == "PASS"
                    else summary,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "An invalid labeled disk fell back to the case-owned 9p source; injected mount failure was atomic and recovered."
                    if status == "PASS"
                    else summary,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "Duplicate unmount and invalid target failed closed; loops, mounts, files, and adjacent VM inventory returned to baseline."
                    if status == "PASS"
                    else summary,
                },
            ],
            "artifacts": artifact_entries,
            "remarks": "No host-shared file content is persisted; the harness records only equality booleans and counts.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
