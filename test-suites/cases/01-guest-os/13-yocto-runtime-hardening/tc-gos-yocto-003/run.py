#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise chrony failure and recovery inside a lease-owned mkosi guest."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time

CASE_ID = "tc-gos-yocto-003"


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded controller or guest command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def write_json(path: pathlib.Path, value: object) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    """Run the complete lease-owned mkosi chrony lifecycle."""
    result = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    values = manifest.get("values") or {}
    ssh = [str(item) for item in values.get("ssh_argv") or []]
    image = str(values.get("image", ""))
    status = "FAIL"
    summary = "mkosi chrony lifecycle did not execute"
    evidence: dict[str, object] = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": image,
    }
    started = time.monotonic()
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest SSH")
        store = pathlib.Path(
            str((runtime.get("environment") or {}).get("DSTACK_TEST_IMAGE_STORE", ""))
        )
        metadata = json.loads((store / image / "metadata.json").read_text())
        if metadata.get("builder") != "mkosi" or metadata.get("is_dev") is not True:
            raise RuntimeError("fixture did not boot a mkosi development image")
        evidence["mkosi"] = {
            key: metadata.get(key) for key in ("builder", "is_dev", "git_revision")
        }
        script = (
            pathlib.Path(str(runtime["repository"]))
            / "test-suites/shared/automation/mkosi-chrony-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-chrony"],
            data=script.read_bytes(),
            timeout=180,
        )
        if installed.returncode:
            raise RuntimeError(
                f"guest script install failed: {installed.stderr.decode(errors='replace')[-500:]}"
            )
        list_vms = [str(item) for item in values.get("list_vms_argv") or []]
        if not list_vms:
            raise RuntimeError("fixture omitted adjacent VM inventory observer")
        inventory_before = run(list_vms, timeout=30)
        if inventory_before.returncode:
            raise RuntimeError("baseline VM inventory query failed")
        completed = run([*ssh, "/run/dstack-test-chrony"], timeout=300)
        log = completed.stdout + completed.stderr
        (artifacts / "mkosi-chrony.log").write_bytes(log)
        if completed.returncode:
            raise RuntimeError(
                f"mkosi chrony rc={completed.returncode}: {log.decode(errors='replace')[-1600:]}"
            )
        rows = [
            line
            for line in completed.stdout.decode().splitlines()
            if line.startswith("{")
        ]
        matrix = json.loads(rows[-1])
        inventory_after = run(list_vms, timeout=30)
        if inventory_after.returncode:
            raise RuntimeError("recovery VM inventory query failed")
        before_rows = json.loads(inventory_before.stdout)
        after_rows = json.loads(inventory_after.stdout)
        before_ids = sorted(
            str(row.get("id")) for row in before_rows if isinstance(row, dict)
        )
        after_ids = sorted(
            str(row.get("id")) for row in after_rows if isinstance(row, dict)
        )
        matrix["inventory_stable"] = before_ids == after_ids
        evidence["inventory"] = {
            "before_count": len(before_ids),
            "after_count": len(after_ids),
        }
        evidence["matrix"] = matrix
        required = (
            "baseline_active",
            "stop_observed",
            "unreachable_source_observed",
            "concurrent_restart",
            "recovered_active",
            "config_restored",
            "inventory_stable",
            "cleanup",
        )
        if any(matrix.get(key) is not True for key in required):
            raise RuntimeError(f"unexpected chrony matrix: {matrix}")
        status = "PASS"
        summary = "Chrony baseline, outage, concurrent restart, recovery, configuration restoration, and adjacent-VM isolation passed inside mkosi."
    except Exception as error:
        summary = f"{type(error).__name__}: {error}"
    finally:
        if ssh:
            evidence["cleanup_returncode"] = run(
                [*ssh, "rm -f /run/dstack-test-chrony"], timeout=30
            ).returncode
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    write_json(artifacts / "mkosi-chrony.json", evidence)
    artifact = {
        "path": "artifacts/mkosi-chrony.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "mkosi chrony lifecycle",
        "description": "Guest provenance and redacted chrony baseline, outage, concurrency, recovery, isolation, and cleanup evidence.",
    }
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    observed = (
        summary
        if status == "FAIL"
        else "The lease-owned mkosi guest restored its exact chrony configuration and healthy service state after controlled local faults."
    )
    write_json(
        result / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-{number:02d}",
                    "status": status,
                    "observed": observed,
                }
                for number in range(1, 4)
            ],
            "artifacts": [artifact],
            "remarks": "The mkosi simulator guest proves chrony configuration, service, dependency-fault, recovery, and isolation behavior; it does not prove a physical TEE clock source.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
