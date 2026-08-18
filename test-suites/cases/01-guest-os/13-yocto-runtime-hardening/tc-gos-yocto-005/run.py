#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Sysbox services, nested containers, fault closure, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import time

CASE_ID = "tc-gos-yocto-005"


def run(argv, *, data=None, timeout=60):
    """Run one bounded host or guest command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def write(path, value):
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main():
    """Execute the complete lease-owned Sysbox lifecycle."""
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
    fixture = values.get("sysbox_lifecycle") or {}
    ssh = [str(x) for x in values.get("ssh_argv") or []]
    status = "FAIL"
    summary = "Sysbox lifecycle did not execute"
    started = time.monotonic()
    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": values.get("image"),
    }
    try:
        required = (
            "nested_workload_image",
            "nested_workload_image_digest",
            "nested_workload_image_id",
            "nested_payload_image",
            "nested_payload_image_digest",
            "nested_payload_image_id",
            "service_units",
            "runtime_name",
        )
        if (
            not ssh
            or values.get("destructive_actions_allowed") is not True
            or fixture.get("destructive_actions_allowed") is not True
        ):
            raise RuntimeError("fixture omitted lease-owned destructive guest control")
        if any(not fixture.get(k) for k in required):
            raise RuntimeError("fixture omitted pinned Sysbox lifecycle inputs")
        store = pathlib.Path(
            str((runtime.get("environment") or {}).get("DSTACK_TEST_IMAGE_STORE", ""))
        )
        metadata = json.loads(
            (store / str(values["image"]) / "metadata.json").read_text()
        )
        if metadata.get("backend") != "mkosi":
            raise RuntimeError("fixture did not boot a mkosi image")
        evidence["mkosi"] = {
            k: metadata.get(k) for k in ("backend", "is_dev", "git_revision")
        }
        script = (
            pathlib.Path(str(runtime["repository"]))
            / "test-suites/shared/automation/sysbox-boundary-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-sysbox-case"],
            data=script.read_bytes(),
            timeout=60,
        )
        if installed.returncode:
            raise RuntimeError("guest script installation failed")
        list_vms = [str(x) for x in values.get("list_vms_argv") or []]
        before = run(list_vms, timeout=30)
        if before.returncode:
            raise RuntimeError("baseline VM inventory query failed")
        args = [
            fixture[k]
            for k in (
                "nested_workload_image",
                "nested_workload_image_digest",
                "nested_workload_image_id",
                "nested_payload_image",
                "nested_payload_image_digest",
                "nested_payload_image_id",
            )
        ]
        completed = run(
            [*ssh, "/run/dstack-test-sysbox-case", *map(str, args)], timeout=300
        )
        (artifacts / "sysbox-lifecycle.log").write_bytes(
            completed.stdout + completed.stderr
        )
        if completed.returncode:
            raise RuntimeError(
                f"guest lifecycle rc={completed.returncode}: {(completed.stdout + completed.stderr).decode(errors='replace')[-1200:]}"
            )
        rows = [x for x in completed.stdout.decode().splitlines() if x.startswith("{")]
        matrix = json.loads(rows[-1])
        after = run(list_vms, timeout=30)
        if after.returncode:
            raise RuntimeError("recovery VM inventory query failed")

        def ids(blob):
            return sorted(
                str(x.get("id")) for x in json.loads(blob) if isinstance(x, dict)
            )

        matrix["inventory_stable"] = ids(before.stdout) == ids(after.stdout)
        required_rows = (
            "baseline",
            "lifecycle",
            "nested_boundary",
            "failure_closed",
            "partial_recovery_closed",
            "recovered",
            "cleanup",
            "inventory_stable",
        )
        if any(matrix.get(k) is not True for k in required_rows):
            raise RuntimeError(f"unexpected Sysbox matrix: {matrix}")
        evidence["matrix"] = matrix
        status = "PASS"
        summary = "Sysbox baseline, remapped lifecycle, true nested container boundary, failure closure, recovery, cleanup, and adjacent-VM isolation passed."
    except Exception as error:
        summary = f"{type(error).__name__}: {error}"
    finally:
        if ssh:
            evidence["cleanup_returncode"] = run(
                [
                    *ssh,
                    "docker rm -f sysbox-case-outer sysbox-case-fast sysbox-case-fault >/dev/null 2>&1 || true; systemctl start sysbox-mgr.service sysbox-fs.service sysbox.service; rm -rf /run/dstack-test-sysbox /run/dstack-test-sysbox-case",
                ],
                timeout=60,
            ).returncode
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    path = artifacts / "sysbox-boundary-lifecycle.json"
    write(path, evidence)
    artifact = {
        "path": "artifacts/sysbox-boundary-lifecycle.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Sysbox boundary lifecycle",
        "description": "Redacted mkosi provenance, remapping, nested workload, fault closure, recovery, cleanup, and adjacent-VM evidence.",
    }
    write(artifacts / "manifest.json", {"artifacts": [artifact]})
    write(
        result / "result.json",
        {
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
                    "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "The test protects the physical host, VMM control plane, agent sockets, and /dev/kvm. Guest-scoped /dev/tdx_guest and guest virtual disks are intentionally not treated as physical-host devices.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
