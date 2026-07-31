#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise stargz integrity, fault handling, restart/cache, and explicit fallback."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
from typing import Any

CASE_ID = "tc-gos-yocto-004"


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    """Run a bounded command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def main() -> int:
    """Run the real mkosi stargz lifecycle matrix."""
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
    fixture = values.get("stargz_lifecycle") or {}
    ssh = [str(value) for value in values.get("ssh_argv") or []]
    status = "PASS"
    summary = "Containerd stargz integrity and explicit fallback lifecycle passed."
    evidence: dict[str, Any] = {}
    try:
        required = (
            "payload_image",
            "payload_image_id",
            "registry_image",
            "registry_image_id",
            "snapshotter_unit",
            "snapshotter_name",
        )
        if not ssh or any(not fixture.get(key) for key in required):
            raise RuntimeError("fixture omitted pinned stargz substrate")
        if values.get("image") != runtime.get("environment", {}).get(
            "DSTACK_TEST_GUEST_IMAGE"
        ):
            raise RuntimeError(
                "fixture did not select the prepared mkosi production image"
            )
        script = (
            pathlib.Path(str(runtime["repository"]))
            / "docs/test-plans/core-components-full/automation/stargz-integrity-lifecycle.sh"
        )
        installed = run(
            [*ssh, "install -m 0755 /dev/stdin /run/dstack-test-stargz-lifecycle"],
            data=script.read_bytes(),
        )
        if installed.returncode:
            raise RuntimeError("lifecycle script installation failed")
        executed = run(
            [
                *ssh,
                "/run/dstack-test-stargz-lifecycle",
                str(fixture["payload_image"]),
                str(fixture["payload_image_id"]),
                str(fixture["registry_image"]),
                str(fixture["registry_image_id"]),
                str(fixture["snapshotter_unit"]),
                str(fixture["snapshotter_name"]),
            ],
            timeout=300,
        )
        (artifacts / "stargz-lifecycle.log").write_bytes(
            executed.stdout + executed.stderr
        )
        rows = [
            row
            for row in executed.stdout.decode(errors="replace").splitlines()
            if row.startswith("{")
        ]
        if executed.returncode or not rows:
            tail = (executed.stdout + executed.stderr).decode(errors="replace")[-2000:]
            raise RuntimeError(f"lifecycle rc={executed.returncode}: {tail}")
        evidence = json.loads(rows[-1])
        required_checks = {
            "overlay_baseline",
            "lazy_execution",
            "restart_recovery",
            "overlay_cache_outage",
            "unavailable_registry_rejected",
            "corrupt_layer_rejected",
            "snapshotter_outage_rejected",
            "explicit_overlay_fallback",
        }
        if not all(evidence.get(key) is True for key in required_checks):
            raise RuntimeError("lifecycle evidence omitted a required successful row")
        if (
            evidence.get("concurrent_pulls") != 2
            or evidence.get("silent_fallback_claimed") is not False
        ):
            raise RuntimeError("concurrency or fallback semantics were not proven")
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
            "path": "artifacts/stargz-lifecycle.json",
            "step_id": f"{CASE_ID}-step-01",
            "name": "Stargz lifecycle matrix",
            "description": "Pinned digests and booleans for overlay baseline, lazy execution, concurrency, restart/cache, corruption and outage rejection, and explicit fallback.",
        },
        {
            "path": "artifacts/stargz-lifecycle.log",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Stargz native lifecycle log",
            "description": "Native bounded command output for the case-scoped registry and snapshotter lifecycle; no credentials are used.",
        },
    ]
    atomic_json(artifacts / "stargz-lifecycle.json", evidence)
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_entries})
    steps = [
        {
            "id": f"{CASE_ID}-step-01",
            "status": status,
            "observed": "Verified normal overlay and optimized eStargz execution with two concurrent pulls."
            if status == "PASS"
            else summary,
        },
        {
            "id": f"{CASE_ID}-step-02",
            "status": status,
            "observed": "Registry outage, corrupted layer, and stopped snapshotter failed closed; restart recovered."
            if status == "PASS"
            else summary,
        },
        {
            "id": f"{CASE_ID}-step-03",
            "status": status,
            "observed": "Stargz execution recovered after restart, overlay cache survived registry outage, and explicit fallback remained isolated; cleanup restored the packaged unit gate."
            if status == "PASS"
            else summary,
        },
    ]
    atomic_json(
        result / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifact_entries,
            "remarks": "Stargz content integrity is OCI digest verification. The product exposes an explicit caller-selected overlay fallback; this case does not claim silent automatic fallback.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
