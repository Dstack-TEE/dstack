#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise simulator selection and platform lifecycle inside a mkosi VM."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time

CASE_ID = "tc-gos-setup-017"


def run(
    argv: list[str], *, data: bytes | None = None, timeout: int = 60
) -> subprocess.CompletedProcess[bytes]:
    """Run one bounded command."""
    return subprocess.run(
        argv, input=data, capture_output=True, timeout=timeout, check=False
    )


def write_json(path: pathlib.Path, value: object) -> None:
    """Write deterministic JSON evidence."""
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    """Execute the complete platform matrix in the fixture-owned guest."""
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
    ssh = [str(x) for x in values.get("ssh_argv") or []]
    image = str(values.get("image", ""))
    env = runtime.get("environment") or {}
    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": image,
    }
    status = "FAIL"
    summary = "Platform lifecycle did not execute."
    started = time.monotonic()
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest SSH")
        expected = str(env.get("DSTACK_TEST_NO_TEE_GUEST_IMAGE", ""))
        store = pathlib.Path(str(env.get("DSTACK_TEST_IMAGE_STORE", "")))
        metadata = json.loads((store / image / "metadata.json").read_text())
        if (
            image != expected
            or metadata.get("backend") != "mkosi"
            or metadata.get("is_dev") is not True
        ):
            raise RuntimeError(
                "fixture did not boot the declared mkosi development image"
            )
        evidence["mkosi"] = {
            k: metadata.get(k) for k in ("backend", "is_dev", "git_revision")
        }
        repo = pathlib.Path(str(runtime["repository"]))
        script = (
            repo
            / "docs/test-plans/core-components-full/automation/simulator-platform-mkosi.sh"
        ).read_bytes()
        binary = pathlib.Path(
            str(runtime["prepared_binaries"]["dstack_tee_simulator"]["path"])
        ).read_bytes()
        for data, target in (
            (binary, "/run/dstack-test-platform/dstack-tee-simulator"),
            (script, "/run/dstack-test-platform/run-case"),
        ):
            done = run(
                [
                    *ssh,
                    f"mkdir -p /run/dstack-test-platform && install -m 0755 /dev/stdin {target}",
                ],
                data=data,
                timeout=180,
            )
            if done.returncode:
                raise RuntimeError(
                    f"guest install failed: {done.stderr.decode(errors='replace')[-500:]}"
                )
        done = run([*ssh, "/run/dstack-test-platform/run-case"], timeout=600)
        log = done.stdout + done.stderr
        (artifacts / "mkosi-platform-lifecycle.log").write_bytes(log)
        if done.returncode:
            raise RuntimeError(
                f"mkosi platform lifecycle rc={done.returncode}: {log.decode(errors='replace')[-1200:]}"
            )
        rows = [
            line for line in done.stdout.decode().splitlines() if line.startswith("{")
        ]
        matrix = json.loads(rows[-1])
        expected_platforms = {
            "dstack-tdx",
            "dstack-gcp-tdx",
            "dstack-amd-sev-snp",
            "dstack-nitro-enclave",
            "dstack-aws-nitro-tpm",
        }
        if (
            set(matrix.get("platforms", [])) != expected_platforms
            or matrix.get("concurrent_reads") != 32
            or matrix.get("adjacent_isolated") is not True
            or matrix.get("retry") is not True
        ):
            raise RuntimeError(f"incomplete platform matrix: {matrix}")
        evidence["matrix"] = matrix
        status = "PASS"
        summary = "All TeeVariant selection, mount, fault, concurrency, recovery, isolation, and cleanup checks passed inside mkosi."
    except Exception as error:
        summary = f"{type(error).__name__}: {error}"
    finally:
        if ssh:
            clean = run(
                [
                    *ssh,
                    "bash",
                    "-lc",
                    'pkill -f /run/dstack-test-platform/dstack-tee-simulator 2>/dev/null || true; for m in /run/dstack-test-platform/*; do fusermount3 -uz "$m" 2>/dev/null || true; done; rm -rf /run/dstack-test-platform',
                ],
                timeout=30,
            )
            evidence["cleanup_returncode"] = clean.returncode
            if clean.returncode and status == "PASS":
                status, summary = "FAIL", f"guest cleanup failed rc={clean.returncode}"
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    ep = artifacts / "simulator-platform-lifecycle.json"
    write_json(ep, evidence)
    artifact = {
        "path": "artifacts/simulator-platform-lifecycle.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "mkosi simulator platform lifecycle",
        "description": "Guest provenance, five TeeVariant rows, selection, fault, concurrency, isolation, and cleanup evidence.",
    }
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    observed = (
        summary
        if status == "FAIL"
        else "The mkosi guest passed all five TeeVariant rows, config and CLI selection, malformed/backend/duplicate failures, 32 concurrent reads, dependency recovery, adjacent identity, signals, and cleanup."
    )
    steps = [
        {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
        for n in range(1, 4)
    ]
    write_json(
        result / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "All rows execute in a lease-owned mkosi VM and confirm simulated functional behavior, not physical TEE isolation.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
