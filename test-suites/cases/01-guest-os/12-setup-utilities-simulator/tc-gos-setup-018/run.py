#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise dstack-util TDX event-log commands inside a mkosi guest."""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import time

CASE_ID = "tc-gos-setup-018"


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
    """Execute the event-log CLI matrix in the fixture-owned guest."""
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
    status = "FAIL"
    summary = "mkosi event-log suite did not execute"
    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "guest_image": image,
    }
    started = time.monotonic()
    try:
        if not ssh or values.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture omitted lease-owned guest SSH")
        env = runtime.get("environment") or {}
        store = pathlib.Path(str(env.get("DSTACK_TEST_IMAGE_STORE", "")))
        metadata = json.loads((store / image / "metadata.json").read_text())
        if metadata.get("builder") != "mkosi" or metadata.get("is_dev") is not True:
            raise RuntimeError("fixture did not boot a mkosi development image")
        evidence["mkosi"] = {
            k: metadata.get(k) for k in ("builder", "is_dev", "git_revision")
        }
        repo = pathlib.Path(str(runtime["repository"]))
        payloads = [
            (
                pathlib.Path(
                    runtime["prepared_binaries"]["dstack_tee_simulator"]["path"]
                ).read_bytes(),
                "/run/dstack-test-eventlog/dstack-tee-simulator",
            ),
            (
                pathlib.Path(
                    runtime["prepared_binaries"]["dstack_util"]["path"]
                ).read_bytes(),
                "/run/dstack-test-eventlog/dstack-util",
            ),
            (
                (
                    repo / "test-suites/shared/automation/tdx-eventlog-mkosi.sh"
                ).read_bytes(),
                "/run/dstack-test-eventlog/run-case",
            ),
        ]
        for data, target in payloads:
            cp = run(
                [
                    *ssh,
                    f"mkdir -p /run/dstack-test-eventlog && install -m 0755 /dev/stdin {target}",
                ],
                data=data,
                timeout=180,
            )
            if cp.returncode:
                raise RuntimeError(
                    f"guest install failed: {cp.stderr.decode(errors='replace')[-500:]}"
                )
        cp = run([*ssh, "/run/dstack-test-eventlog/run-case"], timeout=600)
        log = cp.stdout + cp.stderr
        (artifacts / "mkosi-eventlog.log").write_bytes(log)
        if cp.returncode:
            raise RuntimeError(
                f"mkosi event-log rc={cp.returncode}: {log.decode(errors='replace')[-1600:]}"
            )
        rows = [x for x in cp.stdout.decode().splitlines() if x.startswith("{")]
        matrix = json.loads(rows[-1])
        evidence["matrix"] = matrix
        expected = {
            "concurrent": 8,
            "permissions": "600",
            "replay_matches_live": True,
            "retry_exactly_once": True,
        }
        if (
            any(matrix.get(key) != value for key, value in expected.items())
            or not isinstance(matrix.get("fault_rc"), int)
            or matrix["fault_rc"] <= 0
            or not isinstance(matrix.get("invalid_rc"), int)
            or matrix["invalid_rc"] <= 0
        ):
            raise RuntimeError(f"unexpected matrix: {matrix}")
        status = "PASS"
        summary = "TDX event-log, extend, show, replay, negative, concurrent, fault, retry, and file-safety checks passed inside mkosi."
    except Exception as e:
        summary = f"{type(e).__name__}: {e}"
    finally:
        if ssh:
            evidence["cleanup_returncode"] = run(
                [
                    *ssh,
                    "bash",
                    "-lc",
                    "pkill -f /run/dstack-test-eventlog/dstack-tee-simulator 2>/dev/null || true; fusermount3 -uz /run/dstack-test-eventlog/report 2>/dev/null || true; rm -rf /run/dstack-test-eventlog /run/log/dstack",
                ],
                timeout=30,
            ).returncode
    evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    write_json(artifacts / "tdx-eventlog-mkosi.json", evidence)
    artifact = {
        "path": "artifacts/tdx-eventlog-mkosi.json",
        "step_id": f"{CASE_ID}-step-01",
        "name": "mkosi TDX event-log CLI suite",
        "description": "Guest provenance and event-log/RTMR cryptographic, negative, concurrency, fault, retry, permission, and cleanup evidence.",
    }
    write_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    observed = (
        summary
        if status == "FAIL"
        else "The lease-owned mkosi guest passed all event-log CLI modes and safety boundaries using the TDX simulator ABI."
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
                    "id": f"{CASE_ID}-step-{n:02d}",
                    "status": status,
                    "observed": observed,
                }
                for n in range(1, 4)
            ],
            "artifacts": [artifact],
            "remarks": "Simulator execution proves CLI encoding, RTMR extend/replay, ordering, errors, and file safety; it does not prove physical TDX isolation or firmware measurements.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
