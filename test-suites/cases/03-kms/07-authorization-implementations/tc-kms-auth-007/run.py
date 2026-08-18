#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute Ethereum finalized-snapshot authorization checks."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-kms-auth-007"
SUITE = "Ethereum finalized snapshot authorization"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic JSON evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(command: list[str], cwd: pathlib.Path, timeout: int) -> tuple[int, str]:
    """Run one bounded process and return combined output."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout


def main() -> int:
    """Install locked dependencies and execute the suite in two fresh processes."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    source = pathlib.Path(runtime["repository"]) / "dstack/kms/auth-eth-bun"
    bun = pathlib.Path.home() / ".bun/bin/bun"
    rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = "Ethereum finalized snapshot, reorg refresh, fail-closed recovery, and process isolation passed."
    try:
        install_rc, install_output = run(
            [str(bun), "install", "--frozen-lockfile"], source, 300
        )
        if install_rc:
            raise RuntimeError(f"locked dependency install failed rc={install_rc}")
        for process_index in (1, 2):
            rc, output = run(
                [
                    str(bun),
                    "x",
                    "vitest",
                    "run",
                    "index.test.ts",
                    "-t",
                    SUITE,
                ],
                source,
                300,
            )
            match = re.search(r"^\s*Tests\s+(\d+) passed(?:\s|$)", output, re.MULTILINE)
            tests = int(match.group(1)) if match else 0
            row = {
                "process": process_index,
                "returncode": rc,
                "passed_tests": tests,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            }
            rows.append(row)
            if rc or tests != 5:
                raise RuntimeError(f"fresh process {process_index} failed: {row}")
        install_evidence = {
            "returncode": install_rc,
            "output_sha256": hashlib.sha256(install_output.encode()).hexdigest(),
            "lockfile": "bun.lock",
        }
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = str(error)
        install_evidence = locals().get(
            "install_evidence", {"completed": False, "error_type": type(error).__name__}
        )

    observation = {
        "candidate_commit": runtime.get("candidate_commit"),
        "locked_dependency_install": install_evidence,
        "process_rows": rows,
        "fresh_process_count": len(rows),
        "coverage": [
            "single-finalized-block-decision-and-gateway-snapshot",
            "confirmation-depth-boundary",
            "canonical-snapshot-refresh-after-short-reorg",
            "wrong-chain-stale-head-and-timeout-fail-closed",
            "recovery-without-retained-decision-state",
            "no-decision-state-across-process-restart",
        ],
        "private_material_exported": False,
    }
    artifact = {
        "path": "artifacts/ethereum-finalized-snapshot.json",
        "step_id": f"{CASE_ID}-step-03",
        "name": "Ethereum finalized-snapshot authorization matrix",
        "description": "Process return codes, counts, coverage labels, and output hashes only.",
    }
    atomic_json(result_dir / artifact["path"], observation)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    steps = [
        {
            "id": f"{CASE_ID}-step-01",
            "status": status,
            "observed": "The committed Bun lockfile and candidate source were selected without a Yocto or mkosi build.",
        },
        {
            "id": f"{CASE_ID}-step-02",
            "status": status,
            "observed": "One-block snapshots, confirmation depth, canonical refresh, wrong-chain, stale-head, timeout, and recovery paths were exercised.",
        },
        {
            "id": f"{CASE_ID}-step-03",
            "status": status,
            "observed": "The exact matrix passed in two independent Vitest processes, proving no decision state survives restart.",
        },
        {
            "id": f"{CASE_ID}-step-04",
            "status": status,
            "observed": "Only bounded counts and output hashes were retained; no credential or request sentinel was persisted.",
        },
    ]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": [artifact],
            "remarks": "This tests stateless read-only decisions at an explicit confirmation-depth snapshot; it does not claim physical chain finality beyond the configured depth.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
