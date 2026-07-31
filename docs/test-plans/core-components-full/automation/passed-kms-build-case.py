#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for the promoted KMS build gate."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-kms-build-001"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str]) -> dict[str, Any]:
    """Run one bounded build command."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=600,
        check=False,
    )
    output = completed.stdout[-12000:]
    return {
        "command": command,
        "returncode": completed.returncode,
        "output_bytes": len(completed.stdout.encode()),
        "output_tail_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_tail": output,
    }


def main() -> int:
    """Run the promoted KMS build case."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    workspace = repository / "dstack"
    env = os.environ.copy()
    target = runtime.get("cargo_target_dir") or runtime.get("shared_cargo_target")
    if target:
        env["CARGO_TARGET_DIR"] = str(target)

    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    if not pathlib.Path(cargo).is_file():
        raise RuntimeError("cargo executable is unavailable")
    commands = [
        [cargo, "build", "--locked", "-p", "dstack-kms"],
        [cargo, "test", "--locked", "-p", "dstack-kms"],
        [cargo, "build", "--locked", "--offline", "-p", "dstack-kms"],
        [cargo, "check", "--locked", "-p", "definitely-not-a-kms-package"],
    ]
    observations = [run(command, workspace, env) for command in commands]
    positive = all(item["returncode"] == 0 for item in observations[:3])
    negative = observations[3]["returncode"] != 0
    status = "PASS" if positive and negative else "FAIL"
    evidence = {
        "workspace": "dstack",
        "target_directory": env.get("CARGO_TARGET_DIR", "cargo-default"),
        "observations": observations,
        "checks": {"locked_build_test_offline": positive, "failure_gate": negative},
    }
    atomic_json(artifacts / "kms-build-regression.json", evidence)
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": (
            "Promoted KMS locked build, test, offline rebuild, and failure-detection gate passed."
            if status == "PASS"
            else "Promoted KMS build regression gate failed; inspect bounded command evidence."
        ),
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": "PASS" if positive else "FAIL",
                "observed": "Locked build/test and offline rebuild completed."
                if positive
                else "A locked build/test/offline command failed.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": "PASS" if negative else "FAIL",
                "observed": "Controlled invalid package gate failed closed."
                if negative
                else "Controlled invalid package gate was accepted.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": "PASS" if status == "PASS" else "FAIL",
                "observed": "Harness wrote bounded hashed build evidence without modifying source inputs.",
            },
        ],
        "artifacts": [
            {
                "path": "artifacts/kms-build-regression.json",
                "step_id": f"{case_id}-step-01",
                "name": "KMS build regression evidence",
                "description": "Bounded command status, output sizes, hashes, and tails for locked build/test, offline rebuild, and failure detection.",
            }
        ],
        "remarks": "Deterministic promoted build harness; no image build, service restart, or host mutation performed.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(artifacts / "manifest.json", {"artifacts": result["artifacts"]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
