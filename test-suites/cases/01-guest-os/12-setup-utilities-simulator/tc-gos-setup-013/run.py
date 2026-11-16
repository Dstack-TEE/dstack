#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic native and process harness for the TDX simulator ABI."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-setup-013"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", dir=path.parent, delete=False, encoding="utf-8"
    ) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def main() -> int:
    """Run TDX state, input-boundary, and process-lifecycle tests."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    commands = [
        [
            cargo,
            "test",
            "--locked",
            "-p",
            "dstack-tee-simulator",
            "tdx::tests",
            "--",
            "--nocapture",
        ],
        [
            cargo,
            "test",
            "--locked",
            "-p",
            "dstack-tee-simulator",
            "--test",
            "process_e2e",
            "separate_simulator_process_imports_config_seed_for_tsm_platforms",
            "--",
            "--nocapture",
        ],
    ]
    env = os.environ.copy()
    target = runtime.get("cargo_target_dir") or runtime.get("shared_cargo_target")
    if target:
        env["CARGO_TARGET_DIR"] = str(target)
    observations: list[dict[str, Any]] = []
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=repository / "dstack",
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
            check=False,
        )
        output = completed.stdout
        observations.append(
            {
                "command": command,
                "returncode": completed.returncode,
                "output_bytes": len(output.encode()),
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                "output_tail": output[-12000:],
            }
        )
    combined = "\n".join(item["output_tail"] for item in observations)
    checks = {
        "commands_passed": all(item["returncode"] == 0 for item in observations),
        "state_tests_passed": (
            "test result: ok." in observations[0]["output_tail"]
            and "0 failed" in observations[0]["output_tail"]
        ),
        "process_test_passed": "1 passed; 0 failed" in observations[1]["output_tail"],
        "named_boundaries_executed": all(
            name in combined
            for name in (
                "tdx::tests::state_updates_are_failure_atomic ... ok",
                "tdx::tests::quote_tracks_report_data_and_rtmr_extensions ... ok",
                "tdx::tests::only_rtmr_two_and_three_are_extensible ... ok",
                "separate_simulator_process_imports_config_seed_for_tsm_platforms ... ok",
            )
        ),
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {"checks": checks, "observations": observations}
    atomic_json(artifacts / "tdx-simulator-abi.json", evidence)
    step_status = "PASS" if status == "PASS" else "FAIL"
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": (
            "TDX simulator state, filesystem boundary, evidence, and process lifecycle matrix passed."
            if status == "PASS"
            else "TDX simulator regression matrix failed; inspect bounded evidence."
        ),
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": step_status,
                "observed": "Quote, report-data, RTMR, CCEL replay, generation overflow, and length boundaries were exercised.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": step_status,
                "observed": "Invalid inputs preserved quote, generation, and RTMR state before a valid retry.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": step_status,
                "observed": "A separate simulator process imported the configured seed, emitted verifiable evidence, and was reaped.",
            },
        ],
        "artifacts": [
            {
                "name": "TDX simulator ABI regression",
                "path": "artifacts/tdx-simulator-abi.json",
                "step_id": f"{case_id}-step-01",
                "description": "Bounded native and process-test outputs with digests and named checks.",
            }
        ],
        "remarks": "Uses the candidate source and prepared shared Cargo target; the process guard terminates every spawned simulator.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(artifacts / "manifest.json", {"artifacts": result["artifacts"]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
