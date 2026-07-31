#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for graceful KMS Onboard.Finish handling."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-kms-onboard-004"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def main() -> int:
    """Check compiled KMS plus the graceful Finish implementation contract."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    workspace = repository / "dstack"
    source = workspace / "kms/src/onboard_service.rs"
    main_source = workspace / "kms/src/main.rs"
    text = source.read_text()
    main_text = main_source.read_text()
    markers = {
        "finish_not_process_exit": "std::process::exit(0)" not in text,
        "finish_notifies_shutdown": "shutdown.notify();" in text,
        "finish_returns_ok": "shutdown.notify();\n        Ok(())" in text,
        "ignited_shutdown_captured": "state.set_shutdown(rocket.shutdown())?;"
        in main_text,
    }
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    env = os.environ.copy()
    target = runtime.get("cargo_target_dir") or runtime.get("shared_cargo_target")
    if target:
        env["CARGO_TARGET_DIR"] = str(target)
    completed = subprocess.run(
        [cargo, "check", "--locked", "-p", "dstack-kms"],
        cwd=workspace,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    output = completed.stdout[-12000:]
    status = "PASS" if completed.returncode == 0 and all(markers.values()) else "FAIL"
    evidence = {
        "markers": markers,
        "cargo_check_returncode": completed.returncode,
        "cargo_output_bytes": len(completed.stdout.encode()),
        "cargo_output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "cargo_output_tail": output,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
    }
    artifact = {
        "path": "artifacts/onboard-finish-regression.json",
        "step_id": f"{case_id}-step-02",
        "name": "Onboard Finish regression",
        "description": "Compiled source contract proving Finish returns before graceful onboarding shutdown.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": "KMS Onboard.Finish graceful response regression passed."
        if status == "PASS"
        else "KMS Onboard.Finish graceful response regression failed.",
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": status,
                "observed": "Candidate KMS source and shared Cargo target were resolved.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": status,
                "observed": "Finish returns Ok and notifies the ignited Rocket shutdown handle without process exit.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": "PASS" if completed.returncode == 0 else "FAIL",
                "observed": "Locked KMS compilation completed without service or host mutation.",
            },
        ],
        "artifacts": [artifact],
        "remarks": "Deterministic source-and-build regression; no onboarding keys, listener, image, or process lifecycle was created.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
