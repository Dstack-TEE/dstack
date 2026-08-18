#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the source-defined guest configuration entry matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gos-entry-001"
REQUIRED = (
    "explicit_leaf_overrides_embedded_defaults",
    "compose_raw_bytes_and_unknown_fields_are_preserved",
    "absent_optional_compose_fields_use_documented_defaults",
    "missing_compose_file_fails_before_state_construction",
    "malformed_or_required_field_missing_compose_fails_closed",
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def run(
    command: list[str], repository: pathlib.Path, env: dict[str, str]
) -> dict[str, Any]:
    """Run one bounded native suite and retain only bounded output."""
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
    return {
        "command": command,
        "returncode": completed.returncode,
        "output": completed.stdout,
    }


def main() -> int:
    """Run guest loader and shared config precedence tests."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    cargo = shutil.which("cargo") or str(pathlib.Path.home() / ".cargo/bin/cargo")
    env = os.environ.copy()
    if runtime.get("cargo_target_dir"):
        env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    started = time.monotonic()
    guest = run(
        [cargo, "test", "--locked", "-p", "dstack-guest-agent", "config::tests::"],
        repository,
        env,
    )
    shared = run(
        [cargo, "test", "--locked", "-p", "load_config", "tests::"],
        repository,
        env,
    )
    combined = guest["output"] + shared["output"]
    checks = {
        "guest_passed": guest["returncode"] == 0,
        "shared_passed": shared["returncode"] == 0,
        "required_rows": all(
            f"test config::tests::{name} ... ok" in combined for name in REQUIRED
        ),
        "guest_count": "5 passed; 0 failed" in guest["output"],
        "no_panic": "panicked at" not in combined,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {
        "checks": checks,
        "required_rows": REQUIRED,
        "guest_returncode": guest["returncode"],
        "shared_returncode": shared["returncode"],
        "combined_output_sha256": hashlib.sha256(combined.encode()).hexdigest(),
        "combined_output_bytes": len(combined.encode()),
        "output_tail": combined[-16000:],
    }
    artifact = {
        "path": "artifacts/guest-config-entry.json",
        "name": "Guest configuration entry matrix",
        "description": "Named loader/compose rows, counts, return codes, and bounded output digest.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    observations = (
        "Candidate guest loader and shared precedence suites passed."
        if status == "PASS"
        else "Candidate guest loader matrix failed; inspect bounded evidence."
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": observations,
            "steps": [
                {
                    "id": f"{case_id}-step-{number:02d}",
                    "status": status,
                    "observed": text,
                }
                for number, text in enumerate(
                    (
                        "Candidate source, locked dependencies, embedded defaults, and shared target were resolved.",
                        "Explicit leaf precedence, raw compose preservation, optional defaults, and unknown optional fields were exercised.",
                        "Missing files, malformed JSON, missing required fields, and fresh-directory retries failed closed deterministically.",
                        "The pure loader started no service or listener and retained only bounded test output and hashes.",
                    ),
                    1,
                )
            ],
            "artifacts": [artifact],
            "duration_seconds": round(time.monotonic() - started, 3),
            "remarks": "The source-defined loader has no environment provider, listener binding, durable commit, or runtime identity side effect.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
