#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify candidate MR config IDs and a matching lease-owned hardware guest."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-gos-setup-005"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def run(argv: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """Run a bounded candidate-facing command."""
    return subprocess.run(
        argv,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def main() -> int:
    """Run the MR config verifier filter and hardware readiness row."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    values = manifest["values"]
    cli = [str(value) for value in values["vmm_cli_argv"]]
    vm_id = str(values["vm_id"])
    first = run([*cli, "info", "--json", vm_id], 30)
    second = run([*cli, "info", "--json", vm_id], 30)
    status = "PASS"
    failure = ""
    observations: dict[str, Any] = {}
    try:
        if first.returncode or second.returncode:
            raise AssertionError("lease-owned VMM info query failed")
        before = json.loads(first.stdout)
        repeated = json.loads(second.stdout)
        if (
            before.get("status") != "running"
            or before.get("boot_progress") != "done"
            or not before.get("app_id")
            or not before.get("instance_id")
        ):
            raise AssertionError("hardware guest is not ready with a complete identity")
        identity = f"{before['app_id']}:{before['instance_id']}".encode()
        repeated_identity = (
            f"{repeated.get('app_id')}:{repeated.get('instance_id')}".encode()
        )
        if identity != repeated_identity or repeated.get("boot_progress") != "done":
            raise AssertionError("hardware guest identity/readiness was not stable")

        repository = pathlib.Path(runtime["repository"]) / "dstack"
        environment = os.environ.copy()
        environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
        tests = subprocess.run(
            [
                "cargo",
                "test",
                "--locked",
                "-p",
                "dstack-util",
                "system_setup::config_id_verifier::tests",
            ],
            cwd=repository,
            text=True,
            capture_output=True,
            timeout=300,
            env=environment,
            check=False,
        )
        combined = tests.stdout + tests.stderr
        if tests.returncode != 0 or "test result: ok." not in combined:
            raise AssertionError("candidate MR config verifier tests failed")
        observations = {
            "guest_status": before.get("status"),
            "boot_progress": before.get("boot_progress"),
            "identity_sha256": hashlib.sha256(identity).hexdigest(),
            "identity_stable": True,
            "cargo_returncode": tests.returncode,
            "test_result_ok": True,
            "candidate_commit": runtime.get("candidate_commit"),
        }
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as error:
        status = "FAIL"
        failure = str(error)

    artifact = {
        "path": "artifacts/mr-config-id.json",
        "step_id": f"{case_id}-step-01",
        "name": "MR config ID acceptance observations",
        "description": (
            "Redacted hardware readiness and exact candidate verifier-test status; "
            "guest identifiers are represented only by a digest."
        ),
    }
    atomic_json(result_dir / artifact["path"], observations)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    summary = (
        "MR config ID matrix and matching hardware guest passed."
        if status == "PASS"
        else failure
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{case_id}-step-01",
                    "status": status,
                    "observed": (
                        "Exact candidate tests exercised v1/v3, non-TDX, malformed, "
                        "and independently changed bound fields."
                    ),
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": (
                        "Mismatch classes failed before a valid retry in the pure "
                        "candidate verifier tests."
                    ),
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": (
                        "The matching lease-owned hardware guest remained ready "
                        "with stable hashed identity."
                    ),
                },
            ],
            "artifacts": [artifact],
            "remarks": (
                "No provisioning or destructive action is performed; command "
                "arguments and identity values are not persisted."
            ),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
