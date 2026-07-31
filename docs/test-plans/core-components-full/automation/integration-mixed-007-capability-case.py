#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise optional and unknown protobuf fields across every pinned release."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-int-mixed-007"
RELEASES = ("v0.5.4", "v0.5.8", "v0.5.11")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic JSON evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    """Run the shared wire controller once for every pinned release."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    controller = pathlib.Path(__file__).with_name(
        "integration-compatibility-006-capability-case.py"
    )
    rows: list[dict[str, Any]] = []
    artifact_rows: list[dict[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="dstack-mixed-rpc-") as temporary:
        for release in RELEASES:
            release_result = pathlib.Path(temporary) / release.removeprefix("v")
            release_result.mkdir()
            environment = {
                **os.environ,
                "DSTACK_TEST_RESULT_DIR": str(release_result),
                "DSTACK_RPC_COMPAT_CASE_ID": CASE_ID,
                "DSTACK_RPC_COMPAT_RELEASE": release,
            }
            completed = subprocess.run(
                [str(controller)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=180,
                check=False,
            )
            result_path = release_result / "result.json"
            if completed.returncode or not result_path.is_file():
                raise RuntimeError(
                    f"{release} wire controller failed rc={completed.returncode}: "
                    f"{completed.stdout[-1000:]}"
                )
            result = json.loads(result_path.read_text())
            source = release_result / "artifacts/rpc-wire-compatibility.json"
            if result.get("status") != "PASS" or not source.is_file():
                raise RuntimeError(f"{release} wire matrix did not pass")
            target_name = f"rpc-wire-compatibility-{release.removeprefix('v')}.json"
            target = artifacts / target_name
            shutil.copyfile(source, target)
            evidence = json.loads(target.read_text())
            rows.append(
                {
                    "release": release,
                    "status": "PASS",
                    "counts": evidence["counts"],
                    "sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
                }
            )
            artifact_rows.append(
                {
                    "path": f"artifacts/{target_name}",
                    "name": f"{release} to current RPC wire matrix",
                    "description": "Shared methods/messages plus optional, unknown, malformed, and recovery rows.",
                }
            )
    summary_path = artifacts / "mixed-rpc-wire-summary.json"
    totals = {
        key: sum(int(row["counts"].get(key, 0)) for row in rows)
        for key in (
            "shared_service_methods",
            "shared_messages",
            "current_optional_scalar_fields",
            "unknown_field_acceptance_checks",
            "malformed_field_rejection_checks",
            "post_error_recovery_checks",
        )
    }
    atomic_json(
        summary_path, {"case_id": CASE_ID, "release_rows": rows, "totals": totals}
    )
    summary_artifact = {
        "path": "artifacts/mixed-rpc-wire-summary.json",
        "name": "Pinned-release RPC wire summary",
        "description": "Aggregate counts and immutable hashes for all pinned-release matrices.",
    }
    all_artifacts = [summary_artifact, *artifact_rows]
    atomic_json(artifacts / "manifest.json", {"artifacts": all_artifacts})
    observed = (
        f"All {len(RELEASES)} pinned releases passed: "
        f"{totals['shared_service_methods']} shared method rows, "
        f"{totals['shared_messages']} shared message rows, and "
        f"{totals['current_optional_scalar_fields']} optional-field rows."
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": "PASS",
            "summary": "Pinned-release optional and unknown protobuf compatibility passed",
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": "PASS",
                    "observed": "All pinned and current proto generations compiled.",
                },
                {"id": f"{CASE_ID}-step-02", "status": "PASS", "observed": observed},
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": "PASS",
                    "observed": "Optional presence and unknown-field handling remained release-scoped and deterministic.",
                },
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": "PASS",
                    "observed": "Malformed fields failed closed and each decoder recovered on the next valid request.",
                },
            ],
            "artifacts": all_artifacts,
            "evidence": [
                {
                    "path": summary_artifact["path"],
                    "sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "The matrix uses immutable pinned/current schemas and protoc wire codecs; no persistent state, VM, or credentials are created.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
