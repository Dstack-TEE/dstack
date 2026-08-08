#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate verifier compatibility across evidence generations."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
from typing import Any

SUPPORTED = {"tc-int-compatibil-005", "tc-int-mixed-005"}
ROWS = (
    (
        "dstack-attest",
        "versioned_wire_formats_reject_malformed_boundaries",
        "old-current-envelope-and-unknown-wire-version",
    ),
    ("dstack-attest", "versioned_v0_projects_to_v1", "legacy-envelope-projection"),
    (
        "dstack-attest",
        "into_versioned_uses_v0_when_all_events_are_v1",
        "legacy-event-log-selection",
    ),
    (
        "dstack-attest",
        "into_versioned_upgrades_to_v1_when_any_event_is_v2",
        "current-event-log-selection",
    ),
    (
        "dstack-attest",
        "v1_conversion_rejects_lossy_legacy_projection",
        "downgrade-rejection",
    ),
    (
        "dstack-verifier",
        "deserializes_quote_subset_without_attestation",
        "legacy-quote-event-log-vm-config-request",
    ),
    (
        "dstack-verifier",
        "deserializes_attestation_subset_without_quote",
        "current-versioned-attestation-request",
    ),
    (
        "dstack-verifier",
        "attestation_fixture_ignores_conflicting_top_level_inputs",
        "authenticated-envelope-precedence",
    ),
    (
        "dstack-verifier",
        "image_paths_must_be_confined_and_manifest_paths_must_be_flat",
        "image-manifest-policy",
    ),
    (
        "ra-tls",
        "test_csr_signing_and_verification",
        "attested-certificate-compatibility",
    ),
)
PASS_RE = re.compile(r"test result: ok\. 1 passed; 0 failed")


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write deterministic JSON evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def main() -> int:
    """Run the exact candidate evidence-compatibility matrix."""
    case_id = os.environ.get("DSTACK_TEST_CASE_ID", "")
    if case_id not in SUPPORTED:
        raise SystemExit("unsupported case")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(str(runtime["repository"]))
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    observations: list[dict[str, Any]] = []
    status = "PASS"
    failure = ""
    for package, test, contract in ROWS:
        command = [
            "cargo",
            "test",
            "-p",
            package,
            test,
            "--lib",
            "--",
            "--nocapture",
        ]
        completed = subprocess.run(
            command,
            cwd=repository / "dstack",
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        log = completed.stdout
        log_path = artifacts / f"{len(observations) + 1:02d}-{package}-{test}.log"
        log_path.write_text(log)
        passed = completed.returncode == 0 and PASS_RE.search(log) is not None
        observations.append(
            {
                "package": package,
                "test": test,
                "contract": contract,
                "returncode": completed.returncode,
                "passed": passed,
                "output_sha256": hashlib.sha256(log.encode()).hexdigest(),
            }
        )
        if not passed:
            status = "FAIL"
            failure = f"{package}::{test} did not pass its exact candidate test"
            break
    matrix_path = artifacts / "verifier-evidence-compatibility.json"
    atomic_json(
        matrix_path,
        {
            "candidate_commit": runtime.get("candidate_commit"),
            "rows": observations,
            "passed": sum(int(row["passed"]) for row in observations),
            "expected": len(ROWS),
            "private_material_persisted": False,
            "duration_seconds": round(time.monotonic() - started, 3),
        },
    )
    artifact = {
        "path": "artifacts/verifier-evidence-compatibility.json",
        "name": "Verifier evidence compatibility matrix",
        "description": "Exact candidate-code results for legacy/current envelopes, event logs, vm_config precedence, image manifests, certificates, and downgrade rejection.",
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    passed_count = sum(int(row["passed"]) for row in observations)
    observed = f"Candidate compatibility rows passed {passed_count}/{len(ROWS)}."
    steps = [
        {
            "id": f"{case_id}-step-01",
            "status": status,
            "observed": "Candidate verifier dependencies and exact test inventory were resolved from the prepared runtime."
            if status == "PASS"
            else failure,
        },
        {
            "id": f"{case_id}-step-02",
            "status": status,
            "observed": observed if status == "PASS" else failure,
        },
        {
            "id": f"{case_id}-step-03",
            "status": status,
            "observed": "Unknown/malformed formats and lossy downgrade paths fail closed; authenticated envelope data takes precedence over conflicting unauthenticated inputs."
            if status == "PASS"
            else failure,
        },
    ]
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": case_id,
            "provisional": False,
            "status": status,
            "summary": "Verifier evidence-version compatibility passed"
            if status == "PASS"
            else failure,
            "steps": steps,
            "artifacts": [artifact],
            "evidence": [
                {
                    "path": artifact["path"],
                    "sha256": hashlib.sha256(matrix_path.read_bytes()).hexdigest(),
                }
            ],
            "remarks": "This UNIT-minimum case executes candidate product code against legacy and current in-memory evidence corpora. It does not claim a physical TEE signature for synthetic compatibility rows.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
