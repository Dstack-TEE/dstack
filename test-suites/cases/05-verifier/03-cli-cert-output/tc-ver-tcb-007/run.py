#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the five-platform canonical TCB and auth-policy matrix."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-tcb-007"
ROWS = (
    (
        "five-platform-policy-table",
        [
            "cargo",
            "test",
            "-p",
            "dstack-verifier",
            "tcb_policy_fields_map_each_platform_to_its_own_tcb_source",
            "--lib",
        ],
        "simulation",
    ),
    (
        "tdx-collateral-tcb-outage-recovery",
        [
            "cargo",
            "test",
            "-p",
            "mock-attestation",
            "tdx_quote_collateral_and_tcb_matrix",
            "--lib",
        ],
        "simulation",
    ),
    (
        "sev-snp-hardware-captured-evidence",
        [
            "cargo",
            "test",
            "-p",
            "dstack-attest",
            "--test",
            "sev_snp_verify",
            "verify_sev_snp_attestation_bin",
        ],
        "hardware-captured",
    ),
    (
        "nitro-enclave-hardware-captured-evidence",
        [
            "cargo",
            "test",
            "-p",
            "dstack-attest",
            "--test",
            "nitro_verify",
            "verify_nitro_attestation_bin",
        ],
        "hardware-captured",
    ),
    (
        "gcp-tdx-and-nitro-binding",
        [
            "cargo",
            "test",
            "-p",
            "dstack-verifier",
            "gcp_and_nitro_enclave_measurement_bindings_matrix",
            "--lib",
        ],
        "simulation",
    ),
    (
        "conflicting-top-level-input",
        [
            "cargo",
            "test",
            "-p",
            "dstack-verifier",
            "attestation_fixture_ignores_conflicting_top_level_inputs",
            "--lib",
        ],
        "hardware-captured",
    ),
    (
        "tdx-cross-identity-event-replay",
        [
            "cargo",
            "test",
            "-p",
            "cc-eventlog",
            "rejects_noncanonical_v2_preimage_with_matching_digest",
            "--lib",
        ],
        "simulation",
    ),
    (
        "boot-info-auth-payload",
        [
            "cargo",
            "test",
            "-p",
            "dstack-verifier",
            "policy_boot_info_serializes_as_auth_payload",
            "--lib",
        ],
        "simulation",
    ),
)


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def find_command(environment: dict[str, str], command: str) -> str:
    """Resolve a required command from PATH."""
    for directory in environment.get("PATH", "").split(os.pathsep):
        candidate = pathlib.Path(directory) / command
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    raise OSError(f"required command is unavailable: {command}")


def main() -> int:
    """Execute every exact source-defined TCB policy row."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repository = pathlib.Path(runtime["repository"])
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = (
        "Five-platform TCB, advisory, failure, recovery, and auth-policy matrix passed."
    )
    stage = "baseline"
    try:
        cargo = find_command(environment, "cargo")
        for name, argv, evidence_kind in ROWS:
            stage = name
            command = [cargo, *argv[1:]]
            completed = subprocess.run(
                command,
                cwd=repository / "dstack",
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=300,
                check=False,
            )
            output = completed.stdout + completed.stderr
            passed = bool(re.search(r"test result: ok\. 1 passed; 0 failed", output))
            rows.append(
                {
                    "name": name,
                    "test_filter": command[-2]
                    if command[-1] == "--lib"
                    else command[-1],
                    "evidence_kind": evidence_kind,
                    "returncode": completed.returncode,
                    "passed": passed,
                    "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
                }
            )
            if completed.returncode or not passed:
                raise AssertionError(f"{name} failed with rc={completed.returncode}")
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = f"{stage}: {error}"

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "rows": rows,
        "platforms": ["tdx", "gcp-tdx", "sev-snp", "nitro-tpm", "nitro-enclave"],
        "covered_behaviors": [
            "platform_specific_tcb_source_mapping",
            "advisory_propagation",
            "nitro_tpm_normalized_up_to_date",
            "nitro_enclave_no_tcb_fail_closed",
            "canonical_report_over_conflicting_top_level_input",
            "hardware_captured_snp_and_nitro_signature_verification",
            "tdx_collateral_signature_expiry_outage_and_recovery",
            "noncanonical_event_preimage_rejection",
            "boot_info_auth_payload_projection",
        ],
    }
    artifact = {
        "path": "artifacts/five-platform-tcb-policy-matrix.json",
        "step_id": f"{case_id}-step-01",
        "name": "Five-platform TCB policy matrix",
        "description": "Exact test identities, evidence kinds, row results, and hashed outputs.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
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
                    "observed": f"{len(rows)} exact tests and seven internal TCB decision rows executed.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "Signed/captured evidence and simulator rows independently covered the platform trust and policy bindings.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Collateral outage/recovery, conflicting input, and cross-identity event replay rows executed without persisted state.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "Captured hardware evidence verifies SNP and Nitro Enclave signatures. Mock TDX and functional GCP/NitroTPM rows validate encoding and policy behavior but do not claim physical origin for those simulated rows.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
