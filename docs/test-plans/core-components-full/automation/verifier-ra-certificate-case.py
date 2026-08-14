#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run the current RA-TLS certificate and attestation-binding suite."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-cli-cert-o-002"
PACKAGE = "ra-tls"
REQUIRED_TESTS = (
    "attestation::tests::verify_der_rejects_attestation_not_bound_to_cert_key",
    "attestation::tests::verify_der_rejects_missing_attestation_extension",
    "cert::tests::test_csr_signing_and_verification",
    "cert::tests::test_cert_request_parses_ip_alt_names_as_ip_sans",
    "cert::tests::test_csr_v2_scale_encoding_stable_with_tdx_quote",
    "cert::tests::test_invalid_confirm_word",
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
    """Execute the exact source-defined download-security test."""
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
    row: dict[str, Any] = {"package": PACKAGE, "tests": REQUIRED_TESTS}
    status = "PASS"
    summary = (
        "RA-TLS certificate, CSR, key binding, and attestation-extension suite passed."
    )
    try:
        completed = subprocess.run(
            [
                find_command(environment, "cargo"),
                "test",
                "-p",
                PACKAGE,
                "--lib",
                "--",
                "--nocapture",
            ],
            cwd=repository / "dstack",
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
        output = completed.stdout + completed.stderr
        passed = bool(re.search(r"test result: ok\. 16 passed; 0 failed", output)) and all(
            f"{test} ... ok" in output for test in REQUIRED_TESTS
        )
        row.update(
            {
                "returncode": completed.returncode,
                "passed": passed,
                "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
            }
        )
        if completed.returncode or not passed:
            raise AssertionError(
                f"{PACKAGE} certificate suite failed with rc={completed.returncode}"
            )
    except (AssertionError, KeyError, OSError, subprocess.TimeoutExpired) as error:
        status = "FAIL"
        summary = str(error)

    evidence = {
        "candidate_commit": runtime.get("candidate_commit"),
        "row": row,
        "covered_behaviors": [
            "valid_csr_signature",
            "ip_subject_alt_name_parsing",
            "leaf_key_attestation_binding",
            "missing_attestation_rejection",
            "stable_tdx_quote_csr_encoding",
            "invalid_confirmation_rejection",
        ],
    }
    artifact = {
        "path": "artifacts/ra-certificate-mutation-matrix.json",
        "step_id": f"{case_id}-step-02",
        "name": "RA certificate binding matrix",
        "description": "Exact test identity, return code, covered behaviors, and hashed output.",
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
                    "observed": "The candidate source and prepared Cargo target were selected.",
                },
                {
                    "id": f"{case_id}-step-02",
                    "status": status,
                    "observed": "CSR signatures, IP SAN parsing, stable quote encoding, certificate-key binding, missing attestation, and invalid confirmation were exercised.",
                },
                {
                    "id": f"{case_id}-step-03",
                    "status": status,
                    "observed": "Evidence retains the exact test identity, return code, behavior list, and output hash.",
                },
            ],
            "artifacts": [artifact],
            "remarks": "The mock TDX PKI and PCCS exercise production certificate and attestation verification; physical TDX origin is outside simulator claims.",
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
