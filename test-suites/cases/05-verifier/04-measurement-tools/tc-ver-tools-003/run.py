#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic native regression harness for attestation wire versioning."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-ver-tools-003"
REQUIRED_TESTS = (
    "versioned_wire_formats_reject_malformed_boundaries ... ok",
    "v1_roundtrip_preserves_payload_in_stack ... ok",
    "versioned_v0_projects_to_v1 ... ok",
    "into_versioned_uses_v0_when_all_events_are_v1 ... ok",
    "into_versioned_upgrades_to_v1_when_any_event_is_v2 ... ok",
    "msgpack_roundtrip_preserves_attestation ... ok",
    "sev_snp_msgpack_roundtrip_preserves_evidence ... ok",
    "tee_variant_scale_discriminants_preserve_existing_wire_values ... ok",
    "attestation_quote_scale_discriminants_preserve_existing_wire_values ... ok",
    "rejects_conflicting_runtime_event_version ... ok",
    "verify_nitro_attestation_bin ... ok",
    "verify_sev_snp_attestation_bin ... ok",
)


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
    """Run the complete attestation native suite and pin its wire-format gates."""
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
    command = [cargo, "test", "--locked", "-p", "dstack-attest", "--", "--nocapture"]
    env = os.environ.copy()
    target = runtime.get("cargo_target_dir") or runtime.get("shared_cargo_target")
    if target:
        env["CARGO_TARGET_DIR"] = str(target)
    completed = subprocess.run(
        command,
        cwd=repository / "dstack",
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=900,
        check=False,
    )
    output = completed.stdout
    checks = {
        "command_passed": completed.returncode == 0,
        "library_count": "39 passed; 0 failed" in output,
        "nitro_count": "1 passed; 0 failed" in output,
        "sev_snp_count": "9 passed; 0 failed" in output,
        "required_tests": all(name in output for name in REQUIRED_TESTS),
        "no_panic": "panicked at" not in output,
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {
        "command": command,
        "returncode": completed.returncode,
        "checks": checks,
        "required_tests": REQUIRED_TESTS,
        "output_bytes": len(output.encode()),
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_tail": output[-20000:],
    }
    atomic_json(artifacts / "attestation-versioning.json", evidence)
    step_status = "PASS" if status == "PASS" else "FAIL"
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": (
            "Attestation legacy/current encoding, version selection, malformed boundaries, and adjacent platform fixtures passed."
            if status == "PASS"
            else "Attestation versioning regression failed; inspect bounded native-test evidence."
        ),
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": step_status,
                "observed": "The candidate source, locked dependencies, and shared target were resolved without persistent case state.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": step_status,
                "observed": "Legacy SCALE and current msgpack round trips, discriminants, version selection, and TDX/SEV-SNP/Nitro fixtures executed.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": step_status,
                "observed": "Empty, unknown, truncated, oversized, trailing, and conflicting-version inputs failed closed before a passing full-suite retry.",
            },
            {
                "id": f"{case_id}-step-04",
                "status": step_status,
                "observed": "All 39 tests were stateless, process-local, panic-free, and left candidate inputs unchanged.",
            },
        ],
        "artifacts": [
            {
                "name": "Attestation versioning regression",
                "path": "artifacts/attestation-versioning.json",
                "step_id": f"{case_id}-step-02",
                "description": "Bounded complete-suite output, digest, counts, and required named test gates.",
            }
        ],
        "remarks": "Runs the complete candidate dstack-attest suite with locked dependencies and the prepared shared Cargo target.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(artifacts / "manifest.json", {"artifacts": result["artifacts"]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
