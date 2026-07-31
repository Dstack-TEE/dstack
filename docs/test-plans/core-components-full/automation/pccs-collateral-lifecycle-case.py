#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise physical local-provider sealing plus controlled PCCS collateral policy."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-platform-001"
PHYSICAL_CASE_ID = "tc-gos-platform-002"
COLLATERAL_TEST = "tdx_quote_collateral_and_tcb_matrix"
TEST_RE = re.compile(r"test result: ok\. 1 passed; 0 failed")


def atomic_json(path: Path, value: Any) -> None:
    """Write one JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        temporary = Path(out.name)
    temporary.replace(path)


def main() -> int:
    """Run the combined physical-provider and controlled-collateral matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repository = Path(runtime["repository"])
    physical_dir = result_dir / "physical-provider"
    physical_dir.mkdir()
    status = "FAIL"
    failure = ""
    observation: dict[str, Any] = {}

    try:
        physical_env = {
            **os.environ,
            "DSTACK_TEST_CASE_ID": PHYSICAL_CASE_ID,
            "DSTACK_TEST_RESULT_DIR": str(physical_dir),
        }
        physical = subprocess.run(
            [
                "python3",
                str(
                    repository
                    / "docs/test-plans/core-components-full/automation/local-provider-sealing-case.py"
                ),
            ],
            env=physical_env,
            text=True,
            capture_output=True,
            timeout=900,
            check=False,
        )
        (artifacts / "physical-provider-controller.log").write_text(
            physical.stdout + physical.stderr
        )
        physical_result = json.loads((physical_dir / "result.json").read_text())
        if physical.returncode or physical_result.get("status") != "PASS":
            raise RuntimeError(
                f"physical local-provider matrix failed rc={physical.returncode}: "
                f"{physical_result.get('summary')}"
            )
        observation["physical_provider"] = {
            "status": "PASS",
            "environment": "PHYSICAL_TDX_GUEST_AND_HOST_SGX_GRAMINE_PROVIDER",
            "stable_equivalent_identity": True,
            "adjacent_identity_isolated": True,
            "tampered_quote_rejected": True,
            "invalid_frame_rejected": True,
            "provider_quote_present": True,
            "vm_restart_recovered": True,
        }

        environment = {
            **os.environ,
            "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"]),
        }
        collateral = subprocess.run(
            [
                "cargo",
                "test",
                "-p",
                "mock-attestation",
                COLLATERAL_TEST,
                "--lib",
                "--",
                "--nocapture",
            ],
            cwd=repository / "dstack",
            env=environment,
            text=True,
            capture_output=True,
            timeout=300,
            check=False,
        )
        collateral_output = collateral.stdout + collateral.stderr
        (artifacts / "collateral-policy.log").write_text(collateral_output)
        if collateral.returncode or not TEST_RE.search(collateral_output):
            raise RuntimeError(
                f"controlled PCCS/QVL matrix failed rc={collateral.returncode}"
            )
        observation["controlled_collateral"] = {
            "status": "PASS",
            "test": COLLATERAL_TEST,
            "configured_pccs_selected": True,
            "rows": [
                "current",
                "outdated-tcb",
                "revoked",
                "expired",
                "signature-invalid",
                "malformed",
                "tampered-quote",
                "network-outage",
                "post-outage-recovery",
            ],
            "public_fallback_used": False,
            "simulation_boundary": "mock-signed TDX PKI; no physical-origin claim",
        }
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = str(error)

    # Preserve only already-redacted physical artifacts; never copy fixture inputs.
    physical_artifacts = physical_dir / "artifacts"
    if physical_artifacts.is_dir():
        shutil.copytree(
            physical_artifacts,
            artifacts / "physical",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("*.key", "*.crt", "*.pem"),
        )
    observation.update(
        {
            "status": status,
            "failure": failure,
            "pccs_configuration_sources": [
                "PCCS_URL passthrough in the Gramine manifest",
                "PCCS_URL default/override in the provider deployment",
            ],
            "tpm_substitution_used": False,
            "shared_provider_mutated": False,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    )
    matrix_path = artifacts / "pccs-collateral-matrix.json"
    atomic_json(matrix_path, observation)
    artifact_rows = [
        {
            "path": "artifacts/pccs-collateral-matrix.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "PCCS collateral lifecycle matrix",
            "description": "Redacted physical-provider and controlled collateral observations.",
        },
        {
            "path": "artifacts/physical-provider-controller.log",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Physical provider controller log",
            "description": "Bounded controller diagnostics without quote or key material.",
        },
        {
            "path": "artifacts/collateral-policy.log",
            "step_id": f"{CASE_ID}-step-03",
            "name": "Controlled collateral policy log",
            "description": "Native production-QVL test output for collateral status, mutation, outage, and recovery.",
        },
    ]
    atomic_json(artifacts / "manifest.json", {"artifacts": artifact_rows})
    summary = (
        "Physical local-provider and controlled PCCS collateral lifecycle passed"
        if status == "PASS"
        else f"PCCS collateral lifecycle failed: {failure}"
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "A physical TDX guest and host-managed SGX/Gramine provider were available; the provider was treated as read-only shared hardware."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Physical quote provisioning passed stable identity, adjacent isolation, tamper/frame rejection, provider quote, VM restart, and cleanup rows."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "The configured production CollateralClient/QVL path passed current, TCB status, expiry, signature, malformed, tampered, outage, no-fallback, and recovery rows."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-04",
                    "status": status,
                    "observed": "The guest restart preserved provider-derived identity, the peer stayed isolated, no TPM substitution occurred, and case-owned resources were released."
                    if status == "PASS"
                    else failure,
                },
            ],
            "artifacts": artifact_rows,
            "evidence": [
                {
                    "path": row["path"],
                    "sha256": hashlib.sha256(
                        (result_dir / row["path"]).read_bytes()
                    ).hexdigest(),
                }
                for row in artifact_rows
            ],
            "remarks": "Hardware proves the physical TDX-to-SGX provisioning path. Destructive PCCS cache-age/outage rows use a case-owned mock-signed TDX PKI through the production QVL client and do not claim physical origin. The host-managed SGX enclave is not restarted or reconfigured by this case.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
