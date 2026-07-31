#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the candidate VMM against every pinned Guest image."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import sys
from typing import Any

CASE_ID = "tc-int-mixed-001"
GUESTS = ("0.5.4", "0.5.8", "0.5.11", "0.6.0-candidate")


def support() -> Any:
    """Load the shared physical-TDX version matrix controller."""
    path = pathlib.Path(__file__).with_name("kms_upgrade_matrix_case.py")
    spec = importlib.util.spec_from_file_location("mixed_guest_matrix", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load version matrix support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = support()


def main() -> int:
    """Boot and restart all pinned Guests under the candidate VMM."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime_path = pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"])
    matrix = SUPPORT.MatrixRun(CASE_ID, result_dir, manifest, runtime_path)
    values = manifest["values"]["version_matrix"]
    evidence: dict[str, Any] = {
        "candidate_commit": values["candidate"]["commit"],
        "guest_rows": [],
        "private_material_exported": False,
    }
    created: list[str] = []
    status = "FAIL"
    failure = ""
    try:
        kms = matrix.deploy(
            "candidate", initialized=True, domain_override="10-0-2-2.sslip.io"
        )
        created.append(kms["vm_id"])
        rows: list[tuple[str, dict[str, Any]]] = []
        for version in GUESTS:
            guest = matrix.deploy_client(
                [kms],
                identity=f"mixed-{version}",
                kms_encrypt_row=kms,
                guest_image=values["guest_images"][version],
                legacy_vmm_wire=version != "0.6.0-candidate",
            )
            created.append(guest["vm_id"])
            before = matrix.client_observation(guest, timeout=180)
            public_key = before.get("public_key_sha256")
            if not public_key:
                raise RuntimeError(f"{version} Guest omitted its public identity")
            rows.append((version, guest))
            evidence["guest_rows"].append(
                {
                    "version": version,
                    "image": values["guest_images"][version],
                    "vm_id_sha256": hashlib.sha256(guest["vm_id"].encode()).hexdigest(),
                    "app_id_sha256": hashlib.sha256(
                        guest["app_id"].encode()
                    ).hexdigest(),
                    "public_key_sha256": public_key,
                    "initial_service_healthy": True,
                }
            )

        for (version, guest), observation in zip(
            rows, evidence["guest_rows"], strict=True
        ):
            SUPPORT.run([*matrix.cli, "stop", guest["vm_id"], "--force"], timeout=120)
            code, _ = SUPPORT.http(
                f"http://127.0.0.1:{guest['service_port']}/observation", timeout=15
            )
            if code != 0:
                raise RuntimeError(f"{version} endpoint remained reachable after stop")
            SUPPORT.run([*matrix.cli, "start", guest["vm_id"]], timeout=120)
            after = matrix.client_observation(guest, timeout=180)
            if after.get("public_key_sha256") != observation["public_key_sha256"]:
                raise RuntimeError(f"{version} identity changed after restart")
            observation.update(
                {
                    "stopped_unavailable": True,
                    "restarted_healthy": True,
                    "identity_stable": True,
                }
            )

        evidence["candidate_vmm_hosts_full_matrix"] = True
        evidence["all_lifecycle_rows_passed"] = True
        for vm_id in reversed(created):
            SUPPORT.run([*matrix.cli, "remove", vm_id], timeout=120)
        created.clear()
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = f"{type(error).__name__}: {error}"
        evidence["failure"] = failure

    evidence_path = artifacts / "candidate-vmm-pinned-guests.json"
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": "artifacts/candidate-vmm-pinned-guests.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Candidate VMM pinned Guest matrix",
        "description": "Four physical-TDX Guest generations, public identities, lifecycle recovery, and cleanup observations.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    summary = (
        "Candidate VMM hosted and restarted all four pinned Guest generations with stable public identities"
        if status == "PASS"
        else failure
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 5)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The case uses immutable prepared mkosi Guest images and tests runtime compatibility, not image build correctness. Failure retains the complete case-owned VMM topology for direct debugging.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
