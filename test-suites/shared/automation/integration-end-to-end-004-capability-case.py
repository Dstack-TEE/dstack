#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Record whether the complete integration-end-to-end-004 controller is available."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CASE_ID = "tc-int-end-to-end-004"
CAPABILITY = "integration-end-to-end-004"
ACTION = "Gateway certificate attestation verification"
FIXTURE_KEY = "integration_end_to_end_004"
REQUIRED = [
    "kms_rows",
    "gateway_rows",
    "guest_rows",
    "certificate_rows",
    "issue_argv",
    "attestation_rows",
    "valid_connect_argv",
    "invalid_evidence_rows",
    "certificate_observer_argv",
    "cleanup_argv",
]


def main() -> int:
    """Emit reproducible BLOCKED evidence unless the full controller exists."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    fixture = values.get(FIXTURE_KEY) if isinstance(values, dict) else None
    present = {
        field: isinstance(fixture, dict) and fixture.get(field) is not None
        for field in REQUIRED
    }
    complete = (
        isinstance(fixture, dict)
        and fixture.get("destructive_actions_allowed") is True
        and all(present.values())
    )
    status = "FAIL" if complete else "BLOCKED"
    evidence = {
        "case_id": CASE_ID,
        "status": status,
        "capability": CAPABILITY,
        "declared": isinstance(fixture, dict),
        "destructive_actions_allowed": isinstance(fixture, dict)
        and fixture.get("destructive_actions_allowed") is True,
        "required_fields_present": present,
        "unsafe_substitution_avoided": True,
    }
    artifact_path = result_dir / f"artifacts/{FIXTURE_KEY}.json"
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": f"artifacts/{artifact_path.name}",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Capability contract observation",
        "description": "Bounded field-presence evidence for the complete case-owned controller without substituting narrower shared inputs.",
    }
    (result_dir / "artifacts/manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    observed = (
        "The complete controller is declared; this harness must execute it rather than report a gap."
        if complete
        else "The case manifest lacks the complete case-owned controls and observers required by this matrix."
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": f"{CAPABILITY} is present but execution is not implemented"
        if complete
        else f"missing capability: {CAPABILITY}",
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "No shared gateway, guest, listener, backend, service, address, or credential was substituted or mutated.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
