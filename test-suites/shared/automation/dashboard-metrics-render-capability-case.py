#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Gate dashboard and metrics hostile-input rendering on a complete case-owned fixture."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

CASE_ID = "tc-gos-entry-003"
CAPABILITY = "dashboard-metrics-render-harness"
REQUIRED = [
    "candidate_models",
    "candidate_dashboard_template",
    "candidate_metrics_template",
    "hostile_input_matrix",
    "render_argv",
    "concurrent_render_argv",
    "output_assertion_argv",
    "cleanup_argv",
]


def main() -> int:
    """Record a bounded capability observation and emit BLOCKED or FAIL."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest.get("values", {})
    fixture = values.get("render_model_harness") if isinstance(values, dict) else None
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
    summary = (
        f"{CAPABILITY} is present but execution is not implemented"
        if complete
        else f"missing capability: {CAPABILITY}"
    )
    observed = (
        "The complete controller is declared; this harness must execute it rather than report a gap."
        if complete
        else "The case manifest lacks the complete case-owned inputs, operations, fault controls, observers, isolation target, and cleanup contract required by this matrix."
    )
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
    artifact_path = (
        result_dir / "artifacts/dashboard-metrics-render-capability-case.json"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    artifact = {
        "path": f"artifacts/{artifact_path.name}",
        "step_id": f"{CASE_ID}-step-01",
        "name": "Capability contract observation",
        "description": "Bounded manifest field-presence evidence for the complete required case-owned contract without substituting a narrower input.",
    }
    (result_dir / "artifacts/manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    steps = []
    for number in range(1, 5):
        steps.append(
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": status,
                "observed": observed,
            }
        )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": steps,
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(artifact_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "No shared service, image, device, or credential was substituted or mutated.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
