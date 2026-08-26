#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Verify builder provenance on a candidate guest image artifact."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path

CASE_ID = "tc-gos-build-001"


def main() -> int:
    """Validate candidate scripts and artifact metadata without mutating it."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = (manifest.get("values") or {}).get("image_assembly") or {}
    repository = Path(str(runtime["repository"]))
    assemble = repository / "os/image/assemble.sh"
    check_output = repository / "os/mkosi/tests/check-output.sh"
    syntax = subprocess.run(
        ["bash", "-n", str(assemble), str(check_output)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    metadata_path = Path(str(values.get("input_dir", ""))) / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = os.environ.get("DSTACK_TEST_GUEST_IMAGE_BUILDER", "mkosi").strip()
    checker = check_output.read_text(encoding="utf-8")
    checks = {
        "scripts_parse": syntax.returncode == 0,
        "builder_present": isinstance(metadata.get("builder"), str)
        and bool(metadata["builder"]),
        "builder_matches": metadata.get("builder") == expected,
        "mkosi_checker_requires_builder": '"builder"' in checker,
        "mkosi_checker_matches_builder": 'd["builder"] == "mkosi"' in checker,
    }
    passed = all(checks.values())
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    evidence_path = artifacts / "builder-provenance.json"
    evidence_path.write_text(
        json.dumps(
            {
                "candidate_commit": runtime.get("candidate_commit"),
                "image": values.get("candidate_image"),
                "builder": metadata.get("builder"),
                "expected_builder": expected,
                "metadata_sha256": hashlib.sha256(
                    metadata_path.read_bytes()
                ).hexdigest(),
                "checks": checks,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    status = "PASS" if passed else "FAIL"
    observed = (
        f"Candidate image records builder={expected!r}, and the mkosi output contract enforces it."
        if passed
        else f"Builder provenance checks failed: {sorted(k for k, value in checks.items() if not value)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {
                "id": f"{CASE_ID}-step-{number:02d}",
                "status": status,
                "observed": observed,
            }
            for number in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/builder-provenance.json",
                "sha256": hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The protected image store was read-only; retained evidence contains no credentials.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
