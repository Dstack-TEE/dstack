#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise the candidate gateway authorization client with checked-in Rust harnesses."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

CASE_ID = "tc-gw-internal-003"
ACTION = "Gateway authorization client allow deny and outage"
OLD_ROOT = "/home/kvin/src/dstack.worktrees/candidate-b79ab31"
OLD_COMMIT = "b79ab31dd4dbf20b0991a218e5568e313307d095"


def main() -> int:
    """Run all checked-in authorization client harnesses."""
    result = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    plan = Path(os.environ["DSTACK_TEST_PLAN_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    work = result / "artifacts/auth-client-harnesses"
    source = plan / "automation/assets/gateway-internal-003"
    shutil.copytree(source, work)
    rows = []
    for name in ("allow-deny-outage", "concurrency", "restart"):
        root = work / name
        for path in (root / "Cargo.toml.template", root / "src/main.rs"):
            text = (
                path.read_text()
                .replace(OLD_ROOT, str(repo))
                .replace(OLD_COMMIT, str(runtime.get("candidate_commit", "")))
            )
            path.write_text(text)
        (root / "Cargo.toml").write_text((root / "Cargo.toml.template").read_text())
        env = {**os.environ, "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"])}
        run = subprocess.run(
            ["cargo", "run", "--manifest-path", str(root / "Cargo.toml"), "--offline"],
            capture_output=True,
            text=True,
            timeout=300,
            env=env,
        )
        rows.append(
            {
                "harness": name,
                "returncode": run.returncode,
                "stdout_sha256": hashlib.sha256(run.stdout.encode()).hexdigest(),
                "stderr_excerpt": run.stderr[-500:],
            }
        )
    status = "PASS" if all(x["returncode"] == 0 for x in rows) else "FAIL"
    artifact = result / "artifacts/auth-client-results.json"
    artifact.write_text(json.dumps(rows, indent=2) + "\n")
    item = {
        "path": "artifacts/auth-client-results.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Authorization client harness results",
        "description": "Return codes and output digests from checked-in allow/deny/outage, concurrency, and restart harnesses.",
    }
    (result / "artifacts/manifest.json").write_text(
        json.dumps({"artifacts": [item]}, indent=2) + "\n"
    )
    observed = (
        "All checked-in authorization harnesses passed against the candidate source."
        if status == "PASS"
        else "One or more checked-in authorization harnesses failed against the candidate source."
    )
    out = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(2, 5)
        ],
        "artifacts": [item],
        "evidence": [
            {
                "path": item["path"],
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Harness inputs are checked in and candidate source paths are resolved from the runtime manifest.",
    }
    (result / "result.json").write_text(json.dumps(out, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
