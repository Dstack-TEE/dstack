#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Deterministic regression harness for the KMS auth-mock safety boundary."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
from typing import Any

CASE_ID = "tc-kms-auth-002"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        temporary = pathlib.Path(output.name)
    temporary.replace(path)


def node20_bin() -> pathlib.Path:
    """Resolve an installed Node 20+ binary directory without changing the host."""
    candidates = []
    current = shutil.which("node")
    if current:
        candidates.append(pathlib.Path(current))
    candidates.extend(
        pathlib.Path.home().glob(
            ".local/share/fnm/node-versions/v*/installation/bin/node"
        )
    )
    for candidate in sorted(candidates, reverse=True):
        probe = subprocess.run(
            [str(candidate), "--version"], text=True, capture_output=True, check=False
        )
        try:
            major = int(probe.stdout.strip().lstrip("v").split(".", 1)[0])
        except (ValueError, IndexError):
            continue
        if probe.returncode == 0 and major >= 20:
            return candidate.parent
    raise RuntimeError("Node 20 or newer is unavailable")


def run(command: list[str], cwd: pathlib.Path, env: dict[str, str]) -> dict[str, Any]:
    """Run one bounded command and retain a bounded output tail."""
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    tail = completed.stdout[-12000:]
    return {
        "command": command,
        "returncode": completed.returncode,
        "output_bytes": len(completed.stdout.encode()),
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "output_tail": tail,
    }


def main() -> int:
    """Execute native tests plus the production fail-closed gate."""
    case_id = os.environ["DSTACK_TEST_CASE_ID"]
    if case_id != CASE_ID:
        raise SystemExit(f"unsupported case: {case_id}")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    package = pathlib.Path(runtime["repository"]) / "dstack/kms/auth-mock"
    bun = shutil.which("bun") or str(pathlib.Path.home() / ".bun/bin/bun")
    if not pathlib.Path(bun).is_file():
        raise RuntimeError("Bun is unavailable")
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(
        [
            str(node20_bin()),
            str(package / "node_modules/.bin"),
            str(pathlib.Path(bun).parent),
            env.get("PATH", ""),
        ]
    )
    install = run([bun, "install", "--frozen-lockfile"], package, env)
    tests = run([bun, "run", "test:run"], package, env)
    production_env = dict(env, NODE_ENV="production", PORT="0")
    production = run([bun, "run", "index.ts"], package, production_env)
    checks = {
        "frozen_install": install["returncode"] == 0,
        "native_tests": tests["returncode"] == 0,
        "production_rejected": production["returncode"] != 0
        and "must not run with NODE_ENV=production" in production["output_tail"],
    }
    status = "PASS" if all(checks.values()) else "FAIL"
    evidence = {"checks": checks, "runs": [install, tests, production]}
    artifact = {
        "path": "artifacts/auth-mock-safety.json",
        "step_id": f"{case_id}-step-02",
        "name": "Auth mock safety regression",
        "description": "Frozen dependency install, native test suite, and production fail-closed gate.",
    }
    atomic_json(result_dir / artifact["path"], evidence)
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": "KMS auth-mock safety regression passed."
        if status == "PASS"
        else "KMS auth-mock safety regression failed.",
        "steps": [
            {
                "id": f"{case_id}-step-01",
                "status": "PASS" if checks["frozen_install"] else "FAIL",
                "observed": "Bun dependencies matched the committed lockfile.",
            },
            {
                "id": f"{case_id}-step-02",
                "status": "PASS"
                if checks["native_tests"] and checks["production_rejected"]
                else "FAIL",
                "observed": "Native decisions passed and production startup failed closed.",
            },
            {
                "id": f"{case_id}-step-03",
                "status": status,
                "observed": "Commands were process-local and emitted bounded evidence.",
            },
        ],
        "artifacts": [artifact],
        "remarks": "No image, service fixture, or host lifecycle mutation; temporary package dependencies follow the committed Bun lockfile.",
    }
    atomic_json(result_dir / "result.json", result)
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": [artifact]})
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
