#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute the KMS contract event-audit reconstruction matrix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import time
from typing import Any

CASE_ID = "tc-kms-auth-009"
EXACT_TESTS = 5


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON evidence atomically."""
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def find_node_bin() -> pathlib.Path:
    """Return a Node 20+ bin directory for OpenZeppelin FFI."""
    candidates: list[pathlib.Path] = []
    current = shutil.which("node")
    if current:
        candidates.append(pathlib.Path(current))
    candidates.extend(
        pathlib.Path.home().glob(
            ".local/share/fnm/node-versions/v*/installation/bin/node"
        )
    )
    for node in sorted(candidates, reverse=True):
        probe = subprocess.run([str(node), "--version"], text=True, capture_output=True)
        try:
            major = int(probe.stdout.strip().lstrip("v").split(".", 1)[0])
        except (ValueError, IndexError):
            continue
        if probe.returncode == 0 and major >= 20:
            return node.parent
    raise RuntimeError("Node 20 or newer is unavailable")


def find_forge() -> pathlib.Path:
    """Resolve the prepared Foundry binary."""
    configured = os.environ.get("DSTACK_TEST_FORGE")
    candidates = [pathlib.Path(configured)] if configured else []
    current = shutil.which("forge")
    if current:
        candidates.append(pathlib.Path(current))
    candidates.append(
        pathlib.Path.home() / ".cache/dstack-test/toolchains/foundry/forge"
    )
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("prepared Foundry forge binary is unavailable")


def run_forge(
    forge: pathlib.Path,
    package: pathlib.Path,
    environment: dict[str, str],
    output_dir: pathlib.Path,
    cache_dir: pathlib.Path,
) -> tuple[dict[str, Any], str]:
    """Run one bounded fresh Foundry process and parse its exact summary."""
    command = [
        str(forge),
        "test",
        "--ffi",
        "--match-contract",
        "EventAuditTest",
        "--out",
        str(output_dir),
        "--build-info",
        "--build-info-path",
        str(output_dir / "build-info"),
        "--cache-path",
        str(cache_dir),
        "-vv",
    ]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=package,
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=300,
        check=False,
    )
    output = completed.stdout
    match = re.search(
        r"Ran 1 test suite .*?: (\d+) tests passed, (\d+) failed, (\d+) skipped",
        output,
    )
    passed, failed, skipped = tuple(map(int, match.groups())) if match else (0, 1, 0)
    return (
        {
            "returncode": completed.returncode,
            "passed": passed,
            "failed": failed,
            "skipped": skipped,
            "duration_seconds": round(time.monotonic() - started, 3),
            "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        },
        output,
    )


def main() -> int:
    """Run exact event-audit tests twice and retain bounded evidence."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise SystemExit("unsupported case")
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    repo = pathlib.Path(runtime["repository"])
    package = repo / "dstack/kms/auth-eth"
    required = [
        package / "lib/forge-std/src/Test.sol",
        package
        / "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol",
        package
        / "lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol",
        package / "lib/openzeppelin-foundry-upgrades/src/Upgrades.sol",
    ]
    missing = [
        str(path.relative_to(package)) for path in required if not path.is_file()
    ]
    if missing:
        raise RuntimeError(
            "Foundry contract submodules are not initialized: " + ", ".join(missing)
        )
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    forge = find_forge()
    environment = os.environ.copy()
    environment["PATH"] = os.pathsep.join(
        [str(find_node_bin()), str(forge.parent), environment.get("PATH", "")]
    )
    cache_root = (
        pathlib.Path(runtime["cache_dir_resolved"]) / "kms-event-audit" / commit
    )
    output_dir = cache_root / "out"
    compiler_cache = cache_root / "cache"
    output_dir.mkdir(parents=True, exist_ok=True)
    compiler_cache.mkdir(parents=True, exist_ok=True)
    process_rows: list[dict[str, Any]] = []
    status = "PASS"
    summary = "two fresh Foundry processes passed the exact event-audit matrix"
    with (cache_root / "execution.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        for process_index in (1, 2):
            try:
                row, output = run_forge(
                    forge, package, environment, output_dir, compiler_cache
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                row = {
                    "returncode": -1,
                    "passed": 0,
                    "failed": 1,
                    "skipped": 0,
                    "error_type": type(error).__name__,
                }
                output = str(error)
            row["process"] = process_index
            process_rows.append(row)
            if (
                row["returncode"] != 0
                or row["passed"] != EXACT_TESTS
                or row["failed"] != 0
                or row["skipped"] != 0
            ):
                status = "FAIL"
                summary = f"fresh Foundry process {process_index} failed: {row}"
                debug = result_dir / "debug"
                debug.mkdir(exist_ok=True)
                (debug / f"forge-process-{process_index}.log").write_text(output)
                break

    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-event-audit.json"
    atomic_json(
        detail,
        {
            "candidate_commit": commit,
            "forge_version": subprocess.check_output(
                [str(forge), "--version"], text=True
            ).splitlines()[0],
            "fresh_process_count": len(process_rows),
            "process_rows": process_rows,
            "coverage": [
                "kms-policy-state-reconstruction",
                "app-policy-state-reconstruction",
                "unauthorized-mutation-atomicity",
                "orphan-event-reorg-discard-and-canonical-rebuild",
                "upgrade-actor-and-implementation-binding",
            ],
            "private_material_exported": False,
        },
    )
    artifact = {
        "path": "artifacts/kms-event-audit.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "KMS contract event audit matrix",
        "description": "Exact counts, process durations, coverage labels, and output hashes from two fresh Foundry processes.",
    }
    atomic_json(artifacts / "manifest.json", {"artifacts": [artifact]})
    steps = [
        {
            "id": f"{CASE_ID}-step-01",
            "status": status,
            "observed": "The candidate contracts and prepared Forge/Node toolchains were selected in a commit-keyed isolated output directory.",
        },
        {
            "id": f"{CASE_ID}-step-02",
            "status": status,
            "observed": "Ordered additive audit events reconstructed KMS and app policy state with explicit actor, affected value, and enabled state.",
        },
        {
            "id": f"{CASE_ID}-step-03",
            "status": status,
            "observed": "Unauthorized mutation emitted no audit event and left no partial state; snapshot/revert discarded orphaned events before canonical recovery.",
        },
        {
            "id": f"{CASE_ID}-step-04",
            "status": status,
            "observed": "A second process repeated all exact rows; passing evidence retains no request, key, or endpoint material.",
        },
    ]
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
                "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Local deterministic EVM snapshots model event ordering and reorg handling; no public-chain finality claim is made.",
    }
    atomic_json(result_dir / "result.json", result)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
