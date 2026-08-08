#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Execute a commit-keyed Foundry KMS ownership and policy matrix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

CASE_ROWS = {
    "tc-kms-auth-004": ["ownership_roles", "upgrade_authority", "upgrade_storage"],
    "tc-kms-auth-005": ["node_registration", "node_revocation", "stale_node_rejection"],
    "tc-kms-auth-006": ["app_policy", "image_device_policy", "rollback_tcb_policy"],
    "tc-kms-runtime-005": ["app_policy", "image_device_policy", "rollback_tcb_policy"],
}

COMMANDS = {
    "ownership": r"TransferOwnership|AcceptOwnership|OnlyOwner|OwnerOnlyFunctionsFollowOwnership",
    "upgrade": r"CannotUpgradeWhenDisabled|OnlyOwnerCanUpgrade|Upgrade(Kms|App)Proxy|UpgradeWithInitialization|ComplexUpgradeScenario|ValidationChecks",
    "registration": r"RegisterApp|DeployAndRegisterApp|SetKmsInfo|AddAndRemoveKmsDevice|IsKmsAllowed",
    "policy": r"IsAppAllowed|RejectUnallowedComposeHash|AddComposeHash|RemoveComposeHash|AddDevice|RemoveDevice|SetAllowAnyDevice|AddAndRemoveOsImageHash|RequireTcbUpToDate|FactoryDeploysApp",
}


def find_node_bin() -> Path:
    """Return a Node 20+ bin directory for OpenZeppelin FFI."""
    candidates = []
    current = shutil.which("node")
    if current:
        candidates.append(Path(current))
    candidates.extend(
        Path.home().glob(".local/share/fnm/node-versions/v*/installation/bin/node")
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


def find_forge() -> Path:
    """Resolve a prepared Foundry binary without mutating system state."""
    configured = os.environ.get("DSTACK_TEST_FORGE")
    candidates = [Path(configured)] if configured else []
    current = shutil.which("forge")
    if current:
        candidates.append(Path(current))
    candidates.append(Path.home() / ".cache/dstack-test/toolchains/foundry/forge")
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise RuntimeError("prepared Foundry forge binary is unavailable")


def run(
    argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 300
) -> dict[str, Any]:
    """Run one bounded Foundry command and retain reproducible output evidence."""
    started = time.monotonic()
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    output = completed.stdout
    passed = sum(int(value) for value in re.findall(r"(\d+) tests passed", output))
    failed = sum(int(value) for value in re.findall(r"(\d+) failed", output))
    return {
        "command": argv,
        "exit_code": completed.returncode,
        "passed": passed,
        "failed": failed,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_tail": output[-16000:],
    }


def run_matrix(repo: Path, cache: Path, shared_cache: Path) -> dict[str, Any]:
    """Compile once, execute focused policy groups, and publish atomically."""
    package = repo / "dstack/kms/auth-eth"
    required = [
        package / "lib/forge-std/src/Test.sol",
        package
        / "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol",
        package
        / "lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol",
        package / "lib/openzeppelin-foundry-upgrades/src/Upgrades.sol",
    ]
    if not all(path.is_file() for path in required):
        missing = [str(path.relative_to(package)) for path in required if not path.is_file()]
        raise RuntimeError(
            "Foundry contract submodules are not initialized: " + ", ".join(missing)
        )
    forge = find_forge()
    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(
        [str(find_node_bin()), str(forge.parent), env.get("PATH", "")]
    )
    env["FOUNDRY_CACHE_PATH"] = str(shared_cache)
    runs: dict[str, Any] = {}
    runs["clean"] = run([str(forge), "clean"], package, env, 60)
    if runs["clean"]["exit_code"] == 0:
        runs["build"] = run([str(forge), "build"], package, env)
    if runs.get("build", {}).get("exit_code") == 0:
        for name, pattern in COMMANDS.items():
            runs[name] = run(
                [str(forge), "test", "--ffi", "--match-test", pattern, "-vv"],
                package,
                env,
            )

    def ok(name: str) -> bool:
        return (
            runs.get(name, {}).get("exit_code") == 0
            and runs.get(name, {}).get("passed", 0) > 0
            and runs.get(name, {}).get("failed", 1) == 0
        )

    rows = {
        "ownership_roles": {
            "status": "PASS" if ok("ownership") else "FAIL",
            "run": "ownership",
        },
        "upgrade_authority": {
            "status": "PASS" if ok("upgrade") else "FAIL",
            "run": "upgrade",
        },
        "upgrade_storage": {
            "status": "PASS" if ok("upgrade") else "FAIL",
            "run": "upgrade",
        },
        "node_registration": {
            "status": "PASS" if ok("registration") else "FAIL",
            "run": "registration",
        },
        "node_revocation": {
            "status": "PASS" if ok("registration") and ok("ownership") else "FAIL",
            "run": "registration+ownership",
        },
        "stale_node_rejection": {
            "status": "PASS" if ok("registration") else "FAIL",
            "run": "registration",
        },
        "app_policy": {"status": "PASS" if ok("policy") else "FAIL", "run": "policy"},
        "image_device_policy": {
            "status": "PASS" if ok("policy") and ok("registration") else "FAIL",
            "run": "policy+registration",
        },
        "rollback_tcb_policy": {
            "status": "PASS" if ok("policy") and ok("upgrade") else "FAIL",
            "run": "policy+upgrade",
        },
    }
    payload = {
        "schema_version": "1.0",
        "rows": rows,
        "runs": runs,
        "forge_version": subprocess.check_output(
            [str(forge), "--version"], text=True
        ).splitlines()[0],
    }
    temporary = cache.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(cache)
    return payload


def main() -> int:
    """Select case-owned rows from the shared Foundry matrix."""
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    case_id = case.get("case_id") or case.get("id")
    if case_id not in CASE_ROWS:
        raise SystemExit(f"unsupported case: {case_id}")
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    cache_dir = Path(runtime["cache_dir_resolved"]) / "kms-contract-policy-shared"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = cache_dir / f"{commit}.json"
    with (cache_dir / f"{commit}.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        payload = (
            json.loads(cache.read_text())
            if cache.exists()
            else run_matrix(repo, cache, cache_dir / "foundry-cache")
        )
    selected = [{"name": name, **payload["rows"][name]} for name in CASE_ROWS[case_id]]
    status = "PASS" if all(row["status"] == "PASS" for row in selected) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-contract-policy.json"
    detail.write_text(
        json.dumps(
            {
                "case_id": case_id,
                "commit": commit,
                "forge_version": payload["forge_version"],
                "rows": selected,
                "failed_runs": {
                    name: run
                    for name, run in payload.get("runs", {}).items()
                    if run.get("exit_code") != 0
                },
            },
            indent=2,
        )
        + "\n"
    )
    artifact = {
        "path": "artifacts/kms-contract-policy.json",
        "step_id": f"{case_id}-step-02",
        "name": "KMS contract policy matrix",
        "description": "Focused ownership, registration, boot-policy, and upgrade tests from one clean Foundry build.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    passed = sum(row["status"] == "PASS" for row in selected)
    summary = f"{passed}/{len(selected)} contract-policy groups passed"
    result = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{case_id}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Tests execute deterministic local EVM policy logic; no physical TEE or public-chain finality claim is made.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
