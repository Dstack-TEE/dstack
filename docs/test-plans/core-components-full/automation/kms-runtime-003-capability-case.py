#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103, E701, E702
"""Exercise authorization deployment, management, query, and upgrade scripts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-kms-runtime-003"
DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OTHER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def run(
    argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 240
) -> dict[str, Any]:
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
    redacted = list(argv)
    for index, value in enumerate(redacted[:-1]):
        if value == "--private-key":
            redacted[index + 1] = "<redacted-dev-key>"
    return {
        "command": redacted,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "output_tail": completed.stdout[-10000:],
    }


def stop(proc: subprocess.Popen[str] | None, stream: Any | None) -> None:
    if proc is not None and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if stream is not None:
        stream.close()


def main() -> int:
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    project = repo / "dstack/kms/auth-eth"
    required = [
        project / "lib/forge-std/src/Test.sol",
        project
        / "lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol",
        project
        / "lib/openzeppelin-contracts-upgradeable/lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol",
        project / "lib/openzeppelin-foundry-upgrades/src/Upgrades.sol",
    ]
    missing = [str(path.relative_to(project)) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError(
            "Foundry contract submodules are not initialized: " + ", ".join(missing)
        )
    foundry = Path.home() / ".cache/dstack-test/toolchains/foundry"
    node = Path.home() / ".local/share/fnm/node-versions/v20.19.6/installation/bin"
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(
        [
            str(foundry),
            str(node),
            str(project / "node_modules/.bin"),
            env.get("PATH", ""),
        ]
    )
    port = free_port()
    rpc = f"http://127.0.0.1:{port}"
    root = Path(tempfile.mkdtemp(prefix="dstack-auth-scripts-"))
    log = root / "anvil.log"
    stream = log.open("w", encoding="utf-8")
    anvil = subprocess.Popen(
        [
            str(foundry / "anvil"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--silent",
        ],
        stdout=stream,
        stderr=subprocess.STDOUT,
        text=True,
    )
    runs: dict[str, Any] = {}
    checks: dict[str, bool] = {}
    mr = "0x" + "12" * 32
    image = "0x" + "34" * 32
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            probe = run(
                [str(foundry / "cast"), "chain-id", "--rpc-url", rpc], project, env, 10
            )
            if probe["exit_code"] == 0:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("Anvil did not become ready")
        deploy_env = dict(env, PRIVATE_KEY=DEV_KEY)
        runs["deploy"] = run(
            [
                str(foundry / "forge"),
                "script",
                "script/Deploy.s.sol:DeployScript",
                "--rpc-url",
                rpc,
                "--broadcast",
                "-vv",
            ],
            project,
            deploy_env,
        )
        match = re.search(
            r"DstackKms proxy deployed to:\s*(0x[0-9a-fA-F]{40})",
            runs["deploy"]["output_tail"],
        )
        if runs["deploy"]["exit_code"] or not match:
            raise RuntimeError(f"deployment failed: {runs['deploy']['output_tail']}")
        kms = match.group(1)
        manage_env = dict(
            env,
            PRIVATE_KEY=DEV_KEY,
            KMS_CONTRACT_ADDR=kms,
            OS_IMAGE_HASH=image,
            MR_AGGREGATED=mr,
        )
        base = [str(foundry / "forge"), "script"]
        tail = ["--rpc-url", rpc, "--broadcast", "-vv"]
        runs["add_image"] = run(
            base + ["script/Manage.s.sol:AddOsImage"] + tail, project, manage_env
        )
        runs["add_image_duplicate"] = run(
            base + ["script/Manage.s.sol:AddOsImage"] + tail, project, manage_env
        )
        runs["query_image"] = run(
            base + ["script/Query.s.sol:CheckOsImage", "--rpc-url", rpc, "-vv"],
            project,
            manage_env,
        )
        runs["missing_env"] = run(
            base + ["script/Manage.s.sol:AddOsImage"] + tail,
            project,
            {k: v for k, v in manage_env.items() if k != "OS_IMAGE_HASH"},
        )
        unauthorized_env = dict(manage_env, PRIVATE_KEY=OTHER_KEY)
        runs["unauthorized"] = run(
            base + ["script/Manage.s.sol:AddOsImage"] + tail, project, unauthorized_env
        )
        runs["wrong_rpc"] = run(
            base
            + [
                "script/Query.s.sol:CheckOsImage",
                "--rpc-url",
                f"http://127.0.0.1:{free_port()}",
                "-vv",
            ],
            project,
            manage_env,
            30,
        )
        runs["query_after_failures"] = run(
            base + ["script/Query.s.sol:CheckOsImage", "--rpc-url", rpc, "-vv"],
            project,
            manage_env,
        )
        shutil.rmtree(project / "out/build-info", ignore_errors=True)
        runs["upgrade_build_info"] = run(
            [str(foundry / "forge"), "build", "--build-info"], project, manage_env
        )
        runs["upgrade"] = run(
            base
            + [
                "script/Upgrade.s.sol:UpgradeKmsToV2",
                "--rpc-url",
                rpc,
                "--broadcast",
                "--private-key",
                DEV_KEY,
                "--ffi",
                "-vv",
            ],
            project,
            manage_env,
        )
        runs["query_after_upgrade"] = run(
            base + ["script/Query.s.sol:CheckOsImage", "--rpc-url", rpc, "-vv"],
            project,
            manage_env,
        )
        checks = {
            "deploy_complete": runs["deploy"]["exit_code"] == 0,
            "manage_success": runs["add_image"]["exit_code"] == 0,
            "duplicate_idempotent": runs["add_image_duplicate"]["exit_code"] == 0,
            "query_true": "Is Allowed: true" in runs["query_image"]["output_tail"],
            "missing_env_rejected": runs["missing_env"]["exit_code"] != 0,
            "unauthorized_rejected": runs["unauthorized"]["exit_code"] != 0,
            "wrong_rpc_rejected": runs["wrong_rpc"]["exit_code"] != 0,
            "failure_atomic": runs["query_after_failures"]["exit_code"] == 0
            and "Is Allowed: true" in runs["query_after_failures"]["output_tail"],
            "upgrade_success": runs["upgrade_build_info"]["exit_code"] == 0
            and runs["upgrade"]["exit_code"] == 0,
            "upgrade_preserves_state": runs["query_after_upgrade"]["exit_code"] == 0
            and "Is Allowed: true" in runs["query_after_upgrade"]["output_tail"],
        }
    finally:
        stream.flush()
        logs = log.read_text(errors="replace") if log.exists() else ""
        checks["credential_redacted"] = (
            DEV_KEY not in logs
            and OTHER_KEY not in logs
            and all(
                DEV_KEY not in json.dumps(value) and OTHER_KEY not in json.dumps(value)
                for value in runs.values()
            )
        )
    groups = {
        "deploy_manage_query": all(
            checks.get(k, False)
            for k in (
                "deploy_complete",
                "manage_success",
                "duplicate_idempotent",
                "query_true",
            )
        ),
        "preflight_failure_atomicity": all(
            checks.get(k, False)
            for k in (
                "missing_env_rejected",
                "unauthorized_rejected",
                "wrong_rpc_rejected",
                "failure_atomic",
            )
        ),
        "upgrade_storage": all(
            checks.get(k, False) for k in ("upgrade_success", "upgrade_preserves_state")
        ),
    }
    if all(groups.values()) and checks.get("credential_redacted", False):
        stop(anvil, stream)
        with socket.socket() as sock:
            checks["cleanup_complete"] = sock.connect_ex(("127.0.0.1", port)) != 0
    else:
        checks["cleanup_complete"] = False
        runs["retained_debug"] = {
            "anvil_pid": anvil.pid,
            "rpc_url": rpc,
            "workspace": str(root),
        }
    groups["redaction_cleanup"] = all(
        checks.get(k, False) for k in ("credential_redacted", "cleanup_complete")
    )
    status = "PASS" if all(groups.values()) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-runtime-003-scripts.json"
    detail.write_text(
        json.dumps({"groups": groups, "checks": checks, "runs": runs}, indent=2) + "\n"
    )
    artifact = {
        "path": "artifacts/kms-runtime-003-scripts.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Authorization script lifecycle",
        "description": "One shared Anvil deployment exercises deploy, manage, query, invalid preflight, unauthorized signer, upgrade, persistence, redaction, and cleanup.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    passed = sum(groups.values())
    summary = f"{passed}/{len(groups)} authorization script groups passed"
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": summary}
            for n in range(1, 4)
        ],
        "artifacts": [artifact],
        "evidence": [
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(detail.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "All mutations share one case-owned local Anvil chain; private-key argv is redacted from evidence.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
