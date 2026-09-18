#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103
"""Execute a commit-keyed KMS authorization backend and recovery matrix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASES = {
    "tc-kms-auth-001": ["simple_native", "simple_recovery", "simple_restart_redaction"],
    "tc-kms-attestatio-005": [
        "simple_native",
        "ethereum_native",
        "backend_fail_closed",
    ],
    "tc-kms-auth-008": [
        "ethereum_native",
        "schema_compatibility",
        "backend_fail_closed",
    ],
}


def node20_bin() -> Path:
    candidates = []
    current = shutil.which("node")
    if current:
        candidates.append(Path(current))
    candidates.extend(
        Path.home().glob(".local/share/fnm/node-versions/v*/installation/bin/node")
    )
    for candidate in sorted(candidates, reverse=True):
        probe = subprocess.run(
            [str(candidate), "--version"], text=True, capture_output=True
        )
        try:
            major = int(probe.stdout.strip().lstrip("v").split(".", 1)[0])
        except (ValueError, IndexError):
            continue
        if probe.returncode == 0 and major >= 20:
            return candidate.parent
    raise RuntimeError("Node 20 or newer is unavailable")


def command(
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
    output = completed.stdout
    return {
        "command": argv,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": hashlib.sha256(output.encode()).hexdigest(),
        "output_tail": output[-12000:],
    }


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    port: int, path: str, body: dict[str, Any] | None = None
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return int(response.status), json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        return int(error.code), json.loads(raw) if raw else {}


def wait_health(port: int) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            status, payload = request(port, "/")
            if status == 200:
                return payload
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
    raise RuntimeError("auth-simple did not become healthy")


def lifecycle(package: Path, bun: str, env: dict[str, str]) -> dict[str, Any]:
    sentinel = "AUTH_SECRET_SENTINEL_7d13"
    valid = {
        "gatewayAppId": "gateway-test",
        "kmsContractAddr": "0x" + "11" * 20,
        "chainId": 31337,
        "appImplementation": "0x" + "22" * 20,
        "osImages": ["0x01"],
        "allowedTcbStatuses": ["UpToDate"],
        "kms": {"mrAggregated": ["0x02"], "devices": ["0x03"]},
        "apps": {"0x" + "04" * 20: {"composeHashes": ["0x05"], "devices": ["0x03"]}},
    }
    boot = {
        "mrAggregated": "0x02",
        "osImageHash": "0x01",
        "appId": "0x" + "04" * 20,
        "composeHash": "0x05",
        "instanceId": "0x" + "06" * 20,
        "deviceId": "0x03",
        "tcbStatus": "UpToDate",
        "advisoryIds": [],
        "mrSystem": "0x07",
    }
    with tempfile.TemporaryDirectory(prefix="dstack-auth-simple-") as raw:
        root = Path(raw)
        config = root / "auth.json"
        log = root / "service.log"
        config.write_text(json.dumps(valid) + "\n")
        port = free_port()
        service_env = dict(
            env,
            PORT=str(port),
            AUTH_CONFIG_PATH=str(config),
            AUTH_TEST_SENTINEL=sentinel,
        )

        def start() -> tuple[subprocess.Popen[str], Any]:
            output = log.open("a", encoding="utf-8")
            proc = subprocess.Popen(
                [bun, "run", "index.ts"],
                cwd=package,
                env=service_env,
                text=True,
                stdout=output,
                stderr=subprocess.STDOUT,
            )
            wait_health(port)
            return proc, output

        proc, output = start()
        try:
            ok_status, ok = request(port, "/bootAuth/app", boot)
            config.write_text("{ malformed\n")
            denied_status, denied = request(port, "/bootAuth/app", boot)
            config.write_text(json.dumps(valid) + "\n")
            recovered_status, recovered = request(port, "/bootAuth/app", boot)
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=10)
            output.close()
            proc, output = start()
            health = wait_health(port)
            restart_status, restarted = request(port, "/bootAuth/app", boot)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            output.close()
        logs = log.read_text(errors="replace")
        checks = {
            "valid_allowed": ok_status == 200 and ok.get("isAllowed") is True,
            "malformed_fail_closed": denied_status == 200
            and denied.get("isAllowed") is False,
            "recovered_without_restart": recovered_status == 200
            and recovered.get("isAllowed") is True,
            "restart_healthy": health.get("status") == "ok"
            and restart_status == 200
            and restarted.get("isAllowed") is True,
            "sentinel_redacted": sentinel not in logs,
        }
        return {
            "checks": checks,
            "log_sha256": hashlib.sha256(logs.encode()).hexdigest(),
            "log_tail": logs[-8000:],
        }


def run_matrix(repo: Path, cache: Path) -> dict[str, Any]:
    bun = shutil.which("bun")
    if bun is None or not Path(bun).is_file():
        raise RuntimeError("Bun is unavailable")
    base_env = os.environ.copy()
    base_env["PATH"] = os.pathsep.join(
        [str(node20_bin()), str(Path(bun).parent), base_env.get("PATH", "")]
    )
    packages = {
        name: repo / "dstack/kms" / name for name in ("auth-simple", "auth-eth-bun")
    }
    runs: dict[str, Any] = {}
    for name, package in packages.items():
        env = dict(base_env)
        env["PATH"] = os.pathsep.join([str(package / "node_modules/.bin"), env["PATH"]])
        runs[f"{name}_install"] = command(
            [bun, "install", "--frozen-lockfile"], package, env
        )
        if runs[f"{name}_install"]["exit_code"] == 0:
            runs[f"{name}_tests"] = command([bun, "run", "test:run"], package, env)
            if name == "auth-eth-bun":
                runs["auth-eth-bun_schema_tests"] = command(
                    [bun, "run", "test:run", "--", "-t", "API Schema Compatibility"],
                    package,
                    env,
                )
                runs["auth-eth-bun_error_tests"] = command(
                    [bun, "run", "test:run", "--", "-t", "handle contract errors"],
                    package,
                    env,
                )
    simple_env = dict(base_env)
    simple_env["PATH"] = os.pathsep.join(
        [str(packages["auth-simple"] / "node_modules/.bin"), simple_env["PATH"]]
    )
    life = lifecycle(packages["auth-simple"], bun, simple_env)
    simple_output = runs.get("auth-simple_tests", {}).get("output_tail", "")
    rows = {
        "simple_native": {
            "status": "PASS"
            if runs.get("auth-simple_tests", {}).get("exit_code") == 0
            else "FAIL",
            "evidence": "auth-simple native decision suite",
        },
        "ethereum_native": {
            "status": "PASS"
            if runs.get("auth-eth-bun_tests", {}).get("exit_code") == 0
            else "FAIL",
            "evidence": "auth-eth-bun native backend suite",
        },
        "schema_compatibility": {
            "status": "PASS"
            if runs.get("auth-eth-bun_schema_tests", {}).get("exit_code") == 0
            else "FAIL",
            "evidence": "BootInfo, BootResponse, and SystemInfo schema groups",
        },
        "simple_recovery": {
            "status": "PASS"
            if all(
                life["checks"][key]
                for key in (
                    "valid_allowed",
                    "malformed_fail_closed",
                    "recovered_without_restart",
                )
            )
            else "FAIL",
            "evidence": life["checks"],
        },
        "simple_restart_redaction": {
            "status": "PASS"
            if life["checks"]["restart_healthy"] and life["checks"]["sentinel_redacted"]
            else "FAIL",
            "evidence": life["checks"],
        },
        "backend_fail_closed": {
            "status": "PASS"
            if life["checks"]["malformed_fail_closed"]
            and runs.get("auth-eth-bun_error_tests", {}).get("exit_code") == 0
            else "FAIL",
            "evidence": life["checks"],
        },
    }
    payload = {
        "schema_version": "1.0",
        "rows": rows,
        "runs": runs,
        "lifecycle": life,
        "simple_suite_observed": "auth-simple" in simple_output,
    }
    temporary = cache.with_suffix(".tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n")
    temporary.replace(cache)
    return payload


def main() -> int:
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    case = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    case_id = case.get("case_id") or case.get("id")
    if case_id not in CASES:
        raise SystemExit(f"unsupported case: {case_id}")
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True
    ).strip()
    cache_dir = Path(runtime["cache_dir_resolved"]) / "kms-auth-backend-shared"
    cache_dir.mkdir(parents=True, exist_ok=True)
    cache = cache_dir / f"{commit}.json"
    with (cache_dir / f"{commit}.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        payload = (
            json.loads(cache.read_text()) if cache.exists() else run_matrix(repo, cache)
        )
    selected = [{"name": name, **payload["rows"][name]} for name in CASES[case_id]]
    status = "PASS" if all(row["status"] == "PASS" for row in selected) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-auth-backend-shared.json"
    detail.write_text(
        json.dumps({"case_id": case_id, "commit": commit, "rows": selected}, indent=2)
        + "\n"
    )
    artifact = {
        "path": "artifacts/kms-auth-backend-shared.json",
        "step_id": f"{case_id}-step-02",
        "name": "KMS authorization backend matrix",
        "description": "Shared native suites and live fail-closed, recovery, restart, and redaction lifecycle.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    passed = sum(row.get("status") == "PASS" for row in selected)
    summary = f"{passed}/{len(selected)} authorization backend groups passed"
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
        "remarks": "The matrix uses local deterministic backends and does not claim physical TEE or public-chain finality.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
