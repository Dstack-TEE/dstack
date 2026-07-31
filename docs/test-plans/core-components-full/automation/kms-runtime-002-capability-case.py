#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D103
"""Compare Node/Fastify and Bun/Hono authorization listeners on one corpus."""

from __future__ import annotations

import concurrent.futures
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

CASE_ID = "tc-kms-runtime-002"


def load_helpers(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("kms_runtime_listener_helpers", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runtime listener helper cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def command(argv: list[str], cwd: Path, env: dict[str, str]) -> dict[str, Any]:
    started = time.monotonic()
    completed = subprocess.run(
        argv,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    return {
        "command": argv,
        "exit_code": completed.returncode,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_sha256": hashlib.sha256(completed.stdout.encode()).hexdigest(),
        "output_tail": completed.stdout[-8000:],
    }


def main() -> int:
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    automation = repo / "docs/test-plans/core-components-full/automation"
    helper_path = automation / "kms-runtime-001-capability-case.py"
    helper = load_helpers(helper_path)
    node_package = repo / "dstack/kms/auth-eth"
    bun_package = repo / "dstack/kms/auth-eth-bun"
    node_bin = Path.home() / ".local/share/fnm/node-versions/v20.19.6/installation/bin"
    bun = Path.home() / ".bun/bin/bun"
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(
        [
            str(node_bin),
            str(bun.parent),
            str(node_package / "node_modules/.bin"),
            env.get("PATH", ""),
        ]
    )
    build = command(["npm", "run", "build"], node_package, env)
    if build["exit_code"] != 0:
        raise RuntimeError(f"Node authorization compile failed: {build['output_tail']}")

    rpc_port, node_port, bun_port = (
        helper.free_port(),
        helper.free_port(),
        helper.free_port(),
    )
    root = Path(tempfile.mkdtemp(prefix="dstack-auth-parity-"))
    sentinel = "RPC_CREDENTIAL_SENTINEL_runtime_002"
    logs = {"node": root / "node.log", "bun": root / "bun.log"}
    rpc: subprocess.Popen[str] | None = None
    services: dict[str, tuple[subprocess.Popen[str], Any]] = {}
    checks: dict[str, bool] = {}
    observations: dict[str, Any] = {"build": build}

    def start_rpc() -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [sys.executable, str(helper_path), "--mock-rpc", str(rpc_port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not helper.port_closed(rpc_port):
                return proc
            time.sleep(0.05)
        raise RuntimeError("parity mock RPC did not listen")

    def start_service(name: str, port: int) -> tuple[subprocess.Popen[str], Any]:
        stream = logs[name].open("a", encoding="utf-8")
        service_env = dict(
            env,
            PORT=str(port),
            HOST="127.0.0.1",
            ETH_RPC_URL=f"http://127.0.0.1:{rpc_port}/{sentinel}",
            KMS_CONTRACT_ADDR="0x" + "11" * 20,
        )
        if name == "node":
            argv, cwd = [str(node_bin / "node"), "dist/main.js"], node_package
        else:
            argv, cwd = [str(bun), "run", "index.ts"], bun_package
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=service_env,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        helper.wait_health(port)
        return proc, stream

    valid = {
        "mrAggregated": "0x01",
        "osImageHash": "0x02",
        "appId": "0x03",
        "composeHash": "0x04",
        "instanceId": "0x05",
        "deviceId": "0x06",
        "tcbStatus": "UpToDate",
        "advisoryIds": [],
        "mrSystem": "0x07",
    }
    corpus = [
        ("app_valid", "/bootAuth/app", valid),
        ("kms_valid", "/bootAuth/kms", valid),
        (
            "unprefixed_min",
            "/bootAuth/app",
            {**valid, "mrAggregated": "01", "mrSystem": ""},
        ),
        ("adjacent", "/bootAuth/app", {**valid, "instanceId": "0x09"}),
        ("missing", "/bootAuth/app", {"mrAggregated": "0x01"}),
        ("oversized", "/bootAuth/app", {**valid, "mrAggregated": "0x" + "ab" * 33}),
        ("non_hex", "/bootAuth/app", {**valid, "deviceId": "not-hex"}),
    ]

    try:
        rpc = start_rpc()
        services["node"] = start_service("node", node_port)
        services["bun"] = start_service("bun", bun_port)
        ports = {"node": node_port, "bun": bun_port}
        rows: dict[str, Any] = {}
        for name, path, body in corpus:
            values = {
                impl: helper.request(port, path, body) for impl, port in ports.items()
            }
            rows[name] = {
                impl: {"status": value[0], "payload": value[1]}
                for impl, value in values.items()
            }
            rows[name]["equal"] = values["node"] == values["bun"]

        health = {impl: helper.request(port, "/") for impl, port in ports.items()}
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            concurrent_rows = {
                impl: list(
                    pool.map(
                        lambda _n, p=port: helper.request(p, "/bootAuth/app", valid),
                        range(6),
                    )
                )
                for impl, port in ports.items()
            }
        helper.stop(rpc)
        rpc = None
        outage = {
            impl: helper.request(port, "/bootAuth/app", valid)
            for impl, port in ports.items()
        }
        rpc = start_rpc()
        recovery = {
            impl: helper.request(port, "/bootAuth/app", valid)
            for impl, port in ports.items()
        }
        for impl, (proc, stream) in list(services.items()):
            helper.stop(proc, stream)
            services.pop(impl)
        services["node"] = start_service("node", node_port)
        services["bun"] = start_service("bun", bun_port)
        restarted = {impl: helper.request(port, "/") for impl, port in ports.items()}

        checks = {
            "corpus_equal": all(row["equal"] for row in rows.values()),
            "valid_allowed": all(
                rows[name][impl]["payload"].get("isAllowed") is True
                for name in ("app_valid", "kms_valid", "unprefixed_min", "adjacent")
                for impl in ports
            ),
            "invalid_status_equal": all(
                rows[name][impl]["status"] == 400
                for name in ("missing", "oversized", "non_hex")
                for impl in ports
            ),
            "health_equal": health["node"] == health["bun"],
            "concurrency_equal": concurrent_rows["node"] == concurrent_rows["bun"]
            and all(
                status == 200 and payload.get("isAllowed") is True
                for values in concurrent_rows.values()
                for status, payload in values
            ),
            "outage_equal_fail_closed": outage["node"] == outage["bun"]
            and outage["node"][0] == 200
            and outage["node"][1].get("isAllowed") is False,
            "recovery_equal": recovery["node"] == recovery["bun"]
            and recovery["node"][1].get("isAllowed") is True,
            "restart_equal": restarted["node"] == restarted["bun"]
            and restarted["node"][1].get("status") == "ok",
        }
        observations.update(
            rows=rows,
            health=health,
            outage=outage,
            recovery=recovery,
            concurrent_counts={
                impl: len(values) for impl, values in concurrent_rows.items()
            },
        )
    finally:
        for proc, stream in services.values():
            helper.stop(proc, stream)
        helper.stop(rpc)
        log_text = {
            name: path.read_text(errors="replace") if path.exists() else ""
            for name, path in logs.items()
        }
        checks["credentials_redacted"] = all(
            sentinel not in value for value in log_text.values()
        )
        checks["cleanup_complete"] = all(
            helper.port_closed(port) for port in (rpc_port, node_port, bun_port)
        )
        observations["log_sha256"] = {
            name: hashlib.sha256(value.encode()).hexdigest()
            for name, value in log_text.items()
        }

    groups = {
        "decision_schema_parity": all(
            checks.get(k, False)
            for k in (
                "corpus_equal",
                "valid_allowed",
                "invalid_status_equal",
                "health_equal",
            )
        ),
        "concurrency_parity": checks.get("concurrency_equal", False),
        "failure_recovery_parity": all(
            checks.get(k, False) for k in ("outage_equal_fail_closed", "recovery_equal")
        ),
        "restart_redaction_cleanup": all(
            checks.get(k, False)
            for k in ("restart_equal", "credentials_redacted", "cleanup_complete")
        ),
    }
    status = "PASS" if all(groups.values()) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-runtime-002-parity.json"
    detail.write_text(
        json.dumps(
            {"groups": groups, "checks": checks, "observations": observations}, indent=2
        )
        + "\n"
    )
    artifact = {
        "path": "artifacts/kms-runtime-002-parity.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Node and Bun authorization parity",
        "description": "Same-corpus listener decisions, metadata, boundaries, concurrency, backend outage, recovery, restart, redaction, and cleanup.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    passed = sum(groups.values())
    summary = f"{passed}/{len(groups)} Node/Bun authorization parity groups passed"
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
        "remarks": "Both implementations use one deterministic local Ethereum RPC snapshot; no public-chain finality claim is made.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
