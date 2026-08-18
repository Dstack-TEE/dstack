#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# ruff: noqa: D101, D102, D103
"""Exercise the Ethereum authorization service through its real HTTP listener."""

from __future__ import annotations

import concurrent.futures
import hashlib
import http.server
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CASE_ID = "tc-kms-runtime-001"
GATEWAY_SELECTOR = "0x95f51931"
APP_IMPLEMENTATION_SELECTOR = "0x25a992da"
APP_ALLOWED_SELECTOR = "0x1e079198"
KMS_ALLOWED_SELECTOR = "0xe067ec9d"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def word(value: int) -> str:
    return f"{value:064x}"


def encoded_string(value: str) -> str:
    raw = value.encode().hex()
    return (
        word(32)
        + word(len(value.encode()))
        + raw.ljust(((len(raw) + 63) // 64) * 64, "0")
    )


def encoded_decision(allowed: bool, reason: str) -> str:
    raw = reason.encode().hex()
    return (
        word(int(allowed))
        + word(64)
        + word(len(reason.encode()))
        + raw.ljust(((len(raw) + 63) // 64) * 64, "0")
    )


class RpcHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length))

        def respond(request: dict[str, Any]) -> dict[str, Any]:
            method = request.get("method")
            if method == "eth_chainId":
                result = "0x7a69"
            elif method == "eth_blockNumber":
                result = "0x100"
            elif method == "eth_call":
                data = request.get("params", [{}])[0].get("data", "")[:10]
                if data == GATEWAY_SELECTOR:
                    result = "0x" + encoded_string("gateway-runtime-test")
                elif data == APP_IMPLEMENTATION_SELECTOR:
                    result = "0x" + ("00" * 12) + ("22" * 20)
                elif data in {APP_ALLOWED_SELECTOR, KMS_ALLOWED_SELECTOR}:
                    result = "0x" + encoded_decision(True, "allowed")
                else:
                    return {
                        "jsonrpc": "2.0",
                        "id": request.get("id"),
                        "error": {"code": -32602, "message": "unexpected selector"},
                    }
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": "unexpected RPC method"},
                }
            return {"jsonrpc": "2.0", "id": request.get("id"), "result": result}

        response = (
            [respond(item) for item in payload]
            if isinstance(payload, list)
            else respond(payload)
        )
        body = json.dumps(response).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def run_mock_rpc(port: int) -> int:
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), RpcHandler)
    server.serve_forever()
    return 0


def request(
    port: int, path: str, body: Any | None = None
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return int(response.status), json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        return int(error.code), json.loads(raw) if raw else {}


def wait_health(port: int, expect_ok: bool = True) -> dict[str, Any]:
    deadline = time.monotonic() + 15
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            status, payload = request(port, "/")
            if (status == 200) is expect_ok:
                return payload
        except Exception as error:  # noqa: BLE001
            last = error
        time.sleep(0.1)
    raise RuntimeError(f"authorization listener did not reach expected health: {last}")


def stop(proc: subprocess.Popen[str] | None, output: Any | None = None) -> None:
    if proc is not None and proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if output is not None:
        output.close()


def port_closed(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.5)
        return sock.connect_ex(("127.0.0.1", port)) != 0


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--mock-rpc":
        return run_mock_rpc(int(sys.argv[2]))

    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    repo = Path(runtime["repository"])
    package = repo / "dstack/kms/auth-eth-bun"
    bun = Path.home() / ".bun/bin/bun"
    if not bun.is_file():
        raise RuntimeError("Bun is unavailable")

    rpc_port, service_port = free_port(), free_port()
    root = Path(tempfile.mkdtemp(prefix="dstack-auth-eth-listener-"))
    log = root / "service.log"
    sentinel = "RPC_CREDENTIAL_SENTINEL_runtime_001"
    service: subprocess.Popen[str] | None = None
    rpc: subprocess.Popen[str] | None = None
    output = None
    checks: dict[str, bool] = {}
    observations: dict[str, Any] = {}
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

    def start_rpc() -> subprocess.Popen[str]:
        proc = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--mock-rpc",
                str(rpc_port),
            ],
            text=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not port_closed(rpc_port):
                return proc
            time.sleep(0.05)
        raise RuntimeError("mock RPC did not listen")

    def start_service() -> tuple[subprocess.Popen[str], Any]:
        stream = log.open("a", encoding="utf-8")
        env = dict(
            os.environ,
            PORT=str(service_port),
            ETH_RPC_URL=f"http://127.0.0.1:{rpc_port}/{sentinel}",
            KMS_CONTRACT_ADDR="0x" + "11" * 20,
        )
        proc = subprocess.Popen(
            [str(bun), "run", "index.ts"],
            cwd=package,
            env=env,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        wait_health(service_port)
        return proc, stream

    try:
        rpc = start_rpc()
        service, output = start_service()
        health = wait_health(service_port)
        app_status, app = request(service_port, "/bootAuth/app", valid)
        kms_status, kms = request(service_port, "/bootAuth/kms", valid)
        malformed_status, _ = request(
            service_port, "/bootAuth/app", {"mrAggregated": "0x01"}
        )
        oversized_status, _ = request(
            service_port, "/bootAuth/app", {**valid, "mrAggregated": "0x" + "ab" * 33}
        )
        adjacent_status, adjacent = request(
            service_port, "/bootAuth/app", {**valid, "instanceId": "0x09"}
        )
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            concurrent_results = list(
                pool.map(
                    lambda _n: request(service_port, "/bootAuth/app", valid), range(8)
                )
            )
        stop(rpc)
        rpc = None
        outage_status, outage = request(service_port, "/bootAuth/app", valid)
        rpc = start_rpc()
        recovery_status, recovery = request(service_port, "/bootAuth/app", valid)
        stop(service, output)
        service, output = None, None
        service, output = start_service()
        restarted = wait_health(service_port)

        checks = {
            "listener_schema": health.get("status") == "ok"
            and health.get("chainId") == 31337
            and health.get("kmsContractAddr") == "0x" + "11" * 20,
            "app_and_kms_allowed": app_status == 200
            and app.get("isAllowed") is True
            and kms_status == 200
            and kms.get("isAllowed") is True,
            "malformed_rejected": malformed_status == 400,
            "oversized_rejected": oversized_status == 400,
            "adjacent_isolated": adjacent_status == 200
            and adjacent.get("isAllowed") is True,
            "concurrent_converges": all(
                status == 200 and payload.get("isAllowed") is True
                for status, payload in concurrent_results
            ),
            "outage_fails_closed": outage_status == 200
            and outage.get("isAllowed") is False,
            "recovery_converges": recovery_status == 200
            and recovery.get("isAllowed") is True,
            "restart_healthy": restarted.get("status") == "ok",
        }
        observations = {
            "health_fields": sorted(health),
            "malformed_status": malformed_status,
            "oversized_status": oversized_status,
            "concurrent_passed": sum(
                status == 200 and payload.get("isAllowed") is True
                for status, payload in concurrent_results
            ),
            "outage_status": outage_status,
            "outage_allowed": outage.get("isAllowed"),
            "recovery_status": recovery_status,
        }
    finally:
        stop(service, output)
        stop(rpc)
        logs = log.read_text(errors="replace") if log.exists() else ""
        checks["credential_redacted"] = sentinel not in logs
        checks["cleanup_complete"] = port_closed(service_port) and port_closed(rpc_port)
        observations["log_sha256"] = hashlib.sha256(logs.encode()).hexdigest()
        observations["service_port"] = service_port
        observations["rpc_port"] = rpc_port

    groups = {
        "listener_schema": all(
            checks.get(k, False) for k in ("listener_schema", "app_and_kms_allowed")
        ),
        "boundary_isolation": all(
            checks.get(k, False)
            for k in ("malformed_rejected", "oversized_rejected", "adjacent_isolated")
        ),
        "failure_recovery": all(
            checks.get(k, False) for k in ("outage_fails_closed", "recovery_converges")
        ),
        "concurrency_restart_cleanup": all(
            checks.get(k, False)
            for k in (
                "concurrent_converges",
                "restart_healthy",
                "credential_redacted",
                "cleanup_complete",
            )
        ),
    }
    status = "PASS" if all(groups.values()) else "FAIL"
    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    detail = artifacts / "kms-runtime-001-listener.json"
    detail.write_text(
        json.dumps(
            {"groups": groups, "checks": checks, "observations": observations}, indent=2
        )
        + "\n"
    )
    artifact = {
        "path": "artifacts/kms-runtime-001-listener.json",
        "step_id": f"{CASE_ID}-step-02",
        "name": "Ethereum authorization listener lifecycle",
        "description": "Real Bun listener with deterministic Ethereum JSON-RPC, boundary, outage, recovery, concurrency, restart, redaction, and cleanup evidence.",
    }
    (artifacts / "manifest.json").write_text(
        json.dumps({"artifacts": [artifact]}, indent=2) + "\n"
    )
    passed = sum(groups.values())
    summary = f"{passed}/{len(groups)} Ethereum authorization listener groups passed"
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
        "remarks": "The case uses a local deterministic JSON-RPC backend and makes no public-chain finality claim.",
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
