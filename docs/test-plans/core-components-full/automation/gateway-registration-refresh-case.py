#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise candidate Gateway refresh, persistence, outage, and recovery behavior."""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

CASE_ID = "tc-gos-setup-009"
TEST_FILTER = "gateway_registration_refresh_tests"
RESULT_RE = re.compile(r"test result: ok\. (\d+) passed; 0 failed")


def atomic_json(path: Path, value: Any) -> None:
    """Write one JSON document atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as out:
        json.dump(value, out, indent=2, sort_keys=True)
        out.write("\n")
        temporary = Path(out.name)
    temporary.replace(path)


def wg_public_key() -> str:
    """Generate a case-scoped public key without retaining its private half."""
    completed = subprocess.run(
        ["bash", "-c", "set -o pipefail; wg genkey | wg pubkey"],
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    value = completed.stdout.strip()
    if completed.returncode or len(value) != 44:
        raise RuntimeError("failed to generate WireGuard public key")
    return value


def post(
    url: str, payload: dict[str, Any], context: ssl.SSLContext
) -> tuple[int, dict[str, Any] | None]:
    """Issue one bounded JSON registration and retain only parsed public structure."""
    request = urllib.request.Request(
        url,
        data=json.dumps(payload, separators=(",", ":")).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            body = json.load(response)
            return int(response.status), body if isinstance(body, dict) else None
    except urllib.error.HTTPError as error:
        return int(error.code), None
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return 0, None


def registration(
    url: str, key: str, port: int, context: ssl.SSLContext
) -> tuple[int, dict[str, Any] | None]:
    """Register one public WireGuard identity and port policy."""
    return post(
        f"{url.rstrip('/')}/Gateway.RegisterCvm",
        {
            "client_public_key": key,
            "port_policy": {
                "ports": [{"port": port, "pp": port % 2 == 0}],
                "restrict_mode": True,
            },
        },
        context,
    )


def response_shape(body: dict[str, Any] | None) -> dict[str, Any]:
    """Redact a registration response to structure and counts."""
    if not isinstance(body, dict):
        return {"present": False}
    return {
        "present": True,
        "keys": sorted(body),
        "wg_present": isinstance(body.get("wg"), dict),
        "agent_present": isinstance(body.get("agent"), dict),
        "gateway_count": len(body.get("gateways", []))
        if isinstance(body.get("gateways"), list)
        else -1,
    }


def wait_pid_exit(pid: int, timeout: float) -> bool:
    """Wait until a lease-owned process exits without assuming parenthood."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return True
        time.sleep(0.1)
    return False


def wait_port(url: str, timeout: float) -> bool:
    """Wait for one HTTPS listener to accept TCP connections."""
    host_port = url.split("://", 1)[1].split("/", 1)[0]
    host, port_text = host_port.rsplit(":", 1)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, int(port_text)), timeout=1):
                return True
        except OSError:
            time.sleep(0.25)
    return False


def main() -> int:
    """Run the native and live three-node Gateway refresh matrix."""
    if os.environ.get("DSTACK_TEST_CASE_ID") != CASE_ID:
        raise RuntimeError("unsupported case id")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    artifacts_dir = result_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    values = manifest["values"]
    nodes = values["gateway_cluster"]["nodes"]
    if len(nodes) < 3:
        raise RuntimeError("three lease-owned Gateway nodes are required")
    client = nodes[0]["registration_client"]
    authenticated = ssl._create_unverified_context()
    authenticated.load_cert_chain(client["cert"], client["key"])
    unauthenticated = ssl._create_unverified_context()
    key = wg_public_key()
    peer_key = wg_public_key()
    observations: dict[str, Any] = {}
    replacement: subprocess.Popen[bytes] | None = None
    failure = ""
    status = "FAIL"

    try:
        native = subprocess.run(
            ["cargo", "test", "-p", "dstack-util", TEST_FILTER, "--", "--nocapture"],
            cwd=Path(runtime["repository"]) / "dstack",
            env={**os.environ, "CARGO_TARGET_DIR": str(runtime["cargo_target_dir"])},
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
        )
        native_log = native.stdout + native.stderr
        (artifacts_dir / "native-tests.log").write_text(native_log)
        match = RESULT_RE.search(native_log)
        native_passed = int(match.group(1)) if match else 0
        if native.returncode or native_passed != 8:
            raise RuntimeError(
                f"native persistence/failover rows passed {native_passed}/8 rc={native.returncode}"
            )
        observations["native_tests_passed"] = native_passed

        first_status, first_body = registration(
            nodes[0]["rpc_url"], key, 18080, authenticated
        )
        repeat_status, repeat_body = registration(
            nodes[0]["rpc_url"], key, 18081, authenticated
        )
        second_status, second_body = registration(
            nodes[1]["rpc_url"], key, 18082, authenticated
        )
        peer_status, peer_body = registration(
            nodes[2]["rpc_url"], peer_key, 18083, authenticated
        )
        restore_status, restore_body = registration(
            nodes[0]["rpc_url"], key, 18084, authenticated
        )
        if any(
            code != 200
            for code in (
                first_status,
                repeat_status,
                second_status,
                peer_status,
                restore_status,
            )
        ):
            raise RuntimeError(
                "valid repeat, policy-change, multi-node, or adjacent registration failed"
            )
        observations["live_registration"] = {
            "first": response_shape(first_body),
            "repeat_changed_policy": response_shape(repeat_body),
            "second_node": response_shape(second_body),
            "adjacent_public_identity": response_shape(peer_body),
            "primary_restored": response_shape(restore_body),
        }

        bad_status, _ = registration(
            nodes[0]["rpc_url"], "invalid", 18085, authenticated
        )
        unauth_status, _ = registration(
            nodes[0]["rpc_url"], key, 18086, unauthenticated
        )
        if bad_status < 400 or (unauth_status != 0 and unauth_status < 400):
            raise RuntimeError("malformed or unauthenticated registration was accepted")
        observations["invalid_rejections"] = {
            "malformed_key_status": bad_status,
            "unauthenticated_status": unauth_status,
        }

        with ThreadPoolExecutor(max_workers=8) as pool:
            concurrent = list(
                pool.map(
                    lambda port: registration(
                        nodes[1]["rpc_url"], key, port, authenticated
                    )[0],
                    range(18100, 18108),
                )
            )
        if concurrent != [200] * 8:
            raise RuntimeError(f"concurrent registrations failed: {concurrent}")
        observations["concurrent"] = {"requests": 8, "statuses": concurrent}

        old_pid = int(nodes[0]["pid"])
        os.kill(old_pid, signal.SIGTERM)
        if not wait_pid_exit(old_pid, 20):
            os.kill(old_pid, signal.SIGKILL)
            if not wait_pid_exit(old_pid, 10):
                raise RuntimeError("lease-owned Gateway did not stop")
        down_status, _ = registration(nodes[0]["rpc_url"], key, 18120, authenticated)
        fallback_status, fallback_body = registration(
            nodes[1]["rpc_url"], key, 18120, authenticated
        )
        if down_status != 0 or fallback_status != 200:
            raise RuntimeError(
                "Gateway outage was not isolated by the next healthy node"
            )

        binary = (
            values["prepared_binaries"]["dstack_gateway"].get("resolved_path")
            or values["prepared_binaries"]["dstack_gateway"]["path"]
        )
        recovery_log = artifacts_dir / "gateway-recovery.log"
        log_handle = recovery_log.open("ab")
        replacement = subprocess.Popen(
            [binary, "--config", nodes[0]["config"]],
            stdout=log_handle,
            stderr=subprocess.STDOUT,
        )
        if not wait_port(nodes[0]["rpc_url"], 30):
            raise RuntimeError("restarted Gateway listener did not recover")
        recovered_status, recovered_body = registration(
            nodes[0]["rpc_url"], key, 18121, authenticated
        )
        if recovered_status != 200:
            raise RuntimeError(
                f"registration after Gateway restart failed: {recovered_status}"
            )
        observations["outage_recovery"] = {
            "stopped_endpoint_status": down_status,
            "fallback_status": fallback_status,
            "fallback_shape": response_shape(fallback_body),
            "recovered_status": recovered_status,
            "recovered_shape": response_shape(recovered_body),
        }
        status = "PASS"
    except Exception as error:  # noqa: BLE001
        failure = str(error)
    finally:
        if replacement is not None and replacement.poll() is None:
            replacement.terminate()
            try:
                replacement.wait(timeout=10)
            except subprocess.TimeoutExpired:
                replacement.kill()
                replacement.wait(timeout=5)

    observations.update(
        {
            "status": status,
            "failure": failure,
            "public_key_hashes_distinct": hashlib.sha256(key.encode()).hexdigest()
            != hashlib.sha256(peer_key.encode()).hexdigest(),
            "private_key_material_persisted": False,
            "duration_seconds": round(time.monotonic() - started, 3),
        }
    )
    matrix_path = artifacts_dir / "gateway-refresh-matrix.json"
    atomic_json(matrix_path, observations)
    artifact_rows = [
        {
            "path": "artifacts/native-tests.log",
            "step_id": f"{CASE_ID}-step-01",
            "name": "Native refresh tests",
            "description": "Candidate product tests for ordered failover and private atomic key-store persistence.",
        },
        {
            "path": "artifacts/gateway-refresh-matrix.json",
            "step_id": f"{CASE_ID}-step-02",
            "name": "Gateway refresh matrix",
            "description": "Redacted live three-node registration, concurrency, outage, recovery, and adjacent identity observations.",
        },
        {
            "path": "artifacts/gateway-recovery.log",
            "step_id": f"{CASE_ID}-step-03",
            "name": "Gateway recovery log",
            "description": "Lease-owned replacement process diagnostics.",
        },
    ]
    existing_rows = [
        row for row in artifact_rows if (result_dir / row["path"]).is_file()
    ]
    atomic_json(artifacts_dir / "manifest.json", {"artifacts": existing_rows})
    summary = (
        "Gateway refresh, persistence, live failover, and recovery passed"
        if status == "PASS"
        else f"Gateway refresh matrix failed: {failure}"
    )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": [
                {
                    "id": f"{CASE_ID}-step-01",
                    "status": status,
                    "observed": "8/8 candidate persistence and ordered-selection rows passed."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-02",
                    "status": status,
                    "observed": "Three live Gateway nodes accepted repeat, changed-policy, adjacent identity, and 8-way concurrent registration while rejecting malformed and unauthenticated input."
                    if status == "PASS"
                    else failure,
                },
                {
                    "id": f"{CASE_ID}-step-03",
                    "status": status,
                    "observed": "A stopped primary endpoint failed closed, the next node served the request, and the primary recovered after a case-owned restart."
                    if status == "PASS"
                    else failure,
                },
            ],
            "artifacts": existing_rows,
            "evidence": [
                {
                    "path": row["path"],
                    "sha256": hashlib.sha256(
                        (result_dir / row["path"]).read_bytes()
                    ).hexdigest(),
                }
                for row in existing_rows
            ],
            "remarks": "Only public WireGuard keys were sent; persisted evidence contains response structure and hashes, never client private keys, certificates, or tokens.",
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
