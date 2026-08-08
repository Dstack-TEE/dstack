#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise Gateway-owned TLS local routes and stream error boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import re
import socket
import ssl
import subprocess
import tempfile
import time
from typing import Any

CASE_ID = "tc-gw-internal-005"


def atomic_json(path: pathlib.Path, value: Any) -> None:
    """Write JSON atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        temporary = pathlib.Path(stream.name)
    temporary.replace(path)


def tls_request(address: str, server_name: str, request: bytes) -> tuple[int, bytes]:
    """Send one bounded TLS request to the case-owned proxy listener."""
    host, port_text = address.rsplit(":", 1)
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port_text)), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname=server_name) as stream:
            stream.settimeout(5)
            stream.sendall(request)
            chunks: list[bytes] = []
            size = 0
            while size < 65536:
                chunk = stream.recv(min(8192, 65536 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
    response = b"".join(chunks)
    line = response.split(b"\r\n", 1)[0]
    match = re.fullmatch(rb"HTTP/1\.[01] (\d{3})(?: .*)?", line)
    if match is None:
        raise AssertionError("proxy response lacked a bounded HTTP status line")
    return int(match.group(1)), response


def http_request(method: str, path: str, host: str) -> bytes:
    """Build a bounded HTTP/1.1 request without credentials."""
    return (
        f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    ).encode()


def main() -> int:
    """Run candidate unit and real local-route matrices."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = pathlib.Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text()
    )
    runtime = json.loads(
        pathlib.Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text()
    )
    gateway = manifest["values"]["gateway"]
    proxy_address = str(gateway["proxy_address"])
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    unit = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "dstack-gateway",
            "proxy::tls_terminate::tests::",
            "--",
            "--nocapture",
        ],
        cwd=pathlib.Path(runtime["repository"]) / "dstack",
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )
    unit_output = unit.stdout + unit.stderr
    unit_passed = max(
        (int(value) for value in re.findall(r"(\d+) passed; 0 failed", unit_output)),
        default=0,
    )
    status = "FAIL"
    checks: dict[str, bool] = {}
    steps: list[dict[str, str]] = []
    artifacts: list[dict[str, str]] = []
    summary = "Gateway TLS local-route matrix did not complete"
    try:
        if unit.returncode != 0 or unit_passed < 1:
            raise AssertionError(
                f"candidate stream boundary matrix failed: rc={unit.returncode}, passed={unit_passed}"
            )
        gateway_name = "gateway.localhost"
        health_name = "health.localhost"
        probes = {
            "index": tls_request(
                proxy_address,
                gateway_name,
                http_request("GET", "/.dstack/index", gateway_name),
            ),
            "health": tls_request(
                proxy_address,
                gateway_name,
                http_request("GET", "/health", gateway_name),
            ),
            "method": tls_request(
                proxy_address,
                gateway_name,
                http_request("POST", "/.dstack/index", gateway_name),
            ),
            "missing": tls_request(
                proxy_address,
                gateway_name,
                http_request("GET", "/.dstack/missing", gateway_name),
            ),
            "legacy_health": tls_request(
                proxy_address, health_name, http_request("GET", "/", health_name)
            ),
        }
        codes = {name: value[0] for name, value in probes.items()}
        bodies = {name: value[1] for name, value in probes.items()}
        index_body = bodies["index"].split(b"\r\n\r\n", 1)[-1]
        checks = {
            "candidate_stream_matrix": unit_passed >= 1,
            "local_index_exact": codes["index"] == 200
            and b'"type":"dstack gateway"' in index_body
            and b'"/app-info"' in index_body,
            "local_health_available": codes["health"] == 200,
            "method_rejected": codes["method"] == 405,
            "missing_route_rejected": codes["missing"] == 404,
            "legacy_health_available": codes["legacy_health"] == 200,
            "bounded_responses": all(len(value) <= 65536 for value in bodies.values()),
        }
        if not all(checks.values()):
            raise AssertionError(
                f"local-route checks failed: {sorted(k for k, value in checks.items() if not value)}; statuses={codes}"
            )
        observation = {
            "candidate_commit": runtime["candidate_commit"],
            "checks": checks,
            "http_statuses": codes,
            "response_sizes": {name: len(value) for name, value in bodies.items()},
            "unit_passed": unit_passed,
            "unit_returncode": unit.returncode,
        }
        artifact_path = result_dir / "artifacts/gateway-tls-local-routes.json"
        atomic_json(artifact_path, observation)
        artifacts.append(
            {
                "path": "artifacts/gateway-tls-local-routes.json",
                "step_id": f"{CASE_ID}-step-02",
                "name": "Gateway TLS local-route matrix",
                "description": "HTTP statuses, response sizes, candidate test count, and booleans only; no URL, certificate, key, or body is retained.",
            }
        )
        steps = [
            {
                "id": f"{CASE_ID}-step-01",
                "status": "PASS",
                "observed": f"{unit_passed} candidate stream/response boundary test passed through the shared Cargo target.",
            },
            {
                "id": f"{CASE_ID}-step-02",
                "status": "PASS",
                "observed": "The case-owned TLS proxy served the Gateway index and both current and legacy local health routes.",
            },
            {
                "id": f"{CASE_ID}-step-03",
                "status": "PASS",
                "observed": "Unsupported methods and paths failed with exact bounded status codes while non-EOF stream errors remained visible in the candidate matrix.",
            },
            {
                "id": f"{CASE_ID}-step-04",
                "status": "PASS",
                "observed": "All responses remained bounded and the case retained no endpoint, certificate, key, or native body.",
            },
        ]
        status = "PASS"
        summary = "Gateway TLS local routes, exact response boundaries, expected EOF handling, and visible transport errors passed."
    except Exception as error:  # noqa: BLE001
        steps = [
            {
                "id": f"{CASE_ID}-step-{n:02d}",
                "status": "FAIL" if n == 1 else "NOT_RUN",
                "observed": str(error) if n == 1 else "Not run after failure.",
            }
            for n in range(1, 5)
        ]
        summary = f"Gateway TLS local-route matrix failed: {error}"
    atomic_json(result_dir / "artifacts/manifest.json", {"artifacts": artifacts})
    evidence = []
    for artifact in artifacts:
        path = result_dir / artifact["path"]
        evidence.append(
            {
                "path": artifact["path"],
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    atomic_json(
        result_dir / "result.json",
        {
            "schema_version": "1.0",
            "case_id": CASE_ID,
            "provisional": False,
            "status": status,
            "summary": summary,
            "steps": steps,
            "artifacts": artifacts,
            "evidence": evidence,
            "remarks": "The immutable Cargo target is shared; runtime and evidence remain case-scoped. No URL, certificate, key, credential, or native response body is retained.",
            "duration_seconds": round(time.monotonic() - started, 3),
        },
    )
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
