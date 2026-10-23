#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise live Gateway TLS termination and plaintext backend semantics."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

CASE_ID = "tc-gw-proxy-prot-004"
LARGE_BODY = bytes((index % 251 for index in range(256 * 1024)))


def tls_stream(
    proxy: tuple[str, int], server_name: str, *, h2: bool = False
) -> ssl.SSLSocket:
    """Open one bounded TLS connection to the case-owned proxy."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if h2:
        context.set_alpn_protocols(["h2"])
    raw = socket.create_connection(proxy, timeout=5)
    raw.settimeout(5)
    try:
        return context.wrap_socket(raw, server_hostname=server_name)
    except Exception:
        raw.close()
        raise


def recv_until(stream: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    """Read bounded bytes until a delimiter or EOF."""
    data = bytearray()
    while marker not in data and len(data) < limit:
        chunk = stream.recv(min(8192, limit - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def main() -> int:
    """Run HTTP/1.1, h2, upgrade, streaming, disconnect, failure, and recovery."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    fixture = manifest["values"]["gateway_proxy_protocol_004"]
    proxy_host, proxy_port = str(fixture["proxy_address"]).rsplit(":", 1)
    proxy = (proxy_host, int(proxy_port))
    backend = (str(fixture["backend_address"]), int(fixture["backend_port"]))
    app_id = str(fixture["registered_app_id"])
    base = str(fixture["base_domain"])
    http_name = f"{app_id}-{backend[1]}.{base}"
    h2_name = f"{app_id}-{backend[1]}g.{base}"
    failure_name = f"{app_id}-{int(fixture['failure_port'])}.{base}"
    observations: list[dict[str, object]] = []
    backend_errors: list[str] = []
    ready = threading.Event()

    def serve() -> None:
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(backend)
                listener.listen(8)
                listener.settimeout(20)
                ready.set()
                for _ in range(6):
                    connection, _peer = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        head = recv_until(connection, b"\r\n\r\n", 32768)
                        if head.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
                            observations.append(
                                {"kind": "h2", "preface": True, "size": len(head)}
                            )
                            connection.sendall(b"h2-backend-observed")
                            continue
                        first = head.split(b"\r\n", 1)[0]
                        path = (
                            first.split(b" ")[1] if len(first.split(b" ")) >= 2 else b""
                        )
                        length_match = re.search(
                            rb"(?im)^Content-Length: (\d+)\r?$", head
                        )
                        content_length = (
                            int(length_match.group(1)) if length_match else 0
                        )
                        body = (
                            head.split(b"\r\n\r\n", 1)[1]
                            if b"\r\n\r\n" in head
                            else b""
                        )
                        while len(body) < content_length:
                            chunk = connection.recv(
                                min(65536, content_length - len(body))
                            )
                            if not chunk:
                                break
                            body += chunk
                        if path == b"/disconnect":
                            observations.append(
                                {
                                    "kind": "disconnect",
                                    "declared": content_length,
                                    "received": len(body),
                                }
                            )
                            continue
                        if path == b"/upgrade":
                            connection.sendall(
                                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: dstack-test\r\n\r\n"
                            )
                            tunnel = connection.recv(128)
                            observations.append(
                                {
                                    "kind": "upgrade",
                                    "size": len(tunnel),
                                    "sha256": hashlib.sha256(tunnel).hexdigest(),
                                }
                            )
                            connection.sendall(tunnel)
                            continue
                        kind = "large" if path == b"/large" else "http1"
                        observations.append(
                            {
                                "kind": kind,
                                "size": len(body),
                                "sha256": hashlib.sha256(body).hexdigest(),
                            }
                        )
                        marker = b"large-ok" if kind == "large" else b"http1-ok"
                        connection.sendall(
                            b"HTTP/1.1 200 OK\r\nContent-Length: "
                            + str(len(marker)).encode()
                            + b"\r\nConnection: close\r\n\r\n"
                            + marker
                        )
        except Exception as error:  # noqa: BLE001
            backend_errors.append(type(error).__name__)
            ready.set()

    worker = threading.Thread(target=serve, name="case-owned-tls-backend", daemon=True)
    worker.start()
    ready.wait(5)
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
        cwd=Path(runtime["repository"]) / "dstack",
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
    checks: dict[str, bool] = {
        "fixture_case_owned": fixture.get("case_owned") is True,
        "listener_ready": not backend_errors,
        "stream_error_unit": unit.returncode == 0 and unit_passed >= 1,
    }
    try:
        with tls_stream(proxy, http_name) as stream:
            stream.sendall(
                b"GET /small HTTP/1.1\r\nHost: app\r\nConnection: close\r\n\r\n"
            )
            response = recv_until(stream, b"http1-ok")
            checks["http1"] = b"HTTP/1.1 200" in response and response.endswith(
                b"http1-ok"
            )
        with tls_stream(proxy, http_name) as stream:
            header = f"POST /large HTTP/1.1\r\nHost: app\r\nContent-Length: {len(LARGE_BODY)}\r\nConnection: close\r\n\r\n".encode()
            stream.sendall(header + LARGE_BODY)
            response = recv_until(stream, b"large-ok")
            checks["large_stream"] = response.endswith(b"large-ok")
        tunnel_payload = b"bounded-upgrade-payload"
        with tls_stream(proxy, http_name) as stream:
            stream.sendall(
                b"GET /upgrade HTTP/1.1\r\nHost: app\r\nConnection: Upgrade\r\nUpgrade: dstack-test\r\n\r\n"
            )
            response = recv_until(stream, b"\r\n\r\n")
            stream.sendall(tunnel_payload)
            checks["upgrade"] = (
                b" 101 " in response
                and stream.recv(len(tunnel_payload)) == tunnel_payload
            )
        with tls_stream(proxy, h2_name, h2=True) as stream:
            checks["h2_alpn"] = stream.selected_alpn_protocol() == "h2"
            stream.sendall(
                b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
            )
            checks["h2_preface"] = stream.recv(64) == b"h2-backend-observed"
        stream = tls_stream(proxy, http_name)
        stream.sendall(
            b"POST /disconnect HTTP/1.1\r\nHost: app\r\nContent-Length: 1000\r\n\r\npartial"
        )
        stream.close()
        with tls_stream(proxy, failure_name) as stream:
            try:
                checks["backend_failure"] = stream.recv(64) == b""
            except (ConnectionResetError, ssl.SSLError):
                checks["backend_failure"] = True
        with tls_stream(proxy, http_name) as stream:
            stream.sendall(
                b"GET /recovery HTTP/1.1\r\nHost: app\r\nConnection: close\r\n\r\n"
            )
            checks["recovery"] = recv_until(stream, b"http1-ok").endswith(b"http1-ok")
        worker.join(5)
        checks["backend_sessions"] = len(observations) == 6 and not worker.is_alive()
        by_kind = {str(row["kind"]): row for row in observations}
        checks["backend_http1"] = "http1" in by_kind
        checks["backend_large_exact"] = (
            by_kind.get("large", {}).get("size") == len(LARGE_BODY)
            and by_kind.get("large", {}).get("sha256")
            == hashlib.sha256(LARGE_BODY).hexdigest()
        )
        checks["backend_upgrade_exact"] = (
            by_kind.get("upgrade", {}).get("sha256")
            == hashlib.sha256(tunnel_payload).hexdigest()
        )
        checks["backend_h2"] = by_kind.get("h2", {}).get("preface") is True
        checks["backend_disconnect_partial"] = (
            0 < int(by_kind.get("disconnect", {}).get("received", 0)) < 1000
        )
    except Exception as error:  # noqa: BLE001
        checks["harness_exception_free"] = False
        backend_errors.append(type(error).__name__)
    passed = all(checks.values()) and not backend_errors
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "backend_session_count": len(observations),
        "backend_observations": observations,
        "backend_error_types": backend_errors,
        "unit_passed": unit_passed,
        "unit_returncode": unit.returncode,
        "retained_endpoint_values": False,
    }
    artifact = result_dir / "artifacts/gateway-proxy-tls-termination.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "Live TLS termination and HTTP semantics passed."
        if passed
        else f"TLS termination checks failed: {sorted(k for k, value in checks.items() if not value)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {"id": f"{CASE_ID}-step-{n:02d}", "status": status, "observed": observed}
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/gateway-proxy-tls-termination.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "A real TLS listener and case-owned plaintext backend were used. Evidence retains bounded hashes, sizes, counts, status and booleans only.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
