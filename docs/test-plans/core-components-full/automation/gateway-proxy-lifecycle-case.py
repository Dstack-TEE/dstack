#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise live Gateway connection limits, timeouts, half-close, and recovery."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import threading
import time
from pathlib import Path

CASE_ID = "tc-gw-proxy-prot-006"


def client_hello(server_name: str) -> bytes:
    """Create a native TLS ClientHello for passthrough routing."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    stream = context.wrap_bio(incoming, outgoing, server_hostname=server_name)
    try:
        stream.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def receive_record(stream: socket.socket) -> bytes:
    """Read one bounded TLS record from a routed connection."""
    data = bytearray()
    while len(data) < 5:
        chunk = stream.recv(5 - len(data))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    expected = 5 + int.from_bytes(data[3:5], "big")
    if expected > 65536:
        raise ValueError("oversized TLS record")
    while len(data) < expected:
        chunk = stream.recv(expected - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def routed_socket(proxy: tuple[str, int], name: str) -> socket.socket:
    """Open a routed passthrough socket and send its ClientHello."""
    stream = socket.create_connection(proxy, timeout=5)
    stream.settimeout(5)
    stream.sendall(client_hello(name))
    return stream


def closed_without_data(stream: socket.socket, timeout: float = 2.0) -> bool:
    """Require bounded EOF/reset without application bytes."""
    stream.settimeout(timeout)
    try:
        return stream.recv(64) == b""
    except (ConnectionResetError, BrokenPipeError):
        return True
    except socket.timeout:
        return False


def main() -> int:
    """Run live limit, timeout, half-close, total-timeout, and recovery checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    fixture = manifest["values"]["gateway_proxy_protocol_006"]
    proxy_host, proxy_port = str(fixture["proxy_address"]).rsplit(":", 1)
    proxy = (proxy_host, int(proxy_port))
    backend = (str(fixture["backend_address"]), int(fixture["backend_port"]))
    route_name = (
        f"{fixture['registered_app_id']}-{backend[1]}s.{fixture['base_domain']}"
    )
    release_holds = threading.Event()
    accepted = threading.Condition()
    observations: list[dict[str, object]] = []
    backend_errors: list[str] = []
    ready = threading.Event()
    handler_threads: list[threading.Thread] = []

    def handle(connection: socket.socket, sequence: int) -> None:
        try:
            with connection:
                connection.settimeout(6)
                record = receive_record(connection)
                row: dict[str, object] = {
                    "sequence": sequence,
                    "tls_record": record.startswith(b"\x16\x03"),
                    "record_size": len(record),
                }
                if sequence <= 2:
                    release_holds.wait(5)
                    connection.sendall(f"hold-{sequence}".encode())
                    row["mode"] = "hold"
                elif sequence == 3:
                    connection.sendall(b"recovery")
                    row["mode"] = "recovery"
                elif sequence == 4:
                    row["mode"] = "idle"
                    try:
                        row["idle_eof"] = connection.recv(1) == b""
                    except (ConnectionResetError, socket.timeout):
                        row["idle_eof"] = True
                elif sequence == 5:
                    row["mode"] = "half-close"
                    body = bytearray()
                    while True:
                        chunk = connection.recv(1024)
                        if not chunk:
                            break
                        body.extend(chunk)
                    connection.sendall(b"half-close-drained")
                    row["half_close_extra_bytes"] = len(body)
                elif sequence == 6:
                    row["mode"] = "total-timeout"
                    connection.sendall(b"total-ready")
                    echoed = 0
                    while True:
                        chunk = connection.recv(64)
                        if not chunk:
                            break
                        connection.sendall(chunk)
                        echoed += len(chunk)
                    row["echoed_bytes"] = echoed
                observations.append(row)
        except Exception as error:  # noqa: BLE001
            backend_errors.append(type(error).__name__)

    def serve() -> None:
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(backend)
                listener.listen(8)
                listener.settimeout(15)
                ready.set()
                for sequence in range(1, 7):
                    connection, _ = listener.accept()
                    with accepted:
                        accepted.notify_all()
                    worker = threading.Thread(
                        target=handle,
                        args=(connection, sequence),
                        name=f"proxy-lifecycle-backend-{sequence}",
                        daemon=True,
                    )
                    handler_threads.append(worker)
                    worker.start()
        except Exception as error:  # noqa: BLE001
            backend_errors.append(type(error).__name__)
            ready.set()

    backend_worker = threading.Thread(
        target=serve, name="proxy-lifecycle-listener", daemon=True
    )
    backend_worker.start()
    ready.wait(5)
    checks: dict[str, bool] = {
        "fixture_case_owned": fixture.get("case_owned") is True,
        "backend_ready": ready.is_set() and not backend_errors,
        "configured_limit_two": fixture.get("max_connections_per_app") == 2,
    }
    streams: list[socket.socket] = []
    try:
        streams = [routed_socket(proxy, route_name), routed_socket(proxy, route_name)]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and len(handler_threads) < 2:
            time.sleep(0.02)
        checks["two_connections_admitted"] = len(handler_threads) == 2
        excess = routed_socket(proxy, route_name)
        checks["third_connection_rejected"] = closed_without_data(excess)
        excess.close()
        time.sleep(0.1)
        checks["excess_not_forwarded"] = len(handler_threads) == 2
        release_holds.set()
        hold_markers = [stream.recv(16) for stream in streams]
        checks["admitted_connections_drained"] = sorted(hold_markers) == [
            b"hold-1",
            b"hold-2",
        ]
        for stream in streams:
            stream.close()
        streams = []
        time.sleep(0.2)
        recovery = routed_socket(proxy, route_name)
        checks["counter_recycled_for_recovery"] = recovery.recv(16) == b"recovery"
        recovery.close()

        handshake = socket.create_connection(proxy, timeout=5)
        handshake_started = time.monotonic()
        checks["handshake_timeout_closes"] = closed_without_data(handshake, 1.5)
        checks["handshake_timeout_bounded"] = time.monotonic() - handshake_started < 1.5
        handshake.close()

        idle = routed_socket(proxy, route_name)
        idle_started = time.monotonic()
        checks["idle_timeout_closes"] = closed_without_data(idle, 1.8)
        checks["idle_timeout_bounded"] = time.monotonic() - idle_started < 1.8
        idle.close()

        half = routed_socket(proxy, route_name)
        half.shutdown(socket.SHUT_WR)
        checks["half_close_drains_reverse"] = half.recv(64) == b"half-close-drained"
        half.close()

        total = routed_socket(proxy, route_name)
        checks["total_route_ready"] = total.recv(32) == b"total-ready"
        total_started = time.monotonic()
        echoed = 0
        total_closed = False
        while time.monotonic() - total_started < 4.5:
            try:
                total.sendall(b"x")
                if total.recv(1) == b"x":
                    echoed += 1
                else:
                    total_closed = True
                    break
            except (BrokenPipeError, ConnectionResetError):
                total_closed = True
                break
            time.sleep(0.2)
        checks["total_timeout_closes_active"] = total_closed
        checks["total_timeout_not_idle"] = echoed >= 5
        checks["total_timeout_bounded"] = time.monotonic() - total_started < 4.5
        total.close()
    except Exception as error:  # noqa: BLE001
        checks["harness_exception_free"] = False
        backend_errors.append(type(error).__name__)
    finally:
        release_holds.set()
        for stream in streams:
            stream.close()
    backend_worker.join(5)
    for worker in handler_threads:
        worker.join(2)
    by_mode = {str(row.get("mode")): row for row in observations}
    checks["six_backend_sessions"] = len(handler_threads) == 6
    checks["backend_threads_reaped"] = not backend_worker.is_alive() and all(
        not worker.is_alive() for worker in handler_threads
    )
    checks["all_clienthellos_preserved"] = len(observations) == 6 and all(
        bool(row.get("tls_record")) for row in observations
    )
    checks["backend_observed_idle_close"] = (
        by_mode.get("idle", {}).get("idle_eof") is True
    )
    checks["backend_observed_half_close"] = "half-close" in by_mode
    checks["backend_observed_total_traffic"] = (
        int(by_mode.get("total-timeout", {}).get("echoed_bytes", 0)) >= 5
    )
    passed = all(checks.values()) and not backend_errors
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "backend_session_count": len(handler_threads),
        "backend_observations": observations,
        "backend_error_types": backend_errors,
        "retained_identifiers_or_endpoints": False,
    }
    artifact = result_dir / "artifacts/gateway-proxy-lifecycle.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "Live connection limits, timeouts, half-close, counter recycling, and recovery passed."
        if passed
        else f"Proxy lifecycle checks failed: {sorted(k for k, value in checks.items() if not value)}"
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
                "path": "artifacts/gateway-proxy-lifecycle.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "A real Gateway, registered simulator identity, assigned address, and case-owned backend were used. Six compatible sessions share one immutable fixture; no unrelated mutable state is shared.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
