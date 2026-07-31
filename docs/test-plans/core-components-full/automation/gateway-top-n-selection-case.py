#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise deterministic Top-N selection plus live Gateway route recovery."""

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

CASE_ID = "tc-gw-select-007"


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
    """Read one bounded TLS record."""
    data = bytearray()
    while len(data) < 5:
        chunk = stream.recv(5 - len(data))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    expected = 5 + int.from_bytes(data[3:5], "big")
    while len(data) < expected and expected <= 65536:
        chunk = stream.recv(expected - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def routed_probe(proxy: tuple[str, int], name: str, marker: bytes) -> bool:
    """Require one SNI route to reach the case-owned backend."""
    with socket.create_connection(proxy, timeout=5) as stream:
        stream.settimeout(5)
        stream.sendall(client_hello(name))
        return stream.recv(len(marker)) == marker


def rejected_probe(proxy: tuple[str, int], name: str) -> bool:
    """Require a cross-app identity mutation to close without backend data."""
    with socket.create_connection(proxy, timeout=5) as stream:
        stream.settimeout(5)
        stream.sendall(client_hello(name))
        stream.shutdown(socket.SHUT_WR)
        try:
            return stream.recv(64) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False


def main() -> int:
    """Run the internal selection matrix and two live recovery observations."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    fixture = manifest["values"]["gateway_select_007"]
    proxy_host, proxy_port = str(fixture["proxy_address"]).rsplit(":", 1)
    proxy = (proxy_host, int(proxy_port))
    backend = (str(fixture["backend_address"]), int(fixture["backend_port"]))
    app_id = str(fixture["registered_app_id"])
    route_name = f"{app_id}-{backend[1]}s.{fixture['base_domain']}"
    altered = ("0" if not app_id.startswith("0") else "1") + app_id[1:]
    wrong_name = f"{altered}-{backend[1]}s.{fixture['base_domain']}"
    markers = [b"top-n-route-1", b"top-n-route-2"]
    observations: list[dict[str, object]] = []
    backend_errors: list[str] = []
    ready = threading.Event()

    def serve() -> None:
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(backend)
                listener.listen(2)
                listener.settimeout(12)
                ready.set()
                for marker in markers:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        record = receive_record(connection)
                        observations.append(
                            {
                                "tls_record": record.startswith(b"\x16\x03"),
                                "size": len(record),
                                "sha256": hashlib.sha256(record).hexdigest(),
                            }
                        )
                        connection.sendall(marker)
        except Exception as error:  # noqa: BLE001
            backend_errors.append(type(error).__name__)
            ready.set()

    worker = threading.Thread(target=serve, name="top-n-live-backend", daemon=True)
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
            "gateway_top_n_batch_007",
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
    output = unit.stdout + unit.stderr
    unit_passed = max(
        (int(value) for value in re.findall(r"(\d+) passed; 0 failed", output)),
        default=0,
    )
    checks: dict[str, bool] = {
        "fixture_case_owned": fixture.get("case_owned") is True,
        "backend_ready": ready.is_set() and not backend_errors,
        "selection_matrix": unit.returncode == 0 and unit_passed >= 1,
    }
    try:
        checks["initial_live_route"] = routed_probe(proxy, route_name, markers[0])
        checks["cross_app_rejected"] = rejected_probe(proxy, wrong_name)
        checks["live_route_recovers"] = routed_probe(proxy, route_name, markers[1])
    except Exception as error:  # noqa: BLE001
        checks["harness_exception_free"] = False
        backend_errors.append(type(error).__name__)
    worker.join(5)
    checks["exact_backend_routes"] = len(observations) == 2 and not worker.is_alive()
    checks["clienthello_preserved"] = len(observations) == 2 and all(
        bool(row["tls_record"]) for row in observations
    )
    passed = all(checks.values()) and not backend_errors
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "unit_passed": unit_passed,
        "unit_returncode": unit.returncode,
        "backend_connection_count": len(observations),
        "backend_observations": observations,
        "backend_error_types": backend_errors,
        "retained_identifiers_or_endpoints": False,
    }
    artifact = result_dir / "artifacts/gateway-top-n-selection.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "Top-N health, cache, invalidation, isolation, and live recovery passed."
        if passed
        else f"Top-N checks failed: {sorted(k for k, value in checks.items() if not value)}"
    )
    result = {
        "schema_version": "1.0",
        "case_id": CASE_ID,
        "provisional": False,
        "status": status,
        "summary": observed,
        "steps": [
            {
                "id": f"{CASE_ID}-step-{n:02d}",
                "status": status,
                "observed": observed,
            }
            for n in range(1, 4)
        ],
        "evidence": [
            {
                "path": "artifacts/gateway-top-n-selection.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "The source-defined selection branches run against deterministic in-process state; a real Gateway listener, registered simulator identity, assigned address, and backend verify routing and recovery without retaining identifiers.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
