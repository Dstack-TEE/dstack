#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise real Gateway TLS-passthrough SNI routing and bounded failures."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

CASE_ID = "tc-gw-proxy-prot-003"


def load_support():
    """Load the bounded Gateway RPC helper."""
    path = Path(__file__).with_name("gateway-caa-case.py")
    spec = importlib.util.spec_from_file_location("gateway_sni_support", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Gateway support")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SUPPORT = load_support()


def client_hello(server_name: str) -> bytes:
    """Produce a native TLS ClientHello without opening an external connection."""
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
    data = outgoing.read()
    if not data:
        raise AssertionError("TLS implementation emitted no ClientHello")
    return data


def receive_record(stream: socket.socket) -> bytes:
    """Read one bounded TLS record."""
    data = bytearray()
    while len(data) < 5:
        chunk = stream.recv(5 - len(data))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    expected = 5 + int.from_bytes(data[3:5], "big")
    if expected > 65536:
        raise AssertionError("backend received oversized TLS record")
    while len(data) < expected:
        chunk = stream.recv(expected - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def routed_probe(proxy: tuple[str, int], name: str, marker: bytes) -> bool:
    """Send a ClientHello and require the case-owned backend marker."""
    with socket.create_connection(proxy, timeout=5) as stream:
        stream.settimeout(5)
        stream.sendall(client_hello(name))
        return stream.recv(len(marker)) == marker


def rejected_probe(proxy: tuple[str, int], payload: bytes) -> bool:
    """Require a malformed, unknown, or unavailable route to close without data."""
    with socket.create_connection(proxy, timeout=5) as stream:
        stream.settimeout(5)
        stream.sendall(payload)
        stream.shutdown(socket.SHUT_WR)
        try:
            return stream.recv(64) == b""
        except (ConnectionResetError, BrokenPipeError):
            return True
        except socket.timeout:
            return False


def main() -> int:
    """Run live routing, negative inputs, failover, recovery, and cleanup checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    fixture = manifest["values"]["gateway_proxy_protocol_003"]
    host, proxy_port = str(fixture["proxy_address"]).rsplit(":", 1)
    proxy = (host, int(proxy_port))
    backend = (str(fixture["backend_address"]), int(fixture["backend_port"]))
    app_id = str(fixture["registered_app_id"])
    base_domain = str(fixture["base_domain"])
    app_name = f"{app_id}-{backend[1]}s.{base_domain}"
    instance_name = f"{fixture['registered_instance_id']}-{backend[1]}s.{base_domain}"
    failure_name = f"{app_id}-{int(fixture['failure_port'])}s.{base_domain}"
    replacement = "0" if not app_id.startswith("0") else "1"
    unknown_name = f"{replacement}{app_id[1:]}-{backend[1]}s.{base_domain}"
    markers = [b"dstack-sni-route-1", b"dstack-sni-route-2"]
    admin_token = (
        Path(manifest["values"]["gateway"]["admin_auth_token_file"]).read_text().strip()
    )
    admin_base = str(manifest["values"]["gateway"]["admin_url"])
    declared_instance_id = str(fixture["registered_instance_id"])
    debug_base = str(manifest["values"]["gateway"]["debug_url"])
    sync_code, sync_body = SUPPORT.rpc(debug_base, "", "Debug.GetSyncData", {})
    try:
        sync_data = json.loads(sync_body) if sync_body else {}
    except json.JSONDecodeError:
        sync_data = {}
    matching_instances = [
        row
        for row in sync_data.get("instances", [])
        if isinstance(row, dict) and row.get("app_id") == app_id
    ]
    instance_id = (
        str(matching_instances[0].get("instance_id", ""))
        if len(matching_instances) == 1
        else ""
    )
    routing_identity_ready = (
        sync_code == 200 and len(matching_instances) == 1 and bool(instance_id)
    )
    declared_identity_matches = (
        routing_identity_ready and instance_id == declared_instance_id
    )
    requested_policy = {
        "ports": [
            {"port": backend[1], "pp": False},
            {"port": int(fixture["failure_port"]), "pp": False},
        ],
        "restrict_mode": False,
    }
    set_code, _ = SUPPORT.rpc(
        admin_base,
        admin_token,
        "Admin.SetInstancePortPolicy",
        {"instance_id": instance_id, "policy": requested_policy},
    )
    get_code, get_body = SUPPORT.rpc(
        admin_base,
        admin_token,
        "Admin.GetInstancePortPolicy",
        {"instance_id": instance_id},
    )
    try:
        policy_body = json.loads(get_body) if get_body else {}
    except json.JSONDecodeError:
        policy_body = {}
    effective = policy_body.get("effective") or {}
    effective_ports = {
        row.get("port") for row in effective.get("ports", []) if isinstance(row, dict)
    }
    policy_ready = (
        set_code == 200
        and get_code == 200
        and effective_ports == {backend[1], int(fixture["failure_port"])}
    )
    backend_records: list[dict[str, object]] = []
    backend_error: list[str] = []
    ready = threading.Event()

    def serve() -> None:
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(backend)
                listener.listen(2)
                listener.settimeout(15)
                ready.set()
                for marker in markers:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(5)
                        record = receive_record(connection)
                        backend_records.append(
                            {
                                "tls_record": record.startswith(b"\x16\x03"),
                                "size": len(record),
                                "sha256": hashlib.sha256(record).hexdigest(),
                            }
                        )
                        connection.sendall(marker)
        except Exception as error:  # noqa: BLE001
            backend_error.append(type(error).__name__)
            ready.set()

    worker = threading.Thread(target=serve, name="case-owned-sni-backend", daemon=True)
    worker.start()
    ready.wait(5)
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(runtime["cargo_target_dir"])
    unit = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "--offline",
            "-p",
            "dstack-gateway",
            "proxy::tests::test_parse_destination",
            "--",
            "--nocapture",
        ],
        cwd=Path(runtime["repository"]) / "dstack",
        env=environment,
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
    checks: dict[str, bool] = {}
    try:
        checks["fixture_case_owned"] = fixture.get("case_owned") is True
        checks["routing_identity_ready"] = routing_identity_ready
        checks["declared_identity_matches"] = declared_identity_matches
        checks["effective_policy_ready"] = policy_ready
        checks["effective_policy_source_admin"] = policy_body.get("source") == "admin"
        checks["effective_policy_unrestricted"] = not bool(
            effective.get("restrict_mode", effective.get("restrictMode", False))
        )
        checks["listener_reachable"] = not backend_error
        checks["destination_parser_unit"] = unit.returncode == 0 and unit_passed >= 1
        checks["valid_instance_route"] = routed_probe(proxy, instance_name, markers[0])
        checks["unknown_app_rejected"] = rejected_probe(
            proxy, client_hello(unknown_name)
        )
        checks["malformed_sni_rejected"] = rejected_probe(
            proxy, b"GET / HTTP/1.1\r\nHost: invalid\r\n\r\n"
        )
        checks["ipv6_literal_rejected"] = rejected_probe(
            proxy, client_hello("2001:db8::1")
        )
        checks["backend_failure_bounded"] = rejected_probe(
            proxy, client_hello(failure_name)
        )
        checks["valid_app_route_recovers"] = routed_probe(proxy, app_name, markers[1])
        worker.join(5)
        checks["backend_exactly_two_routes"] = (
            len(backend_records) == 2 and not worker.is_alive()
        )
        checks["backend_received_tls"] = len(backend_records) == 2 and all(
            bool(row["tls_record"]) for row in backend_records
        )
    except Exception as error:  # noqa: BLE001
        checks["harness_exception_free"] = False
        backend_error.append(type(error).__name__)
    log_categories = {
        "app_not_found": 0,
        "policy_denied": 0,
        "connect_failure": 0,
        "invalid_sni": 0,
        "missing_sni": 0,
        "connection_error": 0,
        "dns_resolution_failure": 0,
        "parse_failure": 0,
    }
    log_path = Path(manifest["values"]["gateway"]["log"])
    if log_path.is_file():
        log_text = log_path.read_text(errors="replace").lower()
        patterns = {
            "app_not_found": "app not found",
            "policy_denied": "denied by app port policy",
            "connect_failure": "failed to connect to app",
            "invalid_sni": "invalid sni",
            "missing_sni": "no sni found",
            "connection_error": "connection error",
            "dns_resolution_failure": "failed to resolve app address",
            "parse_failure": "failed to parse",
        }
        log_categories = {
            name: log_text.count(pattern) for name, pattern in patterns.items()
        }
        checks["no_policy_denials"] = log_categories["policy_denied"] == 0
    passed = all(checks.values()) and not backend_error
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "backend_connections": len(backend_records),
        "backend_records": backend_records,
        "backend_error_types": backend_error,
        "gateway_log_categories": log_categories,
        "unit_passed": unit_passed,
        "unit_returncode": unit.returncode,
        "retained_endpoint_values": False,
    }
    artifact = result_dir / "artifacts/gateway-proxy-sni-routing.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "Live SNI routing, bounded failover, rejection, and recovery passed."
        if passed
        else f"SNI routing checks failed: {sorted(k for k, value in checks.items() if not value)}"
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
                "path": "artifacts/gateway-proxy-sni-routing.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "A registered simulator identity and local case-owned backend were used. Evidence retains hashes, sizes, booleans, and counts only; no endpoint, app/instance ID, certificate, key, or payload is retained.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
