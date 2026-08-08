#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Exercise deterministic Gateway app-address DNS routing and cache semantics."""

from __future__ import annotations

import hashlib
import json
import os
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

CASE_ID = "tc-gw-proxy-prot-005"
PREFIX = "_dstack-app-address"
LEGACY_PREFIX = "_tapp-address"


def client_hello(server_name: str) -> bytes:
    """Create a native TLS ClientHello for the requested content name."""
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


def question_end(packet: bytes) -> tuple[int, str, int]:
    """Return the DNS question boundary, normalized name, and query type."""
    offset = 12
    labels: list[str] = []
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("compressed DNS question is unsupported")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    query_type = struct.unpack("!H", packet[offset : offset + 2])[0]
    return offset + 4, ".".join(labels).lower(), query_type


class DnsAuthority:
    """Small case-owned UDP TXT authority with mutable records and query counts."""

    def __init__(
        self,
        address: tuple[str, int],
        records: dict[str, tuple[str, int]],
    ):
        """Initialize the bounded authority without opening a listener."""
        self.address = address
        self.records = records
        self.queries: dict[str, int] = {}
        self.errors: list[str] = []
        self.stop = threading.Event()
        self.ready = threading.Event()
        self.lock = threading.Lock()

    def set_record(self, name: str, value: str, ttl: int = 1) -> None:
        """Atomically replace one TXT record for cache mutation checks."""
        with self.lock:
            self.records[name.lower()] = (value, ttl)

    def serve(self) -> None:
        """Serve bounded UDP TXT responses until the case requests shutdown."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
                server.bind(self.address)
                server.settimeout(0.2)
                self.ready.set()
                while not self.stop.is_set():
                    try:
                        packet, peer = server.recvfrom(4096)
                    except socket.timeout:
                        continue
                    try:
                        end, name, query_type = question_end(packet)
                        with self.lock:
                            self.queries[name] = self.queries.get(name, 0) + 1
                            record = self.records.get(name)
                        if query_type == 16 and record is not None:
                            value, ttl = record
                            encoded = value.encode("utf-8")
                            answer = (
                                b"\xc0\x0c"
                                + struct.pack("!HHIH", 16, 1, ttl, len(encoded) + 1)
                                + bytes([len(encoded)])
                                + encoded
                            )
                            header = packet[:2] + struct.pack(
                                "!HHHHH", 0x8180, 1, 1, 0, 0
                            )
                            response = header + packet[12:end] + answer
                        else:
                            header = packet[:2] + struct.pack(
                                "!HHHHH", 0x8183, 1, 0, 0, 0
                            )
                            response = header + packet[12:end]
                        server.sendto(response, peer)
                    except Exception as error:  # noqa: BLE001
                        self.errors.append(type(error).__name__)
        except Exception as error:  # noqa: BLE001
            self.errors.append(type(error).__name__)
            self.ready.set()


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
    """Require a content name to reach the registered case backend."""
    with socket.create_connection(proxy, timeout=5) as stream:
        stream.settimeout(5)
        stream.sendall(client_hello(name))
        return stream.recv(len(marker)) == marker


def rejected_probe(proxy: tuple[str, int], name: str) -> bool:
    """Require an invalid mapping to close without backend bytes."""
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
    """Run current, legacy, wildcard, mutation, rejection, and cleanup checks."""
    if os.environ["DSTACK_TEST_CASE_ID"] != CASE_ID:
        raise ValueError("unsupported case")
    started = time.monotonic()
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime = json.loads(Path(os.environ["DSTACK_TEST_RUNTIME_MANIFEST"]).read_text())
    fixture = manifest["values"]["gateway_proxy_protocol_005"]
    proxy_host, proxy_port = str(fixture["proxy_address"]).rsplit(":", 1)
    dns_addresses = []
    for address in fixture["dns_addresses"]:
        dns_host, dns_port = str(address).rsplit(":", 1)
        dns_addresses.append((dns_host, int(dns_port)))
    if len(dns_addresses) != 2:
        raise ValueError("the app-address case requires two DNS servers")
    proxy = (proxy_host, int(proxy_port))
    backend = (str(fixture["backend_address"]), int(fixture["backend_port"]))
    app_id = str(fixture["registered_app_id"])
    altered_app_id = ("0" if not app_id.startswith("0") else "1") + app_id[1:]
    target = f"{app_id}:{backend[1]}"
    altered = f"{altered_app_id}:{backend[1]}"
    names = {
        "app": "app-name.case.test",
        "instance": "instance-name.case.test",
        "content": "content-name.case.test",
        "collision": "collision-name.case.test",
        "wrong": "wrong-name.case.alt.test",
        "malformed": "malformed-name.case.alt.test",
        "stale": "stale-name.case.alt.test",
    }
    records = {
        f"{PREFIX}.{names['app']}": (target, 1),
        f"{LEGACY_PREFIX}.{names['instance']}": (target, 1),
        f"{PREFIX}-wildcard.case.test": (target, 1),
        f"{PREFIX}.{names['collision']}": (target, 1),
        f"{LEGACY_PREFIX}.{names['collision']}": (altered, 1),
        f"{PREFIX}.{names['wrong']}": (altered, 1),
        f"{PREFIX}.{names['malformed']}": ("invalid-address", 1),
        f"{PREFIX}.{names['stale']}": (target, 1),
    }
    authorities = [DnsAuthority(address, dict(records)) for address in dns_addresses]
    dns_workers = [
        threading.Thread(
            target=current.serve, name=f"case-owned-dns-{index}", daemon=True
        )
        for index, current in enumerate(authorities, start=1)
    ]
    for dns_worker in dns_workers:
        dns_worker.start()
    for current in authorities:
        current.ready.wait(5)
    backend_records: list[dict[str, object]] = []
    backend_errors: list[str] = []
    backend_ready = threading.Event()
    markers = [f"route-{index}".encode() for index in range(1, 7)]

    def serve_backend() -> None:
        try:
            with socket.socket() as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(backend)
                listener.listen(8)
                listener.settimeout(20)
                backend_ready.set()
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
            backend_errors.append(type(error).__name__)
            backend_ready.set()

    backend_worker = threading.Thread(
        target=serve_backend, name="case-owned-backend", daemon=True
    )
    backend_worker.start()
    backend_ready.wait(5)
    checks: dict[str, bool] = {
        "fixture_case_owned": fixture.get("case_owned") is True,
        "dns_ready": all(current.ready.is_set() for current in authorities)
        and not any(current.errors for current in authorities),
        "backend_ready": backend_ready.is_set() and not backend_errors,
    }
    try:
        checks["current_app_namespace"] = routed_probe(proxy, names["app"], markers[0])
        checks["legacy_instance_namespace"] = routed_probe(
            proxy, names["instance"], markers[1]
        )
        checks["content_wildcard_namespace"] = routed_probe(
            proxy, names["content"], markers[2]
        )
        checks["current_wins_collision"] = routed_probe(
            proxy, names["collision"], markers[3]
        )
        checks["wrong_app_rejected"] = rejected_probe(proxy, names["wrong"])
        checks["malformed_mapping_rejected"] = rejected_probe(proxy, names["malformed"])
        checks["missing_mapping_rejected"] = rejected_probe(
            proxy, "missing.other.alt.test"
        )
        checks["stale_initial_route"] = routed_probe(proxy, names["stale"], markers[4])
        for current in authorities:
            current.set_record(f"{PREFIX}.{names['stale']}", altered, 1)
        checks["positive_cache_deterministic"] = routed_probe(
            proxy, names["stale"], markers[5]
        )
        time.sleep(1.3)
        checks["expired_stale_mapping_rejected"] = rejected_probe(proxy, names["stale"])
        for current in authorities:
            current.set_record(f"{PREFIX}.{names['stale']}", target, 1)
        time.sleep(1.3)
        # The final observation is a bounded DNS recovery check. A backend route
        # is not opened so the six successful sessions remain exact.
        before = sum(
            current.queries.get(f"{PREFIX}.{names['stale']}", 0)
            for current in authorities
        )
        rejected_probe(proxy, names["stale"])
        after = sum(
            current.queries.get(f"{PREFIX}.{names['stale']}", 0)
            for current in authorities
        )
        checks["mapping_requeried_after_ttl"] = after > before
    except Exception as error:  # noqa: BLE001
        checks["harness_exception_free"] = False
        backend_errors.append(type(error).__name__)
    backend_worker.join(5)
    for current in authorities:
        current.stop.set()
    for dns_worker in dns_workers:
        dns_worker.join(2)
    checks["backend_exact_sessions"] = (
        len(backend_records) == 6 and not backend_worker.is_alive()
    )
    checks["tls_clienthello_preserved"] = len(backend_records) == 6 and all(
        bool(row["tls_record"]) for row in backend_records
    )
    checks["dns_clean_shutdown"] = not any(
        dns_worker.is_alive() for dns_worker in dns_workers
    ) and not any(current.errors for current in authorities)
    checks["dns_servers_exercised"] = all(current.queries for current in authorities)
    queried = {name for current in authorities for name in current.queries}
    checks["current_and_legacy_queried"] = any(
        name.startswith(PREFIX + ".") for name in queried
    ) and any(name.startswith(LEGACY_PREFIX + ".") for name in queried)
    passed = all(checks.values()) and not backend_errors
    status = "PASS" if passed else "FAIL"
    evidence = {
        "candidate_commit": runtime["candidate_commit"],
        "checks": checks,
        "backend_connections": len(backend_records),
        "backend_records": backend_records,
        "backend_error_types": backend_errors,
        "dns_error_types": [
            error for current in authorities for error in current.errors
        ],
        "dns_server_query_counts": [
            sum(current.queries.values()) for current in authorities
        ],
        "dns_query_name_classes": {
            "current": sum(
                v
                for current in authorities
                for k, v in current.queries.items()
                if k.startswith(PREFIX + ".")
            ),
            "legacy": sum(
                v
                for current in authorities
                for k, v in current.queries.items()
                if k.startswith(LEGACY_PREFIX + ".")
            ),
            "wildcard": sum(
                v
                for current in authorities
                for k, v in current.queries.items()
                if k.startswith(PREFIX + "-wildcard.")
            ),
        },
        "retained_identifiers_or_endpoints": False,
    }
    artifact = result_dir / "artifacts/gateway-app-address-routing.json"
    artifact.parent.mkdir(parents=True, exist_ok=True)
    artifact.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    observed = (
        "Deterministic app-address namespace, rejection, cache, and recovery checks passed."
        if passed
        else f"App-address checks failed: {sorted(k for k, value in checks.items() if not value)}"
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
                "path": "artifacts/gateway-app-address-routing.json",
                "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
        ],
        "remarks": "Case-owned DNS authorities, a registered simulator identity, assigned loopback address, and backend were used. TLS passthrough preserves the end-to-end ClientHello; certificate validation remains the HTTPS client's responsibility.",
        "duration_seconds": round(time.monotonic() - started, 3),
    }
    (result_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
