#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Expose only public fingerprints from a real tappd-backed upgrade client."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from typing import Any

SOCKET_PATH = os.environ.get("TAPPD_SOCKET", "/var/run/tappd.sock")
DSTACK_SOCKET_PATH = os.environ.get("DSTACK_SOCKET", "/var/run/dstack.sock")
DERIVATION_PATH = os.environ.get("DERIVATION_PATH", "kms-upgrade-009")
GATEWAY_URLS = [url for url in os.environ.get("GATEWAY_URLS", "").split(",") if url]
GATEWAY_REQUEST_CONTRACTS = [
    value
    for value in os.environ.get("GATEWAY_REQUEST_CONTRACTS", "").split(",")
    if value
]
GATEWAY_PORTS = [
    int(port) for port in os.environ.get("GATEWAY_PORTS", "8000").split(",") if port
]
TRUST_CHAIN_OBSERVATION = os.environ.get("TRUST_CHAIN_OBSERVATION") == "1"
ROUTE_INSTANCE = os.environ.get("ROUTE_INSTANCE", "")
CONTINUITY_OBSERVATION = os.environ.get("CONTINUITY_OBSERVATION") == "1"
CONTINUITY_PATH = pathlib.Path("/var/lib/dstack-upgrade-continuity/sentinel")
CONTINUITY_CREATED_BY_PROCESS = False


def guest_rpc(service: str, method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Call one JSON RPC method over the appropriate guest-owned Unix socket."""
    payload = json.dumps(body, separators=(",", ":")).encode()
    path = f"/prpc/{service}.{method}?json" if service == "Tappd" else f"/{method}?json"
    socket_path = SOCKET_PATH if service == "Tappd" else DSTACK_SOCKET_PATH
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    ).encode() + payload
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(30)
        client.connect(socket_path)
        client.sendall(request)
        response = bytearray()
        while chunk := client.recv(65536):
            response.extend(chunk)
    header, raw = bytes(response).split(b"\r\n\r\n", 1)
    if b" 200 " not in header.splitlines()[0]:
        raise RuntimeError(header.splitlines()[0].decode(errors="replace"))
    return json.loads(raw)


def tappd(method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Call the compatibility Tappd service."""
    return guest_rpc("Tappd", method, body)


def public_key_sha256(private_key: str) -> str:
    """Hash the DER public key without writing or returning private material."""
    completed = subprocess.run(
        ["openssl", "pkey", "-pubout", "-outform", "DER"],
        input=private_key.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return hashlib.sha256(completed.stdout).hexdigest()


def certificate_sha256(certificate: str) -> str:
    """Hash one PEM certificate as canonical DER."""
    completed = subprocess.run(
        ["openssl", "x509", "-outform", "DER"],
        input=certificate.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return hashlib.sha256(completed.stdout).hexdigest()


def certificate_public_key_sha256(certificate: str) -> str:
    """Hash the certificate subject public key as canonical DER."""
    public = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout"],
        input=certificate.encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    canonical = subprocess.run(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=public.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return hashlib.sha256(canonical.stdout).hexdigest()


def register_gateway(
    url: str,
    request_contract: str,
    client_public_key: str,
    private_key: str,
    certificate_chain: list[str],
) -> dict[str, Any]:
    """Register through one Gateway without retaining app certificate material."""
    with tempfile.TemporaryDirectory() as directory:
        key_path = os.path.join(directory, "client.key")
        cert_path = os.path.join(directory, "client.crt")
        with open(key_path, "w", encoding="utf-8") as stream:
            stream.write(private_key)
        with open(cert_path, "w", encoding="utf-8") as stream:
            stream.write("".join(certificate_chain))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.load_cert_chain(cert_path, key_path)
        if request_contract not in {"current", "legacy"}:
            raise RuntimeError(
                f"Unsupported Gateway request contract: {request_contract}"
            )
        request_value: dict[str, Any] = {"client_public_key": client_public_key}
        if request_contract == "current":
            request_value["port_policy"] = {
                "ports": [{"port": port, "pp": False} for port in GATEWAY_PORTS]
            }
        payload = json.dumps(request_value, separators=(",", ":")).encode()
        rpc_name = "Tproxy.RegisterCvm"
        for candidate in ("Tproxy.RegisterCvm", "Gateway.RegisterCvm"):
            endpoint = f"{url.rstrip('/')}/prpc/{candidate}?json"

            def post(data: bytes) -> tuple[int, bytes]:
                request = urllib.request.Request(
                    endpoint,
                    data=data,
                    headers={"content-type": "application/json"},
                )
                try:
                    with urllib.request.urlopen(
                        request, context=context, timeout=30
                    ) as response:
                        return response.status, response.read()
                except urllib.error.HTTPError as error:
                    return error.code, error.read()

            code, body = post(payload)
            rpc_name = candidate
            if candidate == "Tproxy.RegisterCvm" and b"Service not found" in body:
                continue
            break
        value = json.loads(body) if body else {}
        error_detail = None
        if code != 200:
            raw_error = value.get("error") if isinstance(value, dict) else None
            if not isinstance(raw_error, str):
                raw_error = body.decode(errors="replace")
            error_detail = raw_error.replace(client_public_key, "<redacted>")[:300]
        return {
            "http": code,
            "rpc_name": rpc_name,
            "assigned_ip": str((value.get("wg") or {}).get("client_ip", "")),
            "request_contract": request_contract,
            "error_detail": error_detail,
            "response_sha256": hashlib.sha256(body).hexdigest(),
            "private_material_exported": False,
        }


def observe() -> dict[str, Any]:
    """Return stable public evidence for the app identity provisioned by KMS."""
    derived = tappd(
        "DeriveKey",
        {"path": DERIVATION_PATH, "subject": DERIVATION_PATH, "alt_names": []},
    )
    private_key = derived.get("key") or derived.get("private_key")
    chain = derived.get("certificate_chain") or derived.get("certificateChain") or []
    if not isinstance(private_key, str) or not private_key:
        raise RuntimeError("Tappd.DeriveKey omitted the private key")
    if not isinstance(chain, list) or not chain:
        raise RuntimeError("Tappd.DeriveKey omitted the certificate chain")
    info = tappd("Info", {})
    registration_identity = tappd(
        "DeriveKey",
        {
            "path": f"{DERIVATION_PATH}-gateway-registration",
            "subject": DERIVATION_PATH,
            "alt_names": [],
            "usage_ra_tls": True,
            "usage_server_auth": False,
            "usage_client_auth": True,
        },
    )
    registration_key = registration_identity.get("key") or registration_identity.get(
        "private_key"
    )
    registration_chain = registration_identity.get(
        "certificate_chain"
    ) or registration_identity.get("certificateChain")
    if not isinstance(registration_key, str) or not isinstance(
        registration_chain, list
    ):
        raise RuntimeError("Tappd.DeriveKey omitted the Gateway registration identity")
    delivered_environment = {
        name: hashlib.sha256(value.encode()).hexdigest()
        for name, value in os.environ.items()
        if name.startswith("DSTACK_TEST_SECRET_") and value
    }
    continuity = None
    if CONTINUITY_OBSERVATION:
        global CONTINUITY_CREATED_BY_PROCESS
        CONTINUITY_PATH.parent.mkdir(parents=True, exist_ok=True)
        if not CONTINUITY_PATH.exists():
            CONTINUITY_CREATED_BY_PROCESS = True
            temporary = CONTINUITY_PATH.with_suffix(".new")
            temporary.write_bytes(os.urandom(64))
            temporary.chmod(0o600)
            temporary.replace(CONTINUITY_PATH)
        value = CONTINUITY_PATH.read_bytes()
        if len(value) != 64:
            raise RuntimeError("protected continuity sentinel has an invalid size")
        continuity = {
            "sha256": hashlib.sha256(value).hexdigest(),
            "created_on_this_boot": CONTINUITY_CREATED_BY_PROCESS,
            "bytes": len(value),
        }
    if len(GATEWAY_REQUEST_CONTRACTS) != len(GATEWAY_URLS):
        raise RuntimeError(
            "Gateway URLs and request contracts must have the same length"
        )
    gateway_client_public_key = __import__("base64").b64encode(os.urandom(32)).decode()
    gateway_registrations = [
        register_gateway(
            url,
            request_contract,
            gateway_client_public_key,
            registration_key,
            registration_chain,
        )
        for url, request_contract in zip(
            GATEWAY_URLS, GATEWAY_REQUEST_CONTRACTS, strict=True
        )
    ]
    trust_chain: dict[str, Any] | None = None
    if TRUST_CHAIN_OBSERVATION:
        identity = {
            "app_id": info.get("app_id") or info.get("appId") or "",
            "instance_id": info.get("instance_id") or info.get("instanceId") or "",
            "compose_hash": info.get("compose_hash") or info.get("composeHash") or "",
            "os_image_hash": info.get("os_image_hash") or info.get("osImageHash") or "",
            "vm_config": info.get("vm_config") or info.get("vmConfig") or "",
        }
        canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
        report_data = hashlib.sha512(canonical).digest()
        quote = guest_rpc("DstackGuest", "GetQuote", {"report_data": report_data.hex()})
        trust_chain = {
            **identity,
            "identity_sha512": report_data.hex(),
            "quote_hex": quote.get("quote") or "",
            "event_log": quote.get("event_log") or quote.get("eventLog") or "",
            "quote_vm_config": quote.get("vm_config") or quote.get("vmConfig") or "",
            "quote_report_data": quote.get("report_data")
            or quote.get("reportData")
            or "",
            "certificate_chain_pem": chain,
        }
    if any(
        row["http"] != 200 or not row["assigned_ip"] for row in gateway_registrations
    ):
        raise RuntimeError(f"Gateway registration failed: {gateway_registrations}")
    return {
        "app_id": info.get("app_id") or info.get("appId"),
        "public_key_sha256": public_key_sha256(private_key),
        "certificate_chain_sha256": [certificate_sha256(item) for item in chain],
        "certificate_public_key_sha256": [
            certificate_public_key_sha256(item) for item in chain
        ],
        "certificate_chain_length": len(chain),
        "gateway_registrations": gateway_registrations,
        "delivered_environment_sha256": delivered_environment,
        "protected_continuity": continuity,
        "private_material_exported": False,
        "trust_chain": trust_chain,
    }


def tls_context() -> ssl.SSLContext:
    """Load the deterministic app key and public chain into an in-memory TLS server."""
    derived = tappd(
        "DeriveKey",
        {
            "path": DERIVATION_PATH,
            "subject": DERIVATION_PATH,
            "alt_names": [],
        },
    )
    key = derived.get("key") or derived.get("private_key")
    chain = derived.get("certificate_chain") or derived.get("certificateChain") or []
    if not isinstance(key, str) or not isinstance(chain, list) or not chain:
        raise RuntimeError("TLS identity derivation omitted key or certificate chain")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory(prefix="dstack-trust-tls-") as directory:
        root = pathlib.Path(directory)
        key_path = root / "key.pem"
        cert_path = root / "chain.pem"
        key_path.write_text(key)
        cert_path.write_text("\n".join(chain) + "\n")
        context.load_cert_chain(cert_path, key_path)
    return context


class Handler(http.server.BaseHTTPRequestHandler):
    """Serve the current public observation to the case controller."""

    def do_GET(self) -> None:  # noqa: N802
        """Return a public observation or a bounded diagnostic."""
        if self.path == "/route" and ROUTE_INSTANCE:
            body = json.dumps({"instance": ROUTE_INSTANCE}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path != "/observation":
            self.send_error(404)
            return
        try:
            body = json.dumps(observe(), sort_keys=True).encode()
            self.send_response(200)
        except Exception as error:  # noqa: BLE001
            body = json.dumps({"error": str(error)}).encode()
            self.send_response(503)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        """Write request metadata without response or key material."""
        print(f"observer: {message % args}", flush=True)


if __name__ == "__main__":
    deadline = time.monotonic() + 180
    while not os.path.exists(SOCKET_PATH):
        if time.monotonic() >= deadline:
            raise SystemExit("tappd socket did not appear")
        time.sleep(1)
    if TRUST_CHAIN_OBSERVATION:
        tls_server = http.server.ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
        tls_server.socket = tls_context().wrap_socket(
            tls_server.socket, server_side=True
        )
        threading.Thread(target=tls_server.serve_forever, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
