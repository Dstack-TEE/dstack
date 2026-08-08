#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Expose Gateway TLS-to-TDX report-data binding without private material."""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import socket
import ssl
import time
from typing import Any

SOCKET_PATH = "/var/run/dstack.sock"


def guest_rpc(method: str, body: dict[str, Any]) -> dict[str, Any]:
    """Call DstackGuest JSON pRPC over the guest-owned Unix socket."""
    payload = json.dumps(body, separators=(",", ":")).encode()
    request = (
        f"POST /{method}?json HTTP/1.1\r\nHost: localhost\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode() + payload
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(30)
        client.connect(SOCKET_PATH)
        client.sendall(request)
        response = bytearray()
        while chunk := client.recv(65536):
            response.extend(chunk)
    header, raw = bytes(response).split(b"\r\n\r\n", 1)
    if b" 200 " not in header.splitlines()[0]:
        raise RuntimeError(header.splitlines()[0].decode(errors="replace"))
    return json.loads(raw)


def observation() -> dict[str, Any]:
    """Bind the current public Gateway leaf to a physical quote challenge."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", 8000), timeout=30) as raw:
        with context.wrap_socket(raw, server_hostname="gateway-candidate.test") as tls:
            certificate = tls.getpeercert(binary_form=True)
    report_data = hashlib.sha512(certificate).digest()
    quote = guest_rpc(
        "GetQuote",
        {"report_data": report_data.hex()},
    )
    raw_quote = bytes.fromhex(quote.get("quote") or "")
    raw_attestation = bytes.fromhex(quote.get("attestation") or "")
    return {
        "certificate_der_sha256": hashlib.sha256(certificate).hexdigest(),
        "report_data_hex": report_data.hex(),
        "quote_hex": raw_quote.hex(),
        "event_log": quote.get("event_log") or quote.get("eventLog") or "",
        "vm_config": quote.get("vm_config") or quote.get("vmConfig") or "",
        "attestation_hex": raw_attestation.hex(),
        "private_material_exported": False,
    }


class Handler(http.server.BaseHTTPRequestHandler):
    """Serve one current public observation."""

    def do_GET(self) -> None:  # noqa: N802
        """Return the bound quote projection."""
        if self.path != "/observation":
            self.send_error(404)
            return
        try:
            body = json.dumps(observation(), sort_keys=True).encode()
            self.send_response(200)
        except Exception as error:  # noqa: BLE001
            body = json.dumps({"error": str(error)}).encode()
            self.send_response(503)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        """Log request metadata only."""
        print(message % args, flush=True)


if __name__ == "__main__":
    deadline = time.monotonic() + 180
    while not os.path.exists(SOCKET_PATH):
        if time.monotonic() >= deadline:
            raise SystemExit("dstack socket did not appear")
        time.sleep(1)
    http.server.ThreadingHTTPServer(("0.0.0.0", 8002), Handler).serve_forever()
