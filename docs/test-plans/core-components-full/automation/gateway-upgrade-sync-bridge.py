#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bridge current Gateway sync traffic with a legacy-compatible RA identity."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import pathlib
import socket
import ssl
import tempfile
import urllib.error
import urllib.request


def tappd(method: str, body: dict[str, object]) -> dict[str, object]:
    """Call one Tappd JSON RPC over its guest-owned Unix socket."""
    payload = json.dumps(body, separators=(",", ":")).encode()
    request = (
        f"POST /prpc/Tappd.{method}?json HTTP/1.1\r\n"
        f"Host: localhost\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n"
    ).encode() + payload
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(30)
        client.connect(os.environ.get("TAPPD_SOCKET", "/var/run/tappd.sock"))
        client.sendall(request)
        response = bytearray()
        while chunk := client.recv(65536):
            response.extend(chunk)
    header, raw = bytes(response).split(b"\r\n\r\n", 1)
    if b" 200 " not in header.splitlines()[0]:
        raise RuntimeError(header.splitlines()[0].decode(errors="replace"))
    return json.loads(raw)


class Bridge(http.server.BaseHTTPRequestHandler):
    """Forward Gateway RPC and WaveKV requests with the bridge identity."""

    upstream = ""
    advertised_url = ""
    client_context: ssl.SSLContext

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        length = int(self.headers.get("content-length", "0"))
        payload = self.rfile.read(length)
        request = urllib.request.Request(
            self.upstream.rstrip("/") + self.path,
            data=payload,
            headers={"content-type": self.headers.get("content-type", "application/octet-stream")},
        )
        try:
            with urllib.request.urlopen(
                request, context=self.client_context, timeout=60
            ) as response:
                status = response.status
                body = response.read()
                content_type = response.headers.get("content-type", "application/octet-stream")
        except urllib.error.HTTPError as error:
            status = error.code
            body = error.read()
            content_type = error.headers.get("content-type", "application/octet-stream")
        if self.path.rstrip("/").endswith("GetPeers") and status == 200:
            value = json.loads(body)
            for peer in value.get("peers", []):
                if peer.get("url") == self.upstream:
                    peer["url"] = self.advertised_url
            body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", content_type)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"gateway-sync-bridge: {format % args}", flush=True)


def main() -> int:
    """Prepare a compatibility identity and run the case-scoped bridge."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:7999")
    parser.add_argument("--upstream", default=os.environ.get("UPSTREAM_URL", ""))
    parser.add_argument("--advertised-url", default=os.environ.get("ADVERTISED_URL", ""))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    host, raw_port = args.listen.rsplit(":", 1)
    port = int(raw_port)
    if args.check:
        with socket.create_connection((host, port), timeout=3):
            return 0
    if not args.upstream or not args.advertised_url:
        raise RuntimeError("UPSTREAM_URL and ADVERTISED_URL are required")
    identity = tappd(
        "DeriveKey",
        {
            "path": "gateway-upgrade-sync-bridge",
            "subject": "dstack-gateway",
            "alt_names": [host],
            "usage_ra_tls": True,
            "usage_server_auth": True,
            "usage_client_auth": True,
        },
    )
    key = identity.get("key") or identity.get("private_key")
    chain = identity.get("certificate_chain") or identity.get("certificateChain")
    if not isinstance(key, str) or not isinstance(chain, list) or not chain:
        raise RuntimeError("Tappd.DeriveKey omitted the bridge identity")
    with tempfile.TemporaryDirectory(prefix="gateway-sync-bridge-", dir="/run") as directory:
        root = pathlib.Path(directory)
        key_path = root / "key.pem"
        cert_path = root / "chain.pem"
        key_path.write_text(key)
        key_path.chmod(0o600)
        cert_path.write_text("\n".join(str(item) for item in chain) + "\n")
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(cert_path, key_path)
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        client_context.load_cert_chain(cert_path, key_path)
        Bridge.upstream = args.upstream.rstrip("/")
        Bridge.advertised_url = args.advertised_url.rstrip("/")
        Bridge.client_context = client_context
        server = http.server.ThreadingHTTPServer((host, port), Bridge)
        server.socket = server_context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
