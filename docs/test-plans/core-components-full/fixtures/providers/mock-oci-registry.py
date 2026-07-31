#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve authenticated and fault-injected case-owned OCI images over HTTPS."""
# ruff: noqa: D101, D102, D103

from __future__ import annotations

import argparse
import json
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse


class RegistryHandler(BaseHTTPRequestHandler):
    server_version = "dstack-test-oci/2"

    def log_message(self, format: str, *args: object) -> None:
        print(format % args, flush=True)

    def send_json(self, status: int, value: object) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def control(self) -> dict[str, object]:
        path = self.server.registry_config.get("control")
        if not path:
            return {"variant": "normal", "auth_required": True, "fault": "none"}
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def authenticated(self, control: dict[str, object]) -> bool:
        if not control.get("auth_required", True):
            return True
        if self.headers.get("Authorization") == "Bearer dstack-test-token":
            return True
        realm = f"https://127.0.0.1:{self.server.server_port}/token"
        self.send_response(401)
        self.send_header(
            "WWW-Authenticate",
            f'Bearer realm="{realm}",service="dstack-test-registry"',
        )
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def variant(self, control: dict[str, object]) -> dict[str, object]:
        config = self.server.registry_config
        variants = config.get("variants")
        if isinstance(variants, dict):
            name = str(control.get("variant") or "normal")
            value = variants.get(name)
            if not isinstance(value, dict):
                raise ValueError(f"unknown registry variant: {name}")
            return value
        return {
            "manifest": config["manifest"],
            "blobs": {config["digest"]: config["layer"]},
        }

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        control = self.control()
        if path == "/token":
            if control.get("fault") == "deny_token":
                self.send_json(403, {"error": "token denied by case fault"})
            else:
                self.send_json(200, {"token": "dstack-test-token"})
            return
        if path == "/v2/":
            if self.authenticated(control):
                self.send_json(200, {})
            return
        if not self.authenticated(control):
            return
        config = self.server.registry_config
        repo = config["repo"]
        if path == f"/v2/{repo}/tags/list":
            self.send_json(200, {"name": repo, "tags": [config["tag"]]})
            return
        variant = self.variant(control)
        if path == f"/v2/{repo}/manifests/{config['tag']}":
            self.send_json(200, variant["manifest"])
            return
        blob_prefix = f"/v2/{repo}/blobs/"
        if path.startswith(blob_prefix):
            digest = path[len(blob_prefix) :]
            blobs = variant.get("blobs") or {}
            blob_path = blobs.get(digest)
            if not blob_path:
                self.send_json(404, {"errors": [{"code": "BLOB_UNKNOWN"}]})
                return
            body = Path(blob_path).read_bytes()
            fault = control.get("fault")
            if fault == "corrupt":
                body = bytes([body[0] ^ 1]) + body[1:]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if fault == "interrupt":
                self.wfile.write(body[: max(1, len(body) // 2)])
                self.wfile.flush()
                self.close_connection = True
            else:
                self.wfile.write(body)
            return
        self.send_json(404, {"errors": [{"code": "NOT_FOUND"}]})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), RegistryHandler)
    server.registry_config = json.loads(args.config.read_text(encoding="utf-8"))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
