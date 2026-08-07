#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Add Cloudflare zone discovery to the DNS mock used by Gateway fixtures."""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    """Serve zone discovery and proxy record operations to the DNS mock."""

    upstream: str

    def log_message(self, _format: str, *_args: object) -> None:
        """Suppress request headers and other unnecessary fixture output."""

    def send_body(self, status: int, body: bytes, content_type: str) -> None:
        """Return one bounded upstream or fixture response."""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def dispatch(self) -> None:
        """Handle zone discovery locally and proxy all record operations."""
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/client/v4/zones":
            query = urllib.parse.parse_qs(parsed.query)
            name = query.get("name", ["gateway-candidate.test"])[0]
            body = json.dumps(
                {
                    "success": True,
                    "result": [{"id": "case-owned-zone", "name": name}],
                    "result_info": {
                        "page": 1,
                        "per_page": 50,
                        "total_pages": 1,
                        "count": 1,
                        "total_count": 1,
                    },
                },
                separators=(",", ":"),
            ).encode()
            self.send_body(200, body, "application/json")
            return

        length = int(self.headers.get("Content-Length", "0"))
        request = urllib.request.Request(
            f"{self.upstream}{self.path}",
            data=self.rfile.read(length) if length else None,
            method=self.command,
        )
        for header in ("Authorization", "Content-Type"):
            if value := self.headers.get(header):
                request.add_header(header, value)
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                self.send_body(
                    response.status,
                    response.read(),
                    response.headers.get_content_type(),
                )
        except urllib.error.HTTPError as error:
            self.send_body(
                error.code,
                error.read(),
                error.headers.get_content_type(),
            )

    do_DELETE = dispatch  # noqa: N815
    do_GET = dispatch  # noqa: N815
    do_POST = dispatch  # noqa: N815


def main() -> None:
    """Run the loopback-only compatibility proxy or probe its health."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--listen-port", type=int, default=18080)
    parser.add_argument("--upstream", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    if args.check:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{args.listen_port}/client/v4/zones?name=fixture.test",
            timeout=2,
        ) as response:
            if response.status != 200:
                raise SystemExit(1)
        return
    Handler.upstream = args.upstream.rstrip("/")
    ThreadingHTTPServer(("127.0.0.1", args.listen_port), Handler).serve_forever()


if __name__ == "__main__":
    main()
