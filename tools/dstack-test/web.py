# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Embedded live dashboard for dstack test runs."""

import http.server
import json
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Callable

HTML = (Path(__file__).with_name("dashboard.html")).read_text(encoding="utf-8")


class Dashboard:
    """Serve a read-only live run dashboard."""

    def __init__(
        self,
        state: Callable[[], dict[str, Any]],
        log: Callable[[str, int], dict[str, Any]],
        case: Callable[[str], dict[str, Any]],
        host: str,
        port: int,
    ):
        """Create a dashboard bound to *host* and *port*."""

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: Any) -> None:
                pass

            def reply(self, value: Any, status: int = 200) -> None:
                data = json.dumps(value, ensure_ascii=False).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/":
                    data = HTML.encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                elif parsed.path == "/api/state":
                    self.reply(state())
                elif parsed.path == "/api/log":
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        self.reply(
                            log(
                                query.get("agent", [""])[0],
                                int(query.get("offset", ["0"])[0]),
                            )
                        )
                    except Exception as error:  # noqa: BLE001 - API boundary
                        self.reply({"error": str(error)}, 400)
                elif parsed.path == "/api/case":
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        self.reply(case(query.get("id", [""])[0]))
                    except Exception as error:  # noqa: BLE001 - API boundary
                        self.reply({"error": str(error)}, 400)
                else:
                    self.send_error(404)

        self.server = http.server.ThreadingHTTPServer((host, port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self) -> tuple[str, int]:
        """Return the effective listening address."""
        host, port = self.server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        """Start serving the dashboard in the background."""
        self.thread.start()

    def close(self) -> None:
        """Stop the dashboard and release its listening socket."""
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
