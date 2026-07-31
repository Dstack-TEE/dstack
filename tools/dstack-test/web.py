# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Embedded live dashboard for dstack test runs."""

import http.server
import json
import secrets
import threading
import urllib.parse
from pathlib import Path
from typing import Any, Callable

DASHBOARD_HTML = Path(__file__).with_name("dashboard.html")


class Dashboard:
    """Serve a live run dashboard with optional token-protected controls."""

    def __init__(
        self,
        state: Callable[[str | None], dict[str, Any]],
        log: Callable[[str, str, int], dict[str, Any]],
        case: Callable[[str, str], dict[str, Any]],
        runs: Callable[[], list[dict[str, Any]]],
        host: str,
        port: int,
        control: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
        control_token: str | None = None,
        attachment: Callable[[str, str, str], tuple[bytes, str, str]] | None = None,
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

            def authorized(self) -> bool:
                if control is None:
                    return False
                supplied = self.headers.get("X-Dstack-Control-Token", "")
                return bool(control_token) and secrets.compare_digest(
                    supplied, control_token
                )

            def read_json(self) -> dict[str, Any]:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError as error:
                    raise ValueError("invalid Content-Length") from error
                if length < 0 or length > 1024 * 1024:
                    raise ValueError("request body is too large")
                value = json.loads(self.rfile.read(length) or b"{}")
                if not isinstance(value, dict):
                    raise ValueError("JSON body must be an object")
                return value

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/":
                    data = DASHBOARD_HTML.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                elif parsed.path == "/api/state":
                    query = urllib.parse.parse_qs(parsed.query)
                    self.reply(state(query.get("run", [None])[0]))
                elif parsed.path == "/api/runs":
                    self.reply({"runs": runs()})
                elif parsed.path == "/api/log":
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        self.reply(
                            log(
                                query.get("run", [""])[0],
                                query.get("agent", [""])[0],
                                int(query.get("offset", ["0"])[0]),
                            )
                        )
                    except Exception as error:  # noqa: BLE001 - API boundary
                        self.reply({"error": str(error)}, 400)
                elif parsed.path == "/api/case":
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        self.reply(
                            case(
                                query.get("run", [""])[0],
                                query.get("id", [""])[0],
                            )
                        )
                    except Exception as error:  # noqa: BLE001 - API boundary
                        self.reply({"error": str(error)}, 400)
                elif parsed.path == "/api/attachment" and attachment is not None:
                    query = urllib.parse.parse_qs(parsed.query)
                    try:
                        data, media_type, name = attachment(
                            query.get("run", [""])[0],
                            query.get("case", [""])[0],
                            query.get("path", [""])[0],
                        )
                        self.send_response(200)
                        self.send_header("Content-Type", media_type)
                        self.send_header("Cache-Control", "no-store")
                        self.send_header(
                            "Content-Disposition",
                            f"inline; filename*=UTF-8''{urllib.parse.quote(name)}",
                        )
                        self.send_header("Content-Length", str(len(data)))
                        self.end_headers()
                        self.wfile.write(data)
                    except Exception as error:  # noqa: BLE001 - API boundary
                        self.reply({"error": str(error)}, 404)
                else:
                    self.send_error(404)

            def do_POST(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path not in ("/api/control/start", "/api/control/stop"):
                    self.send_error(404)
                    return
                if not self.authorized():
                    self.reply({"error": "invalid or missing control token"}, 403)
                    return
                try:
                    action = parsed.path.rsplit("/", 1)[-1]
                    self.reply(control(action, self.read_json()))  # type: ignore[misc]
                except Exception as error:  # noqa: BLE001 - API boundary
                    self.reply({"error": str(error)}, 400)

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
