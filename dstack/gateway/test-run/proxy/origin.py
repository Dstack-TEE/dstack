#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Origin server for the proxy integration tests.

Serves the same content over plain HTTP (what the gateway's TLS-terminate path
talks to) and over TLS (what the passthrough path relays to), so a single test
can compare the two paths against one implementation.

Endpoints:
  /bytes/<n>   `n` bytes of a deterministic pattern
  /close/<n>   the same, then close the connection (no keep-alive)
  /halfclose   reads the request, waits for the client's EOF, *then* replies --
               the shape that used to lose its response before the splice gate
  /trickle/<n> `n` small records spaced out in time, i.e. token streaming
  /health      "ok"

Deterministic payloads mean a test can assert on a digest without a second
fetch, and the pattern is not all-zeroes so a truncated or misaligned relay
cannot accidentally look correct.
"""
import hashlib
import os
import socket
import ssl
import sys
import threading
import time

PATTERN = b"dstack-gateway-proxy-test-0123456789abcdef"


def payload(n: int) -> bytes:
    reps = n // len(PATTERN) + 1
    return (PATTERN * reps)[:n]


def digest(n: int) -> str:
    return hashlib.sha256(payload(n)).hexdigest()


def _respond(conn, body: bytes, close: bool):
    head = [
        b"HTTP/1.1 200 OK",
        b"Content-Type: application/octet-stream",
        b"Content-Length: %d" % len(body),
    ]
    head.append(b"Connection: close" if close else b"Connection: keep-alive")
    conn.sendall(b"\r\n".join(head) + b"\r\n\r\n" + body)


def _read_request(conn) -> bytes | None:
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = conn.recv(65536)
        except (OSError, ssl.SSLError):
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


def handle(conn):
    try:
        while True:
            req = _read_request(conn)
            if req is None:
                return
            path = req.split(b" ")[1].decode()

            if path == "/health":
                _respond(conn, b"ok", close=False)
            elif path.startswith("/bytes/"):
                _respond(conn, payload(int(path.rsplit("/", 1)[1])), close=False)
            elif path.startswith("/close/"):
                _respond(conn, payload(int(path.rsplit("/", 1)[1])), close=True)
                return
            elif path == "/halfclose":
                # Wait for the client's half-close before answering. A relay that
                # treats one direction's EOF as end-of-connection drops this.
                conn.settimeout(20)
                try:
                    while conn.recv(65536):
                        pass
                except (OSError, ssl.SSLError):
                    pass
                _respond(conn, payload(4096), close=True)
                return
            elif path.startswith("/trickle/"):
                count = int(path.rsplit("/", 1)[1])
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                for _ in range(count):
                    conn.sendall(b"40\r\n" + payload(64) + b"\r\n")
                    time.sleep(0.05)
                conn.sendall(b"0\r\n\r\n")
                return
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                return
    except (OSError, ssl.SSLError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(port: int, ctx: ssl.SSLContext | None):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(512)
    while True:
        raw, _ = srv.accept()
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if ctx is not None:
            try:
                raw = ctx.wrap_socket(raw, server_side=True)
            except (OSError, ssl.SSLError):
                raw.close()
                continue
        threading.Thread(target=handle, args=(raw,), daemon=True).start()


def main():
    plain = int(os.environ.get("PLAIN_PORT", "0"))
    tls = int(os.environ.get("TLS_PORT", "0"))
    cert, key = os.environ["CERT"], os.environ["KEY"]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)

    if plain:
        threading.Thread(target=serve, args=(plain, None), daemon=True).start()
    if tls:
        threading.Thread(target=serve, args=(tls, ctx), daemon=True).start()
    print("origin ready", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "digest":
        print(digest(int(sys.argv[2])))
    else:
        main()
