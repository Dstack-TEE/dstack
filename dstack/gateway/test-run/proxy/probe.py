#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""Client-side probes for the gateway proxy integration tests.

Each subcommand exercises one behaviour and prints a single machine-readable
verdict line, so the shell driver stays a list of expectations rather than a
pile of parsing.

Deliberately uses raw sockets and `ssl` rather than an HTTP client: three of the
behaviours under test (half-close, TLS close_notify, idle reaping) are invisible
to a client that hides connection lifecycle from you.
"""

import argparse
import hashlib
import socket
import ssl
import sys
import time

import origin


def tls_context() -> ssl.SSLContext:
    """Build a client context that hides nothing about how a connection ended."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # The gateway ships TLS 1.2 by default; pin it so a version change shows up
    # as a config diff rather than as a mystery here.
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # Ragged EOF is one of the things under test, so never paper over it.
    return ctx


def connect(args):
    """Open one TLS connection to the gateway, routed by SNI."""
    raw = socket.create_connection((args.host, args.port), timeout=args.timeout)
    return tls_context().wrap_socket(
        raw, server_hostname=args.sni, suppress_ragged_eofs=False
    )


def request(sock, path: str, sni: str, close: bool = False):
    """Send one HTTP request."""
    extra = "Connection: close\r\n" if close else ""
    sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {sni}\r\n{extra}\r\n".encode())


def read_response(sock) -> tuple[bytes, str]:
    """Return (body, how_it_ended)."""
    buf = b""
    try:
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                return b"", "eof_before_headers"
            buf += chunk
    except ssl.SSLEOFError:
        return b"", "truncated_before_headers"

    head, body = buf.split(b"\r\n\r\n", 1)
    length = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":")[1])
    if length is None:
        return body, "no_content_length"

    try:
        while len(body) < length:
            chunk = sock.recv(65536)
            if not chunk:
                return body, "clean_eof"
            body += chunk
    except ssl.SSLEOFError:
        return body, "truncated"
    return body, "complete"


# --- probes -----------------------------------------------------------------


def probe_fetch(args):
    """Check the payload survives the proxy byte for byte."""
    sock = connect(args)
    request(sock, f"/bytes/{args.size}", args.sni)
    body, how = read_response(sock)
    sock.close()
    got = hashlib.sha256(body).hexdigest()
    ok = got == origin.digest(args.size) and how == "complete"
    print(
        f"verdict={'pass' if ok else 'FAIL'} bytes={len(body)} want={args.size} end={how}"
    )
    return ok


def probe_halfclose(args):
    """Check a client that half-closes its request still gets the response.

    Not wired into `test_proxy.sh`, and cannot be until it emits a real
    `close_notify`: `shutdown(SHUT_WR)` sends a bare FIN, which mid-TLS is a
    truncation rather than an orderly half-close, so the peer is right to
    abandon the connection. Verified by running this against the origin with no
    gateway in the path -- it fails there too. Doing it properly needs an
    `ssl.SSLObject` on memory BIOs, so the close_notify can be sent without
    waiting for the peer's. The relay-level behaviour is covered by unit tests
    in the meantime; see the note in `test_proxy.sh`.
    """
    sock = connect(args)
    request(sock, "/halfclose", args.sni)
    try:
        sock.shutdown(socket.SHUT_WR)
    except OSError as exc:
        print(f"verdict=FAIL could not half-close: {exc}")
        return False
    body, how = read_response(sock)
    sock.close()
    ok = len(body) == 4096 and how in ("complete", "clean_eof")
    print(f"verdict={'pass' if ok else 'FAIL'} bytes={len(body)} want=4096 end={how}")
    return ok


def probe_close_notify(args):
    """Check the app closing first reaches the client as an orderly TLS shutdown.

    Regression test: after kTLS offload the gateway used to close with a bare
    FIN, which a strict client cannot tell from a truncation attack.
    """
    sock = connect(args)
    request(sock, f"/close/{args.size}", args.sni, close=True)
    body, how = read_response(sock)
    sock.close()
    ok = len(body) == args.size and how in ("complete", "clean_eof")
    print(f"verdict={'pass' if ok else 'FAIL'} bytes={len(body)} end={how}")
    return ok


def probe_idle(args):
    """Check whether a connection that goes quiet is reaped, as configured.

    Regression test: configuring splice or kTLS used to bypass the watchdog
    entirely, leaving `timeouts.total` (5h) as the only bound.
    """
    sock = connect(args)
    request(sock, f"/bytes/{args.size}", args.sni)
    body, _ = read_response(sock)
    if len(body) != args.size:
        print(f"verdict=FAIL setup: read {len(body)} of {args.size}")
        return False

    time.sleep(args.wait)
    try:
        sock.settimeout(10)
        request(sock, "/bytes/64", args.sni)
        alive = bool(sock.recv(200))
    except (OSError, ssl.SSLError):
        alive = False
    finally:
        sock.close()

    want_alive = args.expect == "alive"
    ok = alive == want_alive
    print(
        f"verdict={'pass' if ok else 'FAIL'} "
        f"observed={'alive' if alive else 'reaped'} expected={args.expect}"
    )
    return ok


def probe_concurrent(args):
    """Check many simultaneous transfers all arrive intact.

    Exercises the parts a single-connection test cannot: the pipe pool, the
    per-core balancer, and whatever the gate does under real concurrency.
    """
    import concurrent.futures

    def one(_):
        try:
            sock = connect(args)
            request(sock, f"/bytes/{args.size}", args.sni)
            body, how = read_response(sock)
            sock.close()
            return (
                hashlib.sha256(body).hexdigest() == origin.digest(args.size)
                and how == "complete"
            )
        except Exception:
            return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.count) as pool:
        results = list(pool.map(one, range(args.count)))
    ok = all(results)
    print(
        f"verdict={'pass' if ok else 'FAIL'} "
        f"intact={sum(results)}/{args.count} size={args.size}"
    )
    return ok


PROBES = {
    "fetch": probe_fetch,
    "halfclose": probe_halfclose,
    "close-notify": probe_close_notify,
    "idle": probe_idle,
    "concurrent": probe_concurrent,
}


def main():
    """Run one probe and exit non-zero if it failed."""
    ap = argparse.ArgumentParser()
    ap.add_argument("probe", choices=sorted(PROBES))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--sni", required=True)
    ap.add_argument("--size", type=int, default=1024)
    ap.add_argument("--count", type=int, default=16)
    ap.add_argument("--wait", type=float, default=12.0)
    ap.add_argument("--expect", default="reaped", choices=["alive", "reaped"])
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()
    sys.exit(0 if PROBES[args.probe](args) else 1)


if __name__ == "__main__":
    main()
