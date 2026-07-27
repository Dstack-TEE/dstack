#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0
"""A TLS client that can half-close.

`ssl.SSLSocket` cannot express "I have finished sending, keep sending to me".
Its only shutdown is `unwrap()`, which sends our `close_notify` and then blocks
for the peer's -- but the peer will not send its own until it has finished
replying, which is the very thing under test. Going one level lower and doing
`shutdown(SHUT_WR)` on the socket sends a bare FIN, which mid-TLS is a
truncation rather than an orderly half-close, so the peer is right to abandon
the connection.

Driving the TLS state machine over memory BIOs solves it: `unwrap()` on an
`SSLObject` writes the `close_notify` record into the outgoing BIO before it
raises `SSLWantReadError` waiting for the reply. Flushing that BIO and then
declining to finish the handshake is exactly a half-close -- the peer sees an
orderly end of our stream and can keep writing to us.
"""

import socket
import ssl


class HalfCloseTlsClient:
    """A TLS connection whose write side can be closed independently."""

    def __init__(self, host: str, port: int, sni: str, timeout: float = 30.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        self._tls = ctx.wrap_bio(self._incoming, self._outgoing, server_hostname=sni)
        self._eof = False
        self._run(self._tls.do_handshake)

    # --- BIO plumbing -------------------------------------------------------

    def _flush(self) -> None:
        """Send whatever the TLS engine has queued."""
        data = self._outgoing.read()
        if data:
            self.sock.sendall(data)

    def _fill(self) -> bool:
        """Feed one chunk of wire data in. False once the peer is done."""
        data = self.sock.recv(65536)
        if not data:
            self._incoming.write_eof()
            self._eof = True
            return False
        self._incoming.write(data)
        return True

    def _run(self, op):
        """Drive one TLS operation to completion, pumping both BIOs."""
        while True:
            try:
                result = op()
            except ssl.SSLWantReadError:
                # Always flush first: the engine often needs to *send* something
                # before the peer will send what it is waiting for, and skipping
                # that deadlocks the handshake.
                self._flush()
                if not self._fill():
                    raise
            except ssl.SSLWantWriteError:
                self._flush()
            else:
                self._flush()
                return result

    # --- the interesting part ----------------------------------------------

    def close_write(self) -> None:
        """Send `close_notify` without waiting for the peer's.

        This is the half-close the rest of the suite could not express. The
        `SSLWantReadError` is the engine asking for the peer's reply; ignoring
        it is the point, since the peer owes us a response first. The TCP FIN
        goes out too, so the far side of a passthrough relay sees a genuine
        half-close rather than just a TLS alert.
        """
        try:
            self._tls.unwrap()
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            pass
        self._flush()
        self.sock.shutdown(socket.SHUT_WR)

    # --- ordinary I/O -------------------------------------------------------

    def send(self, data: bytes) -> None:
        self._run(lambda: self._tls.write(data))

    def recv(self, size: int = 65536) -> bytes:
        """Read application data. `b""` means the peer closed cleanly."""
        while True:
            try:
                return self._tls.read(size)
            except ssl.SSLWantReadError:
                if self._eof:
                    return b""
                if not self._fill():
                    return b""
            except ssl.SSLZeroReturnError:
                # The peer's own close_notify: an orderly end of its stream.
                return b""

    def read_http_response(self) -> tuple[bytes, str]:
        """Read one response, returning (body, how_it_ended)."""
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.recv()
            if not chunk:
                return b"", "eof_before_headers"
            buf += chunk
        head, body = buf.split(b"\r\n\r\n", 1)
        length = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        if length is None:
            return body, "no_content_length"
        while len(body) < length:
            chunk = self.recv()
            if not chunk:
                return body, "truncated"
            body += chunk
        return body, "complete"

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass
