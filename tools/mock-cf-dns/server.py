#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

"""Tiny Cloudflare DNS API + UDP TXT DNS mock for dstack gateway E2E.

It implements just the Cloudflare endpoints used by certbot's CloudflareClient:
  GET    /client/v4/zones
  GET    /client/v4/zones/<zone_id>/dns_records?name=<fqdn>
  POST   /client/v4/zones/<zone_id>/dns_records
  DELETE /client/v4/zones/<zone_id>/dns_records/<record_id>

It tracks one thing beyond storing records: names whose issuer CAA set was
emptied, served at /api/caa-gaps, because replacing CAA is meant to leave one
record standing throughout and a gap is invisible once the replacement is done.

It also serves TXT answers on 53, over both UDP and TCP, so Pebble can validate
DNS-01 and dns-persist-01 for real rather than being run with
PEBBLE_VA_ALWAYS_VALID=1. TCP is not optional: Pebble sets its DNS client to
`Net = "tcp"` whenever it is given `-dnsserver`.

Questions outside the configured zones are forwarded upstream, so this can be a
client's only resolver rather than only a CA's `-dnsserver`: certbot resolves
its own challenge records through it while still reaching the other containers
by name. Every question is logged and served at /api/dns-queries, so a test can
assert that a name was actually looked up.
"""

from __future__ import annotations

import json
import os
import re
import socket
import struct
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

STATE_LOCK = threading.RLock()
RECORDS: list[dict[str, Any]] = []
# Every DNS question this mock was asked, so a test can assert that the client
# under test resolved a name rather than inferring it from what happened next.
QUERIES: list[dict[str, Any]] = []
MAX_QUERIES = 2000
QTYPE_ANY = 255
NEXT_ID = 1
# Names whose issuer CAA set went from non-empty to empty at some point.
#
# A client replacing those records is meant to keep at least one in place
# throughout: absent CAA is not "no issuer may" but "any issuer may", so a gap
# is a window in which any CA could have issued. It closes as soon as the
# replacement finishes and is invisible in the result, so it is recorded as it
# happens.
CAA_GAPS: set[str] = set()


def _zones() -> list[dict[str, str]]:
    raw = os.environ.get("MOCK_CF_ZONES", "e2e.test test local")
    names = [
        z.strip().strip(".").lower() for z in re.split(r"[,\s]+", raw) if z.strip()
    ]
    if not names:
        names = ["e2e.test"]
    out = []
    seen = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        out.append({"id": zone_id_for(name), "name": name})
    return out


def zone_id_for(name: str) -> str:
    """Return a deterministic mock zone ID for a DNS name."""
    safe = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or "zone"
    return f"zone-{safe}"


def _json(handler: BaseHTTPRequestHandler, code: int, body: Any) -> None:
    data = json.dumps(body, sort_keys=True).encode()
    handler.send_response(code)
    handler.send_header("content-type", "application/json")
    handler.send_header("content-length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


def _issuer_caa_count(name: str) -> int:
    """How many issue/issuewild CAA records currently sit at `name`."""
    wanted = name.strip(".").lower()
    return sum(
        1
        for r in RECORDS
        if r["type"] == "CAA"
        and r["name"].strip(".").lower() == wanted
        and (r["content"].split() + ["", ""])[1] in ("issue", "issuewild")
    )


def _note_caa_gap(name: str, before: int) -> None:
    """Record `name` if its issuer CAA set just emptied out.

    Called with STATE_LOCK held, `before` sampled ahead of the mutation.
    """
    if before > 0 and _issuer_caa_count(name) == 0:
        CAA_GAPS.add(name.strip(".").lower())


def _record_content(payload: dict[str, Any]) -> str:
    if "content" in payload:
        return str(payload.get("content") or "")
    data = payload.get("data") or {}
    if payload.get("type") == "CAA" and isinstance(data, dict):
        return f'{data.get("flags", 0)} {data.get("tag", "issue")} "{data.get("value", "")}"'
    return ""


def _authorized(handler: BaseHTTPRequestHandler) -> bool:
    """Require the configured Cloudflare bearer token for API operations."""
    expected = os.environ.get("MOCK_CF_API_TOKEN", "test-token")
    if handler.headers.get("Authorization", "") == f"Bearer {expected}":
        return True
    _json(
        handler,
        403,
        {"success": False, "errors": [{"message": "invalid API token"}]},
    )
    return False


class Handler(BaseHTTPRequestHandler):
    """Handle the mock Cloudflare HTTP API."""

    server_version = "dstack-mock-cf-dns/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        """Emit request logs when debug logging is enabled."""
        if os.environ.get("DEBUG", "").lower() in {"1", "true", "yes"}:
            super().log_message(fmt, *args)

    def do_GET(self) -> None:  # noqa: N802
        """Handle supported HTTP GET endpoints."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = urllib.parse.parse_qs(parsed.query)
        if path == "/health":
            _json(self, 200, {"ok": True})
            return
        if path == "/api/caa-gaps":
            with STATE_LOCK:
                _json(self, 200, {"names": sorted(CAA_GAPS)})
            return
        if path == "/api/records":
            with STATE_LOCK:
                _json(self, 200, {"records": RECORDS})
            return
        if path == "/api/dns-queries":
            with STATE_LOCK:
                _json(self, 200, {"queries": QUERIES})
            return
        if path.startswith("/client/v4/") and not _authorized(self):
            return
        if path == "/client/v4/zones":
            zones = _zones()
            _json(
                self,
                200,
                {
                    "success": True,
                    "result": zones,
                    "result_info": {
                        "page": 1,
                        "per_page": 50,
                        "total_pages": 1,
                        "count": len(zones),
                        "total_count": len(zones),
                    },
                },
            )
            return
        m = re.fullmatch(r"/client/v4/zones/([^/]+)/dns_records", path)
        if m:
            name = (query.get("name") or [""])[0].strip().strip(".").lower()
            with STATE_LOCK:
                records = [
                    r
                    for r in RECORDS
                    if not name or r["name"].strip(".").lower() == name
                ]
            _json(
                self,
                200,
                {
                    "success": True,
                    "result": records,
                    "result_info": {"page": 1, "per_page": 100, "total_pages": 1},
                },
            )
            return
        _json(
            self, 404, {"success": False, "errors": [{"message": f"not found: {path}"}]}
        )

    def do_POST(self) -> None:  # noqa: N802
        """Create a mock DNS record."""
        global NEXT_ID
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        m = re.fullmatch(r"/client/v4/zones/([^/]+)/dns_records", path)
        if not m:
            _json(
                self,
                404,
                {"success": False, "errors": [{"message": f"not found: {path}"}]},
            )
            return
        if not _authorized(self):
            return
        length = int(self.headers.get("content-length", "0") or "0")
        payload = json.loads(self.rfile.read(length) or b"{}")
        with STATE_LOCK:
            record_id = f"rec-{NEXT_ID}"
            NEXT_ID += 1
            record = {
                "id": record_id,
                "zone_id": m.group(1),
                "type": str(payload.get("type") or "TXT").upper(),
                "name": str(payload.get("name") or "").strip().strip("."),
                "content": _record_content(payload),
                "ttl": int(payload.get("ttl") or 60),
                "created_on": int(time.time()),
            }
            RECORDS.append(record)
        _json(self, 200, {"success": True, "result": record})

    def do_DELETE(self) -> None:  # noqa: N802
        """Delete a mock DNS record, or forget the CAA gaps seen so far."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/api/caa-gaps":
            with STATE_LOCK:
                CAA_GAPS.clear()
            _json(self, 200, {"success": True})
            return
        m = re.fullmatch(r"/client/v4/zones/([^/]+)/dns_records/([^/]+)", path)
        if not m:
            _json(
                self,
                404,
                {"success": False, "errors": [{"message": f"not found: {path}"}]},
            )
            return
        if not _authorized(self):
            return
        record_id = urllib.parse.unquote(m.group(2))
        with STATE_LOCK:
            doomed = next((r for r in RECORDS if r["id"] == record_id), None)
            caa_name = doomed["name"] if doomed and doomed["type"] == "CAA" else None
            caa_before = _issuer_caa_count(caa_name) if caa_name else 0
            before = len(RECORDS)
            RECORDS[:] = [r for r in RECORDS if r["id"] != record_id]
            removed = before != len(RECORDS)
            if caa_name:
                _note_caa_gap(caa_name, caa_before)
        _json(
            self,
            200,
            {"success": True, "result": {"id": record_id, "removed": removed}},
        )


def parse_qname(packet: bytes, offset: int = 12) -> tuple[str, int]:
    """Parse a DNS question name and return its value and end offset."""
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("bad qname")
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        labels.append(packet[offset : offset + length].decode("ascii", "ignore"))
        offset += length
    return ".".join(labels).strip(".").lower(), offset


def txt_rdata(text: str) -> bytes:
    """Encode text as DNS TXT record data."""
    raw = text.encode()
    chunks = [raw[i : i + 255] for i in range(0, len(raw), 255)] or [b""]
    return b"".join(bytes([len(c)]) + c for c in chunks)


def wire_name(name: str) -> bytes:
    """Encode a domain name uncompressed, for use in RDATA."""
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("ascii", "ignore")[:63]
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def ns_address() -> str | None:
    """Address to advertise as this mock's nameserver, if it is to advertise one.

    A client that reads a challenge record straight from the authoritative
    servers -- which is the only way to dodge a recursive resolver's negative
    cache -- gets there by asking NS for the zone and then A for each answer.
    Unset, this mock answers neither and that client falls back to its system
    resolver, so the authoritative path never runs. Set to the address this
    container is reachable at, and the path is exercised end to end.
    """
    return os.environ.get("MOCK_CF_NS_ADDR") or None


def _synthesized(name: str, qtype: int) -> list[tuple[int, bytes]]:
    """NS at a zone apex and A for the nameserver it names.

    Only at the apex: a name below it must answer NODATA, or a client walking
    up from `_acme-challenge.<name>` looking for the zone cut would stop at the
    wrong place -- and walking up is what it does against a real zone.
    """
    addr = ns_address()
    if not addr:
        return []
    apexes = {zone["name"] for zone in _zones()}
    if qtype in (2, QTYPE_ANY) and name in apexes:
        return [(2, wire_name(f"ns.{name}"))]
    if qtype in (1, QTYPE_ANY) and name.startswith("ns.") and name[3:] in apexes:
        return [(1, socket.inet_aton(addr))]
    return []


def _upstream() -> str:
    """Where to send questions this mock is not authoritative for.

    Docker's embedded resolver, which is what this container's own
    `/etc/resolv.conf` points at, so service names keep resolving for whoever
    is pointed here.
    """
    return os.environ.get("MOCK_DNS_UPSTREAM", "127.0.0.11")


def _is_ours(name: str) -> bool:
    """Whether `name` falls inside one of the configured mock zones."""
    return any(
        name == zone["name"] or name.endswith("." + zone["name"]) for zone in _zones()
    )


def _forward(packet: bytes) -> bytes:
    """Ask the upstream resolver and hand back its answer verbatim.

    Without this the mock is only usable as a CA's `-dnsserver`, because a name
    it does not know is answered NOERROR with no records -- which a resolver
    reads as an authoritative "no such record" and does not retry elsewhere.
    A client configured to use this as its only resolver would then fail to
    resolve the other containers.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    try:
        sock.sendto(packet, (_upstream(), 53))
        return sock.recvfrom(65535)[0]
    finally:
        sock.close()


def _record_query(name: str, qtype: int, answers: int, forwarded: bool) -> None:
    with STATE_LOCK:
        QUERIES.append(
            {
                "name": name,
                "type": qtype,
                "answers": answers,
                "forwarded": forwarded,
                "at": int(time.time()),
            }
        )
        del QUERIES[:-MAX_QUERIES]


def dns_response(packet: bytes) -> bytes:
    """Build a DNS response containing matching TXT records."""
    if len(packet) < 12:
        return b""
    txid = packet[:2]
    qdcount = struct.unpack("!H", packet[4:6])[0]
    if qdcount < 1:
        return b""
    name, qend = parse_qname(packet)
    question = packet[12 : qend + 4]
    qtype = (
        struct.unpack("!H", packet[qend : qend + 2])[0]
        if qend + 4 <= len(packet)
        else 16
    )
    # Only answer for the zones this mock owns; anything else is the caller's
    # ordinary name resolution and belongs upstream.
    if not _is_ours(name):
        try:
            reply = _forward(packet)
            _record_query(name, qtype, -1, True)
            return reply
        except Exception as exc:  # pragma: no cover - diagnostic only
            _debug(f"forwarding {name} failed: {exc}")
            _record_query(name, qtype, 0, True)
            return txid + struct.pack("!HHHHH", 0x8182, 1, 0, 0, 0) + packet[12:qend + 4]

    with STATE_LOCK:
        stored = [
            r
            for r in RECORDS
            if r["type"] == "TXT" and r["name"].strip(".").lower() == name
        ]
    if qtype not in (16, QTYPE_ANY):
        stored = []
    answers = [(16, txt_rdata(r["content"])) for r in stored]
    answers += _synthesized(name, qtype)

    _record_query(name, qtype, len(answers), False)
    header = txid + struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, 0)
    body = question
    for rtype, rdata in answers:
        body += (
            b"\xc0\x0c"
            + struct.pack("!HHIH", rtype, 1, 60, len(rdata))
            + rdata
        )
    return header + body


def bind_host() -> str:
    """Address the mock listens on, for both the HTTP API and DNS.

    Defaults to every interface. This runs as a container on a private compose
    network and its peers -- certbot writing records, and the ACME server
    resolving them -- reach it by an address the process cannot know in
    advance, so narrowing the default would answer nobody. Set MOCK_CF_BIND to
    something specific when running it outside a container, where the default
    would expose a test double that trusts every caller.
    """
    return os.environ.get("MOCK_CF_BIND", "0.0.0.0")


def _debug(message: str) -> None:
    if os.environ.get("DEBUG", "").lower() in {"1", "true", "yes"}:
        print(message, flush=True)


def dns_loop() -> None:
    """Serve mock DNS responses over UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host(), 53))
    while True:
        packet, addr = sock.recvfrom(4096)
        try:
            response = dns_response(packet)
            if response:
                sock.sendto(response, addr)
        except Exception as exc:  # pragma: no cover - diagnostic only
            _debug(f"dns error from {addr}: {exc}")


def _serve_dns_over_tcp(conn: socket.socket, addr: Any) -> None:
    """Answer one TCP DNS client, which frames each message with its length."""
    try:
        conn.settimeout(5)
        while True:
            head = _recv_exactly(conn, 2)
            if head is None:
                return
            (length,) = struct.unpack("!H", head)
            query = _recv_exactly(conn, length)
            if query is None:
                return
            response = dns_response(query)
            if not response:
                return
            conn.sendall(struct.pack("!H", len(response)) + response)
    except Exception as exc:  # pragma: no cover - diagnostic only
        _debug(f"dns/tcp error from {addr}: {exc}")
    finally:
        conn.close()


def _recv_exactly(conn: socket.socket, count: int) -> bytes | None:
    """Read exactly `count` bytes, or None if the peer stopped sending."""
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def dns_tcp_loop() -> None:
    """Serve mock DNS responses over TCP.

    Pebble sets `dnsClient.Net = "tcp"` whenever it is given a custom resolver
    (`-dnsserver`), so a UDP-only mock answers none of its queries and every
    challenge has to be waved through with PEBBLE_VA_ALWAYS_VALID. RFC 1035
    §4.2.2 length-prefixes each message on TCP; that framing is the only
    difference from the UDP path.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_host(), 53))
    sock.listen(16)
    while True:
        conn, addr = sock.accept()
        threading.Thread(
            target=_serve_dns_over_tcp, args=(conn, addr), daemon=True
        ).start()


def main() -> None:
    """Run the mock Cloudflare API and DNS servers."""
    threading.Thread(target=dns_loop, daemon=True).start()
    threading.Thread(target=dns_tcp_loop, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    host = bind_host()
    print(
        f"mock CF API on {host}:{port}; DNS on {host}:53 (udp+tcp); zones={_zones()}",
        flush=True,
    )
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    main()
