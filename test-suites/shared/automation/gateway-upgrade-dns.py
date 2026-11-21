#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Serve case-scoped legacy Gateway app-address TXT records."""

from __future__ import annotations

import argparse
import re
import socket
import struct

APP_ROUTE = re.compile(r"^([0-9a-f]{40})-(\d+)s$")


def question_name(packet: bytes) -> tuple[list[str], int]:
    """Decode the single uncompressed DNS question name."""
    labels: list[str] = []
    offset = 12
    while True:
        length = packet[offset]
        offset += 1
        if length == 0:
            return labels, offset
        if length & 0xC0:
            raise ValueError("compressed query names are unsupported")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length


def txt_response(packet: bytes, value: str, question_end: int) -> bytes:
    """Return one authoritative TXT answer while preserving the query ID."""
    question = packet[12 : question_end + 4]
    payload = value.encode("ascii")
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 16, 1, 0, len(payload) + 1)
        + bytes([len(payload)])
        + payload
    )
    return packet[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + question + answer


def legacy_answer(packet: bytes) -> bytes | None:
    """Build an app-address TXT response or return None for forwarding."""
    labels, end = question_name(packet)
    qtype, qclass = struct.unpack("!HH", packet[end : end + 4])
    if qtype != 16 or qclass != 1 or len(labels) < 2:
        return None
    if labels[0] not in {"_dstack-app-address", "_tapp-address"}:
        return None
    match = APP_ROUTE.fullmatch(labels[1])
    if match is None:
        return None
    return txt_response(packet, f"{match.group(1)}:{match.group(2)}", end)


def main() -> int:
    """Serve DNS until the case-owned container stops."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.55")
    parser.add_argument("--upstream", default="10.0.2.3")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        label = "0" * 40 + "-8443s"
        name = f"_dstack-app-address.{label}.gateway.test"
        question = (
            struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0)
            + b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
            + b"\0"
            + struct.pack("!HH", 16, 1)
        )
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(2)
            client.sendto(question, (args.listen, 53))
            response = client.recv(4096)
        return 0 if b"0" * 40 + b":8443" in response else 1
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((args.listen, 53))
        while True:
            packet, address = server.recvfrom(4096)
            try:
                response = legacy_answer(packet)
            except (IndexError, UnicodeDecodeError, ValueError, struct.error):
                response = None
            if response is None:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream:
                    upstream.settimeout(3)
                    upstream.sendto(packet, (args.upstream, 53))
                    try:
                        response = upstream.recv(4096)
                    except TimeoutError:
                        continue
            server.sendto(response, address)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
