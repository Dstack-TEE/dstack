#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Send one bounded HTTP request to a case-owned AF_VSOCK listener."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
from typing import Any


def shape(value: Any) -> Any:
    """Return a non-secret structural description of a JSON value."""
    if isinstance(value, dict):
        return {key: shape(item) for key, item in value.items()}
    if isinstance(value, list):
        return {
            "type": "array",
            "length": len(value),
            "items": [shape(item) for item in value],
        }
    if isinstance(value, str):
        return {
            "type": "string",
            "length": len(value),
            "sha256": hashlib.sha256(value.encode()).hexdigest(),
        }
    if value is None:
        return {"type": "null"}
    return {"type": type(value).__name__, "value": value}


def main() -> int:
    """Send the request and print its bounded structural response."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--cid", type=int, default=2)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--content-type", default="application/json")
    body_group = parser.add_mutually_exclusive_group()
    body_group.add_argument("--body", default="null")
    body_group.add_argument("--body-file")
    parser.add_argument(
        "--public-json",
        action="store_true",
        help="include a public JSON response verbatim",
    )
    args = parser.parse_args()
    body = open(args.body_file, "rb").read() if args.body_file else args.body.encode()
    request = (
        f"POST {args.path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {args.content_type}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    client = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    client.settimeout(15)
    client.connect((args.cid, args.port))
    client.sendall(request)
    response = bytearray()
    while True:
        chunk = client.recv(65536)
        if not chunk:
            break
        response.extend(chunk)
    header, separator, response_body = bytes(response).partition(b"\r\n\r\n")
    if not separator:
        raise SystemExit("invalid HTTP response")
    lines = header.decode("latin-1").splitlines()
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.lower()] = value.strip()
    result: dict[str, Any] = {
        "status": status,
        "content_type": headers.get("content-type", ""),
        "body_length": len(response_body),
        "body_sha256": hashlib.sha256(response_body).hexdigest(),
    }
    try:
        value = json.loads(response_body)
        result["json_shape"] = shape(value)
        if args.public_json:
            result["json"] = value
        if isinstance(value, dict) and isinstance(value.get("error"), str):
            result["error"] = value["error"]
    except json.JSONDecodeError:
        result["body_base64_prefix"] = base64.b64encode(response_body[:32]).decode()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
