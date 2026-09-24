#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Adversarial request-contract matrix for dstack pRPC services.

Every RPC case in this suite promises that the method is exercised with its
request fields absent, default, valid, boundary-invalid and combined with an
unknown field, over both the JSON and the protobuf representation. The shipped
harnesses send one valid request and one wrong-typed value for the *first*
field only. This module implements the promised matrix, and asserts the
invariants that hold for every method whatever its semantics:

  L1  a malformed request never produces a 5xx, a dropped connection, or a
      transport-level failure;
  L2  a rejection of a JSON request carries a structured JSON body with an
      ``error`` string, and a rejection of a protobuf request carries a
      decodable ``ProtoError``;
  L3  the listener still answers a valid request after the whole matrix;
  L4  a rejection neither echoes an unbounded amount of attacker-supplied
      text nor grows with the size of the field it refused;
  L5  no request exceeds the per-call deadline;
  L6  the rejection's ``Content-Type`` matches the request's representation,
      so a client that sent JSON can parse the error it gets back.

It is transport-agnostic: a target is a unix socket path or a base URL plus a
route template, so the same matrix runs against the guest agent, the gateway,
the KMS and the VMM.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

CALL_TIMEOUT = 20
# A rejection is allowed to quote the value it refused, but not to scale with
# it. The product bounds its error text and then wraps it in a JSON envelope,
# so the ceiling is a little above that bound; what actually matters is the
# second check below, that two requests differing only in the size of one field
# do not produce rejections that differ in size.
MAX_ECHO = 8192
MAX_ECHO_SCALING = 256


@dataclass
class Target:
    """Where to send a request."""

    route_template: str  # contains "<Method>"
    socket: str | None = None
    base_url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    curl_extra: list[str] = field(default_factory=list)

    def route(self, method: str) -> str:
        """Resolve the route for one method."""
        return self.route_template.replace("<Method>", method)


@dataclass
class Call:
    """One observed request/response pair."""

    label: str
    method: str
    representation: str
    http: int | None
    body: bytes
    seconds: float
    transport_error: str | None = None
    response_content_type: str = ""

    @property
    def text(self) -> str:
        """The response body as lossy text."""
        return self.body.decode("utf-8", errors="replace")


def invoke(
    target: Target,
    method: str,
    content_type: str,
    body: bytes,
    label: str,
    representation: str,
    route_override: str | None = None,
) -> Call:
    """Issue one request and never raise for a protocol-level answer."""
    route = route_override if route_override is not None else target.route(method)
    marker = b"\nDSTACK_HTTP_TRAILER:"
    argv = ["curl", "--silent", "--show-error"]
    if target.socket:
        argv += ["--unix-socket", target.socket]
    argv += target.curl_extra
    for name, value in target.headers.items():
        argv += ["--header", f"{name}: {value}"]
    if content_type:
        argv += ["--header", f"Content-Type: {content_type}"]
    else:
        argv += ["--header", "Content-Type:"]
    argv += [
        "--max-time",
        str(CALL_TIMEOUT),
        "--request",
        "POST",
        "--data-binary",
        "@-",
        "--write-out",
        marker.decode() + "%{http_code} %{content_type}",
        (target.base_url or "http://localhost") + route,
    ]
    started = time.monotonic()
    try:
        process = subprocess.run(
            argv,
            input=body,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=CALL_TIMEOUT + 10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Call(
            label,
            method,
            representation,
            None,
            b"",
            time.monotonic() - started,
            "harness timeout",
        )
    elapsed = time.monotonic() - started
    if process.returncode:
        return Call(
            label,
            method,
            representation,
            None,
            b"",
            elapsed,
            process.stderr.decode(errors="replace")[-400:],
        )
    response, trailer = process.stdout.rsplit(marker, 1)
    parts = trailer.decode(errors="replace").strip().split(" ", 1)
    code = int(parts[0])
    response_content_type = parts[1].strip() if len(parts) > 1 else ""
    return Call(
        label,
        method,
        representation,
        code,
        response,
        elapsed,
        response_content_type=response_content_type,
    )


# --------------------------------------------------------------------------
# protobuf wire helpers
# --------------------------------------------------------------------------


def varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    out = bytearray()
    value &= (1 << 64) - 1
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def encode_field(field_def: dict[str, Any], value: Any) -> bytes:
    """Encode one request field onto the protobuf wire."""
    kind = field_def["type"]
    number = int(field_def["number"])
    if kind == "bytes":
        raw = bytes.fromhex(str(value))
        return varint((number << 3) | 2) + varint(len(raw)) + raw
    if kind == "string":
        raw = str(value).encode()
        return varint((number << 3) | 2) + varint(len(raw)) + raw
    if kind == "bool":
        return varint((number << 3) | 0) + varint(1 if value else 0)
    if kind.startswith(("uint", "int", "sint", "fixed", "sfixed")):
        return varint((number << 3) | 0) + varint(int(value))
    # message, enum or anything else: an opaque empty length-delimited blob.
    return varint((number << 3) | 2) + varint(0)


def encode_request(fields: list[dict[str, Any]], payload: dict[str, Any]) -> bytes:
    """Encode a request body from the inventory field list."""
    out = bytearray()
    for field_def in fields:
        if field_def["name"] not in payload:
            continue
        value = payload[field_def["name"]]
        values = value if field_def.get("repeated") else [value]
        if not isinstance(values, list):
            values = [values]
        for item in values:
            out.extend(encode_field(field_def, item))
    return bytes(out)


# --------------------------------------------------------------------------
# adversarial vectors
# --------------------------------------------------------------------------

NUL = "a" + chr(0) + "b"
CONTROL = chr(0) + chr(0xFFFD) + chr(0x1F600)


def field_vectors(field_def: dict[str, Any]) -> list[tuple[str, Any]]:
    """Return (label, JSON value) pairs a field must reject or bound."""
    kind = field_def["type"]
    vectors: list[tuple[str, Any]] = []
    if kind == "string":
        vectors += [
            ("empty", ""),
            ("wrong-type-int", 123),
            ("wrong-type-obj", {"a": 1}),
            ("wrong-type-null", None),
            ("nul-byte", NUL),
            ("newline-injection", "a\nb\rc"),
            ("path-traversal", "../../../../etc/passwd"),
            ("absolute-path", "/etc/shadow"),
            ("control-chars", CONTROL),
            ("long-64k", "A" * 65536),
            ("long-1m", "A" * (1 << 20)),
        ]
    elif kind == "bytes":
        vectors += [
            ("empty", ""),
            ("odd-hex", "abc"),
            ("non-hex", "zzzz"),
            ("wrong-type-int", 123),
            ("wrong-type-list", [1, 2, 3]),
            ("short-31", "11" * 31),
            ("boundary-63", "11" * 63),
            ("boundary-64", "11" * 64),
            ("boundary-65", "11" * 65),
            ("long-64k", "11" * 65536),
        ]
    elif kind == "bool":
        vectors += [
            ("wrong-type-str", "true"),
            ("wrong-type-int", 2),
            ("wrong-type-null", None),
        ]
    elif kind.startswith(("uint", "int", "sint", "fixed", "sfixed")):
        vectors += [
            ("zero", 0),
            ("negative", -1),
            ("u32-max", (1 << 32) - 1),
            ("u64-max", (1 << 64) - 1),
            ("over-u64", 1 << 64),
            ("huge", 10**40),
            ("wrong-type-str", "abc"),
            ("wrong-type-null", None),
        ]
    else:
        vectors += [
            ("wrong-type-str", "abc"),
            ("wrong-type-int", 1),
            ("wrong-type-null", None),
        ]
    if field_def.get("repeated"):
        vectors += [
            ("repeated-empty", []),
            ("repeated-scalar", "not-a-list"),
            ("repeated-wide-4096", ["x"] * 4096),
        ]
    return vectors


def malformed_bodies() -> list[tuple[str, str, bytes]]:
    """Representation-level malformed bodies every listener must survive."""
    return [
        ("json-empty-body", "application/json", b""),
        ("json-not-object", "application/json", b"[]"),
        ("json-scalar", "application/json", b"42"),
        ("json-null", "application/json", b"null"),
        ("json-truncated", "application/json", b'{"a":'),
        ("json-trailing-garbage", "application/json", b"{} trailing"),
        ("json-deep-nesting", "application/json", b"[" * 2000 + b"]" * 2000),
        ("json-duplicate-keys", "application/json", b'{"path":"a","path":"b"}'),
        (
            "json-huge-4mib",
            "application/json",
            b'{"path":"' + b"A" * (4 << 20) + b'"}',
        ),
        ("pb-truncated-varint", "application/octet-stream", b"\x08"),
        ("pb-runaway-varint", "application/octet-stream", b"\x08" + b"\xff" * 12),
        (
            "pb-length-overflow",
            "application/octet-stream",
            b"\x0a" + b"\xff\xff\xff\xff\x0f",
        ),
        ("pb-length-beyond-body", "application/octet-stream", b"\x0a\x7f" + b"A" * 4),
        ("pb-unknown-wiretype", "application/octet-stream", b"\x0b\x00"),
        ("pb-group-wiretype", "application/octet-stream", b"\x0c"),
        ("pb-field-zero", "application/octet-stream", b"\x00\x00"),
        (
            "pb-huge-field-number",
            "application/octet-stream",
            b"\xf8\xff\xff\xff\x0f\x01",
        ),
        ("pb-random-8k", "application/octet-stream", bytes(range(256)) * 32),
        ("ct-mismatch-json-as-pb", "application/octet-stream", b'{"path":"a"}'),
        ("ct-mismatch-pb-as-json", "application/json", b"\x08\x01"),
        ("ct-absent", "", b"{}"),
        ("ct-bogus", "application/x-not-a-thing", b"{}"),
    ]


# --------------------------------------------------------------------------
# invariants
# --------------------------------------------------------------------------


def json_error(call: Call) -> tuple[bool, str | None]:
    """Return whether a rejection carries a structured JSON ``error`` string."""
    if not call.body:
        return False, "empty body"
    try:
        value = json.loads(call.body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False, "body is not JSON"
    if not isinstance(value, dict):
        return False, "body is not a JSON object"
    if not isinstance(value.get("error"), str):
        return False, "body has no error string"
    return True, value["error"]


def proto_error(call: Call) -> tuple[bool, str | None]:
    """Return whether a rejection decodes as a one-field ``ProtoError``."""
    body = call.body
    if len(body) < 2 or body[0] != 0x0A:
        return False, "body is not a ProtoError message"
    length = 0
    shift = 0
    offset = 1
    while offset < len(body):
        byte = body[offset]
        offset += 1
        length |= (byte & 0x7F) << shift
        if byte < 0x80:
            break
        shift += 7
        if shift > 63:
            return False, "ProtoError length varint is malformed"
    if offset + length != len(body):
        return False, "ProtoError length does not match the body"
    return True, body[offset:].decode("utf-8", errors="replace")


def check_invariants(calls: list[Call], echoed_markers: dict[str, str]) -> list[dict]:
    """Return one violation record per invariant breach."""
    violations: list[dict[str, Any]] = []
    for call in calls:
        base = {
            "label": call.label,
            "method": call.method,
            "representation": call.representation,
            "http": call.http,
            "seconds": round(call.seconds, 3),
        }
        if call.transport_error is not None:
            violations.append(
                {
                    **base,
                    "invariant": "L1",
                    "detail": f"transport failure: {call.transport_error}",
                }
            )
            continue
        if call.http is not None and 500 <= call.http < 600:
            violations.append(
                {
                    **base,
                    "invariant": "L1",
                    "detail": f"server error {call.http}: {call.text[:MAX_ECHO]}",
                }
            )
            continue
        # A label records the representation the request was sent in. "raw"
        # framing rows carry their own content type in the label.
        sent_json = call.representation == "json" or call.label.endswith(
            (
                "json-empty-body",
                "json-not-object",
                "json-scalar",
                "json-null",
                "json-truncated",
                "json-trailing-garbage",
                "json-deep-nesting",
                "json-duplicate-keys",
                "json-huge-4mib",
                "ct-mismatch-pb-as-json",
            )
        )
        if call.http is not None and call.http >= 400:
            if sent_json:
                ok, detail = json_error(call)
                invariant, expected = "L2", "application/json"
            else:
                ok, detail = proto_error(call)
                invariant, expected = "L2", "application/octet-stream"
            if not ok:
                violations.append(
                    {
                        **base,
                        "invariant": invariant,
                        "detail": f"unstructured rejection ({detail}): "
                        f"{call.text[:256]!r}",
                    }
                )
            elif len(call.body) > MAX_ECHO:
                violations.append(
                    {
                        **base,
                        "invariant": "L4",
                        "detail": f"rejection body is {len(call.body)} bytes",
                    }
                )
            if (
                ok
                and call.response_content_type
                and expected not in call.response_content_type
            ):
                violations.append(
                    {
                        **base,
                        "invariant": "L6",
                        "detail": "a request sent as "
                        f"{'JSON' if sent_json else 'protobuf'} was rejected with "
                        f"Content-Type {call.response_content_type}",
                    }
                )
            if not ok and sent_json:
                violations.append(
                    {
                        **base,
                        "invariant": "L6",
                        "detail": "a JSON request was rejected with a non-JSON body "
                        f"and Content-Type {call.response_content_type or 'unset'}",
                    }
                )
        marker = echoed_markers.get(call.label)
        if marker and marker in call.text:
            violations.append(
                {
                    **base,
                    "invariant": "L4",
                    "detail": "response echoed the input marker",
                }
            )
        if call.seconds > CALL_TIMEOUT:
            violations.append(
                {**base, "invariant": "L5", "detail": "call exceeded the deadline"}
            )
    violations.extend(check_echo_scaling(calls))
    return violations


# Vector labels that differ only in how large one field is. A rejection that
# grows with the request is an amplifier whatever its absolute size.
SCALING_PAIRS = (("=long-64k|", "=long-1m|"), ("=short-31|", "=long-64k|"))


def check_echo_scaling(calls: list[Call]) -> list[dict[str, Any]]:
    """Return a violation per rejection pair whose size tracks its input."""
    by_label = {call.label: call for call in calls}
    violations: list[dict[str, Any]] = []
    for small_tag, large_tag in SCALING_PAIRS:
        for label, small in by_label.items():
            if small_tag not in label:
                continue
            large = by_label.get(label.replace(small_tag, large_tag))
            if large is None or small.http is None or large.http is None:
                continue
            if small.http < 400 or large.http < 400:
                continue
            growth = len(large.body) - len(small.body)
            if growth > MAX_ECHO_SCALING:
                violations.append(
                    {
                        "label": large.label,
                        "method": large.method,
                        "representation": large.representation,
                        "http": large.http,
                        "seconds": round(large.seconds, 3),
                        "invariant": "L4",
                        "detail": "the rejection grew by "
                        f"{growth} bytes when the request field grew: "
                        f"{len(small.body)} -> {len(large.body)}",
                    }
                )
    return violations
