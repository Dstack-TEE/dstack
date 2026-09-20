#!/usr/bin/env python3
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Prove the KMS key hierarchy against a running, lease-owned KMS.

The KMS chapter already exercises `KMS.GetAppKey` and `KMS.GetMeta` for their
request/response contract, and `dstack/kms/src/crypto.rs` pins the signature
bytes with golden vectors.  Neither closes the loop: no case asks a live KMS
for derived application material twice and compares it, and no case recovers
the public key from an issued signature chain and checks it against the root
key the same KMS advertises.  This harness does exactly that, using only
material the RPC surface returns.

Everything it asserts is derived from two sources, both cited per case:

  * `dstack/kms/src/main_service.rs` -- the `derive_dh_secret` contexts
    `app_id || instance_id || "app-disk-crypt-key"`, `app_id ||
    "env-encrypt-key"` and, through `derive_k256_key`, `app_id || "app-key"`.
  * `dstack/kms/src/crypto.rs` -- the signature preimages
    `keccak256(prefix || ":" || app_id || public_key)` and
    `keccak256(prefix || ":" || app_id || be64(timestamp) || public_key)`,
    over the 65-byte `r || s || v` envelope.

Secret material stays in memory.  Only hashes, public keys, signatures and
lengths are written to the artifacts; a derived private key is never printed
and never persisted.

Standalone use (the lab fixture is not needed for `--self-test`):

    kms-key-hierarchy-case.py --self-test
    kms-key-hierarchy-case.py --standalone --case tc-kms-keyhier-003 \
        --values lease-values.json --runtime-manifest runtime-manifest.json \
        --result-dir /tmp/keyhier-003

`--values` accepts either a case manifest (`{"values": {...}}`) or the bare
lease values object, as a path or as inline JSON.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import hashlib
import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterator

# --------------------------------------------------------------------------
# Keccak-256
# --------------------------------------------------------------------------
# dstack signs `keccak256(preimage)`, which is the original Keccak padding and
# not the SHA3-256 the standard library ships, so the permutation is spelled
# out here rather than borrowed from hashlib.

# fmt: off
_KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]
# fmt: on
_KECCAK_ROTATIONS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]
_LANE_MASK = (1 << 64) - 1
_KECCAK_RATE = 136


def _rotate_left(value: int, count: int) -> int:
    return ((value << count) | (value >> (64 - count))) & _LANE_MASK


def _keccak_permutation(state: list[list[int]]) -> None:
    for round_constant in _KECCAK_ROUND_CONSTANTS:
        parity = [
            state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
            for x in range(5)
        ]
        theta = [
            parity[(x - 1) % 5] ^ _rotate_left(parity[(x + 1) % 5], 1) for x in range(5)
        ]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= theta[x]
        rotated = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                rotated[y][(2 * x + 3 * y) % 5] = _rotate_left(
                    state[x][y], _KECCAK_ROTATIONS[x][y]
                )
        for x in range(5):
            for y in range(5):
                state[x][y] = rotated[x][y] ^ (
                    (~rotated[(x + 1) % 5][y]) & _LANE_MASK & rotated[(x + 2) % 5][y]
                )
        state[0][0] ^= round_constant


def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 digest, with the pre-NIST 0x01 padding."""
    state = [[0] * 5 for _ in range(5)]
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % _KECCAK_RATE:
        padded.append(0x00)
    padded[-1] |= 0x80
    for offset in range(0, len(padded), _KECCAK_RATE):
        block = padded[offset : offset + _KECCAK_RATE]
        for index in range(_KECCAK_RATE // 8):
            lane = int.from_bytes(block[index * 8 : index * 8 + 8], "little")
            state[index % 5][index // 5] ^= lane
        _keccak_permutation(state)
    digest = bytearray()
    for index in range(4):
        digest += state[index % 5][index // 5].to_bytes(8, "little")
    return bytes(digest)


# --------------------------------------------------------------------------
# secp256k1
# --------------------------------------------------------------------------

SECP256K1_P = 2**256 - 2**32 - 977
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
Point = tuple[int, int]


def _modular_inverse(value: int, modulus: int) -> int:
    return pow(value, modulus - 2, modulus)


def _point_add(left: Point | None, right: Point | None) -> Point | None:
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] + right[1]) % SECP256K1_P == 0:
        return None
    if left == right:
        slope = (
            3
            * left[0]
            * left[0]
            % SECP256K1_P
            * _modular_inverse(2 * left[1] % SECP256K1_P, SECP256K1_P)
            % SECP256K1_P
        )
    else:
        slope = (
            (right[1] - left[1])
            % SECP256K1_P
            * _modular_inverse((right[0] - left[0]) % SECP256K1_P, SECP256K1_P)
            % SECP256K1_P
        )
    x = (slope * slope - left[0] - right[0]) % SECP256K1_P
    return (x, (slope * (left[0] - x) - left[1]) % SECP256K1_P)


def _point_multiply(point: Point | None, scalar: int) -> Point | None:
    result: Point | None = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def sec1_compressed(point: Point) -> bytes:
    """Encode a point the way `VerifyingKey::to_sec1_bytes` does: 33 bytes."""
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def sec1_uncompressed(point: Point) -> bytes:
    """Encode a point as the 65-byte uncompressed SEC1 form."""
    return b"\x04" + point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


def secp256k1_public_point(secret: bytes) -> Point:
    """Return the public point of a 32-byte secp256k1 private scalar."""
    scalar = int.from_bytes(secret, "big")
    if not 0 < scalar < SECP256K1_N:
        raise ValueError("secp256k1 private scalar is out of range")
    point = _point_multiply(SECP256K1_G, scalar)
    if point is None:
        raise ValueError("secp256k1 private scalar produced the point at infinity")
    return point


def recover_public_point(signature: bytes, digest: bytes) -> Point:
    """Recover the signer's point from a 65-byte `r || s || v` envelope.

    `ra_tls::api_v1::sign_recoverable_keccak256` appends `recovery_id.to_byte()`
    to the low-S normalised signature, so `v` is 0..3 and not the 27-based
    Ethereum form.
    """
    if len(signature) != 65:
        raise ValueError(f"signature must be 65 bytes, got {len(signature)}")
    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    recovery_id = signature[64]
    if recovery_id > 3:
        raise ValueError(f"recovery id {recovery_id} is out of range")
    if not 0 < r < SECP256K1_N or not 0 < s < SECP256K1_N:
        raise ValueError("signature scalars are out of range")
    x = r + (recovery_id >> 1) * SECP256K1_N
    if x >= SECP256K1_P:
        raise ValueError("recovered x coordinate is out of range")
    alpha = (x * x * x + 7) % SECP256K1_P
    y = pow(alpha, (SECP256K1_P + 1) // 4, SECP256K1_P)
    if (y * y - alpha) % SECP256K1_P:
        raise ValueError("recovered x coordinate is not on the curve")
    if y % 2 != recovery_id % 2:
        y = SECP256K1_P - y
    exponent = int.from_bytes(digest, "big") % SECP256K1_N
    point = _point_multiply(
        _point_add(
            _point_multiply((x, y), s),
            _point_multiply(SECP256K1_G, SECP256K1_N - exponent),
        ),
        _modular_inverse(r, SECP256K1_N),
    )
    if point is None:
        raise ValueError("recovery produced the point at infinity")
    return point


# --------------------------------------------------------------------------
# X25519
# --------------------------------------------------------------------------

_P25519 = 2**255 - 19
_X25519_BASEPOINT = (9).to_bytes(32, "little")


def x25519(scalar: bytes, u_coordinate: bytes) -> bytes:
    """RFC 7748 X25519, including the clamping `mul_base_clamped` applies."""
    if len(scalar) != 32 or len(u_coordinate) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    clamped = bytearray(scalar)
    clamped[0] &= 248
    clamped[31] &= 127
    clamped[31] |= 64
    k = int.from_bytes(clamped, "little")
    u = int.from_bytes(u_coordinate, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for bit in range(254, -1, -1):
        kt = (k >> bit) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P25519
        aa = a * a % _P25519
        b = (x2 - z2) % _P25519
        bb = b * b % _P25519
        e = (aa - bb) % _P25519
        c = (x3 + z3) % _P25519
        d = (x3 - z3) % _P25519
        da = d * a % _P25519
        cb = c * b % _P25519
        x3 = (da + cb) % _P25519
        x3 = x3 * x3 % _P25519
        z3 = (da - cb) % _P25519
        z3 = x1 * z3 % _P25519 * z3 % _P25519
        x2 = aa * bb % _P25519
        z2 = e * (aa + 121665 * e) % _P25519
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    shared = x2 * pow(z2, _P25519 - 2, _P25519) % _P25519
    return shared.to_bytes(32, "little")


def x25519_public(secret: bytes) -> bytes:
    """Return the public key `x25519_dalek::PublicKey::from(&StaticSecret)` gives."""
    return x25519(secret, _X25519_BASEPOINT)


# --------------------------------------------------------------------------
# Signature preimages
# --------------------------------------------------------------------------

ISSUED_KEY_PREFIX = b"dstack-kms-issued"
ENV_PUBKEY_PREFIX = b"dstack-env-encrypt-pubkey"


def signature_digest(prefix: bytes, app_id: bytes, message: bytes) -> bytes:
    """`crypto::sign_message`: keccak256(prefix || ":" || app_id || message)."""
    return keccak256(prefix + b":" + app_id + message)


def timestamped_signature_digest(
    prefix: bytes, app_id: bytes, timestamp: int, message: bytes
) -> bytes:
    """`crypto::sign_message_with_timestamp`, with the timestamp big-endian."""
    if not 0 <= timestamp < 2**64:
        raise ValueError("timestamp does not fit in u64")
    return keccak256(prefix + b":" + app_id + timestamp.to_bytes(8, "big") + message)


def recovers_to(signature: bytes, digest: bytes, public_key: bytes) -> bool:
    """Report whether `signature` over `digest` recovers to `public_key`."""
    try:
        point = recover_public_point(signature, digest)
    except ValueError:
        return False
    return sec1_compressed(point) == public_key


# --------------------------------------------------------------------------
# Golden vectors
# --------------------------------------------------------------------------
# ISSUED_KEY_VECTOR is copied verbatim from
# `issued_app_key_signatures_match_their_golden_vectors` in
# `dstack/kms/src/crypto.rs`. The four timestamped envelopes and the legacy
# environment envelope were produced by re-running the same k256/sha3 code path
# over the same `[7u8; 32]` root key; the issued row is reproduced byte for
# byte by that generator, which is what ties the generated rows back to the
# committed vector.
#
# These are not fixtures to refresh. A mismatch means the harness's arithmetic
# drifted, or the signing envelope in the product changed -- and a change to
# the envelope is a change to key material already held by deployed CVMs.

GOLDEN_ROOT_KEY = bytes([7]) * 32
GOLDEN_ROOT_PUBKEY = bytes.fromhex(
    "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f"
)
GOLDEN_ISSUED_APP_KEY = bytes.fromhex(
    "ed0fd39ce7c26a185f396945168972807b2f77820f14ee4bda9e1f46e8b4596d"
)
GOLDEN_ISSUED_SIGNATURE = bytes.fromhex(
    "e12a5f4567f6d9f80b01944dea333bbed5b418347f4260ed95e9ee198a03014e"
    "1716a40d2ed6cd367e335b33e231510aa98216e62b631f2b75c181c2f9896568"
    "00"
)
GOLDEN_ENV_APP_ID = b"app-a"
GOLDEN_ENV_PUBLIC_KEY = bytes([0x42]) * 32
GOLDEN_ENV_LEGACY_SIGNATURE = bytes.fromhex(
    "a233a00d5256ddc0154a40afbfb85364464c0a4751bfd58d0c02bf8f468b3e41"
    "715633de6c0dcdd545e4f55d778fd64fe3329bae66a1095075997a70d2ef2c67"
    "01"
)
GOLDEN_ENV_TIMESTAMPED_SIGNATURES = {
    0: bytes.fromhex(
        "07c5c57126835935b3c1c34add64b0884ee9785683801d2162465de3a7c6facd"
        "7bc0a9110baef602f0272880314191c034b2d9f36ec6b6ec81333267e48a1f17"
        "01"
    ),
    1: bytes.fromhex(
        "1c1bb678e449eebfca114ce02807856c0dbb4db17a450619ba2ebc9df57499a5"
        "19e7d9adc9a1740acd9b3b3850b0c28ed2ef50e0e4979d051ced36946088a3e3"
        "00"
    ),
    1786194000: bytes.fromhex(
        "12e6d05e8a2e95eabc5b5cc4790b28ac9acfc58f978577a5bbcd2b9ba2fd831a"
        "3147df284bd671d8e2b31103dd8c53d11cbb48fa8ab4672771065a6b17edfbe8"
        "01"
    ),
    2**64 - 1: bytes.fromhex(
        "2040bdfbe952d7d9ed82d5ab5796480ad0e854f40e893abc4f3efb39275bb84c"
        "67829f6f65bbc92a96501e0bf897227e8ee1ce474066155a291888cd10bb1a65"
        "01"
    ),
}
# RFC 7748 section 6.1.
RFC7748_SECRET = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)
RFC7748_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)


def check_primitives() -> dict[str, Any]:
    """Check every primitive this harness relies on against a golden vector.

    Run first in every case. A live assertion about a signature chain is only
    worth as much as the arithmetic behind it, and this is the part that can be
    checked without the fixture.
    """
    rows: list[dict[str, Any]] = []

    def row(name: str, ok: bool, detail: str) -> None:
        rows.append({"name": name, "ok": bool(ok), "detail": detail})
        if not ok:
            raise AssertionError(f"primitive self-test failed: {name} ({detail})")

    row(
        "keccak256_empty",
        keccak256(b"").hex()
        == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        "the pre-NIST Keccak padding, not SHA3-256",
    )
    row(
        "keccak256_abc",
        keccak256(b"abc").hex()
        == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        "second Keccak-256 vector",
    )
    root_point = secp256k1_public_point(GOLDEN_ROOT_KEY)
    row(
        "secp256k1_scalar_multiplication",
        sec1_compressed(root_point) == GOLDEN_ROOT_PUBKEY,
        "the golden root key's public point",
    )
    issued_point = secp256k1_public_point(GOLDEN_ISSUED_APP_KEY)
    digest = signature_digest(
        ISSUED_KEY_PREFIX, GOLDEN_ENV_APP_ID, sec1_compressed(issued_point)
    )
    row(
        "issued_app_key_signature_recovers",
        recovers_to(GOLDEN_ISSUED_SIGNATURE, digest, GOLDEN_ROOT_PUBKEY),
        "crypto.rs golden vector recovers to the root key",
    )
    uncompressed_digest = signature_digest(
        ISSUED_KEY_PREFIX, GOLDEN_ENV_APP_ID, sec1_uncompressed(issued_point)
    )
    row(
        "issued_signature_pins_the_compressed_encoding",
        not recovers_to(
            GOLDEN_ISSUED_SIGNATURE, uncompressed_digest, GOLDEN_ROOT_PUBKEY
        ),
        "the preimage carries the 33-byte SEC1 form, not the 65-byte one",
    )
    row(
        "legacy_env_signature_recovers",
        recovers_to(
            GOLDEN_ENV_LEGACY_SIGNATURE,
            signature_digest(
                ENV_PUBKEY_PREFIX, GOLDEN_ENV_APP_ID, GOLDEN_ENV_PUBLIC_KEY
            ),
            GOLDEN_ROOT_PUBKEY,
        ),
        "untimestamped environment envelope",
    )
    for timestamp, vector in GOLDEN_ENV_TIMESTAMPED_SIGNATURES.items():
        row(
            f"timestamped_env_signature_recovers_at_{timestamp}",
            recovers_to(
                vector,
                timestamped_signature_digest(
                    ENV_PUBKEY_PREFIX,
                    GOLDEN_ENV_APP_ID,
                    timestamp,
                    GOLDEN_ENV_PUBLIC_KEY,
                ),
                GOLDEN_ROOT_PUBKEY,
            ),
            "timestamped environment envelope",
        )
        row(
            f"timestamped_env_signature_rejects_a_shifted_timestamp_{timestamp}",
            not recovers_to(
                vector,
                timestamped_signature_digest(
                    ENV_PUBKEY_PREFIX,
                    GOLDEN_ENV_APP_ID,
                    (timestamp + 1) % 2**64,
                    GOLDEN_ENV_PUBLIC_KEY,
                ),
                GOLDEN_ROOT_PUBKEY,
            ),
            "a replayed signature does not verify under another timestamp",
        )
    row(
        "x25519_rfc7748_basepoint",
        x25519_public(RFC7748_SECRET) == RFC7748_PUBLIC,
        "RFC 7748 section 6.1 public key",
    )
    row(
        "protobuf_roundtrip",
        decode_protobuf(
            encode_protobuf({1: ("bytes", b"\x00\xff"), 3: ("varint", 300)})
        )
        == {1: b"\x00\xff", 3: 300},
        "length-delimited and varint encoding agree in both directions",
    )
    return {"rows": rows, "passed": len(rows)}


# --------------------------------------------------------------------------
# Minimal protobuf
# --------------------------------------------------------------------------


def varint(value: int) -> bytes:
    """Encode an unsigned protobuf varint."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def encode_protobuf(fields: dict[int, tuple[str, Any]]) -> bytes:
    """Encode a flat message from `{number: (kind, value)}` in field order."""
    out = bytearray()
    for number in sorted(fields):
        kind, value = fields[number]
        if kind == "varint":
            out += varint(number << 3) + varint(int(value))
        elif kind in ("bytes", "string"):
            raw = value.encode() if kind == "string" else bytes(value)
            out += varint((number << 3) | 2) + varint(len(raw)) + raw
        else:
            raise ValueError(f"unsupported protobuf field kind: {kind}")
    return bytes(out)


def decode_protobuf(data: bytes) -> dict[int, Any]:
    """Decode a flat message into `{number: bytes | int}`, last value winning."""
    values: dict[int, Any] = {}
    offset = 0

    def read_varint() -> int:
        nonlocal offset
        result = 0
        shift = 0
        while True:
            if offset >= len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[offset]
            offset += 1
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result
            shift += 7

    while offset < len(data):
        key = read_varint()
        number, wire = key >> 3, key & 7
        if wire == 0:
            values[number] = read_varint()
        elif wire == 2:
            length = read_varint()
            values[number] = data[offset : offset + length]
            offset += length
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
    return values


APP_KEY_FIELDS = {
    1: "ca_cert",
    2: "disk_crypt_key",
    3: "env_crypt_key",
    4: "k256_key",
    5: "k256_signature",
    6: "tproxy_app_id",
    7: "gateway_app_id",
    8: "os_image_hash",
}
PUBLIC_KEY_FIELDS = {1: "public_key", 2: "signature", 3: "timestamp", 4: "signature_v1"}
SECRET_FIELDS = ("disk_crypt_key", "env_crypt_key", "k256_key")


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


class RpcError(RuntimeError):
    """A pRPC call that did not return HTTP 200."""

    def __init__(self, method: str, status: int, body: bytes) -> None:
        detail = body[:300].decode(errors="replace").replace("\n", " ")
        super().__init__(f"{method} returned HTTP {status}: {detail}")
        self.status = status


def tls_context(identity: dict[str, Any] | None) -> ssl.SSLContext:
    """Build the client context.

    The lease's KMS serves a self-signed RPC certificate on a loopback port it
    owns, so the case cannot pin a name; the property under test is the key
    hierarchy, and the caller's own attested certificate is what authorises the
    call.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if identity:
        context.load_cert_chain(str(identity["cert"]), str(identity["key"]))
    return context


def call(
    base_url: str,
    method: str,
    body: bytes,
    *,
    identity: dict[str, Any] | None = None,
    json_transport: bool = True,
    timeout: float = 90,
) -> tuple[int, bytes]:
    """Invoke one pRPC method and return its status and native body."""
    suffix = "?json" if json_transport else ""
    content_type = "application/json" if json_transport else "application/octet-stream"
    request = urllib.request.Request(
        f"{base_url}/{method}{suffix}",
        data=body,
        headers={"content-type": content_type},
    )
    try:
        with urllib.request.urlopen(
            request, context=tls_context(identity), timeout=timeout
        ) as response:
            return int(response.status), response.read()
    except urllib.error.HTTPError as error:
        return int(error.code), error.read()


def call_json(
    base_url: str,
    method: str,
    payload: dict[str, Any],
    *,
    identity: dict[str, Any] | None = None,
    timeout: float = 90,
) -> dict[str, Any]:
    """Invoke one pRPC method over JSON and require success."""
    status, raw = call(
        base_url,
        method,
        json.dumps(payload, separators=(",", ":")).encode(),
        identity=identity,
        timeout=timeout,
    )
    if status != 200:
        raise RpcError(method, status, raw)
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise AssertionError(f"{method} did not return a JSON object")
    return value


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTP over a Unix socket, for the simulator's `DstackGuest` listener."""

    def __init__(self, socket_path: str, timeout: float = 20) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stream.settimeout(self.timeout)
        stream.connect(self.socket_path)
        self.sock = stream


def simulator_app_identity(values: dict[str, Any]) -> dict[str, bytes]:
    """Return the app and instance IDs the attested client actually carries.

    `AppKeyResponse` deliberately does not echo the identity it derived from,
    so the signature preimage has to come from the same place the KMS read it:
    the guest whose attestation the client certificate embeds.
    """
    service = (
        values.get("kms_guest_simulator", {}).get("services", {}).get("DstackGuest", {})
    )
    socket_path = str(service.get("socket", ""))
    route = str(service.get("route", "")).replace("<Method>", "Info")
    if not socket_path or not route:
        raise RuntimeError("fixture does not expose the simulator's DstackGuest.Info")
    connection = UnixHTTPConnection(socket_path)
    try:
        connection.request(
            "POST", route, body=b"{}", headers={"Content-Type": "application/json"}
        )
        response = connection.getresponse()
        raw = response.read()
        if response.status != 200:
            raise RuntimeError(f"DstackGuest.Info returned HTTP {response.status}")
    finally:
        connection.close()
    info = json.loads(raw)
    identity = {
        "app_id": bytes.fromhex(str(info["app_id"])),
        "instance_id": bytes.fromhex(str(info["instance_id"])),
    }
    if len(identity["app_id"]) != 20:
        raise AssertionError("simulator reported an app_id that is not 20 bytes")
    return identity


# --------------------------------------------------------------------------
# KMS calls
# --------------------------------------------------------------------------


def get_meta(base_url: str) -> dict[str, Any]:
    """Read the KMS public identity."""
    meta = call_json(base_url, "KMS.GetMeta", {})
    for field in ("ca_cert", "k256_pubkey"):
        if not isinstance(meta.get(field), str) or not meta[field]:
            raise AssertionError(f"GetMeta omitted {field}")
    return meta


def root_k256_pubkey(base_url: str) -> bytes:
    """Return the root k256 public key in its 33-byte SEC1 form."""
    raw = bytes.fromhex(str(get_meta(base_url)["k256_pubkey"]))
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise AssertionError(
            f"GetMeta.k256_pubkey is not a compressed SEC1 point ({len(raw)} bytes)"
        )
    return raw


def get_app_key(
    base_url: str,
    identity: dict[str, Any],
    *,
    vm_config: str | None = None,
    api_version: int = 1,
    timeout: float = 120,
) -> dict[str, Any]:
    """Call `KMS.GetAppKey` with the fixture's attested client identity."""
    payload = {
        "api_version": api_version,
        "vm_config": vm_config if vm_config is not None else str(identity["vm_config"]),
    }
    response = call_json(
        base_url, "KMS.GetAppKey", payload, identity=identity, timeout=timeout
    )
    for field in APP_KEY_FIELDS.values():
        if field not in response:
            raise AssertionError(f"GetAppKey omitted {field}")
    return response


def get_env_pubkey(
    base_url: str, app_id: bytes, *, timeout: float = 60
) -> dict[str, Any]:
    """Call `KMS.GetAppEnvEncryptPubKey`, which needs no client identity."""
    response = call_json(
        base_url,
        "KMS.GetAppEnvEncryptPubKey",
        {"app_id": app_id.hex()},
        timeout=timeout,
    )
    for field in ("public_key", "signature", "timestamp", "signature_v1"):
        if field not in response:
            raise AssertionError(f"GetAppEnvEncryptPubKey omitted {field}")
    return response


def app_key_material(response: dict[str, Any]) -> dict[str, bytes]:
    """Decode the hex fields of an `AppKeyResponse` into raw bytes."""
    return {
        name: bytes.fromhex(str(response[name]))
        for name in (
            "disk_crypt_key",
            "env_crypt_key",
            "k256_key",
            "k256_signature",
            "os_image_hash",
        )
    }


def redacted_app_key(response: dict[str, Any]) -> dict[str, Any]:
    """Summarise an `AppKeyResponse` without retaining a single secret byte."""
    material = app_key_material(response)
    summary: dict[str, Any] = {
        "ca_cert_sha256": hashlib.sha256(str(response["ca_cert"]).encode()).hexdigest(),
        "gateway_app_id": str(response["gateway_app_id"]),
        "os_image_hash": material["os_image_hash"].hex(),
        "k256_signature": material["k256_signature"].hex(),
    }
    for name in SECRET_FIELDS:
        summary[f"{name}_sha256"] = hashlib.sha256(material[name]).hexdigest()
        summary[f"{name}_len"] = len(material[name])
    summary["env_public_key"] = x25519_public(material["env_crypt_key"]).hex()
    summary["k256_public_key"] = sec1_compressed(
        secp256k1_public_point(material["k256_key"])
    ).hex()
    return summary


# --------------------------------------------------------------------------
# Lease-owned KMS restart
# --------------------------------------------------------------------------


def stop_process(pid: int, timeout: float = 15) -> bool:
    """Stop one lease-owned process, escalating only if it ignores SIGTERM."""
    if not Path(f"/proc/{pid}").exists():
        return False
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and Path(f"/proc/{pid}").exists():
        time.sleep(0.1)
    if Path(f"/proc/{pid}").exists():
        os.kill(pid, signal.SIGKILL)
    return True


def wait_for_listener(host: str, port: int, timeout: float = 45) -> None:
    """Wait until the replacement KMS is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with socket.socket() as probe:
            probe.settimeout(1.0)
            if probe.connect_ex((host, port)) == 0:
                return
        time.sleep(0.2)
    raise TimeoutError(f"no listener on {host}:{port} within {timeout}s")


def listener_address(url: str) -> tuple[str, int]:
    """Split a `https://host:port/...` URL into its host and port."""
    authority = url.split("//", 1)[1].split("/", 1)[0]
    host, _, port = authority.rpartition(":")
    return host, int(port)


def start_replacement_kms(
    values: dict[str, Any], runtime: dict[str, Any], log_path: Path
) -> subprocess.Popen[bytes]:
    """Stop the lease's KMS and start one reading the same configuration.

    Returns as soon as the replacement is spawned so the caller can register
    its cleanup before waiting for it: a replacement that never becomes ready
    still has to be stopped.
    """
    kms = values["kms"]
    binary = str(
        runtime.get("prepared_binaries", {}).get("dstack_kms", {}).get("path", "")
    )
    if not binary or not Path(binary).is_file():
        raise RuntimeError("the prepared dstack-kms binary is unavailable")
    agent_socket = values["kms_guest_simulator"]["services"]["DstackGuest"]["socket"]
    stop_process(int(kms["pid"]))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    stream = log_path.open("ab")
    return subprocess.Popen(
        [binary, "--config", str(kms["config"])],
        env={**os.environ, "DSTACK_AGENT_ADDRESS": f"unix:{agent_socket}"},
        stdout=stream,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )


def wait_until_serving(url: str, host: str, port: int, timeout: float = 60) -> None:
    """Wait for the listener, then for the service behind it to answer."""
    wait_for_listener(host, port, timeout)
    deadline = time.monotonic() + timeout
    last = "no attempt"
    while time.monotonic() < deadline:
        try:
            get_meta(url)
            return
        except (OSError, ValueError, AssertionError, RpcError) as error:
            last = f"{type(error).__name__}: {error}"
            time.sleep(0.3)
    raise TimeoutError(f"the replacement KMS never answered GetMeta ({last})")


def reap(process: subprocess.Popen[bytes]) -> None:
    """Stop a process this case started and collect it."""
    stop_process(process.pid)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=5)


# --------------------------------------------------------------------------
# Case context
# --------------------------------------------------------------------------


class Context:
    """One case's lease bindings, step ledger and artifact directory."""

    def __init__(
        self,
        case_id: str,
        values: dict[str, Any],
        runtime: dict[str, Any],
        artifacts: Path,
    ) -> None:
        self.case_id = case_id
        self.values = values
        self.runtime = runtime
        self.artifacts = artifacts
        self.steps: list[dict[str, str]] = []
        self.evidence: dict[str, Any] = {"case_id": case_id}
        self.cleanup: list[Callable[[], None]] = []

    @property
    def url(self) -> str:
        """The lease-owned KMS pRPC base URL."""
        return str(self.values["kms"]["rpc_prpc_url"])

    @property
    def identity(self) -> dict[str, Any]:
        """The fixture's attested client identity."""
        identity = self.values.get("kms_attested_client")
        if not isinstance(identity, dict):
            raise RuntimeError("fixture declares no attested KMS client")
        for key in ("cert", "key", "ca_cert", "vm_config"):
            if not identity.get(key):
                raise RuntimeError(f"attested client identity omits {key}")
        for key in ("cert", "key", "ca_cert"):
            if not Path(str(identity[key])).is_file():
                raise RuntimeError(f"attested client {key} is missing on disk")
        return identity

    @contextlib.contextmanager
    def step(self, number: int) -> Iterator[dict[str, str]]:
        """Run one numbered step, emitting the runner's STEP/EVIDENCE markers."""
        step_id = f"{self.case_id}-step-{number:02d}"
        print(f"STEP {step_id} START", flush=True)
        record = {"id": step_id, "status": "PASS", "observed": ""}
        try:
            yield record
        except Exception as error:  # noqa: BLE001 - step boundary
            record["status"] = "FAIL"
            record["observed"] = f"{type(error).__name__}: {error}"
            self.steps.append(record)
            print(f"EVIDENCE {step_id} - {record['observed']}", flush=True)
            print(f"STEP {step_id} END - FAIL", flush=True)
            raise
        self.steps.append(record)
        print(f"EVIDENCE {step_id} - {record['observed']}", flush=True)
        print(f"STEP {step_id} END - PASS", flush=True)

    def preflight(self, record: dict[str, str], extra: str = "") -> None:
        """Self-test the primitives and confirm the listener answers."""
        self.evidence["primitive_self_test"] = check_primitives()
        meta = get_meta(self.url)
        self.evidence["kms_identity"] = {
            "k256_pubkey": str(meta["k256_pubkey"]),
            "ca_cert_sha256": hashlib.sha256(str(meta["ca_cert"]).encode()).hexdigest(),
            "is_dev": meta.get("is_dev"),
        }
        passed = self.evidence["primitive_self_test"]["passed"]
        record["observed"] = (
            f"{passed} primitive vectors from crypto.rs and RFC 7748 matched, and the "
            f"lease-owned KMS answered GetMeta with a compressed root k256 public key."
            + (f" {extra}" if extra else "")
        )


# --------------------------------------------------------------------------
# Cases
# --------------------------------------------------------------------------


def case_restart_determinism(ctx: Context) -> str:
    """tc-kms-keyhier-001: identical derived material across a KMS restart."""
    substrate = ctx.values.get("component_substrate", {})
    with ctx.step(1) as record:
        if substrate.get("destructive_actions_allowed") is not True:
            raise RuntimeError("fixture did not authorise lease-scoped restarts")
        ctx.preflight(record, "Lease-scoped process control is authorised.")

    identity = ctx.identity
    with ctx.step(2) as record:
        before = get_app_key(ctx.url, identity)
        before_material = app_key_material(before)
        before_meta = get_meta(ctx.url)
        ctx.evidence["before"] = redacted_app_key(before)
        ctx.evidence["before_pid"] = int(ctx.values["kms"]["pid"])
        record["observed"] = (
            "The attested identity received a complete AppKeyResponse; only hashes and "
            "public derivations of it were retained."
        )

    with ctx.step(3) as record:
        log_path = ctx.artifacts / "restarted-kms.log"
        host, port = listener_address(str(ctx.values["kms"]["rpc_url"]))
        replacement = start_replacement_kms(ctx.values, ctx.runtime, log_path)
        ctx.cleanup.append(lambda: reap(replacement))
        wait_until_serving(ctx.url, host, port)
        after = get_app_key(ctx.url, identity)
        after_material = app_key_material(after)
        after_meta = get_meta(ctx.url)
        differing = sorted(
            name
            for name in (
                "disk_crypt_key",
                "env_crypt_key",
                "k256_key",
                "k256_signature",
            )
            if before_material[name] != after_material[name]
        )
        if differing:
            raise AssertionError(
                f"derived material changed across the restart: {differing}"
            )
        if before["ca_cert"] != after["ca_cert"]:
            raise AssertionError("the app CA certificate changed across the restart")
        for field in ("k256_pubkey", "ca_cert"):
            if before_meta[field] != after_meta[field]:
                raise AssertionError(f"GetMeta.{field} changed across the restart")
        ctx.evidence["after"] = redacted_app_key(after)
        ctx.evidence["after_pid"] = replacement.pid
        ctx.evidence["restart"] = {
            "pid_changed": replacement.pid != int(ctx.values["kms"]["pid"]),
            "identical_fields": [
                "disk_crypt_key",
                "env_crypt_key",
                "k256_key",
                "k256_signature",
                "ca_cert",
            ],
            "log": log_path.name,
        }
        if not ctx.evidence["restart"]["pid_changed"]:
            raise AssertionError("the KMS was never actually replaced")
        record["observed"] = (
            f"A replacement KMS (pid {replacement.pid}) reading the same configuration "
            "returned byte-identical disk, environment and k256 material, the same "
            "issued signature and the same public identity."
        )
    return (
        "The same attested identity received byte-identical derived material before "
        "and after the lease-owned KMS was replaced."
    )


def separation_app_ids() -> list[bytes]:
    """A fixed, obviously non-production table of 20-byte application IDs."""
    table = [bytes([value]) * 20 for value in (0x00, 0x01, 0x02, 0x7F, 0xFF)]
    table += [
        hashlib.sha256(f"dstack-test-keyhier-app-{index}".encode()).digest()[:20]
        for index in range(1, 5)
    ]
    return table


def case_app_separation(ctx: Context) -> str:
    """tc-kms-keyhier-002: app-scoped environment keys separate by app_id."""
    with ctx.step(1) as record:
        ctx.preflight(record)

    table = separation_app_ids()
    with ctx.step(2) as record:
        observed: dict[str, bytes] = {}
        rows: list[dict[str, Any]] = []
        for app_id in table:
            first = get_env_pubkey(ctx.url, app_id)
            second = get_env_pubkey(ctx.url, app_id)
            public_key = bytes.fromhex(str(first["public_key"]))
            if public_key != bytes.fromhex(str(second["public_key"])):
                raise AssertionError(
                    f"app {app_id.hex()} received two different environment keys"
                )
            if len(public_key) != 32:
                raise AssertionError("environment public key is not 32 bytes")
            if public_key == bytes(32):
                raise AssertionError("environment public key is the all-zero point")
            observed[app_id.hex()] = public_key
            rows.append(
                {
                    "app_id": app_id.hex(),
                    "public_key": public_key.hex(),
                    "repeatable": True,
                }
            )
        collisions = [
            (left, right)
            for index, left in enumerate(sorted(observed))
            for right in sorted(observed)[index + 1 :]
            if observed[left] == observed[right]
        ]
        if collisions:
            raise AssertionError(f"distinct app IDs shared a key: {collisions}")
        ctx.evidence["env_public_keys"] = rows
        ctx.evidence["pairwise_comparisons"] = len(table) * (len(table) - 1) // 2
        record["observed"] = (
            f"{len(table)} application IDs each received a repeatable 32-byte "
            f"environment public key, and all "
            f"{len(table) * (len(table) - 1) // 2} pairs differed."
        )

    with ctx.step(3) as record:
        app_identity = simulator_app_identity(ctx.values)
        app_id = app_identity["app_id"]
        response = get_app_key(ctx.url, ctx.identity)
        material = app_key_material(response)
        derived_public = x25519_public(material["env_crypt_key"])
        published = bytes.fromhex(str(get_env_pubkey(ctx.url, app_id)["public_key"]))
        if derived_public != published:
            raise AssertionError(
                "the environment secret issued to the attested identity does not "
                "belong to its own app_id namespace"
            )
        foreign_id = next(entry for entry in table if entry != app_id)
        foreign = bytes.fromhex(str(get_env_pubkey(ctx.url, foreign_id)["public_key"]))
        if derived_public == foreign:
            raise AssertionError("a foreign app_id produced the same environment key")
        distinct_contexts = {
            material["disk_crypt_key"],
            material["env_crypt_key"],
            material["k256_key"],
        }
        if len(distinct_contexts) != 3:
            raise AssertionError(
                "two of the three derivation contexts produced the same key"
            )
        rejected = {}
        for length in (19, 21):
            status, _ = call(
                ctx.url,
                "KMS.GetAppEnvEncryptPubKey",
                json.dumps({"app_id": (b"\x11" * length).hex()}).encode(),
            )
            rejected[length] = status
            if status < 400:
                raise AssertionError(
                    f"a {length}-byte app_id was accepted with HTTP {status}"
                )
        ctx.evidence["identity_binding"] = {
            "app_id": app_id.hex(),
            "instance_id": app_identity["instance_id"].hex(),
            "env_public_key": derived_public.hex(),
            "foreign_app_id": foreign_id.hex(),
            "matches_published_app_key": True,
            "distinct_derivation_contexts": 3,
            "app_id_length_rejections": rejected,
        }
        record["observed"] = (
            "The environment secret inside the attested identity's AppKeyResponse has "
            "the public key GetAppEnvEncryptPubKey publishes for that same app_id, a "
            "foreign app_id publishes a different one, the three derivation contexts "
            "produce three different keys, and a 19- or 21-byte app_id is refused."
        )
    return (
        "Environment key material is app-scoped: identical for one app_id, different "
        "for every other, and the attested identity's own secret lands in its "
        "published app_id namespace."
    )


def case_issued_signature_chain(ctx: Context) -> str:
    """tc-kms-keyhier-003: the issued k256 signature recovers to the root key."""
    with ctx.step(1) as record:
        ctx.preflight(record)

    identity = ctx.identity
    with ctx.step(2) as record:
        root_pubkey = root_k256_pubkey(ctx.url)
        app_id = simulator_app_identity(ctx.values)["app_id"]
        response = get_app_key(ctx.url, identity)
        material = app_key_material(response)
        derived_point = secp256k1_public_point(material["k256_key"])
        derived_pubkey = sec1_compressed(derived_point)
        digest = signature_digest(ISSUED_KEY_PREFIX, app_id, derived_pubkey)
        if not recovers_to(material["k256_signature"], digest, root_pubkey):
            raise AssertionError(
                "the issued k256 signature does not recover to GetMeta.k256_pubkey"
            )
        ctx.evidence["chain"] = {
            "app_id": app_id.hex(),
            "root_k256_pubkey": root_pubkey.hex(),
            "derived_k256_pubkey": derived_pubkey.hex(),
            "k256_signature": material["k256_signature"].hex(),
            "preimage_digest": digest.hex(),
            "preimage": 'keccak256("dstack-kms-issued" || ":" || app_id || pubkey)',
        }
        record["observed"] = (
            "The public key of the issued k256 private key, signed under "
            'keccak256("dstack-kms-issued" || ":" || app_id || pubkey), recovers to '
            "the root k256 public key GetMeta advertises."
        )

    with ctx.step(3) as record:
        signature = material["k256_signature"]
        mutated_r = bytearray(signature)
        mutated_r[0] ^= 0x01
        mutated_s = bytearray(signature)
        mutated_s[40] ^= 0x01
        other_recovery = bytearray(signature)
        other_recovery[64] ^= 0x01
        negatives = {
            "mutated_r": recovers_to(bytes(mutated_r), digest, root_pubkey),
            "mutated_s": recovers_to(bytes(mutated_s), digest, root_pubkey),
            "swapped_recovery_id": recovers_to(
                bytes(other_recovery), digest, root_pubkey
            ),
            "foreign_app_id": recovers_to(
                signature,
                signature_digest(ISSUED_KEY_PREFIX, b"\x00" * 20, derived_pubkey),
                root_pubkey,
            ),
            "uncompressed_pubkey": recovers_to(
                signature,
                signature_digest(
                    ISSUED_KEY_PREFIX, app_id, sec1_uncompressed(derived_point)
                ),
                root_pubkey,
            ),
            "wrong_domain_prefix": recovers_to(
                signature,
                signature_digest(ENV_PUBKEY_PREFIX, app_id, derived_pubkey),
                root_pubkey,
            ),
        }
        accepted = sorted(name for name, ok in negatives.items() if ok)
        if accepted:
            raise AssertionError(f"a mutated chain still verified: {accepted}")
        protobuf_status, protobuf_body = call(
            ctx.url,
            "KMS.GetAppKey",
            encode_protobuf(
                {1: ("varint", 1), 2: ("string", str(identity["vm_config"]))}
            ),
            identity=identity,
            json_transport=False,
            timeout=120,
        )
        if protobuf_status != 200:
            raise RpcError("KMS.GetAppKey", protobuf_status, protobuf_body)
        wire = decode_protobuf(protobuf_body)
        mismatched = sorted(
            APP_KEY_FIELDS[number]
            for number in (2, 3, 4, 5, 8)
            if bytes(wire.get(number, b""))
            != bytes.fromhex(str(response[APP_KEY_FIELDS[number]]))
        )
        if mismatched:
            raise AssertionError(
                f"protobuf and JSON representations disagree: {mismatched}"
            )
        ctx.evidence["negatives"] = negatives
        ctx.evidence["representation"] = {
            "protobuf_status": protobuf_status,
            "hex_fields_match": True,
            "compared_fields": [APP_KEY_FIELDS[n] for n in (2, 3, 4, 5, 8)],
        }
        record["observed"] = (
            f"All {len(negatives)} mutated chains failed to recover to the root key, "
            "and the protobuf representation carried byte-identical key material to "
            "the hex-encoded JSON one."
        )
    return (
        "The issued k256 signature chain closes against the root key the same KMS "
        "publishes, and every mutation of it fails."
    )


def case_signature_v1_freshness(ctx: Context) -> str:
    """tc-kms-keyhier-004: `signature_v1` binds the timestamp, legacy still holds."""
    with ctx.step(1) as record:
        ctx.preflight(record)

    with ctx.step(2) as record:
        root_pubkey = root_k256_pubkey(ctx.url)
        app_id = simulator_app_identity(ctx.values)["app_id"]
        first = get_env_pubkey(ctx.url, app_id)
        public_key = bytes.fromhex(str(first["public_key"]))
        signature_v1 = bytes.fromhex(str(first["signature_v1"]))
        legacy = bytes.fromhex(str(first["signature"]))
        timestamp = int(first["timestamp"])
        now = int(time.time())
        if not now - 120 <= timestamp <= now + 120:
            raise AssertionError(
                f"the response timestamp {timestamp} is not near the wall clock {now}"
            )
        if not recovers_to(
            signature_v1,
            timestamped_signature_digest(
                ENV_PUBKEY_PREFIX, app_id, timestamp, public_key
            ),
            root_pubkey,
        ):
            raise AssertionError("signature_v1 does not recover to the root k256 key")
        if not recovers_to(
            legacy,
            signature_digest(ENV_PUBKEY_PREFIX, app_id, public_key),
            root_pubkey,
        ):
            raise AssertionError(
                "the legacy signature no longer recovers to the root k256 key"
            )
        negatives = {
            "shifted_timestamp": recovers_to(
                signature_v1,
                timestamped_signature_digest(
                    ENV_PUBKEY_PREFIX, app_id, timestamp + 1, public_key
                ),
                root_pubkey,
            ),
            "foreign_app_id": recovers_to(
                signature_v1,
                timestamped_signature_digest(
                    ENV_PUBKEY_PREFIX, b"\x00" * 20, timestamp, public_key
                ),
                root_pubkey,
            ),
            "wrong_domain_prefix": recovers_to(
                signature_v1,
                timestamped_signature_digest(
                    ISSUED_KEY_PREFIX, app_id, timestamp, public_key
                ),
                root_pubkey,
            ),
            "untimestamped_preimage": recovers_to(
                signature_v1,
                signature_digest(ENV_PUBKEY_PREFIX, app_id, public_key),
                root_pubkey,
            ),
        }
        accepted = sorted(name for name, ok in negatives.items() if ok)
        if accepted:
            raise AssertionError(
                f"signature_v1 verified under a wrong claim: {accepted}"
            )
        ctx.evidence["first_response"] = {
            "app_id": app_id.hex(),
            "public_key": public_key.hex(),
            "timestamp": timestamp,
            "signature": legacy.hex(),
            "signature_v1": signature_v1.hex(),
        }
        ctx.evidence["negatives"] = negatives
        record["observed"] = (
            "signature_v1 recovers to the root k256 key over "
            'keccak256(prefix || ":" || app_id || be64(timestamp) || pubkey), the '
            f"legacy signature still recovers over its own preimage, and all "
            f"{len(negatives)} substituted claims fail."
        )

    with ctx.step(3) as record:
        deadline = time.monotonic() + 5
        second = get_env_pubkey(ctx.url, app_id)
        while int(second["timestamp"]) == timestamp and time.monotonic() < deadline:
            time.sleep(0.3)
            second = get_env_pubkey(ctx.url, app_id)
        second_timestamp = int(second["timestamp"])
        if second_timestamp <= timestamp:
            raise AssertionError(
                "the response timestamp did not advance between two calls"
            )
        if bytes.fromhex(str(second["public_key"])) != public_key:
            raise AssertionError("the published environment key changed between calls")
        if bytes.fromhex(str(second["signature"])) != legacy:
            raise AssertionError(
                "the legacy signature changed although its preimage did not"
            )
        second_v1 = bytes.fromhex(str(second["signature_v1"]))
        if second_v1 == signature_v1:
            raise AssertionError(
                "signature_v1 was reused across two different timestamps"
            )
        if not recovers_to(
            second_v1,
            timestamped_signature_digest(
                ENV_PUBKEY_PREFIX, app_id, second_timestamp, public_key
            ),
            root_pubkey,
        ):
            raise AssertionError("the second signature_v1 does not recover")
        if recovers_to(
            second_v1,
            timestamped_signature_digest(
                ENV_PUBKEY_PREFIX, app_id, timestamp, public_key
            ),
            root_pubkey,
        ):
            raise AssertionError(
                "the second signature_v1 also verifies under the first timestamp"
            )
        protobuf_status, protobuf_body = call(
            ctx.url,
            "KMS.GetAppEnvEncryptPubKey",
            encode_protobuf({1: ("bytes", app_id)}),
            json_transport=False,
            timeout=60,
        )
        if protobuf_status != 200:
            raise RpcError("KMS.GetAppEnvEncryptPubKey", protobuf_status, protobuf_body)
        wire = decode_protobuf(protobuf_body)
        if wire.get(1) != public_key:
            raise AssertionError(
                "the protobuf representation published a different environment key"
            )
        if not recovers_to(
            bytes(wire.get(4, b"")),
            timestamped_signature_digest(
                ENV_PUBKEY_PREFIX, app_id, int(wire.get(3, 0)), public_key
            ),
            root_pubkey,
        ):
            raise AssertionError(
                "the protobuf representation's signature_v1 does not recover"
            )
        ctx.evidence["second_response"] = {
            "timestamp": second_timestamp,
            "advanced_by_seconds": second_timestamp - timestamp,
            "public_key_stable": True,
            "legacy_signature_stable": True,
            "signature_v1": second_v1.hex(),
        }
        ctx.evidence["representation"] = {
            "protobuf_status": protobuf_status,
            "protobuf_fields": sorted(PUBLIC_KEY_FIELDS.get(n, str(n)) for n in wire),
            "protobuf_signature_v1_recovers": True,
        }
        record["observed"] = (
            f"The timestamp advanced from {timestamp} to {second_timestamp} while the "
            "published key and legacy signature stayed identical, the new signature_v1 "
            "verifies only under the new timestamp, and the protobuf representation "
            "carries an equally valid chain."
        )
    return (
        "signature_v1 binds the domain, the app_id, the timestamp and the published "
        "key, and a signature issued at one second does not verify at another."
    )


def concurrent_app_keys(
    ctx: Context, requests: list[str | None], timeout: float = 150
) -> list[dict[str, Any]]:
    """Issue one `GetAppKey` per entry, all in flight at the same time."""
    identity = ctx.identity
    barrier = threading.Barrier(len(requests))

    def worker(vm_config: str | None) -> dict[str, Any]:
        barrier.wait(timeout=30)
        started = time.monotonic()
        response = get_app_key(ctx.url, identity, vm_config=vm_config, timeout=timeout)
        return {
            "vm_config": vm_config,
            "elapsed": round(time.monotonic() - started, 3),
            "response": response,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(requests)) as pool:
        return [
            future.result() for future in [pool.submit(worker, r) for r in requests]
        ]


def case_concurrent_identity(ctx: Context) -> str:
    """tc-kms-keyhier-005: concurrent calls for one identity agree byte for byte."""
    with ctx.step(1) as record:
        ctx.preflight(record)

    concurrency = 8
    with ctx.step(2) as record:
        baseline = get_app_key(ctx.url, ctx.identity)
        baseline_material = app_key_material(baseline)
        ctx.evidence["baseline"] = redacted_app_key(baseline)
        results = concurrent_app_keys(ctx, [None] * concurrency)
        ctx.evidence["concurrency"] = concurrency
        ctx.evidence["latencies"] = sorted(item["elapsed"] for item in results)
        record["observed"] = (
            f"{concurrency} GetAppKey calls for the same attested identity were "
            "released together and all returned HTTP 200."
        )

    with ctx.step(3) as record:
        digests = set()
        for item in results:
            material = app_key_material(item["response"])
            differing = sorted(
                name for name in material if material[name] != baseline_material[name]
            )
            if differing:
                raise AssertionError(
                    f"a concurrent call returned different material: {differing}"
                )
            if item["response"]["ca_cert"] != baseline["ca_cert"]:
                raise AssertionError("a concurrent call returned a different CA")
            digests.add(
                hashlib.sha256(
                    json.dumps(item["response"], sort_keys=True).encode()
                ).hexdigest()
            )
        if len(digests) != 1:
            raise AssertionError(
                f"concurrent responses were not byte-identical: {len(digests)} variants"
            )
        ctx.evidence["response_digest"] = sorted(digests)
        ctx.evidence["distinct_responses"] = len(digests)
        record["observed"] = (
            f"All {concurrency} concurrent responses hashed to one value and matched "
            "the sequential baseline field for field."
        )
    return (
        f"{concurrency} concurrent GetAppKey calls for one attested identity returned "
        "byte-identical derived material."
    )


def case_concurrent_image_hashes(ctx: Context) -> str:
    """tc-kms-keyhier-006: concurrent distinct `os_image_hash` values stay separate."""
    with ctx.step(1) as record:
        ctx.preflight(record)

    concurrency = 8
    with ctx.step(2) as record:
        base_config = json.loads(str(ctx.identity["vm_config"]))
        if "os_image_hash" not in base_config:
            raise RuntimeError("the fixture vm_config declares no os_image_hash")
        requests: list[str | None] = []
        expected: list[str] = []
        for index in range(concurrency):
            digest = hashlib.sha256(
                f"dstack-test-keyhier-image-{index}".encode()
            ).hexdigest()
            expected.append(digest)
            requests.append(
                json.dumps(
                    {**base_config, "os_image_hash": digest}, separators=(",", ":")
                )
            )
        if len(set(expected)) != concurrency:
            raise AssertionError("the image-hash table is not distinct")
        results = concurrent_app_keys(ctx, requests)
        ctx.evidence["requested_image_hashes"] = expected
        ctx.evidence["latencies"] = sorted(item["elapsed"] for item in results)
        record["observed"] = (
            f"{concurrency} GetAppKey calls carrying {concurrency} distinct, "
            "never-before-seen os_image_hash values were released together and all "
            "returned HTTP 200."
        )

    with ctx.step(3) as record:
        material_digests = set()
        echoed: list[str] = []
        for item, wanted in zip(results, expected):
            material = app_key_material(item["response"])
            got = material["os_image_hash"].hex()
            echoed.append(got)
            if got != wanted:
                raise AssertionError(
                    f"a concurrent response echoed {got} for a request carrying {wanted}"
                )
            material_digests.add(tuple(material[name] for name in SECRET_FIELDS))
        if len(material_digests) != 1:
            raise AssertionError(
                "derived key material varied with os_image_hash, which is not one of "
                "its derivation inputs"
            )
        ctx.evidence["echoed_image_hashes"] = echoed
        ctx.evidence["distinct_material_sets"] = len(material_digests)
        ctx.evidence["material_sha256"] = {
            name: hashlib.sha256(
                app_key_material(results[0]["response"])[name]
            ).hexdigest()
            for name in SECRET_FIELDS
        }
        record["observed"] = (
            "Every response echoed exactly the os_image_hash its own request carried, "
            "no response was served another caller's image hash, and the derived "
            "material was identical across all of them."
        )
    return (
        f"{concurrency} concurrent GetAppKey calls with distinct uncached image hashes "
        "all succeeded, each answered with its own hash."
    )


CASES: dict[str, dict[str, Any]] = {
    "tc-kms-keyhier-001": {
        "title": "Derived key determinism across a KMS restart",
        "handler": case_restart_determinism,
        "artifact": "Restart determinism evidence",
    },
    "tc-kms-keyhier-002": {
        "title": "Application-scoped environment key separation",
        "handler": case_app_separation,
        "artifact": "Environment key separation matrix",
    },
    "tc-kms-keyhier-003": {
        "title": "Issued k256 signature chain recovery",
        "handler": case_issued_signature_chain,
        "artifact": "Signature chain recovery evidence",
    },
    "tc-kms-keyhier-004": {
        "title": "Environment public key signature_v1 freshness",
        "handler": case_signature_v1_freshness,
        "artifact": "signature_v1 freshness evidence",
    },
    "tc-kms-keyhier-005": {
        "title": "Concurrent GetAppKey for one identity",
        "handler": case_concurrent_identity,
        "artifact": "Concurrent identity evidence",
    },
    "tc-kms-keyhier-006": {
        "title": "Concurrent GetAppKey across distinct image hashes",
        "handler": case_concurrent_image_hashes,
        "artifact": "Concurrent image-hash evidence",
    },
}

REMARKS = (
    "Derived secrets stayed in memory; the artifacts hold hashes, public keys and "
    "signatures only. The attested client is the fixture's seed-matched simulated TDX "
    "identity, so the case proves key-hierarchy behaviour for a verified identity and "
    "makes no physical-origin trust claim."
)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def write_json(path: Path, value: Any) -> None:
    """Write JSON evidence atomically."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=path.parent, delete=False
    ) as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def load_document(value: str) -> dict[str, Any]:
    """Load a JSON document given either as a path or inline."""
    candidate = Path(value)
    text = candidate.read_text(encoding="utf-8") if candidate.is_file() else value
    document = json.loads(text)
    if not isinstance(document, dict):
        raise SystemExit("expected a JSON object")
    return document


def parse_args(argv: list[str]) -> argparse.Namespace:
    """Parse the standalone options; the runner supplies everything by env."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--standalone",
        action="store_true",
        help="take the fixture bindings from the command line instead of the runner",
    )
    parser.add_argument("--case", help="case ID to execute")
    parser.add_argument(
        "--values", help="lease values or case manifest, as a path or inline JSON"
    )
    parser.add_argument(
        "--runtime-manifest",
        help="runtime manifest path; only tc-kms-keyhier-001 needs its KMS binary",
    )
    parser.add_argument("--result-dir", help="where to write result.json and artifacts")
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="check the crypto primitives against their golden vectors and exit",
    )
    return parser.parse_args(argv)


def resolve_inputs(args: argparse.Namespace) -> tuple[str, Path, dict, dict]:
    """Resolve the case ID, result directory, lease values and runtime manifest."""
    if args.standalone:
        if not args.case or not args.values:
            raise SystemExit("--standalone requires --case and --values")
        case_id = args.case
        document = load_document(args.values)
        values = document.get("values", document)
        runtime = load_document(args.runtime_manifest) if args.runtime_manifest else {}
        result_dir = Path(args.result_dir or tempfile.mkdtemp(prefix=f"{case_id}-"))
        return case_id, result_dir, values, runtime
    case_id = args.case or os.environ.get("DSTACK_TEST_CASE_ID", "")
    result_dir = Path(os.environ["DSTACK_TEST_RESULT_DIR"])
    manifest = json.loads(Path(os.environ["DSTACK_TEST_CASE_MANIFEST"]).read_text())
    runtime_path = os.environ.get("DSTACK_TEST_RUNTIME_MANIFEST", "")
    runtime = (
        json.loads(Path(runtime_path).read_text())
        if runtime_path and Path(runtime_path).is_file()
        else {}
    )
    return case_id, result_dir, manifest.get("values", {}), runtime


def main(argv: list[str] | None = None) -> int:
    """Execute one KMS key-hierarchy case."""
    args = parse_args(list(argv if argv is not None else sys.argv[1:]))
    if args.self_test:
        report = check_primitives()
        print(json.dumps(report, indent=2))
        return 0
    case_id, result_dir, values, runtime = resolve_inputs(args)
    spec = CASES.get(case_id)
    if spec is None:
        raise SystemExit(f"unsupported KMS key-hierarchy case: {case_id}")

    artifacts = result_dir / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    ctx = Context(case_id, values, runtime, artifacts)
    started = time.monotonic()
    status = "PASS"
    summary = ""
    failure = ""
    try:
        summary = spec["handler"](ctx)
    except Exception as error:  # noqa: BLE001 - case boundary
        status = "FAIL"
        failure = f"{type(error).__name__}: {error}"
        summary = failure
    finally:
        for action in reversed(ctx.cleanup):
            try:
                action()
            except Exception as error:  # noqa: BLE001 - cleanup must not mask
                print(f"EVIDENCE {case_id} - cleanup failed: {error}", flush=True)

    for number in range(len(ctx.steps) + 1, 4):
        ctx.steps.append(
            {
                "id": f"{case_id}-step-{number:02d}",
                "status": "NOT_RUN",
                "observed": "Not run after an earlier failure.",
            }
        )
    ctx.evidence["duration_seconds"] = round(time.monotonic() - started, 3)
    ctx.evidence["secret_material_persisted"] = False
    evidence_name = f"{case_id}.json"
    write_json(artifacts / evidence_name, ctx.evidence)
    artifact = {
        "path": f"artifacts/{evidence_name}",
        "step_id": f"{case_id}-step-02",
        "name": spec["artifact"],
        "description": (
            "Primitive self-test rows, public keys, signatures, hashes of derived "
            "secrets, and the per-row comparisons this case asserts."
        ),
    }
    entries = [artifact]
    log = artifacts / "restarted-kms.log"
    if log.is_file():
        entries.append(
            {
                "path": f"artifacts/{log.name}",
                "step_id": f"{case_id}-step-03",
                "name": "Replacement KMS log",
                "description": "Startup output of the KMS the case restarted.",
            }
        )
    write_json(artifacts / "manifest.json", {"artifacts": entries})
    result: dict[str, Any] = {
        "schema_version": "1.0",
        "case_id": case_id,
        "provisional": False,
        "status": status,
        "summary": summary,
        "steps": ctx.steps,
        "artifacts": entries,
        "remarks": REMARKS,
    }
    if failure:
        result["failure"] = failure
    write_json(result_dir / "result.json", result)
    print(json.dumps({"status": status, "summary": summary}), flush=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
