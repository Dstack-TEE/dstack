# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
"""Root epoch chain hashes, as KMS authorization backends register them."""

from __future__ import annotations

from typing import Any

from Crypto.Hash import keccak
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def epoch0_chain_hash(meta: dict[str, Any]) -> str:
    """The root epoch 0 chain hash of the keys a KMS's GetMeta publishes."""
    cert = x509.load_pem_x509_certificate(str(meta["ca_cert"]).encode())
    ca = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    k256 = bytes.fromhex(str(meta["k256_pubkey"]))
    return "0x" + keccak256(bytes(32) + keccak256(ca) + keccak256(k256)).hex()
