# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Local signature and signature-chain verification.

Verification needs no key material and no attestation, so it does not belong
behind an RPC to the guest agent: the agent's answer arrives over the socket
unattested, which is no better than a caller checking the signature itself. The
``Verify`` RPC these functions replace was removed in v0.6.0.

Two levels are available:

* :func:`verify_signature` checks one signature against a public key you
  already have. It is the direct replacement for the old RPC and, on its own,
  proves only that whoever holds that key signed the data.
* :func:`verify_signature_chain` walks the full chain from a ``SignResponse``
  back to a KMS root key **you supply**, which is what actually establishes
  that the signer was a dstack app under that KMS.
"""

from typing import Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from eth_keys import keys
from eth_utils import keccak

__all__ = ["verify_signature", "verify_signature_chain", "SIGN_PATH", "SIGN_PURPOSE"]

#: Domain-separation prefix the KMS signs app root keys under.
_KMS_ISSUED_PREFIX = b"dstack-kms-issued"
_SEPARATOR = b":"

#: ``Sign`` derives its key at this path with this purpose; both are fixed agent-side.
SIGN_PATH = "vms"
SIGN_PURPOSE = "signing"

#: Order of the secp256k1 group. Signatures with ``s`` above half of this are
#: the malleable "high-S" form.
_SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP256K1_HALF_ORDER = _SECP256K1_ORDER // 2


def _normalize_algorithm(algorithm: str) -> str:
    """``k256`` and ``secp256k1`` name the same thing; the agent normalized these too."""
    return "secp256k1" if algorithm == "k256" else algorithm


def _parse_k256_signature(signature: bytes) -> tuple[int, int]:
    """Split a raw 64-byte ``r || s`` signature, rejecting the high-S form.

    ECDSA is malleable: ``(r, n - s)`` verifies wherever ``(r, s)`` does. The
    Rust SDK's k256 backend rejects the high-S form, so we must too -- otherwise
    a signature stops being a unique identifier for a signed message, and this
    SDK would disagree with every other dstack component about whether a given
    blob is valid. ``cryptography`` accepts high-S happily, hence the explicit
    check here.
    """
    if len(signature) != 64:
        raise ValueError(
            f"secp256k1 signature must be 64 raw bytes (r || s), but received {len(signature)}"
        )
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if r == 0 or r >= _SECP256K1_ORDER or s == 0 or s >= _SECP256K1_ORDER:
        raise ValueError("invalid secp256k1 signature: r or s out of range")
    if s > _SECP256K1_HALF_ORDER:
        raise ValueError("non-canonical (high-S) secp256k1 signature")
    return r, s


def _load_k256_public_key(public_key: bytes) -> ec.EllipticCurvePublicKey:
    """Load a SEC1 secp256k1 key, compressed (33 bytes) or uncompressed (65)."""
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), public_key)
    except ValueError as exc:
        raise ValueError(f"invalid secp256k1 public key: {exc}") from exc


def _compress(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return public_key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)


def verify_signature(
    algorithm: str,
    data: bytes,
    signature: bytes,
    public_key: bytes,
) -> bool:
    """Verify one signature against ``public_key``.

    ``algorithm`` is ``ed25519``, ``secp256k1`` (alias ``k256``), or
    ``secp256k1_prehashed``, where ``data`` is already a 32-byte digest.

    Returns ``False`` when the inputs are well-formed but the signature does not
    check out, and raises when they are not well-formed at all (bad key
    encoding, wrong signature length, unknown algorithm) -- a malformed input is
    a caller bug, not a verdict.
    """
    normalized = _normalize_algorithm(algorithm)

    if normalized == "ed25519":
        if len(public_key) != 32:
            raise ValueError(
                f"ed25519 public key must be 32 bytes, but received {len(public_key)}"
            )
        if len(signature) != 64:
            raise ValueError(
                f"ed25519 signature must be 64 bytes, but received {len(signature)}"
            )
        try:
            ed_key = Ed25519PublicKey.from_public_bytes(public_key)
        except Exception as exc:  # noqa: BLE001 - re-raised as a caller-facing error
            raise ValueError(f"invalid ed25519 public key: {exc}") from exc
        try:
            ed_key.verify(signature, data)
            return True
        except InvalidSignature:
            return False

    if normalized in ("secp256k1", "secp256k1_prehashed"):
        prehashed = normalized == "secp256k1_prehashed"
        if prehashed and len(data) != 32:
            raise ValueError(
                "pre-hashed verification requires a 32-byte digest, "
                f"but received {len(data)} bytes"
            )
        k256_key = _load_k256_public_key(public_key)
        r, s = _parse_k256_signature(signature)
        # k256's `sign` hashes with SHA-256, so verification must too.
        algo = (
            ec.ECDSA(utils.Prehashed(hashes.SHA256()))
            if prehashed
            else ec.ECDSA(hashes.SHA256())
        )
        try:
            k256_key.verify(utils.encode_dss_signature(r, s), data, algo)
            return True
        except InvalidSignature:
            return False

    raise ValueError(f"unsupported algorithm: {algorithm}")


def _recover_compressed(message: bytes, signature: bytes) -> bytes:
    """Recover the public key behind a recoverable signature, compressed.

    The signature is 65 bytes, ``r || s || recid``, over ``keccak256(message)``.
    """
    if len(signature) != 65:
        raise ValueError(
            f"recoverable signature must be 65 bytes, but received {len(signature)}"
        )
    # Rejects high-S and out-of-range r/s before we hand anything to eth_keys.
    _parse_k256_signature(signature[:64])
    recid = signature[64]
    if recid > 3:
        raise ValueError(f"invalid recovery id {recid}")
    if recid > 1:
        # eth_keys only models v in {0, 1}; recid 2 and 3 mean r overflowed the
        # curve order, which dstack signers never produce. Say so plainly rather
        # than letting eth_keys fail with a validation error about `vrs`.
        raise ValueError(f"unsupported recovery id {recid}: only 0 and 1 are supported")
    try:
        recovered = keys.Signature(
            signature_bytes=signature
        ).recover_public_key_from_msg_hash(keccak(message))
    except Exception as exc:  # noqa: BLE001 - re-raised as a caller-facing error
        raise ValueError(f"failed to recover public key: {exc}") from exc
    return recovered.to_compressed_bytes()


def verify_signature_chain(
    algorithm: str,
    data: bytes,
    public_key: bytes,
    signature_chain: Sequence[bytes],
    app_id: bytes,
    kms_root_pubkey: bytes,
    purpose: str = SIGN_PURPOSE,
) -> bytes:
    """Verify a ``Sign`` signature chain end to end.

    Three links, all of which must hold:

    1. ``signature_chain[0]`` is a signature over ``data`` by ``public_key``.
    2. ``signature_chain[1]`` is the app root key attesting
       ``"{purpose}:{hex(public_key)}"``.
    3. ``signature_chain[2]`` is ``kms_root_pubkey`` attesting that app root key
       for ``app_id``.

    Link 3 is the one that matters. Without comparing against a KMS root key you
    independently trust, a chain is just three signatures an attacker could have
    produced with their own keys. Get that key from the ``DstackKms`` contract
    (``kmsInfo().k256Pubkey``) or pin it; reading it from the KMS you are
    verifying against proves nothing.

    ``app_id`` must likewise be the app id you *expect*, not merely whatever
    ``AppInfo`` echoed back -- that comes from the CVM being checked. Comparing a
    chain against an app id the same CVM supplied proves only that it is
    self-consistent.

    Returns the app root public key (compressed SEC1, 33 bytes) on success, and
    raises on any failure.
    """
    if len(signature_chain) != 3:
        raise ValueError(
            f"signature chain must have 3 elements, but received {len(signature_chain)}"
        )
    if len(app_id) != 20:
        raise ValueError(f"app_id must be 20 bytes, but received {len(app_id)}")

    # Link 1: the payload signature. chain[0] *is* that signature; what matters
    # is that it checks out under `public_key`, which links 2 and 3 then cover.
    if not verify_signature(algorithm, data, signature_chain[0], public_key):
        raise ValueError("payload signature is not valid for the given public key")

    # Link 2: recover the app root key that vouched for the signing key.
    message = f"{purpose}:{public_key.hex()}".encode()
    app_root_pubkey = _recover_compressed(message, signature_chain[1])

    # Link 3: recover the KMS root key that vouched for the app root key, and
    # check it is the one we were told to trust.
    kms_message = _KMS_ISSUED_PREFIX + _SEPARATOR + app_id + app_root_pubkey
    recovered_kms = _recover_compressed(kms_message, signature_chain[2])

    # Normalize the expected key so callers may pass either SEC1 encoding.
    try:
        expected_kms = _compress(_load_k256_public_key(kms_root_pubkey))
    except ValueError as exc:
        raise ValueError(f"invalid KMS root public key: {exc}") from exc
    if recovered_kms != expected_kms:
        raise ValueError("signature chain is not anchored at the expected KMS root key")

    return app_root_pubkey
