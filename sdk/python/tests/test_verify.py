# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Drives the shared cross-SDK vectors in ``sdk/tests/vectors/signature_chain.json``.

The Rust, Go and JavaScript suites assert against the same file, so any port that
disagrees about the byte format fails here too.
"""

import json
from pathlib import Path

import pytest

from dstack_sdk import verify_signature
from dstack_sdk import verify_signature_chain
from dstack_sdk.verify import SIGN_PURPOSE

VECTORS_PATH = (
    Path(__file__).resolve().parents[2] / "tests" / "vectors" / "signature_chain.json"
)


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text())


VECTORS = _vectors()
CASES = VECTORS["cases"]
INVALID_CASES = VECTORS["invalid_cases"]
APP_ID = bytes.fromhex(VECTORS["app_id"])
KMS_ROOT = bytes.fromhex(VECTORS["kms_root_pubkey"])
WRONG_KMS_ROOT = bytes.fromhex(VECTORS["wrong_kms_root_pubkey"])
APP_ROOT = bytes.fromhex(VECTORS["app_root_pubkey"])


def _case(algorithm: str) -> dict:
    return next(c for c in CASES if c["algorithm"] == algorithm)


def _chain(case: dict) -> list[bytes]:
    return [bytes.fromhex(sig) for sig in case["signature_chain"]]


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["algorithm"])
def test_valid_signatures_verify(case):
    assert (
        verify_signature(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["signature"]),
            bytes.fromhex(case["public_key"]),
        )
        is True
    )


@pytest.mark.parametrize("case", INVALID_CASES, ids=lambda c: c["name"])
def test_invalid_signatures_are_rejected(case):
    args = (
        case["algorithm"],
        bytes.fromhex(case["data"]),
        bytes.fromhex(case["signature"]),
        bytes.fromhex(case["public_key"]),
    )
    if case["name"] == "secp256k1_high_s":
        # High-S is refused outright rather than reported false, because it is a
        # malformed encoding rather than a legitimate signature that fails to match.
        with pytest.raises(ValueError, match="high-S"):
            verify_signature(*args)
    else:
        assert verify_signature(*args) is False


def test_k256_is_an_alias_for_secp256k1():
    case = _case("secp256k1")
    assert (
        verify_signature(
            "k256",
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["signature"]),
            bytes.fromhex(case["public_key"]),
        )
        is True
    )


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["algorithm"])
def test_full_chain_verifies_to_the_kms_root(case):
    app_root = verify_signature_chain(
        case["algorithm"],
        bytes.fromhex(case["data"]),
        bytes.fromhex(case["public_key"]),
        _chain(case),
        APP_ID,
        KMS_ROOT,
    )
    assert app_root == APP_ROOT
    assert len(app_root) == 33


def test_chain_accepts_an_uncompressed_kms_root():
    """Callers may pass either SEC1 encoding of the key they pinned."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import PublicFormat

    uncompressed = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), KMS_ROOT
    ).public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    assert len(uncompressed) == 65

    case = CASES[0]
    assert (
        verify_signature_chain(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["public_key"]),
            _chain(case),
            APP_ID,
            uncompressed,
        )
        == APP_ROOT
    )


def test_chain_anchored_at_a_foreign_kms_root_is_rejected():
    case = CASES[0]
    with pytest.raises(ValueError, match="not anchored"):
        verify_signature_chain(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["public_key"]),
            _chain(case),
            APP_ID,
            WRONG_KMS_ROOT,
        )


def test_chain_for_a_different_app_id_is_rejected():
    case = CASES[0]
    tampered_app_id = bytes([APP_ID[0] ^ 0xFF]) + APP_ID[1:]
    with pytest.raises(ValueError):
        verify_signature_chain(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["public_key"]),
            _chain(case),
            tampered_app_id,
            KMS_ROOT,
        )


def test_tampered_payload_breaks_the_chain():
    case = CASES[0]
    with pytest.raises(ValueError):
        verify_signature_chain(
            case["algorithm"],
            b"a different payload entirely",
            bytes.fromhex(case["public_key"]),
            _chain(case),
            APP_ID,
            KMS_ROOT,
        )


def test_tampered_public_key_breaks_the_chain():
    """Swapping the signing key invalidates link 1 and the app-root link's message."""
    case = _case("secp256k1")
    public_key = bytearray(bytes.fromhex(case["public_key"]))
    public_key[-1] ^= 0xFF
    with pytest.raises(ValueError):
        verify_signature_chain(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes(public_key),
            _chain(case),
            APP_ID,
            KMS_ROOT,
        )


def test_chain_requires_three_links():
    case = CASES[0]
    with pytest.raises(ValueError, match="3 elements"):
        verify_signature_chain(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["public_key"]),
            _chain(case)[:2],
            APP_ID,
            KMS_ROOT,
        )


def test_chain_requires_a_20_byte_app_id():
    case = CASES[0]
    with pytest.raises(ValueError, match="20 bytes"):
        verify_signature_chain(
            case["algorithm"],
            bytes.fromhex(case["data"]),
            bytes.fromhex(case["public_key"]),
            _chain(case),
            APP_ID[:19],
            KMS_ROOT,
        )


def test_malformed_inputs_error_rather_than_report_false():
    with pytest.raises(ValueError):
        verify_signature("rsa", b"x", bytes(64), bytes(32))
    with pytest.raises(ValueError):
        verify_signature("ed25519", b"x", bytes(64), bytes(31))
    with pytest.raises(ValueError):
        verify_signature("ed25519", b"x", bytes(63), bytes(32))
    # A prehashed digest must be exactly 32 bytes.
    case = _case("secp256k1_prehashed")
    with pytest.raises(ValueError, match="32-byte digest"):
        verify_signature(
            "secp256k1_prehashed",
            b"short",
            bytes.fromhex(case["signature"]),
            bytes.fromhex(case["public_key"]),
        )
    # A raw r || s signature is 64 bytes; DER or truncated blobs are caller bugs.
    secp = _case("secp256k1")
    with pytest.raises(ValueError, match="64 raw bytes"):
        verify_signature(
            "secp256k1",
            bytes.fromhex(secp["data"]),
            bytes.fromhex(secp["signature"])[:63],
            bytes.fromhex(secp["public_key"]),
        )
    with pytest.raises(ValueError, match="public key"):
        verify_signature(
            "secp256k1",
            bytes.fromhex(secp["data"]),
            bytes.fromhex(secp["signature"]),
            bytes(33),
        )


def test_sign_purpose_is_the_agent_side_constant():
    assert SIGN_PURPOSE == "signing"
    assert VECTORS["purpose"] == SIGN_PURPOSE
