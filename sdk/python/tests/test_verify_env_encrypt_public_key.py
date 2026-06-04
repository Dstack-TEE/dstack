# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import time
import warnings

from eth_keys import keys
from eth_utils import keccak
import pytest

from dstack_sdk import verify_env_encrypt_public_key
from dstack_sdk import verify_env_encrypt_public_key_legacy

# Known-good legacy fixture lifted from vmm-cli verify_signature docstring.
LEGACY_PUBLIC_KEY = bytes.fromhex(
    "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
)
LEGACY_SIGNATURE = bytes.fromhex(
    "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed"
    "7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
)
LEGACY_APP_ID = "00" * 20
LEGACY_EXPECTED_SIGNER = (
    "0x0217610d74cbd39b6143842c6d8bc310d79da1d82cc9d17f8876376221eda0c38f"
)


def _sign_v1(
    private_key: keys.PrivateKey,
    public_key_bytes: bytes,
    app_id_hex: str,
    timestamp: int,
) -> bytes:
    """Build the v1 message exactly the way KMS does and sign it."""
    message = (
        b"dstack-env-encrypt-pubkey"
        + b":"
        + bytes.fromhex(app_id_hex)
        + timestamp.to_bytes(8, "big")
        + public_key_bytes
    )
    return private_key.sign_msg_hash(keccak(message)).to_bytes()


def test_legacy_recovery_matches_known_signer():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        recovered = verify_env_encrypt_public_key_legacy(
            LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE, LEGACY_APP_ID
        )
    assert recovered == LEGACY_EXPECTED_SIGNER


def test_legacy_recovery_strips_0x_prefix():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with_prefix = verify_env_encrypt_public_key_legacy(
            LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE, "0x" + LEGACY_APP_ID
        )
        without_prefix = verify_env_encrypt_public_key_legacy(
            LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE, LEGACY_APP_ID
        )
    assert with_prefix == without_prefix == LEGACY_EXPECTED_SIGNER


def test_legacy_emits_deprecation_warning():
    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        verify_env_encrypt_public_key_legacy(
            LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE, LEGACY_APP_ID
        )
    assert any(
        issubclass(w.category, DeprecationWarning)
        and "verify_env_encrypt_public_key_legacy" in str(w.message)
        for w in captured
    )


def test_legacy_rejects_invalid_signature_length():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        too_short = verify_env_encrypt_public_key_legacy(
            LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE[:64], LEGACY_APP_ID
        )
        too_long = verify_env_encrypt_public_key_legacy(
            LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE + b"\x00", LEGACY_APP_ID
        )
    assert too_short is None
    assert too_long is None


def test_legacy_rejects_malformed_app_id():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert (
            verify_env_encrypt_public_key_legacy(
                LEGACY_PUBLIC_KEY, LEGACY_SIGNATURE, "not-hex"
            )
            is None
        )


def test_v1_recovers_signer_for_round_trip_signature():
    signer = keys.PrivateKey(b"\x01" * 32)
    app_id = "ab" * 20
    public_key = b"\xde" * 32
    timestamp = int(time.time())
    signature = _sign_v1(signer, public_key, app_id, timestamp)

    recovered = verify_env_encrypt_public_key(public_key, signature, app_id, timestamp)
    assert recovered == "0x" + signer.public_key.to_compressed_bytes().hex()


def test_v1_rejects_expired_timestamp():
    signer = keys.PrivateKey(b"\x02" * 32)
    app_id = "cd" * 20
    public_key = b"\xab" * 32
    timestamp = int(time.time()) - 10_000  # well beyond the 300s default
    signature = _sign_v1(signer, public_key, app_id, timestamp)

    assert (
        verify_env_encrypt_public_key(public_key, signature, app_id, timestamp) is None
    )


def test_v1_rejects_future_timestamp_beyond_skew():
    signer = keys.PrivateKey(b"\x03" * 32)
    app_id = "ef" * 20
    public_key = b"\xcc" * 32
    timestamp = int(time.time()) + 600  # outside the 60s future skew tolerance
    signature = _sign_v1(signer, public_key, app_id, timestamp)

    assert (
        verify_env_encrypt_public_key(public_key, signature, app_id, timestamp) is None
    )


def test_v1_accepts_small_future_skew():
    signer = keys.PrivateKey(b"\x04" * 32)
    app_id = "01" * 20
    public_key = b"\x11" * 32
    timestamp = int(time.time()) + 30  # within the 60s tolerance
    signature = _sign_v1(signer, public_key, app_id, timestamp)

    recovered = verify_env_encrypt_public_key(public_key, signature, app_id, timestamp)
    assert recovered == "0x" + signer.public_key.to_compressed_bytes().hex()


def test_v1_respects_custom_max_age():
    signer = keys.PrivateKey(b"\x05" * 32)
    app_id = "02" * 20
    public_key = b"\x22" * 32
    timestamp = int(time.time()) - 400  # past default but within max_age=1000
    signature = _sign_v1(signer, public_key, app_id, timestamp)

    assert (
        verify_env_encrypt_public_key(public_key, signature, app_id, timestamp) is None
    )
    recovered = verify_env_encrypt_public_key(
        public_key, signature, app_id, timestamp, max_age_seconds=1000
    )
    assert recovered == "0x" + signer.public_key.to_compressed_bytes().hex()


@pytest.mark.parametrize("bad_sig_len", [0, 32, 64, 66, 128])
def test_v1_rejects_wrong_signature_length(bad_sig_len):
    assert (
        verify_env_encrypt_public_key(
            b"\x00" * 32, b"\x00" * bad_sig_len, "00" * 20, int(time.time())
        )
        is None
    )


def test_v1_rejects_malformed_app_id():
    signer = keys.PrivateKey(b"\x06" * 32)
    public_key = b"\x33" * 32
    timestamp = int(time.time())
    # Sign with the well-formed app_id but verify with a malformed one.
    signature = _sign_v1(signer, public_key, "ab" * 20, timestamp)
    assert (
        verify_env_encrypt_public_key(public_key, signature, "not-hex", timestamp)
        is None
    )


def test_v1_returns_none_on_tampered_signature():
    signer = keys.PrivateKey(b"\x07" * 32)
    app_id = "03" * 20
    public_key = b"\x44" * 32
    timestamp = int(time.time())
    signature = bytearray(_sign_v1(signer, public_key, app_id, timestamp))
    signature[0] ^= 0xFF
    # A flipped byte may either recover a wrong signer or fail outright; either
    # way it must not match the genuine signer.
    recovered = verify_env_encrypt_public_key(
        public_key, bytes(signature), app_id, timestamp
    )
    assert recovered != "0x" + signer.public_key.to_compressed_bytes().hex()
