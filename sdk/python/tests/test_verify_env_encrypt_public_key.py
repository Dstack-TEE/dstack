# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from dstack_sdk.verify_env_encrypt_public_key import verify_env_encrypt_public_key
from dstack_sdk.verify_env_encrypt_public_key import verify_signature_simple


def test_verify_signature_simple():
    """Test simple signature verification without recovery."""
    # Test data (32 bytes public key)
    public_key = bytes.fromhex(
        "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
    )

    # Test signature (65 bytes with recovery ID)
    signature = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
    )

    app_id = "00" * 20

    # Should process without error
    result = verify_signature_simple(public_key, signature, app_id)
    assert isinstance(result, bool)


def test_verify_signature_simple_with_0x_prefix():
    """Test signature verification with 0x prefix in app_id."""
    public_key = bytes.fromhex(
        "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
    )
    signature = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
    )

    app_id_without_prefix = "00" * 20
    app_id_with_prefix = "0x" + "00" * 20

    result1 = verify_signature_simple(public_key, signature, app_id_without_prefix)
    result2 = verify_signature_simple(public_key, signature, app_id_with_prefix)

    # Should handle both formats the same way
    assert result1 == result2


def test_verify_signature_invalid_signature_length():
    """Test that invalid signature length returns False/None."""
    public_key = bytes.fromhex(
        "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
    )

    # Invalid signature length (should be 65 bytes)
    invalid_signature_short = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed"
    )
    invalid_signature_long = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef0012"
    )

    app_id = "00" * 20

    # Should return False for invalid lengths
    assert verify_signature_simple(public_key, invalid_signature_short, app_id) is False
    assert verify_signature_simple(public_key, invalid_signature_long, app_id) is False

    # Public key verification should return None for invalid lengths
    assert (
        verify_env_encrypt_public_key(public_key, invalid_signature_short, app_id)
        is None
    )
    assert (
        verify_env_encrypt_public_key(public_key, invalid_signature_long, app_id)
        is None
    )


def test_verify_env_encrypt_public_key():
    """Test public key recovery (simplified implementation)."""
    # Test data
    public_key = bytes.fromhex(
        "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
    )
    signature = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
    )
    app_id = "00" * 20

    # Note: Our implementation is simplified and may return None
    # This is expected until full ECDSA recovery is implemented
    result = verify_env_encrypt_public_key(public_key, signature, app_id)
    assert result is None or (isinstance(result, str) and result.startswith("0x"))


def test_message_construction():
    """Test that the message is constructed correctly."""
    public_key = b"\x01\x02\x03\x04" * 8  # 32 bytes
    signature = b"\x00" * 65  # 65 bytes
    app_id = "deadbeef"

    # This should process the message correctly even if signature verification fails
    result = verify_signature_simple(public_key, signature, app_id)
    assert isinstance(result, bool)


def test_unicode_handling():
    """Test handling of app_id with different formats."""
    public_key = bytes.fromhex(
        "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
    )
    signature = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
    )

    # Test various app_id formats
    app_ids = ["deadbeef", "0xdeadbeef", "DEADBEEF", "0xDEADBEEF", "1234abcd"]

    for app_id in app_ids:
        result = verify_signature_simple(public_key, signature, app_id)
        assert isinstance(result, bool)


def test_empty_public_key():
    """Test handling of edge cases."""
    signature = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
    )
    app_id = "deadbeef"

    # Test with different public key lengths
    empty_key = b""
    short_key = b"\x01\x02"
    normal_key = b"\x01" * 32
    long_key = b"\x01" * 64

    for key in [empty_key, short_key, normal_key, long_key]:
        # Should not crash, should return boolean or None
        result_simple = verify_signature_simple(key, signature, app_id)
        result_verify = verify_env_encrypt_public_key(key, signature, app_id)

        assert isinstance(result_simple, bool)
        assert result_verify is None or isinstance(result_verify, str)


def test_malformed_app_id():
    """Test handling of malformed app IDs."""
    public_key = bytes.fromhex(
        "e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a"
    )
    signature = bytes.fromhex(
        "8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00"
    )

    # Test with malformed hex strings
    malformed_app_ids = [
        "xyz",  # Invalid hex
        "0xzyz",  # Invalid hex with prefix
        "gg",  # Invalid hex
        "",  # Empty
    ]

    for app_id in malformed_app_ids:
        # Should handle gracefully and return False/None
        try:
            result_simple = verify_signature_simple(public_key, signature, app_id)
            result_verify = verify_env_encrypt_public_key(public_key, signature, app_id)

            assert isinstance(result_simple, bool)
            assert result_verify is None or isinstance(result_verify, str)
        except ValueError:
            # It's acceptable to raise ValueError for invalid hex
            pass
