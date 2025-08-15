# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import pytest

from dstack_sdk.encrypt_env_vars import EnvVar
from dstack_sdk.encrypt_env_vars import encrypt_env_vars
from dstack_sdk.encrypt_env_vars import encrypt_env_vars_sync


def test_encrypt_env_vars_sync():
    """Test synchronous environment variable encryption."""
    # Test data
    envs = [
        EnvVar(key="NODE_ENV", value="production"),
        EnvVar(key="API_KEY", value="secret123"),
        EnvVar(key="DATABASE_URL", value="postgres://localhost:5432/mydb"),
    ]

    # Mock public key (32 bytes hex)
    public_key_hex = "deadbeef" * 8

    # Test encryption
    encrypted_hex = encrypt_env_vars_sync(envs, public_key_hex)

    # Verify output
    assert isinstance(encrypted_hex, str)
    assert len(encrypted_hex) > 0
    assert len(encrypted_hex) % 2 == 0  # Should be valid hex

    # Should be able to decode as hex
    encrypted_bytes = bytes.fromhex(encrypted_hex)

    # Should contain: 32 bytes public key + 12 bytes IV + encrypted data
    assert len(encrypted_bytes) >= 44  # At least 32 + 12 bytes


@pytest.mark.asyncio
async def test_encrypt_env_vars_async():
    """Test asynchronous environment variable encryption."""
    # Test data
    envs = [
        EnvVar(key="NODE_ENV", value="production"),
        EnvVar(key="API_KEY", value="secret123"),
    ]

    # Mock public key (32 bytes hex)
    public_key_hex = "0x" + "deadbeef" * 8

    # Test encryption
    encrypted_hex = await encrypt_env_vars(envs, public_key_hex)

    # Verify output
    assert isinstance(encrypted_hex, str)
    assert len(encrypted_hex) > 0
    assert len(encrypted_hex) % 2 == 0  # Should be valid hex


def test_encrypt_env_vars_empty():
    """Test encryption with empty environment variables."""
    envs = []
    public_key_hex = "deadbeef" * 8

    encrypted_hex = encrypt_env_vars_sync(envs, public_key_hex)
    assert isinstance(encrypted_hex, str)
    assert len(encrypted_hex) > 0


def test_encrypt_env_vars_single():
    """Test encryption with single environment variable."""
    envs = [EnvVar(key="TEST", value="value")]
    public_key_hex = "deadbeef" * 8

    encrypted_hex = encrypt_env_vars_sync(envs, public_key_hex)
    assert isinstance(encrypted_hex, str)
    assert len(encrypted_hex) > 0


def test_encrypt_env_vars_different_keys():
    """Test that different public keys produce different results."""
    envs = [EnvVar(key="TEST", value="value")]

    public_key1 = "deadbeef" * 8
    public_key2 = "abcdef01" * 8

    encrypted1 = encrypt_env_vars_sync(envs, public_key1)
    encrypted2 = encrypt_env_vars_sync(envs, public_key2)

    # Should be different due to different public keys
    assert encrypted1 != encrypted2


def test_env_var_namedtuple():
    """Test EnvVar namedtuple properties."""
    env = EnvVar(key="TEST_KEY", value="test_value")

    assert env.key == "TEST_KEY"
    assert env.value == "test_value"
    assert isinstance(env, tuple)


def test_encrypt_env_vars_unicode():
    """Test encryption with Unicode values."""
    envs = [
        EnvVar(key="MESSAGE", value="Hello 世界 🌍"),
        EnvVar(key="EMOJI", value="🚀🎉💻"),
    ]

    public_key_hex = "deadbeef" * 8
    encrypted_hex = encrypt_env_vars_sync(envs, public_key_hex)

    assert isinstance(encrypted_hex, str)
    assert len(encrypted_hex) > 0
