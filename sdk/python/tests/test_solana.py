# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import warnings

import pytest
from solders.keypair import Keypair

from dstack_sdk import AsyncDstackClient
from dstack_sdk import DstackClient
from dstack_sdk import GetKeyResponse
from dstack_sdk.solana import to_keypair
from dstack_sdk.solana import to_keypair_secure


@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncDstackClient()
    result = await client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    keypair = to_keypair(result)
    assert isinstance(keypair, Keypair)


def test_sync_to_keypair():
    client = DstackClient()
    result = client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    keypair = to_keypair(result)
    assert isinstance(keypair, Keypair)


@pytest.mark.asyncio
async def test_async_to_keypair_secure():
    client = AsyncDstackClient()
    result = await client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    keypair = to_keypair_secure(result)
    assert isinstance(keypair, Keypair)


def test_sync_to_keypair_secure():
    client = DstackClient()
    result = client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    keypair = to_keypair_secure(result)
    assert isinstance(keypair, Keypair)


def test_to_keypair_with_tls_key():
    """Test to_keypair with TLS key response (should show warning)."""
    client = DstackClient()
    result = client.get_tls_key()

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        keypair = to_keypair(result)

        assert isinstance(keypair, Keypair)
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "Please don't use getTlsKey method" in str(w[0].message)


def test_to_keypair_secure_with_tls_key():
    """Test to_keypair_secure with TLS key response (should show warning)."""
    client = DstackClient()
    result = client.get_tls_key()

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        keypair = to_keypair_secure(result)

        assert isinstance(keypair, Keypair)
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "Please don't use getTlsKey method" in str(w[0].message)


def test_to_keypair_secure_hashes_full_key_material_for_get_key_response():
    """Regression: the GetKeyResponse branch previously fell through unhashed,
    silently contradicting the "SHA256 of full key material" docstring."""
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )

    legacy_keypair = to_keypair(mock_result)
    secure_keypair = to_keypair_secure(mock_result)

    assert bytes(secure_keypair.pubkey()) != bytes(legacy_keypair.pubkey())
