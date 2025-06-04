import pytest
import hashlib
from solders.keypair import Keypair

from dstack_sdk import AsyncTappdClient, DeriveKeyResponse
from dstack_sdk.solana import to_keypair, to_keypair_secure

@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    assert isinstance(result, DeriveKeyResponse)
    keypair = to_keypair(result)
    assert isinstance(keypair, Keypair)

@pytest.mark.asyncio
async def test_async_to_keypair_secure():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    assert isinstance(result, DeriveKeyResponse)
    keypair = to_keypair_secure(result)
    assert isinstance(keypair, Keypair)

@pytest.mark.asyncio
async def test_deprecated_vs_secure_api_differences():
    """Test that deprecated and secure APIs generate different keys"""
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    
    deprecated_keypair = to_keypair(result)
    secure_keypair = to_keypair_secure(result)
    
    # Should generate different keys
    assert deprecated_keypair.pubkey() != secure_keypair.pubkey()
    
    # Verify deprecated API uses first 32 bytes
    first_32_bytes = result.toBytes(32)
    expected_deprecated = Keypair.from_seed(first_32_bytes)
    assert deprecated_keypair.pubkey() == expected_deprecated.pubkey()
    
    # Verify secure API uses SHA256 of complete key material
    hashed = hashlib.sha256(result.toBytes()).digest()
    expected_secure = Keypair.from_seed(hashed)
    assert secure_keypair.pubkey() == expected_secure.pubkey()