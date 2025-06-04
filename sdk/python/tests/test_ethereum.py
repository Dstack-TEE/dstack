import pytest
import hashlib
from eth_account.signers.local import LocalAccount
from eth_account import Account

from dstack_sdk import AsyncTappdClient, DeriveKeyResponse
from dstack_sdk.ethereum import to_account, to_account_secure

@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    assert isinstance(result, DeriveKeyResponse)
    account = to_account(result)
    assert isinstance(account, LocalAccount)

@pytest.mark.asyncio
async def test_async_to_account_secure():
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    assert isinstance(result, DeriveKeyResponse)
    account = to_account_secure(result)
    assert isinstance(account, LocalAccount)

@pytest.mark.asyncio
async def test_deprecated_vs_secure_api_differences():
    """Test that deprecated and secure APIs generate different accounts"""
    client = AsyncTappdClient()
    result = await client.derive_key('test')
    
    deprecated_account = to_account(result)
    secure_account = to_account_secure(result)
    
    # Should generate different accounts
    assert deprecated_account.address != secure_account.address
    
    # Verify deprecated API uses first 32 bytes
    first_32_bytes = result.toBytes(32)
    expected_deprecated = Account.from_key(first_32_bytes)
    assert deprecated_account.address == expected_deprecated.address
    
    # Verify secure API uses SHA256 of complete key material
    hashed = hashlib.sha256(result.toBytes()).digest()
    expected_secure = Account.from_key(hashed)
    assert secure_account.address == expected_secure.address