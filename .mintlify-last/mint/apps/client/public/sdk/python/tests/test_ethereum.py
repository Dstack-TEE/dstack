import pytest
from eth_account.signers.local import LocalAccount

from dstack_sdk import AsyncDstackClient, GetKeyResponse
from dstack_sdk.ethereum import to_account

@pytest.mark.asyncio
async def test_async_to_keypair():
    client = AsyncDstackClient()
    result = await client.get_key('test')
    assert isinstance(result, GetKeyResponse)
    account = to_account(result)
    assert isinstance(account, LocalAccount)