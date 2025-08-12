# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import pytest
from eth_account.signers.local import LocalAccount

from dstack_sdk import AsyncDstackClient
from dstack_sdk import DstackClient
from dstack_sdk import GetKeyResponse
from dstack_sdk.ethereum import to_account
from dstack_sdk.ethereum import to_account_secure


@pytest.mark.asyncio
async def test_async_to_account():
    client = AsyncDstackClient()
    result = await client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    account = to_account(result)
    assert isinstance(account, LocalAccount)


def test_sync_to_account():
    client = DstackClient()
    result = client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    account = to_account(result)
    assert isinstance(account, LocalAccount)


@pytest.mark.asyncio
async def test_async_to_account_secure():
    client = AsyncDstackClient()
    result = await client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    account = to_account_secure(result)
    assert isinstance(account, LocalAccount)


def test_sync_to_account_secure():
    client = DstackClient()
    result = client.get_key("test")
    assert isinstance(result, GetKeyResponse)
    account = to_account_secure(result)
    assert isinstance(account, LocalAccount)


def test_to_account_with_tls_key():
    """Test to_account with TLS key response (should show warning)."""
    client = DstackClient()
    result = client.get_tls_key()

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        account = to_account(result)

        assert isinstance(account, LocalAccount)
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "Please don't use getTlsKey method" in str(w[0].message)


def test_to_account_secure_with_tls_key():
    """Test to_account_secure with TLS key response (should show warning)."""
    client = DstackClient()
    result = client.get_tls_key()

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        account = to_account_secure(result)

        assert isinstance(account, LocalAccount)
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "Please don't use getTlsKey method" in str(w[0].message)
