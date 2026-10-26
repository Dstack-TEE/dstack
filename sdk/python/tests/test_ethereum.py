# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from eth_account.signers.local import LocalAccount
import pytest

from dstack_sdk import GetKeyResponse
from dstack_sdk.ethereum import to_account
from dstack_sdk.ethereum import to_account_secure


@pytest.mark.asyncio
async def test_async_to_account():
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account(mock_result)
    assert isinstance(account, LocalAccount)


def test_sync_to_account():
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account(mock_result)
    assert isinstance(account, LocalAccount)


@pytest.mark.asyncio
async def test_async_to_account_secure():
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account_secure(mock_result)
    assert isinstance(account, LocalAccount)


def test_sync_to_account_secure():
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account_secure(mock_result)
    assert isinstance(account, LocalAccount)


@pytest.mark.parametrize("adapter", [to_account, to_account_secure])
def test_account_adapters_reject_tls_keys(adapter):
    from dstack_sdk import GetTlsKeyResponse

    response = GetTlsKeyResponse(key="not used", certificate_chain=[])
    with pytest.raises(TypeError, match="TLS keys cannot be used"):
        adapter(response)  # type: ignore[arg-type]
