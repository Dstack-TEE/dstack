# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import warnings

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


def test_to_account_with_tls_key():
    """Test to_account with TLS key response (should show warning)."""
    from dstack_sdk import GetTlsKeyResponse

    # Use mock TLS key response instead of actual server call
    mock_result = GetTlsKeyResponse(
        key="""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKONKWRjMvhgxHDmr
SY7zfjPHe3Qp8vCO9HqjzjqhXNKhRANCAAT5XHKyj7JRGHl2nQ2SltGKjQ3A7MPJ
/7JDkUxMNYhTxKqYdJZ6l1C8XrjKc7SFsVJhYgdJjLzQ3xKJz6l5jKzQ
-----END PRIVATE KEY-----""",
        certificate_chain=["cert1", "cert2"],
    )

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        account = to_account(mock_result)

        assert isinstance(account, LocalAccount)
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "Please don't use getTlsKey method" in str(w[0].message)


def test_to_account_secure_with_tls_key():
    """Test to_account_secure with TLS key response (should show warning)."""
    from dstack_sdk import GetTlsKeyResponse

    # Use mock TLS key response instead of actual server call
    mock_result = GetTlsKeyResponse(
        key="""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgKONKWRjMvhgxHDmr
SY7zfjPHe3Qp8vCO9HqjzjqhXNKhRANCAAT5XHKyj7JRGHl2nQ2SltGKjQ3A7MPJ
/7JDkUxMNYhTxKqYdJZ6l1C8XrjKc7SFsVJhYgdJjLzQ3xKJz6l5jKzQ
-----END PRIVATE KEY-----""",
        certificate_chain=["cert1", "cert2"],
    )

    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        account = to_account_secure(mock_result)

        assert isinstance(account, LocalAccount)
        assert len(w) == 1
        assert issubclass(w[0].category, DeprecationWarning)
        assert "Please don't use getTlsKey method" in str(w[0].message)
