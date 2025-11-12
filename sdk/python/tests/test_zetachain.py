# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import warnings

from eth_account.signers.local import LocalAccount
import pytest

from dstack_sdk import GetKeyResponse
from dstack_sdk.zetachain import to_account
from dstack_sdk.zetachain import to_account_secure


@pytest.mark.asyncio
async def test_async_to_account():
    """Test async to_account with ZetaChain."""
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account(mock_result)
    assert isinstance(account, LocalAccount)
    # Verify it's a valid Ethereum-compatible address (0x + 40 hex chars)
    assert account.address.startswith("0x")
    assert len(account.address) == 42


def test_sync_to_account():
    """Test sync to_account with ZetaChain."""
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account(mock_result)
    assert isinstance(account, LocalAccount)
    # Verify it's a valid Ethereum-compatible address
    assert account.address.startswith("0x")
    assert len(account.address) == 42


@pytest.mark.asyncio
async def test_async_to_account_secure():
    """Test async to_account_secure with ZetaChain."""
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account_secure(mock_result)
    assert isinstance(account, LocalAccount)
    # Verify it's a valid Ethereum-compatible address
    assert account.address.startswith("0x")
    assert len(account.address) == 42


def test_sync_to_account_secure():
    """Test sync to_account_secure with ZetaChain."""
    # Use mock GetKeyResponse instead of actual server call
    mock_result = GetKeyResponse(
        key="1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        signature_chain=["sig1", "sig2"],
    )
    assert isinstance(mock_result, GetKeyResponse)
    account = to_account_secure(mock_result)
    assert isinstance(account, LocalAccount)
    # Verify it's a valid Ethereum-compatible address
    assert account.address.startswith("0x")
    assert len(account.address) == 42


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


def test_deterministic_keys():
    """Test that same key input produces same ZetaChain account."""
    # Same key should produce same account
    key_hex = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"

    mock_result1 = GetKeyResponse(
        key=key_hex,
        signature_chain=["sig1"],
    )
    mock_result2 = GetKeyResponse(
        key=key_hex,
        signature_chain=["sig1"],
    )

    account1 = to_account_secure(mock_result1)
    account2 = to_account_secure(mock_result2)

    # Same key should produce same address
    assert account1.address == account2.address


def test_different_keys_produce_different_accounts():
    """Test that different keys produce different ZetaChain accounts."""
    mock_result1 = GetKeyResponse(
        key="1111111111111111111111111111111111111111111111111111111111111111",
        signature_chain=["sig1"],
    )
    mock_result2 = GetKeyResponse(
        key="2222222222222222222222222222222222222222222222222222222222222222",
        signature_chain=["sig1"],
    )

    account1 = to_account_secure(mock_result1)
    account2 = to_account_secure(mock_result2)

    # Different keys should produce different addresses
    assert account1.address != account2.address
