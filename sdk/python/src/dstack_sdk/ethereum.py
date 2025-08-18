# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Ethereum helpers for deriving accounts from dstack keys.

Use with ``dstack_sdk.DstackClient`` responses to create ``eth_account``
objects for signing and transacting.
"""

import hashlib
import warnings

from eth_account import Account
from eth_account.signers.local import LocalAccount

from .dstack_client import GetKeyResponse
from .dstack_client import GetTlsKeyResponse


def to_account(get_key_response: GetKeyResponse | GetTlsKeyResponse) -> LocalAccount:
    """Create an Ethereum account from DstackClient key response.

    DEPRECATED: Use to_account_secure instead. This method has security concerns.
    Current implementation uses raw key material without proper hashing.

    Args:
        get_key_response: Response from get_key() or get_tls_key()

    Returns:
        Account: Ethereum account object

    """
    if isinstance(get_key_response, GetTlsKeyResponse):
        warnings.warn(
            "to_account: Please don't use getTlsKey method to get key, use getKey instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        key_bytes = get_key_response.as_uint8array(32)
        return Account.from_key(key_bytes)  # type: ignore[no-any-return]
    else:  # GetKeyResponse
        return Account.from_key(get_key_response.decode_key())  # type: ignore[no-any-return]


def to_account_secure(
    get_key_response: GetKeyResponse | GetTlsKeyResponse,
) -> LocalAccount:
    """Create an Ethereum account using SHA256 of full key material for security."""
    if isinstance(get_key_response, GetTlsKeyResponse):
        warnings.warn(
            "to_account_secure: Please don't use getTlsKey method to get key, use getKey instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            # Hash the complete key material with SHA256
            key_bytes = get_key_response.as_uint8array()
            hashed_key = hashlib.sha256(key_bytes).digest()
            return Account.from_key(hashed_key)  # type: ignore[no-any-return]
        except Exception as e:
            raise RuntimeError(
                "to_account_secure: missing SHA256 support, please upgrade your system"
            ) from e
    else:  # GetKeyResponse
        return Account.from_key(get_key_response.decode_key())  # type: ignore[no-any-return]
