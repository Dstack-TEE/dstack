# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""ZetaChain helpers for deriving accounts from dstack keys.

Use with ``dstack_sdk.DstackClient`` responses to create ZetaChain
accounts for signing and transacting on ZetaChain networks.

ZetaChain is fully EVM-compatible, so this module uses the same
eth_account library as the Ethereum integration.
"""

import hashlib
import warnings

from eth_account import Account
from eth_account.signers.local import LocalAccount

from .dstack_client import GetKeyResponse
from .dstack_client import GetTlsKeyResponse


def to_account(get_key_response: GetKeyResponse | GetTlsKeyResponse) -> LocalAccount:
    """Create a ZetaChain account from DstackClient key response.

    DEPRECATED: Use to_account_secure instead. This method has security concerns.
    Current implementation uses raw key material without proper hashing.

    Args:
        get_key_response: Response from get_key() or get_tls_key()

    Returns:
        Account: ZetaChain account object (EVM-compatible)

    Example:
        >>> from dstack_sdk import DstackClient
        >>> from dstack_sdk.zetachain import to_account
        >>> client = DstackClient()
        >>> key = client.get_key('zetachain/mainnet', 'wallet')
        >>> account = to_account(key)
        >>> print(f"ZetaChain address: {account.address}")

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
    """Create a ZetaChain account using SHA256 of full key material for security.

    This is the recommended method for creating ZetaChain accounts from dstack keys.

    Args:
        get_key_response: Response from get_key() or get_tls_key()

    Returns:
        LocalAccount: ZetaChain account object with enhanced security

    Example:
        >>> from dstack_sdk import DstackClient
        >>> from dstack_sdk.zetachain import to_account_secure
        >>> from web3 import Web3
        >>>
        >>> # Initialize dstack client
        >>> client = DstackClient()
        >>>
        >>> # Derive a deterministic key for ZetaChain
        >>> key = client.get_key('zetachain/mainnet', 'wallet')
        >>> account = to_account_secure(key)
        >>>
        >>> # Use with Web3 for ZetaChain
        >>> w3 = Web3(Web3.HTTPProvider('https://zetachain-evm.blockpi.network/v1/rpc/public'))
        >>> balance = w3.eth.get_balance(account.address)
        >>> print(f"Balance: {w3.from_wei(balance, 'ether')} ZETA")

    """
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
