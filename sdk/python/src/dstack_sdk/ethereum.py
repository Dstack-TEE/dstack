# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Ethereum helpers for deriving accounts from dstack keys.

Use with ``dstack_sdk.DstackClientV0`` responses to create ``eth_account``
objects for signing and transacting. These helpers take the v0 response models;
for a v1 key, hand ``GetKeyResponseV1.key`` to ``Account.from_key``
yourself.
"""

from eth_account import Account
from eth_account.signers.local import LocalAccount

from .dstack_client_v0 import GetKeyResponse
from .dstack_client_v0 import GetTlsKeyResponse


def _reject_tls_key(response: GetKeyResponse | GetTlsKeyResponse) -> None:
    if isinstance(response, GetTlsKeyResponse):
        raise TypeError(
            "TLS keys cannot be used to derive Ethereum accounts; use get_key()"
        )


def to_account(get_key_response: GetKeyResponse) -> LocalAccount:
    """Create an Ethereum account from a DstackClientV0 get_key() response.

    DEPRECATED: Use to_account_secure instead.
    """
    _reject_tls_key(get_key_response)
    return Account.from_key(get_key_response.decode_key())  # type: ignore[no-any-return]


def to_account_secure(get_key_response: GetKeyResponse) -> LocalAccount:
    """Create an Ethereum account from a DstackClientV0 get_key() response."""
    _reject_tls_key(get_key_response)
    return Account.from_key(get_key_response.decode_key())  # type: ignore[no-any-return]
