# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Solana helpers for deriving keypairs from dstack keys.

Use with ``dstack_sdk.DstackClientV0`` responses to create ``solders.Keypair``
objects for signing transactions on Solana. These helpers take the v0 response
models; for a v1 key, hand ``GetKeyResponseV1.key`` to
``Keypair.from_seed`` yourself.
"""

from solders.keypair import Keypair

from .dstack_client_v0 import GetKeyResponse
from .dstack_client_v0 import GetTlsKeyResponse


def _reject_tls_key(response: GetKeyResponse | GetTlsKeyResponse) -> None:
    if isinstance(response, GetTlsKeyResponse):
        raise TypeError(
            "TLS keys cannot be used to derive Solana keypairs; use get_key()"
        )


def to_keypair(get_key_response: GetKeyResponse) -> Keypair:
    """Create a Solana keypair from a DstackClientV0 get_key() response.

    DEPRECATED: Use to_keypair_secure instead.
    """
    _reject_tls_key(get_key_response)
    return Keypair.from_seed(get_key_response.decode_key())


def to_keypair_secure(get_key_response: GetKeyResponse) -> Keypair:
    """Create a Solana keypair from a DstackClientV0 get_key() response."""
    _reject_tls_key(get_key_response)
    return Keypair.from_seed(get_key_response.decode_key())
