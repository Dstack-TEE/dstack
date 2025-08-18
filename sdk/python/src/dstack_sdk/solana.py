# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Solana helpers for deriving keypairs from dstack keys.

Use with ``dstack_sdk.DstackClient`` responses to create ``solders.Keypair``
objects for signing transactions on Solana.
"""

import hashlib
import warnings

from solders.keypair import Keypair

from .dstack_client import GetKeyResponse
from .dstack_client import GetTlsKeyResponse


def to_keypair(get_key_response: GetKeyResponse | GetTlsKeyResponse) -> Keypair:
    """Create a Solana Keypair from DstackClient key response.

    DEPRECATED: Use to_keypair_secure instead. This method has security concerns.
    Current implementation uses raw key material without proper hashing.

    Args:
        get_key_response: Response from get_key() or get_tls_key()

    Returns:
        Keypair: Solana keypair object

    """
    if isinstance(get_key_response, GetTlsKeyResponse):
        warnings.warn(
            "to_keypair: Please don't use getTlsKey method to get key, use getKey instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        # Restored original behavior: using first 32 bytes directly
        key_bytes = get_key_response.as_uint8array(32)
        return Keypair.from_seed(key_bytes)
    else:  # GetKeyResponse
        return Keypair.from_seed(get_key_response.decode_key())


def to_keypair_secure(get_key_response: GetKeyResponse | GetTlsKeyResponse) -> Keypair:
    """Create a Solana Keypair using SHA256 of full key material for security."""
    if isinstance(get_key_response, GetTlsKeyResponse):
        warnings.warn(
            "to_keypair_secure: Please don't use getTlsKey method to get key, use getKey instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            # Hash the complete key material with SHA256
            key_bytes = get_key_response.as_uint8array()
            hashed_key = hashlib.sha256(key_bytes).digest()
            return Keypair.from_seed(hashed_key)
        except Exception as e:
            raise RuntimeError(
                "to_keypair_secure: missing SHA256 support, please upgrade your system"
            ) from e
    else:  # GetKeyResponse
        return Keypair.from_seed(get_key_response.decode_key())
