# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Solana helpers for deriving keypairs from dstack keys.

Use with ``dstack_sdk.DstackClientV0`` responses to create ``solders.Keypair``
objects for signing transactions on Solana. These helpers take the v0 response
models; for a v1 key, hand ``GetKeyResponseV1.key`` to
``Keypair.from_seed`` yourself.
"""

import hashlib
import warnings

from solders.keypair import Keypair

from .dstack_client_v0 import GetKeyResponse
from .dstack_client_v0 import GetTlsKeyResponse


def to_keypair(get_key_response: GetKeyResponse | GetTlsKeyResponse) -> Keypair:
    """Create a Solana Keypair from a DstackClientV0 key response.

    DEPRECATED: Use to_keypair_secure instead. This method has security concerns.
    A GetTlsKeyResponse is used without hashing; a GetKeyResponse gives the
    same result as to_keypair_secure.

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
    """Create a Solana Keypair from a DstackClientV0 key response.

    A GetTlsKeyResponse is hashed with SHA256 before use. A GetKeyResponse key
    is used as is: it is already a KMS-derived key specific to its path and
    purpose, so it needs no further hashing. Derive wallet keys from a
    dedicated path rather than reusing one key for several purposes.
    """
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
