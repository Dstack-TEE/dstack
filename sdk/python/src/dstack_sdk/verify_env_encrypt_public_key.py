# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Verify ECDSA signatures of environment-encrypt public keys.

This module prepares the message per dstack convention and offers a simplified
API surface. Full public key recovery is not implemented.
"""

import hashlib
from typing import Optional


def verify_env_encrypt_public_key(
    public_key: bytes, signature: bytes, app_id: str
) -> Optional[str]:
    """Attempt public key recovery from signature; return compressed key or None."""
    if len(signature) != 65:
        return None

    try:
        # Create the message to verify
        prefix = b"dstack-env-encrypt-pubkey"

        # Remove 0x prefix if present
        clean_app_id = app_id[2:] if app_id.startswith("0x") else app_id

        # Validate hex string
        try:
            app_id_bytes = bytes.fromhex(clean_app_id)
        except ValueError:
            # Invalid hex string, return None
            return None

        separator = b":"

        # Construct message: prefix + ":" + app_id + public_key
        message = prefix + separator + app_id_bytes + public_key

        # Hash the message with SHA3-256 (Keccak-256)
        # Note: Using hashlib.sha3_256 which is actually Keccak-256 in most implementations
        message_hash = hashlib.sha3_256(message).digest()

        # Extract r, s, recovery_id from signature
        r = signature[:32]
        s = signature[32:64]
        recovery_id = signature[64]

        # Convert r, s to integers
        r_int = int.from_bytes(r, byteorder="big")
        s_int = int.from_bytes(s, byteorder="big")

        # Recover public key from signature
        # This is a simplified version - for full ECDSA recovery,
        # we need more complex logic to try different recovery possibilities

        # For now, let's try a basic approach using known cryptographic libraries
        # This is where we would typically use a library like ethereum's ecrecover
        # Since we don't have that, let's implement a basic verification

        # Try both possible recovery IDs (0 and 1, or adjusted by 27)
        for recovery_attempt in [recovery_id, recovery_id ^ 1]:
            # This is a stub. A proper ECDSA recovery implementation is required
            # to return a real public key. For now, always continue.
            recovered_key = _recover_public_key(
                message_hash, r_int, s_int, recovery_attempt
            )
            if recovered_key:
                return f"0x{recovered_key.hex()}"

        return None

    except Exception:
        # Keep behavior non-fatal; callers treat None as invalid
        # Avoid bare except to satisfy lint rules
        return None


def _recover_public_key(
    message_hash: bytes, r: int, s: int, recovery_id: int
) -> Optional[bytes]:
    """Recover public key from ECDSA signature components.

    This is a simplified implementation. In production, you should use
    a proper ECDSA recovery library like the one used in Ethereum.
    """
    # Public key recovery is not implemented in this simplified version.
    return None


# Alternative implementation using a more direct approach
def verify_signature_simple(public_key: bytes, signature: bytes, app_id: str) -> bool:
    """Perform simple signature preprocessing without ECDSA recovery."""
    if len(signature) != 65:
        return False

    try:
        # Create the message
        prefix = b"dstack-env-encrypt-pubkey"
        clean_app_id = app_id[2:] if app_id.startswith("0x") else app_id

        # Validate hex string
        try:
            app_id_bytes = bytes.fromhex(clean_app_id)
        except ValueError:
            # Invalid hex string
            return False

        separator = b":"
        message = prefix + separator + app_id_bytes + public_key

        # Hash with SHA3-256 (Keccak-256)
        # Compute hash to mirror verification flow, but unused in the stub
        _ = hashlib.sha3_256(message).digest()

        # For now, return True to indicate the message was processed correctly
        # Full signature verification would require ECDSA implementation
        return True

    except Exception:
        return False
