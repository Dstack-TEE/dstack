import hashlib
import warnings
from solders.keypair import Keypair

from .tappd_client import DeriveKeyResponse

def to_keypair(derive_key_response: DeriveKeyResponse) -> Keypair:
    """
    DEPRECATED: This method has security concerns.
    Please use to_keypair_secure instead.
    
    Current implementation uses raw key material without proper hashing.
    """
    warnings.warn(
        "to_keypair: this method has security concerns. "
        "Please use to_keypair_secure instead.",
        DeprecationWarning,
        stacklevel=2
    )
    # Restored original behavior: using first 32 bytes directly
    return Keypair.from_seed(derive_key_response.toBytes(32))

def to_keypair_secure(derive_key_response: DeriveKeyResponse) -> Keypair:
    """
    Creates a Solana Keypair from DeriveKeyResponse using secure key derivation.
    This method applies SHA256 hashing to the complete key material for enhanced security.
    """
    hashed = hashlib.sha256(derive_key_response.toBytes()).digest()
    return Keypair.from_seed(hashed)