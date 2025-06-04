import hashlib
import warnings
from eth_account import Account

from .tappd_client import DeriveKeyResponse

def to_account(derive_key_response: DeriveKeyResponse) -> Account:
    """
    DEPRECATED: This method has security concerns.
    Please use to_account_secure instead.
    
    Current implementation uses raw key material without proper hashing.
    """
    warnings.warn(
        "to_account: this method has security concerns. "
        "Please use to_account_secure instead.",
        DeprecationWarning,
        stacklevel=2
    )
    # Restored original behavior: using first 32 bytes directly
    return Account.from_key(derive_key_response.toBytes(32))

def to_account_secure(derive_key_response: DeriveKeyResponse) -> Account:
    """
    Creates an Ethereum account from DeriveKeyResponse using secure key derivation.
    This method applies SHA256 hashing to the complete key material for enhanced security.
    """
    hashed = hashlib.sha256(derive_key_response.toBytes()).digest()
    return Account.from_key(hashed)
