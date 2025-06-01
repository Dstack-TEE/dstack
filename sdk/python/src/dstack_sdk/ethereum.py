import hashlib
from eth_account import Account

from .tappd_client import DeriveKeyResponse

def to_account(derive_key_response: DeriveKeyResponse) -> Account:
    hashed = hashlib.sha256(derive_key_response.toBytes()).digest()
    return Account.from_key(hashed)
