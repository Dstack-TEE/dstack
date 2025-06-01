import hashlib
from solders.keypair import Keypair

from .tappd_client import DeriveKeyResponse

def to_keypair(derive_key_response: DeriveKeyResponse) -> Keypair:
    hashed = hashlib.sha256(derive_key_response.toBytes()).digest()
    return Keypair.from_seed(hashed)