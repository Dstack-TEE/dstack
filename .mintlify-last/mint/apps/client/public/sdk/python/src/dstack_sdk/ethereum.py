from eth_account import Account

from .dstack_client import GetKeyResponse

def to_account(get_key_response: GetKeyResponse) -> Account:
    return Account.from_key(get_key_response.decode_key())
