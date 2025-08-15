# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from solders.keypair import Keypair

from .dstack_client import GetKeyResponse

def to_keypair(get_key_response: GetKeyResponse) -> Keypair:
    return Keypair.from_seed(get_key_response.decode_key())
