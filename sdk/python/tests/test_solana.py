# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import pytest
from solders.keypair import Keypair

from dstack_sdk import GetKeyResponse
from dstack_sdk import GetTlsKeyResponse
from dstack_sdk.solana import to_keypair
from dstack_sdk.solana import to_keypair_secure


@pytest.mark.parametrize("adapter", [to_keypair, to_keypair_secure])
def test_keypair_adapters_accept_derived_keys(adapter):
    response = GetKeyResponse(key="01" * 32, signature_chain=[])
    assert isinstance(adapter(response), Keypair)


@pytest.mark.parametrize("adapter", [to_keypair, to_keypair_secure])
def test_keypair_adapters_reject_tls_keys(adapter):
    response = GetTlsKeyResponse(key="not used", certificate_chain=[])
    with pytest.raises(TypeError, match="TLS keys cannot be used"):
        adapter(response)  # type: ignore[arg-type]
