# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Script to test mypy type checking on dstack client methods."""

import os
from unittest.mock import Mock
from unittest.mock import patch

try:
    from typing_extensions import reveal_type
except ImportError:
    from typing import reveal_type  # type: ignore

import pytest

from dstack_sdk import AsyncDstackClient
from dstack_sdk import DstackClient


def test_sync_client_types():
    """Test sync client method type inference with mypy."""
    # Use the simulator endpoint if available, otherwise use a mock
    endpoint = os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:8080")

    with patch("httpx.Client.post") as mock_post:
        # Mock the HTTP response for the tests
        mock_response = Mock()
        mock_response.status_code = 200

        # Mock response for get_tls_key
        mock_response.json.return_value = {
            "key": "test_key",
            "certificate_chain": ["test_cert_1", "test_cert_2"],
        }
        mock_post.return_value = mock_response

        client = DstackClient(endpoint)

        # Test get_tls_key - this should be GetTlsKeyResponse, not Coroutine
        tls_result = client.get_tls_key()
        reveal_type(tls_result)  # Should be GetTlsKeyResponse

        # Mock response for get_key
        mock_response.json.return_value = {
            "key": "test_key_hex",
            "signature_chain": ["sig1", "sig2"],
        }

        # Test get_key
        key_result = client.get_key()
        reveal_type(key_result)  # Should be GetKeyResponse

        # Mock response for is_reachable
        mock_response.json.return_value = True

        # Test is_reachable
        reachable = client.is_reachable()
        reveal_type(reachable)  # Should be bool


@pytest.mark.asyncio
async def test_async_client_types():
    """Test async client method type inference with mypy."""
    # Use the simulator endpoint if available, otherwise use a mock
    endpoint = os.environ.get("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:8080")

    with patch("httpx.AsyncClient.post") as mock_post:
        # Mock the HTTP response for the tests
        mock_response = Mock()
        mock_response.status_code = 200

        # Mock response for get_tls_key
        mock_response.json.return_value = {
            "key": "test_key",
            "certificate_chain": ["test_cert_1", "test_cert_2"],
        }
        mock_post.return_value = mock_response

        client = AsyncDstackClient(endpoint)

        # Test get_tls_key - this should be GetTlsKeyResponse
        tls_result = await client.get_tls_key()
        reveal_type(tls_result)  # Should be GetTlsKeyResponse

        # Mock response for get_key
        mock_response.json.return_value = {
            "key": "test_key_hex",
            "signature_chain": ["sig1", "sig2"],
        }

        # Test get_key
        key_result = await client.get_key()
        reveal_type(key_result)  # Should be GetKeyResponse

        # Mock response for is_reachable
        mock_response.json.return_value = True

        # Test is_reachable
        reachable = await client.is_reachable()
        reveal_type(reachable)  # Should be bool


if __name__ == "__main__":
    # This script is meant to be checked with mypy, not executed
    pass
