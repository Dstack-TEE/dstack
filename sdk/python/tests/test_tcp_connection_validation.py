# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import unittest.mock

import pytest

from dstack_sdk import AsyncDstackClient
from dstack_sdk import DstackClient


class TestTCPConnectionValidation:
    """Test actual TCP connection behavior."""

    @pytest.mark.asyncio
    async def test_async_client_connection_object_reuse(self):
        """Test that the actual httpx client object is reused in async context manager."""
        client = AsyncDstackClient()

        async with client:
            first_client_obj = client._client
            assert first_client_obj is not None

            # Verify client object has expected attributes
            assert hasattr(first_client_obj, "post")
            assert hasattr(first_client_obj, "_transport")

            # Make a request to establish connection state
            with unittest.mock.patch.object(first_client_obj, "post") as mock_post:
                mock_response = unittest.mock.Mock()
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = {"key": "test", "signature_chain": []}
                mock_post.return_value = mock_response

                await client.get_key("test1")

                # Verify the same client object is still being used
                assert client._client is first_client_obj

                await client.get_key("test2")

                # Still the same client object
                assert client._client is first_client_obj
                assert mock_post.call_count == 2

    def test_sync_client_connection_object_reuse(self):
        """Test that the actual httpx client object is reused in sync context manager."""
        client = DstackClient()

        with client:
            # For sync clients, check _sync_client instead of _client
            first_client_obj = client.async_client._sync_client
            assert first_client_obj is not None

            # Verify client object has expected attributes
            assert hasattr(first_client_obj, "post")
            assert hasattr(first_client_obj, "_transport")

            # Make a request to establish connection state
            with unittest.mock.patch.object(first_client_obj, "post") as mock_post:
                mock_response = unittest.mock.Mock()
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = {"key": "test", "signature_chain": []}
                mock_post.return_value = mock_response

                client.get_key("test1")

                # Verify the same client object is still being used
                assert client.async_client._sync_client is first_client_obj

                client.get_key("test2")

                # Still the same client object
                assert client.async_client._sync_client is first_client_obj
                assert mock_post.call_count == 2

    @pytest.mark.asyncio
    async def test_async_transport_configuration_preserved(self):
        """Test that transport configuration is preserved when using context manager."""
        # Test with HTTP endpoint
        http_client = AsyncDstackClient(endpoint="http://localhost:8080")

        async with http_client:
            assert http_client._client is not None
            assert isinstance(
                http_client._client._transport, type(http_client.async_transport)
            )
            assert http_client._client.base_url == "http://localhost:8080"

    def test_sync_transport_configuration_preserved(self):
        """Test that transport configuration is preserved when using context manager."""
        # Test with HTTP endpoint
        http_client = DstackClient(endpoint="http://localhost:8080")

        with http_client:
            # For sync clients, check _sync_client instead of _client
            assert http_client.async_client._sync_client is not None
            assert isinstance(
                http_client.async_client._sync_client._transport,
                type(http_client.async_client.sync_transport),
            )
            assert (
                http_client.async_client._sync_client.base_url
                == "http://localhost:8080"
            )

    @pytest.mark.asyncio
    async def test_reference_counting_behavior(self):
        """Test that reference counting works correctly for nested contexts."""
        client = AsyncDstackClient()

        # Initially no client and ref count is 0
        assert client._client is None
        assert client._client_ref_count == 0

        async with client:  # ref_count = 1
            assert client._client_ref_count == 1
            first_client = client._client
            assert first_client is not None

            async with client:  # ref_count = 2
                assert client._client_ref_count == 2
                assert client._client is first_client  # Same client

                async with client:  # ref_count = 3
                    assert client._client_ref_count == 3
                    assert client._client is first_client  # Still same client
                # ref_count = 2
                assert client._client_ref_count == 2
                assert client._client is first_client  # Client still alive
            # ref_count = 1
            assert client._client_ref_count == 1
            assert client._client is first_client  # Client still alive
        # ref_count = 0
        assert client._client_ref_count == 0
        assert client._client is None  # Client closed

    def test_sync_reference_counting_behavior(self):
        """Test that reference counting works correctly for nested sync contexts."""
        client = DstackClient()

        # Initially no client and ref count is 0
        assert client.async_client._sync_client is None
        assert client.async_client._client_ref_count == 0

        with client:  # ref_count = 1
            assert client.async_client._client_ref_count == 1
            first_client = client.async_client._sync_client
            assert first_client is not None

            with client:  # ref_count = 2
                assert client.async_client._client_ref_count == 2
                assert client.async_client._sync_client is first_client  # Same client

                with client:  # ref_count = 3
                    assert client.async_client._client_ref_count == 3
                    assert (
                        client.async_client._sync_client is first_client
                    )  # Still same client
                # ref_count = 2
                assert client.async_client._client_ref_count == 2
                assert (
                    client.async_client._sync_client is first_client
                )  # Client still alive
            # ref_count = 1
            assert client.async_client._client_ref_count == 1
            assert (
                client.async_client._sync_client is first_client
            )  # Client still alive
        # ref_count = 0
        assert client.async_client._client_ref_count == 0
        assert client.async_client._sync_client is None  # Client closed
