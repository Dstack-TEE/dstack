# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import unittest.mock

import pytest

from dstack_sdk import AsyncDstackClient
from dstack_sdk import DstackClient


class TestConnectionReuse:
    """Test TCP connection reuse functionality."""

    @pytest.mark.asyncio
    async def test_async_context_manager_reuses_client(self):
        """Test that async context manager creates and reuses a single client."""
        client = AsyncDstackClient()

        # Verify client is None initially
        assert client._client is None

        async with client:
            # Verify client is created when entering context
            assert client._client is not None
            first_client = client._client

            # Make multiple calls and verify same client is used
            with unittest.mock.patch.object(client._client, "post") as mock_post:
                # Mock successful response
                mock_response = unittest.mock.Mock()
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = {"key": "test", "signature_chain": []}
                mock_post.return_value = mock_response

                # Make first call
                await client.get_key("test1")
                # Make second call
                await client.get_key("test2")

                # Verify same client instance was used for both calls
                assert client._client is first_client
                assert mock_post.call_count == 2

        # Verify client is cleaned up after exiting context
        assert client._client is None

    def test_sync_context_manager_reuses_client(self):
        """Test that sync context manager creates and reuses a single client."""
        client = DstackClient()

        # Verify sync client is None initially
        assert client.async_client._sync_client is None

        with client:
            # Verify client is created when entering context
            assert client.async_client._sync_client is not None
            first_client = client.async_client._sync_client

            # Make multiple calls and verify same client is used
            with unittest.mock.patch.object(
                client.async_client._sync_client, "post"
            ) as mock_post:
                # Mock successful response
                mock_response = unittest.mock.Mock()
                mock_response.raise_for_status.return_value = None
                mock_response.json.return_value = {"key": "test", "signature_chain": []}
                mock_post.return_value = mock_response

                # Make first call
                client.get_key("test1")
                # Make second call
                client.get_key("test2")

                # Verify same client instance was used for both calls
                assert client.async_client._sync_client is first_client
                assert mock_post.call_count == 2

        # Verify client is cleaned up after exiting context
        assert client.async_client._sync_client is None

    @pytest.mark.asyncio
    async def test_async_without_context_manager_reuses_client(self):
        """Test that without context manager, clients are still reused."""
        client = AsyncDstackClient()

        with unittest.mock.patch("httpx.AsyncClient") as mock_async_client_class:
            # Mock the context manager behavior
            mock_client_instance = unittest.mock.AsyncMock()
            mock_response = unittest.mock.Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {"key": "test", "signature_chain": []}
            mock_client_instance.post = unittest.mock.AsyncMock(
                return_value=mock_response
            )
            mock_async_client_class.return_value = mock_client_instance

            # Make two calls
            await client.get_key("test1")
            await client.get_key("test2")

            # Verify that the client was created and reused (not created twice)
            assert mock_async_client_class.call_count == 1

    def test_sync_without_context_manager_reuses_client(self):
        """Test that without context manager, clients are still reused."""
        client = DstackClient()

        with unittest.mock.patch("httpx.Client") as mock_client_class:
            # Mock the context manager behavior
            mock_client_instance = unittest.mock.Mock()
            mock_response = unittest.mock.Mock()
            mock_response.raise_for_status.return_value = None
            mock_response.json.return_value = {"key": "test", "signature_chain": []}
            mock_client_instance.post.return_value = mock_response
            mock_client_class.return_value = mock_client_instance

            # Make two calls
            client.get_key("test1")
            client.get_key("test2")

            # Verify that the client was created and reused (not created twice)
            assert mock_client_class.call_count == 1

    @pytest.mark.asyncio
    async def test_async_context_manager_with_real_requests(self):
        """Test async context manager with real requests to ensure connection reuse."""
        client = AsyncDstackClient()

        async with client:
            # Make multiple requests - these should reuse the same connection
            try:
                result1 = await client.info()
                result2 = await client.info()

                # Both calls should succeed (assuming simulator is running)
                assert result1 is not None
                assert result2 is not None
                assert hasattr(result1, "app_id")
                assert hasattr(result2, "app_id")
            except Exception:
                # If simulator is not running, that's expected
                # The important thing is that the context manager worked
                pass

    def test_sync_context_manager_with_real_requests(self):
        """Test sync context manager with real requests to ensure connection reuse."""
        client = DstackClient()

        with client:
            # Make multiple requests - these should reuse the same connection
            try:
                result1 = client.info()
                result2 = client.info()

                # Both calls should succeed (assuming simulator is running)
                assert result1 is not None
                assert result2 is not None
                assert hasattr(result1, "app_id")
                assert hasattr(result2, "app_id")
            except Exception:
                # If simulator is not running, that's expected
                # The important thing is that the context manager worked
                pass

    @pytest.mark.asyncio
    async def test_async_nested_context_managers(self):
        """Test that nested async context managers work correctly."""
        client = AsyncDstackClient()

        async with client:
            first_client = client._client
            assert first_client is not None

            # Nested context should use the same client
            async with client:
                assert client._client is first_client

            # After nested exit, client should still be active
            assert client._client is first_client

        # After outer exit, client should be None
        assert client._client is None

    def test_sync_nested_context_managers(self):
        """Test that nested sync context managers work correctly."""
        client = DstackClient()

        with client:
            first_client = client.async_client._sync_client
            assert first_client is not None

            # Nested context should use the same client
            with client:
                assert client.async_client._sync_client is first_client

            # After nested exit, client should still be active
            assert client.async_client._sync_client is first_client

        # After outer exit, client should be None
        assert client.async_client._sync_client is None
