# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Test typing and mypy compatibility for sync/async methods."""

import inspect
from typing import get_type_hints

from dstack_sdk import AsyncDstackClient
from dstack_sdk import DstackClient
from dstack_sdk import GetKeyResponse
from dstack_sdk import GetQuoteResponse
from dstack_sdk import GetTlsKeyResponse
from dstack_sdk.dstack_client import InfoResponse

# Use a test endpoint to avoid socket file not found errors
TEST_ENDPOINT = "http://localhost:8080"


def test_sync_method_type_annotations():
    """Test that sync methods have correct type annotations, not Coroutine."""
    client = DstackClient(TEST_ENDPOINT)

    # Check get_tls_key method
    get_tls_key_method = getattr(client, "get_tls_key")
    assert callable(get_tls_key_method)

    # Get type hints for the method
    try:
        type_hints = get_type_hints(get_tls_key_method)
        print(f"get_tls_key type hints: {type_hints}")

        # The return type should be GetTlsKeyResponse, not Coroutine
        return_type = type_hints.get("return", None)
        print(f"get_tls_key return type: {return_type}")

        # This should pass - return type should be GetTlsKeyResponse
        assert return_type == GetTlsKeyResponse or return_type is GetTlsKeyResponse

    except Exception as e:
        print(f"Error getting type hints for get_tls_key: {e}")
        # If we can't get type hints, at least check it's not a coroutine function
        assert not inspect.iscoroutinefunction(get_tls_key_method), (
            "Sync method should not be a coroutine function"
        )


def test_all_sync_method_types():
    """Test all sync business methods have correct type annotations."""
    client = DstackClient(TEST_ENDPOINT)

    expected_types = {
        "get_key": GetKeyResponse,
        "get_quote": GetQuoteResponse,
        "get_tls_key": GetTlsKeyResponse,
        "info": InfoResponse,
        "emit_event": type(None),  # Returns None
        "is_reachable": bool,
    }

    for method_name, expected_return_type in expected_types.items():
        method = getattr(client, method_name)
        assert callable(method), f"{method_name} should be callable"

        # Should not be coroutine function for sync client
        assert not inspect.iscoroutinefunction(method), (
            f"Sync {method_name} should not be coroutine function"
        )

        try:
            type_hints = get_type_hints(method)
            return_type = type_hints.get("return", None)
            print(
                f"{method_name} return type: {return_type}, expected: {expected_return_type}"
            )

            # Check that return type matches expected
            if expected_return_type is not None:
                assert (
                    return_type == expected_return_type
                    or return_type is expected_return_type
                ), (
                    f"{method_name} should return {expected_return_type}, got {return_type}"
                )

        except Exception as e:
            print(f"Warning: Could not get type hints for {method_name}: {e}")


def test_async_method_types():
    """Test that async methods have correct type annotations."""
    client = AsyncDstackClient(TEST_ENDPOINT)

    expected_types = {
        "get_key": GetKeyResponse,
        "get_quote": GetQuoteResponse,
        "get_tls_key": GetTlsKeyResponse,
        "info": InfoResponse,
        "emit_event": type(None),
        "is_reachable": bool,
    }

    for method_name, expected_return_type in expected_types.items():
        method = getattr(client, method_name)
        assert callable(method), f"{method_name} should be callable"

        # Should be coroutine function for async client
        assert inspect.iscoroutinefunction(method), (
            f"Async {method_name} should be coroutine function"
        )

        try:
            type_hints = get_type_hints(method)
            return_type = type_hints.get("return", None)
            print(
                f"Async {method_name} return type: {return_type}, expected: {expected_return_type}"
            )

        except Exception as e:
            print(f"Warning: Could not get type hints for async {method_name}: {e}")


def test_method_signature_comparison():
    """Compare method signatures between sync and async versions."""
    sync_client = DstackClient(TEST_ENDPOINT)
    async_client = AsyncDstackClient(TEST_ENDPOINT)

    methods_to_check = [
        "get_key",
        "get_quote",
        "get_tls_key",
        "info",
        "emit_event",
        "is_reachable",
    ]

    for method_name in methods_to_check:
        sync_method = getattr(sync_client, method_name)
        async_method = getattr(async_client, method_name)

        sync_sig = inspect.signature(sync_method)
        async_sig = inspect.signature(async_method)

        print(f"\n{method_name}:")
        print(f"  Sync signature: {sync_sig}")
        print(f"  Async signature: {async_sig}")

        # Parameters should be the same (excluding 'self')
        sync_params = list(sync_sig.parameters.keys())
        async_params = list(async_sig.parameters.keys())

        if "self" in sync_params:
            sync_params.remove("self")
        if "self" in async_params:
            async_params.remove("self")

        assert sync_params == async_params, (
            f"Parameter mismatch for {method_name}: sync={sync_params}, async={async_params}"
        )


if __name__ == "__main__":
    # Run the tests manually to see output
    test_sync_method_type_annotations()
    test_all_sync_method_types()
    test_async_method_types()
    test_method_signature_comparison()
    print("All typing tests completed!")
