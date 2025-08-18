# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import warnings

from evidence_api.tdx.quote import TdxQuote
import pytest

from dstack_sdk import AsyncDstackClient
from dstack_sdk import AsyncTappdClient
from dstack_sdk import DstackClient
from dstack_sdk import GetKeyResponse
from dstack_sdk import GetQuoteResponse
from dstack_sdk import GetTlsKeyResponse
from dstack_sdk import TappdClient
from dstack_sdk.dstack_client import InfoResponse
from dstack_sdk.dstack_client import TcbInfo


def test_sync_client_get_key():
    client = DstackClient()
    result = client.get_key()
    assert isinstance(result, GetKeyResponse)
    assert isinstance(result.decode_key(), bytes)
    assert len(result.decode_key()) == 32


def test_sync_client_get_quote():
    client = DstackClient()
    result = client.get_quote("test")
    assert isinstance(result, GetQuoteResponse)


def test_sync_client_get_tls_key():
    client = DstackClient()
    result = client.get_tls_key()
    assert isinstance(result, GetTlsKeyResponse)
    assert isinstance(result.key, str)
    assert len(result.key) > 0
    assert len(result.certificate_chain) > 0


def test_sync_client_get_info():
    client = DstackClient()
    result = client.info()
    check_info_response(result)


def check_info_response(result: InfoResponse):
    assert isinstance(result, InfoResponse)
    assert isinstance(result.app_id, str)
    assert isinstance(result.instance_id, str)
    assert isinstance(result.tcb_info, TcbInfo)
    assert len(result.tcb_info.mrtd) == 96
    assert len(result.tcb_info.rtmr0) == 96
    assert len(result.tcb_info.rtmr1) == 96
    assert len(result.tcb_info.rtmr2) == 96
    assert len(result.tcb_info.rtmr3) == 96
    assert len(result.tcb_info.compose_hash) == 64
    assert len(result.tcb_info.device_id) == 64
    assert len(result.tcb_info.app_compose) > 0
    assert len(result.tcb_info.event_log) > 0


@pytest.mark.asyncio
async def test_async_client_get_key():
    client = AsyncDstackClient()
    result = await client.get_key()
    assert isinstance(result, GetKeyResponse)


@pytest.mark.asyncio
async def test_async_client_get_quote():
    client = AsyncDstackClient()
    result = await client.get_quote("test")
    assert isinstance(result, GetQuoteResponse)


@pytest.mark.asyncio
async def test_async_client_get_tls_key():
    client = AsyncDstackClient()
    result = await client.get_tls_key()
    assert isinstance(result, GetTlsKeyResponse)
    assert isinstance(result.key, str)
    assert result.key.startswith("-----BEGIN PRIVATE KEY-----")
    assert len(result.certificate_chain) > 0


@pytest.mark.asyncio
async def test_async_client_get_info():
    client = AsyncDstackClient()
    result = await client.info()
    check_info_response(result)


@pytest.mark.asyncio
async def test_tls_key_uniqueness():
    """Test that TLS keys are unique across multiple calls."""
    client = AsyncDstackClient()
    result1 = await client.get_tls_key()
    result2 = await client.get_tls_key()
    # TLS keys should be unique for each call
    assert result1.key != result2.key


@pytest.mark.asyncio
async def test_replay_rtmr():
    client = AsyncDstackClient()
    result = await client.get_quote("test")
    # TODO evidence_api is a bit out-of-date, we need an up-to-date implementation.
    tdxQuote = TdxQuote(bytearray(bytes.fromhex(result.quote)))
    rtmrs = result.replay_rtmrs()
    assert rtmrs[0] == tdxQuote.body.rtmr0.hex()
    assert rtmrs[1] == tdxQuote.body.rtmr1.hex()
    assert rtmrs[2] == tdxQuote.body.rtmr2.hex()
    assert rtmrs[3] == tdxQuote.body.rtmr3.hex()


@pytest.mark.asyncio
async def test_get_quote_raw_hash_error():
    with pytest.raises(ValueError) as excinfo:
        client = AsyncDstackClient()
        await client.get_quote("0" * 65)
    assert "64 bytes" in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        client = AsyncDstackClient()
        await client.get_quote(b"0" * 129)
    assert "64 bytes" in str(excinfo.value)


@pytest.mark.asyncio
async def test_report_data():
    reportdata = "test"
    client = AsyncDstackClient()
    result = await client.get_quote(reportdata)
    tdxQuote = TdxQuote(bytearray(result.decode_quote()))
    reportdata = reportdata.encode("utf-8") + b"\x00" * (64 - len(reportdata))
    assert reportdata == tdxQuote.body.reportdata


def test_sync_client_is_reachable():
    """Test that sync client can check if service is reachable."""
    client = DstackClient()
    is_reachable = client.is_reachable()
    assert isinstance(is_reachable, bool)
    assert is_reachable


@pytest.mark.asyncio
async def test_async_client_is_reachable():
    """Test that async client can check if service is reachable."""
    client = AsyncDstackClient()
    is_reachable = await client.is_reachable()
    assert isinstance(is_reachable, bool)
    assert is_reachable


def test_tls_key_as_uint8array():
    """Test that TLS key can be converted to bytes with as_uint8array method."""
    client = DstackClient()
    result = client.get_tls_key()

    # Test full length
    full_bytes = result.as_uint8array()
    assert isinstance(full_bytes, bytes)
    assert len(full_bytes) > 0

    # Test with max_length
    key_32 = result.as_uint8array(32)
    assert isinstance(key_32, bytes)
    assert len(key_32) == 32
    assert len(key_32) != len(full_bytes)


def test_tls_key_with_alt_names():
    """Test TLS key generation with alt names."""
    client = DstackClient()
    alt_names = ["localhost", "127.0.0.1"]
    result = client.get_tls_key(
        subject="test-subject",
        alt_names=alt_names,
        usage_ra_tls=True,
        usage_server_auth=True,
        usage_client_auth=True,
    )
    assert isinstance(result, GetTlsKeyResponse)
    assert result.key is not None
    assert len(result.certificate_chain) > 0


def test_unix_socket_file_not_exist():
    """Test that client raises error when Unix socket file doesn't exist."""
    # Temporarily remove environment variable to test file check
    import os

    saved_env = os.environ.get("DSTACK_SIMULATOR_ENDPOINT")
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        del os.environ["DSTACK_SIMULATOR_ENDPOINT"]

    try:
        with pytest.raises(FileNotFoundError) as exc_info:
            DstackClient("/non/existent/socket")
        assert "Unix socket file /non/existent/socket does not exist" in str(
            exc_info.value
        )
    finally:
        # Restore environment variable
        if saved_env:
            os.environ["DSTACK_SIMULATOR_ENDPOINT"] = saved_env


def test_non_unix_socket_endpoints():
    """Test that client doesn't throw error for non-unix socket paths."""
    import os

    saved_env = os.environ.get("DSTACK_SIMULATOR_ENDPOINT")
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        del os.environ["DSTACK_SIMULATOR_ENDPOINT"]

    try:
        # These should not raise errors
        client1 = DstackClient("http://localhost:8080")
        client2 = DstackClient("https://example.com")
        assert client1 is not None
        assert client2 is not None
    finally:
        # Restore environment variable
        if saved_env:
            os.environ["DSTACK_SIMULATOR_ENDPOINT"] = saved_env


@pytest.mark.asyncio
async def test_emit_event():
    """Test emit event functionality."""
    client = AsyncDstackClient()
    # This should not raise an error
    await client.emit_event("test-event", "test payload")
    await client.emit_event("test-event-bytes", b"test payload bytes")


def test_sync_emit_event():
    """Test sync emit event functionality."""
    client = DstackClient()
    # This should not raise an error
    client.emit_event("test-event", "test payload")
    client.emit_event("test-event-bytes", b"test payload bytes")


def test_emit_event_validation():
    """Test emit event input validation."""
    client = DstackClient()

    # Empty event name should raise error
    with pytest.raises(ValueError) as exc_info:
        client.emit_event("", "payload")
    assert "event name cannot be empty" in str(exc_info.value)


# Test deprecated TappdClient
def test_tappd_client_deprecated():
    """Test that TappdClient shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        TappdClient()

        # Filter for TappdClient deprecation warnings specifically
        tappd_warnings = [
            warning
            for warning in w
            if issubclass(warning.category, DeprecationWarning)
            and "TappdClient is deprecated" in str(warning.message)
        ]

        assert len(tappd_warnings) == 1
        assert "TappdClient is deprecated" in str(tappd_warnings[0].message)


def test_tappd_client_derive_key_deprecated():
    """Test that TappdClient.derive_key shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        client = TappdClient()

        client.derive_key("/", "test")
        # Should have warnings for both constructor and derive_key
        warning_messages = [str(warning.message) for warning in w]
        assert any("TappdClient is deprecated" in msg for msg in warning_messages)
        assert any("derive_key is deprecated" in msg for msg in warning_messages)


def test_tappd_client_tdx_quote_deprecated():
    """Test that TappdClient.tdx_quote shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        client = TappdClient()

        client.tdx_quote("test data", "raw")
        # Should have warnings for both constructor and tdx_quote
        warning_messages = [str(warning.message) for warning in w]
        assert any("TappdClient is deprecated" in msg for msg in warning_messages)
        assert any("tdx_quote is deprecated" in msg for msg in warning_messages)


# Test AsyncTappdClient
def test_async_tappd_client_deprecated():
    """Test that AsyncTappdClient shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        AsyncTappdClient()

        # Filter for AsyncTappdClient deprecation warnings specifically
        tappd_warnings = [
            warning
            for warning in w
            if issubclass(warning.category, DeprecationWarning)
            and "AsyncTappdClient is deprecated" in str(warning.message)
        ]

        assert len(tappd_warnings) == 1
        assert "AsyncTappdClient is deprecated" in str(tappd_warnings[0].message)


@pytest.mark.asyncio
async def test_async_tappd_client_derive_key_deprecated():
    """Test that AsyncTappdClient.derive_key shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        client = AsyncTappdClient()

        await client.derive_key("/", "test")
        # Should have warnings for both constructor and derive_key
        warning_messages = [str(warning.message) for warning in w]
        assert any("AsyncTappdClient is deprecated" in msg for msg in warning_messages)
        assert any("derive_key is deprecated" in msg for msg in warning_messages)


@pytest.mark.asyncio
async def test_async_tappd_client_tdx_quote_deprecated():
    """Test that AsyncTappdClient.tdx_quote shows deprecation warning."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        client = AsyncTappdClient()

        await client.tdx_quote("test data", "raw")
        # Should have warnings for both constructor and tdx_quote
        warning_messages = [str(warning.message) for warning in w]
        assert any("AsyncTappdClient is deprecated" in msg for msg in warning_messages)
        assert any("tdx_quote is deprecated" in msg for msg in warning_messages)


@pytest.mark.asyncio
async def test_async_tappd_client_is_reachable():
    """Test that AsyncTappdClient can check if service is reachable."""
    client = AsyncTappdClient()
    is_reachable = await client.is_reachable()
    assert isinstance(is_reachable, bool)
    assert is_reachable


# Test sync client called from async context
@pytest.mark.asyncio
async def test_sync_client_in_async_context_get_key():
    """Test that sync client works when called from async context."""
    client = DstackClient()
    result = client.get_key()
    assert isinstance(result, GetKeyResponse)
    assert isinstance(result.decode_key(), bytes)
    assert len(result.decode_key()) == 32


@pytest.mark.asyncio
async def test_sync_client_in_async_context_get_info():
    """Test that sync client info works when called from async context."""
    client = DstackClient()
    result = client.info()
    check_info_response(result)


@pytest.mark.asyncio
async def test_mixed_sync_async_calls():
    """Test mixing sync and async client calls in the same async context."""
    sync_client = DstackClient()
    async_client = AsyncDstackClient()

    # Call sync client from async context
    sync_result = sync_client.get_key()
    assert isinstance(sync_result, GetKeyResponse)

    # Call async client normally
    async_result = await async_client.get_key()
    assert isinstance(async_result, GetKeyResponse)

    # Both should work and return valid results
    assert len(sync_result.decode_key()) == 32
    assert len(async_result.decode_key()) == 32
