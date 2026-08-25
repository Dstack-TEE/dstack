# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import os
import warnings

from evidence_api.tdx.quote import TdxQuote
import pytest

from dstack_sdk import AsyncDstackClientV0
from dstack_sdk import AsyncTappdClient
from dstack_sdk import AttestResponse
from dstack_sdk import DstackClientV0
from dstack_sdk import GetKeyResponse
from dstack_sdk import GetQuoteResponse
from dstack_sdk import GetTlsKeyResponse
from dstack_sdk import SignResponse
from dstack_sdk import TappdClient
from dstack_sdk import VerifyResponse
from dstack_sdk import VersionResponse
from dstack_sdk.dstack_client_v0 import InfoResponse
from dstack_sdk.dstack_client_v0 import TcbInfo


def test_sync_client_get_key():
    client = DstackClientV0()
    result = client.get_key()  # Test default algorithm (secp256k1)
    assert isinstance(result, GetKeyResponse)
    assert isinstance(result.decode_key(), bytes)
    assert len(result.decode_key()) == 32

    # Test specifying algorithm
    result_ed = client.get_key(algorithm="ed25519")
    assert isinstance(result_ed, GetKeyResponse)
    assert len(result_ed.decode_key()) == 32

    with pytest.raises(Exception):  # Assuming unsupported algo raises error
        client.get_key(algorithm="rsa")


def test_sync_client_get_quote():
    client = DstackClientV0()
    result = client.get_quote("test")
    assert isinstance(result, GetQuoteResponse)


def test_sync_client_attest():
    client = DstackClientV0()
    result = client.attest("test")
    assert isinstance(result, AttestResponse)
    assert len(result.attestation) > 0


def test_sync_client_get_tls_key():
    client = DstackClientV0()
    result = client.get_tls_key()
    assert isinstance(result, GetTlsKeyResponse)
    assert isinstance(result.key, str)
    assert len(result.key) > 0
    assert len(result.certificate_chain) > 0


def test_sync_client_get_info():
    client = DstackClientV0()
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
    # Cloud provider fields available on dstack OS >= 0.5.7. Older OS or the
    # simulator may omit them; the attribute must still exist and be a str.
    assert isinstance(result.cloud_vendor, str)
    assert isinstance(result.cloud_product, str)


@pytest.mark.asyncio
async def test_async_client_get_key():
    client = AsyncDstackClientV0()
    result = await client.get_key()  # Test default algorithm (secp256k1)
    assert isinstance(result, GetKeyResponse)
    assert isinstance(result.decode_key(), bytes)
    assert len(result.decode_key()) == 32

    # Test specifying algorithm
    result_ed = await client.get_key(algorithm="ed25519")
    assert isinstance(result_ed, GetKeyResponse)
    assert len(result_ed.decode_key()) == 32

    with pytest.raises(Exception):  # Assuming unsupported algo raises error
        await client.get_key(algorithm="rsa")


@pytest.mark.asyncio
async def test_async_client_get_quote():
    client = AsyncDstackClientV0()
    result = await client.get_quote("test")
    assert isinstance(result, GetQuoteResponse)


@pytest.mark.asyncio
async def test_async_client_attest():
    client = AsyncDstackClientV0()
    result = await client.attest("test")
    assert isinstance(result, AttestResponse)
    assert len(result.attestation) > 0


def test_v0_surface_has_no_gpu_or_v1_methods():
    """The frozen surface never gained the GPU methods; the agent 404s them."""
    for name in ["attest_gpu", "gpu_info", "issue_cert"]:
        assert not hasattr(DstackClientV0, name)
        assert not hasattr(AsyncDstackClientV0, name)


def test_sync_client_attest_takes_report_data_only():
    """The frozen Attest has one field; a GPU flag belongs to v1."""
    client = DstackClientV0()
    with pytest.raises(TypeError):
        client.attest("test", include_boottime_gpu_evidence=True)


def test_sync_client_emit_event_reports_its_removal():
    """The agent always fails EmitEvent now; surface its message, do not swallow it."""
    client = DstackClientV0()
    with pytest.raises(Exception) as excinfo:
        client.emit_event("test-event", b"payload")
    assert "EmitEvent was removed" in str(excinfo.value)


@pytest.mark.asyncio
async def test_async_client_emit_event_reports_its_removal():
    client = AsyncDstackClientV0()
    with pytest.raises(Exception) as excinfo:
        await client.emit_event("test-event", b"payload")
    assert "EmitEvent was removed" in str(excinfo.value)


@pytest.mark.asyncio
async def test_async_client_emit_event_rejects_empty_name():
    client = AsyncDstackClientV0()
    with pytest.raises(ValueError):
        await client.emit_event("", b"payload")


@pytest.mark.asyncio
async def test_async_client_get_tls_key():
    client = AsyncDstackClientV0()
    result = await client.get_tls_key()
    assert isinstance(result, GetTlsKeyResponse)
    assert isinstance(result.key, str)
    assert result.key.startswith("-----BEGIN PRIVATE KEY-----")
    assert len(result.certificate_chain) > 0


@pytest.mark.asyncio
async def test_async_client_get_info():
    client = AsyncDstackClientV0()
    result = await client.info()
    check_info_response(result)


@pytest.mark.asyncio
async def test_tls_key_uniqueness():
    """Test that TLS keys are unique across multiple calls."""
    client = AsyncDstackClientV0()
    result1 = await client.get_tls_key()
    result2 = await client.get_tls_key()
    # TLS keys should be unique for each call
    assert result1.key != result2.key


@pytest.mark.asyncio
async def test_get_quote_raw_hash_error():
    with pytest.raises(ValueError) as excinfo:
        client = AsyncDstackClientV0()
        await client.get_quote("0" * 65)
    assert "64 bytes" in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        client = AsyncDstackClientV0()
        await client.get_quote(b"0" * 129)
    assert "64 bytes" in str(excinfo.value)


@pytest.mark.asyncio
async def test_report_data():
    reportdata = "test"
    client = AsyncDstackClientV0()
    result = await client.get_quote(reportdata)
    tdxQuote = TdxQuote(bytearray(result.decode_quote()))
    reportdata = reportdata.encode("utf-8") + b"\x00" * (64 - len(reportdata))
    assert reportdata == tdxQuote.body.reportdata


def test_sync_client_is_reachable():
    """Test that sync client can check if service is reachable."""
    client = DstackClientV0()
    is_reachable = client.is_reachable()
    assert isinstance(is_reachable, bool)
    assert is_reachable


@pytest.mark.asyncio
async def test_async_client_is_reachable():
    """Test that async client can check if service is reachable."""
    client = AsyncDstackClientV0()
    is_reachable = await client.is_reachable()
    assert isinstance(is_reachable, bool)
    assert is_reachable


def test_tls_key_as_uint8array():
    """Test that TLS key can be converted to bytes with as_uint8array method."""
    client = DstackClientV0()
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
    client = DstackClientV0()
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
    saved_env = os.environ.get("DSTACK_SIMULATOR_ENDPOINT")
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        del os.environ["DSTACK_SIMULATOR_ENDPOINT"]

    try:
        with pytest.raises(FileNotFoundError) as exc_info:
            DstackClientV0("/non/existent/socket")
        assert "Unix socket file /non/existent/socket does not exist" in str(
            exc_info.value
        )
    finally:
        # Restore environment variable
        if saved_env:
            os.environ["DSTACK_SIMULATOR_ENDPOINT"] = saved_env


def test_non_unix_socket_endpoints():
    """Test that client doesn't throw error for non-unix socket paths."""
    saved_env = os.environ.get("DSTACK_SIMULATOR_ENDPOINT")
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        del os.environ["DSTACK_SIMULATOR_ENDPOINT"]

    try:
        # These should not raise errors
        client1 = DstackClientV0("http://localhost:8080")
        client2 = DstackClientV0("https://example.com")
        assert client1 is not None
        assert client2 is not None
    finally:
        # Restore environment variable
        if saved_env:
            os.environ["DSTACK_SIMULATOR_ENDPOINT"] = saved_env


SIGN_TEST_DATA = b"Test message for signing"
SIGN_BAD_DATA = b"This is not the original message"


def test_sync_sign_then_verify_ed25519():
    client = DstackClientV0()
    algo = "ed25519"
    sign_resp = client.sign(algo, SIGN_TEST_DATA)
    assert isinstance(sign_resp, SignResponse)
    assert len(sign_resp.decode_signature()) > 0
    assert len(sign_resp.decode_public_key()) > 0
    assert len(sign_resp.signature_chain) == 3

    signature = sign_resp.decode_signature()
    public_key = sign_resp.decode_public_key()
    good = client.verify(algo, SIGN_TEST_DATA, signature, public_key)
    assert isinstance(good, VerifyResponse)
    assert good.valid is True
    assert client.verify(algo, SIGN_BAD_DATA, signature, public_key).valid is False


def test_sync_sign_then_verify_secp256k1():
    client = DstackClientV0()
    algo = "secp256k1"
    sign_resp = client.sign(algo, SIGN_TEST_DATA)
    assert isinstance(sign_resp, SignResponse)
    assert len(sign_resp.signature_chain) == 3

    signature = sign_resp.decode_signature()
    public_key = sign_resp.decode_public_key()
    assert client.verify(algo, SIGN_TEST_DATA, signature, public_key).valid is True
    assert client.verify(algo, SIGN_BAD_DATA, signature, public_key).valid is False


def test_sync_sign_then_verify_secp256k1_prehashed():
    client = DstackClientV0()
    algo = "secp256k1_prehashed"
    digest = hashlib.sha256(SIGN_TEST_DATA).digest()
    assert len(digest) == 32

    sign_resp = client.sign(algo, digest)
    assert isinstance(sign_resp, SignResponse)
    assert len(sign_resp.signature_chain) == 3

    signature = sign_resp.decode_signature()
    public_key = sign_resp.decode_public_key()
    assert client.verify(algo, digest, signature, public_key).valid is True

    bad_digest = hashlib.sha256(SIGN_BAD_DATA).digest()
    assert client.verify(algo, bad_digest, signature, public_key).valid is False


def test_sync_sign_prehashed_length_error():
    client = DstackClientV0()
    algo = "secp256k1_prehashed"
    with pytest.raises(ValueError) as excinfo:
        client.sign(algo, b"too short")
    assert "32-byte digest" in str(excinfo.value)


@pytest.mark.asyncio
async def test_async_sign_then_verify_ed25519():
    client = AsyncDstackClientV0()
    algo = "ed25519"
    sign_resp = await client.sign(algo, SIGN_TEST_DATA)
    assert isinstance(sign_resp, SignResponse)
    assert len(sign_resp.decode_signature()) > 0
    assert len(sign_resp.decode_public_key()) > 0

    signature = sign_resp.decode_signature()
    public_key = sign_resp.decode_public_key()
    good = await client.verify(algo, SIGN_TEST_DATA, signature, public_key)
    assert good.valid is True
    bad = await client.verify(algo, SIGN_BAD_DATA, signature, public_key)
    assert bad.valid is False


@pytest.mark.asyncio
async def test_async_sign_then_verify_secp256k1():
    client = AsyncDstackClientV0()
    algo = "secp256k1"
    sign_resp = await client.sign(algo, SIGN_TEST_DATA)
    assert isinstance(sign_resp, SignResponse)

    signature = sign_resp.decode_signature()
    public_key = sign_resp.decode_public_key()
    good = await client.verify(algo, SIGN_TEST_DATA, signature, public_key)
    assert good.valid is True
    bad = await client.verify(algo, SIGN_BAD_DATA, signature, public_key)
    assert bad.valid is False


@pytest.mark.asyncio
async def test_async_sign_then_verify_secp256k1_prehashed():
    client = AsyncDstackClientV0()
    algo = "secp256k1_prehashed"
    digest = hashlib.sha256(SIGN_TEST_DATA).digest()

    sign_resp = await client.sign(algo, digest)
    assert isinstance(sign_resp, SignResponse)

    signature = sign_resp.decode_signature()
    public_key = sign_resp.decode_public_key()
    good = await client.verify(algo, digest, signature, public_key)
    assert good.valid is True

    bad_digest = hashlib.sha256(SIGN_BAD_DATA).digest()
    bad = await client.verify(algo, bad_digest, signature, public_key)
    assert bad.valid is False


@pytest.mark.asyncio
async def test_async_sign_prehashed_length_error():
    client = AsyncDstackClientV0()
    algo = "secp256k1_prehashed"
    with pytest.raises(ValueError) as excinfo:
        await client.sign(algo, b"too short")
    assert "32-byte digest" in str(excinfo.value)


# Test deprecated TappdClient
def test_dstack_client_v0_deprecated():
    """The v0 client warns at construction.

    The frozen surface is what a 0.5.x program keeps working against, so the
    class stays -- but the unsuffixed ``DstackClient`` name now means v1, and a
    caller who landed on v0 by way of the rename should be told rather than
    discovering it when the derived key does not match.
    """
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        DstackClientV0()

        v0_warnings = [
            warning
            for warning in w
            if issubclass(warning.category, DeprecationWarning)
            and "DstackClientV0 is deprecated" in str(warning.message)
        ]

        assert len(v0_warnings) == 1
        assert "frozen at dstack 0.5.11" in str(v0_warnings[0].message)


def test_async_dstack_client_v0_deprecated():
    """Same for the async client; both are entry points to the frozen API."""
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        AsyncDstackClientV0()

        v0_warnings = [
            warning
            for warning in w
            if issubclass(warning.category, DeprecationWarning)
            and "AsyncDstackClientV0 is deprecated" in str(warning.message)
        ]

        assert len(v0_warnings) == 1


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


def test_sync_client_version():
    client = DstackClientV0()
    result = client.version()
    assert isinstance(result, VersionResponse)
    assert result.version != ""


@pytest.mark.asyncio
async def test_async_client_version():
    client = AsyncDstackClientV0()
    result = await client.version()
    assert isinstance(result, VersionResponse)
    assert result.version != ""


def test_sync_client_get_key_k256_alias():
    client = DstackClientV0()
    result_k256 = client.get_key(path="/test", purpose="p", algorithm="k256")
    result_secp = client.get_key(path="/test", purpose="p", algorithm="secp256k1")
    # k256 is an alias for secp256k1, should produce the same key
    assert result_k256.decode_key() == result_secp.decode_key()


@pytest.mark.asyncio
async def test_async_client_get_key_k256_alias():
    client = AsyncDstackClientV0()
    result_k256 = await client.get_key(path="/test", purpose="p", algorithm="k256")
    result_secp = await client.get_key(path="/test", purpose="p", algorithm="secp256k1")
    assert result_k256.decode_key() == result_secp.decode_key()


def test_sync_client_get_key_secp256k1_prehashed_rejected():
    client = DstackClientV0()
    with pytest.raises(Exception):
        client.get_key(algorithm="secp256k1_prehashed")


@pytest.mark.asyncio
async def test_async_client_get_key_secp256k1_prehashed_rejected():
    client = AsyncDstackClientV0()
    with pytest.raises(Exception):
        await client.get_key(algorithm="secp256k1_prehashed")


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
    client = DstackClientV0()
    result = client.get_key()
    assert isinstance(result, GetKeyResponse)
    assert isinstance(result.decode_key(), bytes)
    assert len(result.decode_key()) == 32


@pytest.mark.asyncio
async def test_sync_client_in_async_context_get_info():
    """Test that sync client info works when called from async context."""
    client = DstackClientV0()
    result = client.info()
    check_info_response(result)


@pytest.mark.asyncio
async def test_mixed_sync_async_calls():
    """Test mixing sync and async client calls in the same async context."""
    sync_client = DstackClientV0()
    async_client = AsyncDstackClientV0()

    # Call sync client from async context
    sync_result = sync_client.get_key()
    assert isinstance(sync_result, GetKeyResponse)

    # Call async client normally
    async_result = await async_client.get_key()
    assert isinstance(async_result, GetKeyResponse)

    # Both should work and return valid results
    assert len(sync_result.decode_key()) == 32
    assert len(async_result.decode_key()) == 32


@pytest.mark.asyncio
async def test_get_tls_key_new_options_payload(monkeypatch):
    """0.5.7+ TLS options reach the payload and trigger the Version probe."""
    calls: list = []

    async def fake_send(self, method, payload):
        calls.append((method, payload))
        if method == "Version":
            return {"version": "0.5.7", "rev": "test"}
        return {"key": "k", "certificate_chain": []}

    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:0")
    monkeypatch.setattr(AsyncDstackClientV0, "_send_rpc_request", fake_send)
    client = AsyncDstackClientV0()
    result = await client.get_tls_key(
        subject="api.example.com",
        not_before=1_700_000_000,
        not_after=1_800_000_000,
        with_app_info=True,
    )
    assert isinstance(result, GetTlsKeyResponse)
    assert [c[0] for c in calls] == ["Version", "GetTlsKey"]
    payload = calls[1][1]
    assert payload["not_before"] == 1_700_000_000
    assert payload["not_after"] == 1_800_000_000
    assert payload["with_app_info"] is True


@pytest.mark.asyncio
async def test_get_tls_key_legacy_options_skip_version_probe(monkeypatch):
    """Calls without the new options must NOT probe Version (backward compat)."""
    calls: list = []

    async def fake_send(self, method, payload):
        calls.append((method, payload))
        return {"key": "k", "certificate_chain": []}

    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:0")
    monkeypatch.setattr(AsyncDstackClientV0, "_send_rpc_request", fake_send)
    client = AsyncDstackClientV0()
    await client.get_tls_key(subject="api.example.com")
    assert [c[0] for c in calls] == ["GetTlsKey"]
    payload = calls[0][1]
    assert "not_before" not in payload
    assert "not_after" not in payload
    assert "with_app_info" not in payload


@pytest.mark.asyncio
async def test_get_tls_key_new_options_require_version(monkeypatch):
    """Raise a clear error when Version RPC is unavailable on older OS."""

    async def fake_send(self, method, payload):
        if method == "Version":
            raise RuntimeError("Version not implemented")
        return {"key": "k", "certificate_chain": []}

    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:0")
    monkeypatch.setattr(AsyncDstackClientV0, "_send_rpc_request", fake_send)
    client = AsyncDstackClientV0()
    with pytest.raises(RuntimeError, match="TLS key options"):
        await client.get_tls_key(with_app_info=False)


def test_v0_warns_even_when_the_caller_asks_for_sync_http():
    """``use_sync_http`` is a public transport option, not a warning switch.

    The sync wrappers build their async twin with it, and used to suppress the
    deprecation warning by reading it -- so a user who set the documented flag
    themselves was silently opted out of the one signal telling them the surface
    is frozen.
    """
    with pytest.warns(DeprecationWarning, match="AsyncDstackClientV0 is deprecated"):
        AsyncDstackClientV0(use_sync_http=True)


def test_v0_sync_wrapper_warns_exactly_once():
    """It builds an AsyncDstackClientV0 internally; that must not warn twice."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        DstackClientV0()
    v0_warnings = [
        w for w in caught if "DstackClientV0 is deprecated" in str(w.message)
    ]
    assert len(v0_warnings) == 1, [str(w.message) for w in caught]
