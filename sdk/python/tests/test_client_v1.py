# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from typing import List

from pydantic import ValidationError
import pytest

from dstack_sdk import AsyncDstackClient
from dstack_sdk import AsyncDstackClientV0
from dstack_sdk import AsyncDstackClientV1
from dstack_sdk import AttestGpuResponseV1
from dstack_sdk import AttestResponseV1
from dstack_sdk import DstackClient
from dstack_sdk import DstackClientV0
from dstack_sdk import DstackClientV1
from dstack_sdk import GetKeyResponseV1
from dstack_sdk import GpuEvidenceBundleV1
from dstack_sdk import InfoResponseV1
from dstack_sdk import IssueCertResponseV1
from dstack_sdk import VersionResponseV1

NONCE = bytes([0xAB]) * 32


def test_v1_posts_to_the_v1_path():
    """The agent picks the version from the URL path alone."""
    assert AsyncDstackClientV1.PATH_PREFIX == "/v1/"
    assert AsyncDstackClientV0.PATH_PREFIX == "/"


def test_unsuffixed_names_are_the_v1_clients():
    """Unsuffixed means v1: it is the default, and the V1 names are the same class."""
    assert DstackClient is DstackClientV1
    assert AsyncDstackClient is AsyncDstackClientV1


def test_v0_call_shapes_fail_loudly_on_the_default_client():
    """Pre-0.6 code aimed at the unsuffixed name breaks, rather than deriving other keys.

    Both v0 spellings of get_key are rejected before a request goes out, so an
    upgraded caller sees a TypeError instead of a key it did not ask for.
    """
    client = DstackClient()
    with pytest.raises(TypeError):
        client.get_key(path="storage-encryption", purpose="mainnet")
    with pytest.raises(TypeError):
        client.get_key("storage-encryption")
    for name in ["sign", "verify", "emit_event", "get_quote", "get_tls_key"]:
        assert not hasattr(client, name)


def test_v1_surface_is_exactly_six_methods():
    """v1 serves only what needs the TEE: no sign, verify, emit_event, quote or GPU info."""
    for name in [
        "sign",
        "verify",
        "emit_event",
        "get_quote",
        "gpu_info",
        "get_tls_key",
    ]:
        assert not hasattr(DstackClientV1, name)
        assert not hasattr(AsyncDstackClientV1, name)
    for name in [
        "issue_cert",
        "get_key",
        "attest",
        "attest_gpu",
        "info",
        "version",
    ]:
        assert hasattr(DstackClientV1, name)
        assert hasattr(AsyncDstackClientV1, name)


def test_sync_v1_version():
    result = DstackClientV1().version()
    assert isinstance(result, VersionResponseV1)
    assert result.version != ""


@pytest.mark.asyncio
async def test_async_v1_version():
    result = await AsyncDstackClientV1().version()
    assert isinstance(result, VersionResponseV1)
    assert result.version != ""


def test_sync_v1_info():
    result = DstackClientV1().info()
    check_info_response(result)


@pytest.mark.asyncio
async def test_async_v1_info():
    result = await AsyncDstackClientV1().info()
    check_info_response(result)


def check_info_response(result: InfoResponseV1):
    assert isinstance(result, InfoResponseV1)
    # bytes, not hex: the lengths are the raw ones the proto declares.
    assert len(result.app_id) == 20
    assert len(result.compose_hash) == 32
    assert len(result.instance_id) == 20
    assert len(result.device_id) == 32
    assert len(result.os_image_hash) in (0, 32)
    assert len(result.mr_aggregated) == 32
    assert len(result.app_compose) > 0
    # The measurement registers and the event log belong to attest(), which
    # returns them quote-backed. They must not reappear here.
    assert not hasattr(result, "tcb_info")
    assert not hasattr(result, "app_cert")


def test_sync_v1_get_key():
    client = DstackClientV1()
    result = client.get_key("storage-encryption", "secp256k1")
    assert isinstance(result, GetKeyResponseV1)
    assert len(result.key) == 32
    # secp256k1 public keys are SEC1 compressed, and the chain's first link
    # commits to exactly these bytes.
    assert len(result.public_key) == 33
    assert len(result.signature_chain) == 2

    ed = client.get_key("storage-encryption", "ed25519")
    assert len(ed.key) == 32
    assert len(ed.public_key) == 32
    # The v1 KDF binds the algorithm, so one name no longer serves two curves.
    assert ed.key != result.key


@pytest.mark.asyncio
async def test_async_v1_get_key_is_deterministic_per_domain():
    client = AsyncDstackClientV1()
    first = await client.get_key("a", "secp256k1")
    again = await client.get_key("a", "secp256k1")
    other = await client.get_key("a/b", "secp256k1")
    assert first.key == again.key
    # Derivation is flat: `a/b` is not a child of `a`.
    assert other.key != first.key


def test_v1_get_key_requires_an_algorithm():
    client = DstackClientV1()
    with pytest.raises(ValueError, match="algorithm is required"):
        client.get_key("storage-encryption", "")


@pytest.mark.asyncio
async def test_async_v1_get_key_rejects_the_v0_k256_alias():
    """v0 accepted `k256`; v1 refuses rather than guess what the caller meant."""
    client = AsyncDstackClientV1()
    with pytest.raises(Exception) as excinfo:
        await client.get_key("storage-encryption", "k256")
    assert "k256" in str(excinfo.value)


def test_v1_keys_differ_from_v0_keys():
    """No compatibility mode: the same name yields different key material."""
    v0 = DstackClientV0().get_key("storage-encryption", "")
    v1 = DstackClientV1().get_key("storage-encryption", "secp256k1")
    assert v1.key != v0.decode_key()


def test_sync_v1_attest():
    result = DstackClientV1().attest(b"user:alice:nonce123")
    assert isinstance(result, AttestResponseV1)
    assert len(result.attestation) > 0


@pytest.mark.asyncio
async def test_async_v1_attest_boottime_gpu_evidence(monkeypatch):
    """Boot-time evidence arrives in the same bundle shape attest_gpu returns."""
    evidence = b'{"result_code":0,"claims":[]}'

    async def fake_send(self, method, payload):
        assert method == "Attest"
        assert payload["include_boottime_gpu_evidence"] is True
        return {
            "attestation": "deadbeef",
            "boottime_gpu_evidence": [
                {
                    "vendor": "nvidia",
                    "format": "nvidia-nvattest-boottime-json-v1",
                    "evidence": evidence.hex(),
                }
            ],
        }

    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:0")
    monkeypatch.setattr(AsyncDstackClientV1, "_send_rpc_request", fake_send)
    result = await AsyncDstackClientV1().attest(
        b"test", include_boottime_gpu_evidence=True
    )
    assert isinstance(result, AttestResponseV1)
    bundle = result.boottime_gpu_evidence[0]
    assert isinstance(bundle, GpuEvidenceBundleV1)
    assert bundle.format == "nvidia-nvattest-boottime-json-v1"
    # sha256 of exactly these bytes is what the `gpu-attestation` event commits
    # to, so the decode must be byte-for-byte, not a re-serialized parse.
    assert bundle.evidence == evidence


def test_sync_v1_attest_boottime_gpu_evidence_defaults_to_empty():
    """No GPU output in the simulator: absence is an empty list, not a sentinel."""
    result = DstackClientV1().attest(
        b"user:alice:nonce123", include_boottime_gpu_evidence=True
    )
    assert result.boottime_gpu_evidence == []
    # Same model as attest_gpu's bundles, so one parser serves both methods.
    bundles = List[GpuEvidenceBundleV1]
    assert AttestResponseV1.model_fields["boottime_gpu_evidence"].annotation == bundles
    assert AttestGpuResponseV1.model_fields["bundles"].annotation == bundles


@pytest.mark.asyncio
async def test_async_v1_attest_report_data_bounds():
    client = AsyncDstackClientV1()
    with pytest.raises(ValueError):
        await client.attest(b"")
    with pytest.raises(ValueError, match="64 bytes"):
        await client.attest(b"0" * 65)
    # 64 bytes is the maximum, not one past it.
    assert len((await client.attest(b"0" * 64)).attestation) > 0


@pytest.mark.asyncio
async def test_async_v1_attest_refuses_str():
    """v1 takes bytes, so a hex digest cannot be attested as its characters.

    v0 UTF-8 encoded a str, which made ``attest("deadbeef")`` commit to eight
    ASCII characters rather than the four bytes they spell -- no error, just a
    quote over the wrong value. The v0 client keeps that behaviour; v1 does not.
    """
    client = AsyncDstackClientV1()
    with pytest.raises(TypeError, match="bytes.fromhex"):
        await client.attest("deadbeef")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="must be bytes, not int"):
        await client.attest(42)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_async_v1_attest_gpu_refuses_str():
    """A 32-character str would otherwise pass the length check unnoticed."""
    client = AsyncDstackClientV1()
    with pytest.raises(TypeError, match="must be bytes"):
        await client.attest_gpu("a" * 32)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_async_v1_attest_gpu(monkeypatch):
    evidence = b"\x01\x02\x03opaque"

    async def fake_send(self, method, payload):
        assert method == "AttestGpu"
        assert payload == {"nonce": NONCE.hex()}
        return {
            "bundles": [
                {
                    "vendor": "nvidia",
                    "format": "nvidia-test-v1",
                    "evidence": evidence.hex(),
                }
            ]
        }

    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:0")
    monkeypatch.setattr(AsyncDstackClientV1, "_send_rpc_request", fake_send)
    result = await AsyncDstackClientV1().attest_gpu(NONCE)
    assert isinstance(result, AttestGpuResponseV1)
    assert len(result.bundles) == 1
    assert result.bundles[0].vendor == "nvidia"
    assert result.bundles[0].evidence == evidence


@pytest.mark.asyncio
async def test_async_v1_attest_gpu_rejects_wrong_nonce_length():
    """SPDM fixes the evidence nonce at 32 bytes; catch it before the round trip."""
    client = AsyncDstackClientV1()
    for bad in [b"", bytes(31), bytes(33)]:
        with pytest.raises(ValueError, match="32 bytes"):
            await client.attest_gpu(bad)
    # A non-bytes nonce is a TypeError, not a length complaint -- see
    # test_async_v1_attest_gpu_refuses_str.
    with pytest.raises(TypeError):
        await client.attest_gpu(object())  # type: ignore[arg-type]


def test_sync_v1_attest_gpu_reaches_the_agent():
    """No GPU in the simulator, so the agent's own refusal is the success signal.

    501 rather than 4xx, and the client must pass both the status and the
    agent's own words through: a caller that sees 4xx retries a call this image
    can never answer.
    """
    with pytest.raises(Exception) as excinfo:
        DstackClientV1().attest_gpu(NONCE)
    message = str(excinfo.value)
    assert "501" in message, message
    assert "GPU attestation is not available" in message, message


def test_sync_v1_issue_cert():
    result = DstackClientV1().issue_cert(subject="api.example.com")
    assert isinstance(result, IssueCertResponseV1)
    assert result.key.startswith("-----BEGIN PRIVATE KEY-----")
    assert len(result.certificate_chain) > 0


@pytest.mark.asyncio
async def test_async_v1_issue_cert_key_is_fresh_per_call():
    client = AsyncDstackClientV1()
    first = await client.issue_cert(subject="api.example.com")
    again = await client.issue_cert(subject="api.example.com")
    assert first.key != again.key


@pytest.mark.asyncio
async def test_async_v1_issue_cert_payload(monkeypatch):
    calls: list = []

    async def fake_send(self, method, payload):
        calls.append((method, payload))
        return {"key": "k", "certificate_chain": []}

    monkeypatch.setenv("DSTACK_SIMULATOR_ENDPOINT", "http://localhost:0")
    monkeypatch.setattr(AsyncDstackClientV1, "_send_rpc_request", fake_send)
    await AsyncDstackClientV1().issue_cert(
        subject="api.example.com",
        alt_names=["localhost"],
        usage_ra_tls=True,
        with_app_info=True,
        not_before=1_700_000_000,
        not_after=1_800_000_000,
    )
    method, payload = calls[0]
    # v1 requires a 0.6 agent, so unlike v0 it never probes Version first.
    assert [c[0] for c in calls] == ["IssueCert"]
    assert method == "IssueCert"
    assert payload["subject"] == "api.example.com"
    assert payload["alt_names"] == ["localhost"]
    assert payload["usage_ra_tls"] is True
    assert payload["with_app_info"] is True
    assert payload["not_before"] == 1_700_000_000
    assert payload["not_after"] == 1_800_000_000


@pytest.mark.asyncio
async def test_async_v1_client_context_manager():
    async with AsyncDstackClientV1() as client:
        assert (await client.version()).version != ""


def test_sync_v1_client_context_manager():
    client = DstackClientV1()
    with client:
        assert client.version().version != ""
    assert client.async_client._sync_client is None


def test_v1_unix_socket_file_not_exist(monkeypatch):
    monkeypatch.delenv("DSTACK_SIMULATOR_ENDPOINT", raising=False)
    with pytest.raises(FileNotFoundError):
        DstackClientV1("/non/existent/socket")


# The wire is hex; anything else is a response no verifier should act on. Go
# names the field it could not decode and Rust refuses the string outright, so
# Python doing the same is what keeps a malformed answer malformed in every
# SDK rather than in three of four.
@pytest.mark.parametrize(
    "bad",
    [
        "aabbzz",  # a non-hex pair
        "abc",  # odd length: the last digit has nowhere to go
        "aa bb",  # bytes.fromhex() skips whitespace; the wire never has any
        "aa\nbb",
    ],
)
def test_v1_malformed_hex_is_rejected(bad: str):
    with pytest.raises(ValidationError):
        GetKeyResponseV1(key=bad, public_key="bb" * 33, signature_chain=[])


def test_v1_malformed_chain_link_is_rejected():
    """One bad link must fail the chain, not silently shorten it."""
    with pytest.raises(ValidationError):
        GetKeyResponseV1(
            key="aa" * 32, public_key="bb" * 33, signature_chain=["aabb", "qq"]
        )


def test_v1_absent_identity_hashes_are_empty():
    """`os_image_hash` and `mr_aggregated` default rather than reject.

    Both are plain `bytes` in the proto, so a current agent always sends them --
    empty when it could not compute one. Reading a response that omits one as
    those same empty bytes keeps a degraded `Info` parseable instead of
    unparseable, which is what Rust's `#[serde(default)]` already did.
    """
    info = InfoResponseV1(
        app_id="aa" * 20,
        compose_hash="bb" * 32,
        instance_id="cc" * 20,
        device_id="dd" * 32,
    )
    assert info.os_image_hash == b""
    assert info.mr_aggregated == b""
    assert info.app_id == b"\xaa" * 20
