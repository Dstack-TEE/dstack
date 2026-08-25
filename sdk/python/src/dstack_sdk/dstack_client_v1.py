# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""Client for the ``dstack.guest.v1`` guest agent API.

v1 is a separate surface, not a newer dialect of the frozen one: it is served
at ``/v1/<Method>`` on the same socket, and the guest agent picks the version
from the URL path alone. This client mirrors that surface and nothing else. It
does not translate calls to v0, and it has no ``Sign``, ``Verify``,
``EmitEvent``, ``GetQuote`` or ``GpuInfo``, because v1 has none of them.

Keys are the one thing that must not be assumed to carry over: the v1 KDF binds
the algorithm and its own context tag alongside the domain, so ``get_key`` here
returns different key material than ``DstackClientV0.get_key`` does for the same
name. There is no compatibility mode. See ``docs/guest-api-v1.md``.
"""

import binascii
import re
from typing import Annotated
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from pydantic import BaseModel
from pydantic import BeforeValidator
from pydantic import PlainSerializer

from .dstack_client_v0 import AsyncBaseClient
from .dstack_client_v0 import BaseClient
from .dstack_client_v0 import call_async

#: An even number of hex digits, and nothing else.
_HEX_ONLY = re.compile(r"\A(?:[0-9a-fA-F]{2})*\Z")


def _decode_hex(value: Any) -> Any:
    r"""Turn a wire hex string into bytes, leaving anything else to pydantic.

    The regex is not redundant with ``bytes.fromhex``: that helper skips ASCII
    whitespace, so ``"aa bb"`` and ``"aa\nbb"`` decode happily while the error
    message here promises they do not. Rust and Go reject both, and a field
    one SDK accepts and another refuses is a field verifiers cannot rely on.
    """
    if isinstance(value, str):
        if not _HEX_ONLY.match(value):
            raise ValueError(f"expected an even-length hex string, got {value!r}")
        return bytes.fromhex(value)
    return value


#: A protobuf ``bytes`` field: lowercase hex on the wire, ``bytes`` in Python.
#:
#: v0 exposed these as ``str`` with a ``decode_*`` helper beside them, which
#: made the wrong call the easy one -- ``public_key`` passed straight to a
#: signature-chain claim builder is 66 ASCII characters, not a 33-byte key, and
#: nothing raises until the chain fails to verify. The annotation also replaces
#: pydantic's own ``str`` -> ``bytes`` coercion, which would UTF-8 encode the
#: hex string rather than decode it -- the same silent wrong answer.
#:
#: Serialization is hex only in JSON mode, so ``model_dump_json()`` round-trips
#: through the wire form while ``model_dump()`` keeps the bytes.
HexBytes = Annotated[
    bytes,
    BeforeValidator(_decode_hex),
    PlainSerializer(lambda value: value.hex(), return_type=str, when_used="json"),
]


class IssueCertResponseV1(BaseModel):
    # PEM-encoded private key, freshly generated for this call. It is not
    # derived from the app identity: two calls with the same arguments return
    # two unrelated keys. get_key is the method that derives a stable one.
    key: str
    # Leaf first, each entry PEM-encoded, exactly as the signer returned it.
    certificate_chain: List[str]


class GetKeyResponseV1(BaseModel):
    # 32 bytes for both algorithms.
    key: HexBytes
    # SEC1 compressed (33 bytes) for secp256k1, raw (32 bytes) for ed25519.
    # This is the exact byte string the chain's first link commits to.
    public_key: HexBytes
    # Two links: the app root key's signature over the v1 key claim, then the
    # KMS root key's signature over the app root public key.
    signature_chain: List[HexBytes]


class GpuEvidenceBundleV1(BaseModel):
    """One vendor's GPU evidence, however it was obtained.

    The same bundle shape carries both fresh ``attest_gpu()`` output and the
    boot-time record in ``AttestResponseV1.boottime_gpu_evidence``, so a caller
    writes one parser and switches on ``format``:

    - ``nvidia-nvattest-collect-evidence-json-v1`` -- collected on demand,
      against the nonce passed to ``attest_gpu()``.
    - ``nvidia-nvattest-boottime-json-v1`` -- the record nvattest wrote at guest
      boot, against its own nonce.
    """

    vendor: str
    format: str
    # Opaque vendor-native evidence, hex-encoded on the wire and exactly as the
    # vendor emitted it. Do not assume UTF-8 or JSON.
    #
    # The exactness matters for the boot-time format: the binding rule is
    # sha256 over precisely these bytes, compared against ``evidence_sha256``
    # in the measured ``gpu-attestation`` event. Parsing and re-serializing the
    # JSON changes key order and whitespace, and so changes the digest.
    evidence: HexBytes


class AttestResponseV1(BaseModel):
    attestation: HexBytes
    # The GPU evidence nvattest recorded during guest boot, in the same bundle
    # shape attest_gpu returns. Empty unless the request set
    # include_boottime_gpu_evidence and the guest has boot-time output. Not
    # bound to report_data: verify each bundle by replaying the runtime event
    # log and comparing sha256 of its `evidence` against evidence_sha256 in the
    # `gpu-attestation` event.
    boottime_gpu_evidence: List[GpuEvidenceBundleV1] = []


class AttestGpuResponseV1(BaseModel):
    """Result of fresh, on-demand GPU evidence collection."""

    bundles: List[GpuEvidenceBundleV1]


class VersionResponseV1(BaseModel):
    version: str
    rev: str


class InfoResponseV1(BaseModel):
    """Identity and configuration. Not attestation.

    Nothing here is evidence: it arrives over a local socket with no quote
    behind it. The measurement registers and the event log are deliberately
    absent -- they belong to ``attest()``, which returns them quote-backed.
    ``compose_hash``, ``os_image_hash`` and ``mr_aggregated`` are here because
    they identify *which* application and image this is, and a relying party
    still confirms them against an attestation.

    The identity fields are ``bytes``, matching the proto, where the v0
    ``InfoResponse`` hands back hex strings. Call ``.hex()`` to print one.
    """

    app_id: HexBytes
    app_name: str = ""
    compose_hash: HexBytes
    # Verbatim deployed bytes; compose_hash is sha256 over exactly these. Do
    # not parse and re-serialize before hashing -- key order, whitespace and
    # unknown fields all change the digest, and that digest is what gets
    # whitelisted on chain.
    app_compose: str = ""
    instance_id: HexBytes
    # Identifies the host machine, not this instance.
    device_id: HexBytes
    # Plain `bytes` in the proto, so the agent always sends these -- empty when
    # it could not compute one. A response that omits one is read as those same
    # empty bytes rather than rejected, as Rust's `#[serde(default)]` does.
    os_image_hash: HexBytes = b""
    mr_aggregated: HexBytes = b""
    vm_config: str = ""
    key_provider_info: str = ""
    cloud_vendor: str = ""
    cloud_product: str = ""


class AsyncDstackClientV1(AsyncBaseClient):
    """Async client for the ``dstack.guest.v1`` API, served at ``/v1``.

    Construction, endpoint resolution and timeouts match
    ``AsyncDstackClientV0``; only the path prefix and the method set differ.
    """

    PATH_PREFIX = "/v1/"

    async def issue_cert(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = True,
        usage_client_auth: bool = False,
        *,
        with_app_info: bool = False,
        not_before: Optional[int] = None,
        not_after: Optional[int] = None,
    ) -> IssueCertResponseV1:
        """Issue a certificate for this application.

        v0 called this ``get_tls_key``, which named the by-product rather than
        the request. ``not_before`` / ``not_after`` are seconds since the UNIX
        epoch, and the agent rejects a ``not_before`` that is not earlier than
        ``not_after``.
        """
        data: Dict[str, Any] = {
            "subject": subject or "",
            "usage_ra_tls": usage_ra_tls,
            "usage_server_auth": usage_server_auth,
            "usage_client_auth": usage_client_auth,
            "with_app_info": with_app_info,
        }
        if alt_names:
            data["alt_names"] = list(alt_names)
        if not_before is not None:
            data["not_before"] = not_before
        if not_after is not None:
            data["not_after"] = not_after

        result = await self._send_rpc_request("IssueCert", data)
        return IssueCertResponseV1(**result)

    async def get_key(self, domain: str, algorithm: str) -> GetKeyResponseV1:
        """Derive an application key from ``(domain, algorithm)``.

        Both arguments are required. Derivation is flat: two domains yield
        unrelated keys, and ``a/b`` is not a child of ``a``. ``algorithm`` is
        exactly ``secp256k1`` or ``ed25519`` -- there is no default and no
        ``k256`` alias, because in v0 a typo silently produced a key of the
        wrong type under a name the caller thought meant something else.
        """
        if not algorithm:
            raise ValueError("algorithm is required, use `secp256k1` or `ed25519`")
        data: Dict[str, Any] = {"domain": domain, "algorithm": algorithm}
        result = await self._send_rpc_request("GetKey", data)
        return GetKeyResponseV1(**result)

    async def attest(
        self,
        report_data: str | bytes,
        include_boottime_gpu_evidence: bool = False,
    ) -> AttestResponseV1:
        """Produce a versioned attestation over the given report data.

        The sole CVM attestation entry point in v1: the dstack attestation
        format already carries the quote and the event log, so v0's TDX-only
        ``get_quote`` has nothing left to add.

        Set include_boottime_gpu_evidence to also return the boot-time GPU
        attestation evidence in ``AttestResponseV1.boottime_gpu_evidence``, as
        the same ``GpuEvidenceBundleV1`` list ``attest_gpu`` returns. A guest
        with no boot-time output returns an empty list.
        """
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        report_bytes: bytes = (
            report_data.encode() if isinstance(report_data, str) else report_data
        )
        if len(report_bytes) > 64:
            raise ValueError("report_data must be at most 64 bytes")
        data: Dict[str, Any] = {
            "report_data": binascii.hexlify(report_bytes).decode(),
            "include_boottime_gpu_evidence": include_boottime_gpu_evidence,
        }
        result = await self._send_rpc_request("Attest", data)
        return AttestResponseV1(**result)

    async def attest_gpu(self, nonce: bytes) -> AttestGpuResponseV1:
        """Collect vendor-native GPU evidence now, against a 32-byte nonce.

        Select a verifier using each bundle's vendor and format, then check the
        signature, certificate chain, measurements, and the nonce embedded in
        the evidence. The nonce is passed to the GPU verbatim, so it can be
        compared directly against the ``eat_nonce`` claim; to bind a longer
        challenge, hash it yourself.
        """
        if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != 32:
            raise ValueError("nonce must be exactly 32 bytes")
        result = await self._send_rpc_request(
            "AttestGpu", {"nonce": binascii.hexlify(bytes(nonce)).decode()}
        )
        return AttestGpuResponseV1(**result)

    async def info(self) -> InfoResponseV1:
        """Return this application's identity and measurements."""
        result = await self._send_rpc_request("Info", {})
        return InfoResponseV1(**result)

    async def version(self) -> VersionResponseV1:
        """Return the guest agent version."""
        result = await self._send_rpc_request("Version", {})
        return VersionResponseV1(**result)


class DstackClientV1(BaseClient):
    """Sync client for the ``dstack.guest.v1`` API, served at ``/v1``.

    See ``AsyncDstackClientV1``; every method here is its blocking twin.
    """

    PATH_PREFIX = "/v1/"

    def __init__(self, endpoint: str | None = None, *, timeout: float = 3):
        """Initialize client with HTTP or Unix-socket transport.

        If a non-HTTP(S) endpoint is provided, it is treated as a Unix socket
        path and validated for existence.
        """
        self.async_client = AsyncDstackClientV1(
            endpoint, use_sync_http=True, timeout=timeout
        )

    @call_async
    def issue_cert(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = True,
        usage_client_auth: bool = False,
        *,
        with_app_info: bool = False,
        not_before: Optional[int] = None,
        not_after: Optional[int] = None,
    ) -> IssueCertResponseV1:
        """Issue a certificate for this application."""
        raise NotImplementedError

    @call_async
    def get_key(self, domain: str, algorithm: str) -> GetKeyResponseV1:
        """Derive an application key from ``(domain, algorithm)``."""
        raise NotImplementedError

    @call_async
    def attest(
        self,
        report_data: str | bytes,
        include_boottime_gpu_evidence: bool = False,
    ) -> AttestResponseV1:
        """Produce a versioned attestation over the given report data."""
        raise NotImplementedError

    @call_async
    def attest_gpu(self, nonce: bytes) -> AttestGpuResponseV1:
        """Collect vendor-native GPU evidence now, against a 32-byte nonce."""
        raise NotImplementedError

    @call_async
    def info(self) -> InfoResponseV1:
        """Return this application's identity and measurements."""
        raise NotImplementedError

    @call_async
    def version(self) -> VersionResponseV1:
        """Return the guest agent version."""
        raise NotImplementedError

    @call_async
    def __enter__(self):
        raise NotImplementedError

    @call_async
    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError


#: The recommended client: unsuffixed means v1, the surface that gains
#: capabilities. Code written against the pre-0.6 unsuffixed name -- which then
#: meant v0 -- breaks loudly here rather than quietly deriving other keys,
#: because the v1 methods have different signatures and ``get_key`` refuses to
#: guess an algorithm. Pin such code to ``DstackClientV0`` to keep the frozen
#: surface.
DstackClient = DstackClientV1

#: The recommended async client; see ``DstackClient``.
AsyncDstackClient = AsyncDstackClientV1
