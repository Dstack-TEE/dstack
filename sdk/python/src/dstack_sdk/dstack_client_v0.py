# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import functools
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
import json
import logging
import os
from typing import Any
from typing import Dict
from typing import Generic
from typing import List
from typing import Optional
from typing import TypeVar
from typing import cast
import warnings

import httpx
from pydantic import BaseModel

logger = logging.getLogger("dstack_sdk")

try:
    __version__ = _pkg_version("dstack-sdk")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"


def get_endpoint(endpoint: str | None = None) -> str:
    if endpoint:
        return endpoint
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(
            f"Using simulator endpoint: {os.environ['DSTACK_SIMULATOR_ENDPOINT']}"
        )
        return os.environ["DSTACK_SIMULATOR_ENDPOINT"]
    # Try paths in order: legacy paths first, then namespaced paths
    socket_paths = [
        "/var/run/dstack.sock",
        "/run/dstack.sock",
        "/var/run/dstack/dstack.sock",
        "/run/dstack/dstack.sock",
    ]
    for path in socket_paths:
        if os.path.exists(path):
            return path
    # Default to new path even if not exists (will fail with clear error)
    return socket_paths[0]


def get_tappd_endpoint(endpoint: str | None = None) -> str:
    if endpoint:
        return endpoint
    if "TAPPD_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(f"Using tappd endpoint: {os.environ['TAPPD_SIMULATOR_ENDPOINT']}")
        return os.environ["TAPPD_SIMULATOR_ENDPOINT"]
    # Try paths in order: legacy paths first, then namespaced paths
    socket_paths = [
        "/var/run/tappd.sock",
        "/run/tappd.sock",
        "/var/run/dstack/tappd.sock",
        "/run/dstack/tappd.sock",
    ]
    for path in socket_paths:
        if os.path.exists(path):
            return path
    return socket_paths[0]


def emit_deprecation_warning(message: str, stacklevel: int = 2) -> None:
    warnings.warn(message, DeprecationWarning, stacklevel=stacklevel)


def call_async(func):
    """Call async methods synchronously.

    This decorator wraps a method to call its async counterpart from
    self.async_client and run it synchronously using `coro.send(None)`.

    Supports being called from within async contexts by using
    a sync HTTP client internally and a custom coroutine runner.
    """

    def _step_coro(coro):
        """Step through a coroutine that only does sync operations."""
        try:
            result = coro.send(None)
            raise RuntimeError(f"Coroutine yielded unexpected value: {result}")
        except StopIteration as e:
            return e.value

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        magic_map = {
            "__enter__": "__aenter__",
            "__exit__": "__aexit__",
        }
        async_method_name = magic_map.get(func.__name__) or func.__name__
        async_method = getattr(self.async_client, async_method_name)
        return _step_coro(async_method(*args, **kwargs))

    return wrapper


class GetTlsKeyResponse(BaseModel):
    key: str
    certificate_chain: List[str]

    def as_uint8array(self, max_length: Optional[int] = None) -> bytes:
        content = self.key.replace("-----BEGIN PRIVATE KEY-----", "")
        content = content.replace("-----END PRIVATE KEY-----", "")
        content = content.replace("\n", "").replace(" ", "")

        binary_der = base64.b64decode(content)

        if max_length is None:
            return binary_der
        else:
            result = bytearray(max_length)
            copy_len = min(len(binary_der), max_length)
            result[:copy_len] = binary_der[:copy_len]
            return bytes(result)


class GetKeyResponse(BaseModel):
    key: str
    signature_chain: List[str]

    def decode_key(self) -> bytes:
        return bytes.fromhex(self.key)

    def decode_signature_chain(self) -> List[bytes]:
        return [bytes.fromhex(chain) for chain in self.signature_chain]


class GetQuoteResponse(BaseModel):
    quote: str
    event_log: str
    report_data: str = ""
    vm_config: str = ""

    def decode_quote(self) -> bytes:
        return bytes.fromhex(self.quote)

    def decode_event_log(self) -> "List[EventLog]":
        return [EventLog(**event) for event in json.loads(self.event_log)]


class AttestResponse(BaseModel):
    attestation: str

    def decode_attestation(self) -> bytes:
        return bytes.fromhex(self.attestation)


class SignResponse(BaseModel):
    signature: str
    signature_chain: List[str]
    public_key: str

    def decode_signature(self) -> bytes:
        return bytes.fromhex(self.signature)

    def decode_signature_chain(self) -> List[bytes]:
        return [bytes.fromhex(chain) for chain in self.signature_chain]

    def decode_public_key(self) -> bytes:
        return bytes.fromhex(self.public_key)


class VerifyResponse(BaseModel):
    valid: bool


class VersionResponse(BaseModel):
    version: str
    rev: str


class EventLog(BaseModel):
    imr: int
    event_type: int
    digest: str
    event: str
    event_payload: str
    version: Optional[int] = None
    preimage: Optional[str] = None


class TcbInfo(BaseModel):
    """Base TCB (Trusted Computing Base) information structure."""

    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    app_compose: str
    event_log: List[EventLog]


class TcbInfoV03x(TcbInfo):
    """TCB information for dstack OS version 0.3.x."""

    rootfs_hash: Optional[str] = None


class TcbInfoV05x(TcbInfo):
    """TCB information for dstack OS version 0.5.x."""

    mr_aggregated: str
    os_image_hash: str
    compose_hash: str
    device_id: str


# Type variable for TCB info versions
T = TypeVar("T", bound=TcbInfo)


class InfoResponse(BaseModel, Generic[T]):
    app_id: str
    instance_id: str
    app_cert: str
    tcb_info: T
    app_name: str
    device_id: str
    mr_aggregated: str = ""
    os_image_hash: str = ""
    key_provider_info: str
    compose_hash: str
    vm_config: str = ""
    # Cloud provider sys_vendor (e.g. "Google"). Available on dstack OS >= 0.5.7.
    cloud_vendor: str = ""
    # Cloud provider product_name (e.g. "Google Compute Engine"). Available on dstack OS >= 0.5.7.
    cloud_product: str = ""

    @classmethod
    def parse_response(cls, obj: Any, tcb_info_type: type[T]) -> "InfoResponse[T]":
        """Parse response from service, automatically deserializing tcb_info.

        Args:
            obj: Raw response object from service
            tcb_info_type: The specific TcbInfo subclass to use for parsing

        """
        if (
            isinstance(obj, dict)
            and "tcb_info" in obj
            and isinstance(obj["tcb_info"], str)
        ):
            obj = dict(obj)
            obj["tcb_info"] = tcb_info_type(**json.loads(obj["tcb_info"]))
        return cls(**obj)


class BaseClient:
    pass


def raise_for_status(response: httpx.Response) -> None:
    """Raise on an error status, carrying the guest agent's message.

    prpc reports "no such method" and "the handler failed" alike as an HTTP
    400 with the reason in the JSON body, so the status line on its own cannot
    tell a removed method from a rejected argument. httpx's own
    ``raise_for_status`` shows only the status line, which would hide exactly
    the text a caller needs -- for instance the one ``EmitEvent`` returns
    naming its removal.
    """
    try:
        response.raise_for_status()
        return
    except httpx.HTTPStatusError as exc:
        message = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                message = str(body.get("error", ""))
        except Exception:
            message = response.text.strip()
        if not message:
            raise
        raise httpx.HTTPStatusError(
            f"{exc.args[0]}\nguest agent said: {message}",
            request=exc.request,
            response=response,
        ) from None


class AsyncBaseClient(BaseClient):
    """Transport shared by every async client, whatever surface it speaks.

    Subclasses differ only in ``PATH_PREFIX``: the guest agent selects the API
    version from the URL path alone, never from a header.
    """

    PATH_PREFIX = "/"

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        use_sync_http: bool = False,
        timeout: float = 3,
    ):
        """Initialize async client with HTTP or Unix-socket transport.

        Args:
            endpoint: HTTP/HTTPS URL or Unix socket path
            use_sync_http: If True, use sync HTTP client internally
            timeout: Timeout in seconds

        """
        endpoint = get_endpoint(endpoint)
        self.use_sync_http = use_sync_http
        self._client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None
        self._client_ref_count = 0
        self._timeout = timeout

        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            self.async_transport = httpx.AsyncHTTPTransport()
            self.sync_transport = httpx.HTTPTransport()
            self.base_url = endpoint
        else:
            # Check if Unix socket file exists
            if endpoint.startswith("/") and not os.path.exists(endpoint):
                raise FileNotFoundError(f"Unix socket file {endpoint} does not exist")
            self.async_transport = httpx.AsyncHTTPTransport(uds=endpoint)
            self.sync_transport = httpx.HTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=self.async_transport,
                base_url=self.base_url,
                timeout=self._timeout,
            )
        return self._client

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                transport=self.sync_transport,
                base_url=self.base_url,
                timeout=self._timeout,
            )
        return self._sync_client

    async def _send_rpc_request(
        self, method: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send an RPC request and return parsed JSON.

        Uses sync or async HTTP client based on use_sync_http flag.
        Maintains async signature for compatibility.
        """
        path = self.PATH_PREFIX + method
        headers = {
            "Content-Type": "application/json",
            "User-Agent": f"dstack-sdk-python/{__version__}",
        }

        if self.use_sync_http:
            # Use sync HTTP client - works from any context
            sync_client: httpx.Client = self._get_sync_client()
            response = sync_client.post(path, json=payload, headers=headers)
        else:
            # Use async HTTP client - traditional async behavior
            async_client: httpx.AsyncClient = self._get_client()
            response = await async_client.post(path, json=payload, headers=headers)
        raise_for_status(response)
        return cast(Dict[str, Any], response.json())

    async def __aenter__(self):
        self._client_ref_count += 1
        # Eagerly create client when entering context
        if self.use_sync_http:
            self._get_sync_client()
        else:
            self._get_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._client_ref_count -= 1
        if self._client_ref_count == 0:
            if self._client:
                await self._client.aclose()
                self._client = None
            if self._sync_client:
                self._sync_client.close()
                self._sync_client = None


class AsyncDstackClientV0(AsyncBaseClient):
    """Legacy async client for the frozen v0.5.11 guest agent API.

    .. deprecated:: 0.6.0
       Prefer ``AsyncDstackClient`` (which is ``AsyncDstackClientV1``). This
       class stays for code that must keep the v0 key derivation or needs
       ``sign`` / ``verify``, which v1 does not serve.

    Served at the historical unversioned paths (``/GetKey``) and, since 0.6.0,
    equivalently at ``/v0/GetKey``. The surface is frozen: it gains no method
    and no field. New capabilities live on ``AsyncDstackClientV1``.
    """

    PATH_PREFIX = "/"

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        use_sync_http: bool = False,
        timeout: float = 3,
    ):
        """Initialize the legacy async client, warning that v0 is deprecated."""
        # Only when this class is what the caller actually asked for. A
        # subclass (``AsyncTappdClient``) names its own surface in its own
        # warning, and ``use_sync_http`` means this instance is the transport
        # behind ``DstackClientV0``, which has already warned.
        if type(self) is AsyncDstackClientV0 and not use_sync_http:
            emit_deprecation_warning(
                "AsyncDstackClientV0 is deprecated: the v0 surface is frozen at "
                "dstack 0.5.11. Use AsyncDstackClient (AsyncDstackClientV1), "
                "which derives different key material -- see docs/guest-api-v1.md"
            )
        super().__init__(endpoint, use_sync_http=use_sync_http, timeout=timeout)

    async def _ensure_algorithm_supported(self, algorithm: str) -> None:
        """Check OS version when a non-secp256k1 algorithm is requested."""
        if algorithm in ("secp256k1", "k256", ""):
            return
        try:
            await self.version()
        except Exception:
            raise RuntimeError(
                f'algorithm "{algorithm}" is not supported: '
                "OS version too old (Version RPC unavailable)"
            )

    async def _ensure_tls_key_options_supported(self, feature_names: List[str]) -> None:
        """Check OS version when 0.5.7+ TLS key options are requested."""
        try:
            await self.version()
        except Exception:
            features = ", ".join(feature_names)
            raise RuntimeError(
                f"TLS key options [{features}] are not supported: "
                "OS version too old (Version RPC unavailable)"
            )

    async def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
        algorithm: str = "secp256k1",
    ) -> GetKeyResponse:
        """Derive a key from the given path, purpose, and algorithm."""
        await self._ensure_algorithm_supported(algorithm)
        data: Dict[str, Any] = {
            "path": path or "",
            "purpose": purpose or "",
            "algorithm": algorithm,
        }
        result = await self._send_rpc_request("GetKey", data)
        return GetKeyResponse(**result)

    async def get_quote(
        self,
        report_data: str | bytes,
    ) -> GetQuoteResponse:
        """Request a TDX quote for the provided report data.

        Needs Intel TDX. Without it the guest agent returns an error, and on
        GCP Confidential VMs it answers with the TDX quote alone, leaving out
        the vTPM quote GCP's verification also binds. Use ``attest()`` in both
        cases.
        """
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        report_bytes: bytes = (
            report_data.encode() if isinstance(report_data, str) else report_data
        )
        if len(report_bytes) > 64:
            raise ValueError("report_data must be less than 64 bytes")
        hex = binascii.hexlify(report_bytes).decode()
        result = await self._send_rpc_request("GetQuote", {"report_data": hex})
        return GetQuoteResponse(**result)

    async def attest(
        self,
        report_data: str | bytes,
    ) -> AttestResponse:
        """Request a versioned attestation for the provided report data."""
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        report_bytes: bytes = (
            report_data.encode() if isinstance(report_data, str) else report_data
        )
        if len(report_bytes) > 64:
            raise ValueError("report_data must be less than 64 bytes")
        hex = binascii.hexlify(report_bytes).decode()
        result = await self._send_rpc_request("Attest", {"report_data": hex})
        return AttestResponse(**result)

    async def info(self) -> InfoResponse[TcbInfo]:
        """Fetch service information including parsed TCB info."""
        result = await self._send_rpc_request("Info", {})
        return InfoResponse.parse_response(result, TcbInfoV05x)

    async def emit_event(
        self,
        event: str,
        payload: str | bytes,
    ) -> None:
        """Emit an event that extends RTMR3 on TDX platforms.

        Removed in dstack 0.6.0: runtime RTMR3 events are system-owned, and the
        agent now fails every call. The method stays so that a caller written
        against 0.5.x gets the agent's own explanation rather than a 404.
        """
        if not event:
            raise ValueError("event name cannot be empty")

        payload_bytes: bytes = payload.encode() if isinstance(payload, str) else payload
        hex_payload = binascii.hexlify(payload_bytes).decode()
        await self._send_rpc_request(
            "EmitEvent", {"event": event, "payload": hex_payload}
        )
        return None

    async def get_tls_key(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = True,
        usage_client_auth: bool = False,
        *,
        not_before: Optional[int] = None,
        not_after: Optional[int] = None,
        with_app_info: Optional[bool] = None,
    ) -> GetTlsKeyResponse:
        """Request a TLS key from the service with optional parameters.

        ``not_before`` / ``not_after`` (seconds since UNIX epoch) and
        ``with_app_info`` require dstack OS >= 0.5.7. When any of them is set,
        the SDK probes the guest agent ``Version`` RPC first and raises a
        clear error on older OS images.
        """
        new_features: List[str] = []
        if not_before is not None:
            new_features.append("not_before")
        if not_after is not None:
            new_features.append("not_after")
        if with_app_info is not None:
            new_features.append("with_app_info")
        if new_features:
            await self._ensure_tls_key_options_supported(new_features)

        data: Dict[str, Any] = {
            "subject": subject or "",
            "usage_ra_tls": usage_ra_tls,
            "usage_server_auth": usage_server_auth,
            "usage_client_auth": usage_client_auth,
        }
        if alt_names:
            data["alt_names"] = list(alt_names)
        if not_before is not None:
            data["not_before"] = not_before
        if not_after is not None:
            data["not_after"] = not_after
        if with_app_info is not None:
            data["with_app_info"] = with_app_info

        result = await self._send_rpc_request("GetTlsKey", data)
        return GetTlsKeyResponse(**result)

    async def sign(self, algorithm: str, data: str | bytes) -> SignResponse:
        """Signs data using a derived key."""
        data_bytes = data.encode() if isinstance(data, str) else data
        if algorithm == "secp256k1_prehashed" and len(data_bytes) != 32:
            raise ValueError(
                f"Pre-hashed signing requires a 32-byte digest, but received {len(data_bytes)} bytes"
            )

        hex_data = binascii.hexlify(data_bytes).decode()
        payload = {"algorithm": algorithm, "data": hex_data}
        result = await self._send_rpc_request("Sign", payload)
        return SignResponse(**result)

    async def verify(
        self,
        algorithm: str,
        data: str | bytes,
        signature: str | bytes,
        public_key: str | bytes,
    ) -> VerifyResponse:
        """Verify a signature."""
        data_bytes = data.encode() if isinstance(data, str) else data
        sig_bytes = signature.encode() if isinstance(signature, str) else signature
        pk_bytes = public_key.encode() if isinstance(public_key, str) else public_key

        payload = {
            "algorithm": algorithm,
            "data": binascii.hexlify(data_bytes).decode(),
            "signature": binascii.hexlify(sig_bytes).decode(),
            "public_key": binascii.hexlify(pk_bytes).decode(),
        }
        result = await self._send_rpc_request("Verify", payload)
        return VerifyResponse(**result)

    async def version(self) -> VersionResponse:
        """Query the guest-agent version.

        Returns the version on OS >= 0.5.7.
        Raises an error on older OS versions that lack the Version RPC.
        """
        result = await self._send_rpc_request("Version", {})
        return VersionResponse(**result)

    async def is_reachable(self) -> bool:
        """Return True if the service responds to a quick health call."""
        try:
            await self._send_rpc_request("Info", {})
            return True
        except Exception:
            return False


class DstackClientV0(BaseClient):
    """Legacy sync client for the frozen v0.5.11 guest agent API.

    .. deprecated:: 0.6.0
       Prefer ``DstackClient`` (which is ``DstackClientV1``); see
       ``AsyncDstackClientV0`` for when staying on v0 is the right call.

    Every method here is the blocking twin of ``AsyncDstackClientV0``'s.
    """

    PATH_PREFIX = "/"

    def __init__(self, endpoint: str | None = None, *, timeout: float = 3):
        """Initialize client with HTTP or Unix-socket transport.

        If a non-HTTP(S) endpoint is provided, it is treated as a Unix socket
        path and validated for existence.
        """
        if type(self) is DstackClientV0:
            emit_deprecation_warning(
                "DstackClientV0 is deprecated: the v0 surface is frozen at "
                "dstack 0.5.11. Use DstackClient (DstackClientV1), which "
                "derives different key material -- see docs/guest-api-v1.md"
            )
        self.async_client = AsyncDstackClientV0(
            endpoint, use_sync_http=True, timeout=timeout
        )

    @call_async
    def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
        algorithm: str = "secp256k1",
    ) -> GetKeyResponse:
        """Derive a key from the given path, purpose, and algorithm."""
        raise NotImplementedError

    @call_async
    def get_quote(
        self,
        report_data: str | bytes,
    ) -> GetQuoteResponse:
        """Request a TDX quote for the provided report data.

        Needs Intel TDX. Without it the guest agent returns an error, and on
        GCP Confidential VMs it answers with the TDX quote alone, leaving out
        the vTPM quote GCP's verification also binds. Use ``attest()`` in both
        cases.
        """
        raise NotImplementedError

    @call_async
    def attest(
        self,
        report_data: str | bytes,
    ) -> AttestResponse:
        """Request a versioned attestation for the provided report data."""
        raise NotImplementedError

    @call_async
    def info(self) -> InfoResponse[TcbInfo]:
        """Fetch service information including parsed TCB info."""
        raise NotImplementedError

    @call_async
    def emit_event(
        self,
        event: str,
        payload: str | bytes,
    ) -> None:
        """Emit an event that extends RTMR3 on TDX platforms.

        Removed in dstack 0.6.0; see ``AsyncDstackClientV0.emit_event``.
        """
        raise NotImplementedError

    @call_async
    def get_tls_key(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = True,
        usage_client_auth: bool = False,
        *,
        not_before: Optional[int] = None,
        not_after: Optional[int] = None,
        with_app_info: Optional[bool] = None,
    ) -> GetTlsKeyResponse:
        """Request a TLS key from the service with optional parameters."""
        raise NotImplementedError

    @call_async
    def sign(self, algorithm: str, data: str | bytes) -> SignResponse:
        """Signs data using a derived key."""
        raise NotImplementedError

    @call_async
    def verify(
        self,
        algorithm: str,
        data: str | bytes,
        signature: str | bytes,
        public_key: str | bytes,
    ) -> VerifyResponse:
        """Verify a signature."""
        raise NotImplementedError

    @call_async
    def version(self) -> VersionResponse:
        """Query the guest-agent version."""
        raise NotImplementedError

    @call_async
    def is_reachable(self) -> bool:
        """Return True if the service responds to a quick health call."""
        raise NotImplementedError

    @call_async
    def __enter__(self):
        raise NotImplementedError

    @call_async
    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError


class AsyncTappdClient(AsyncDstackClientV0):
    """Deprecated async client kept for backward compatibility.

    DEPRECATED: Use ``AsyncDstackClientV0`` instead. It is named explicitly
    here because tappd only ever spoke v0, and the unsuffixed
    ``AsyncDstackClient`` now means v1, which derives different keys.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        *,
        use_sync_http: bool = False,
        timeout: float = 3,
    ):
        """Initialize deprecated async tappd client wrapper."""
        if not use_sync_http:
            # Already warned in TappdClient.__init__
            emit_deprecation_warning(
                "AsyncTappdClient is deprecated, please use AsyncDstackClientV0 instead"
            )

        endpoint = get_tappd_endpoint(endpoint)
        super().__init__(endpoint, use_sync_http=use_sync_http, timeout=timeout)
        # Set the correct path prefix for tappd
        self.PATH_PREFIX = "/prpc/Tappd."

    async def derive_key(
        self,
        path: str | None = None,
        subject: str | None = None,
        alt_names: List[str] | None = None,
    ) -> GetTlsKeyResponse:
        """Use ``get_key`` instead (deprecated)."""
        emit_deprecation_warning("derive_key is deprecated, please use get_key instead")

        data: Dict[str, Any] = {
            "path": path or "",
            "subject": subject or path or "",
        }
        if alt_names:
            data["alt_names"] = alt_names

        result = await self._send_rpc_request("DeriveKey", data)
        return GetTlsKeyResponse(**result)

    async def tdx_quote(
        self,
        report_data: str | bytes,
        hash_algorithm: str | None = None,
    ) -> GetQuoteResponse:
        """Use ``get_quote`` instead (deprecated)."""
        emit_deprecation_warning(
            "tdx_quote is deprecated, please use get_quote instead"
        )

        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")

        report_bytes: bytes = (
            report_data.encode() if isinstance(report_data, str) else report_data
        )
        hex_data = binascii.hexlify(report_bytes).decode()

        if hash_algorithm == "raw":
            if len(hex_data) > 128:
                raise ValueError(
                    "Report data is too large, it should less then 64 bytes when hash_algorithm is raw."
                )
            if len(hex_data) < 128:
                hex_data = hex_data.zfill(128)

        payload = {"report_data": hex_data, "hash_algorithm": hash_algorithm or "raw"}

        result = await self._send_rpc_request("TdxQuote", payload)

        if "error" in result:
            raise RuntimeError(result["error"])

        return GetQuoteResponse(**result)

    async def info(self) -> InfoResponse[TcbInfo]:
        """Fetch service information including parsed TCB info."""
        result = await self._send_rpc_request("Info", {})
        return InfoResponse.parse_response(result, TcbInfoV03x)


class TappdClient(DstackClientV0):
    """Deprecated client kept for backward compatibility.

    DEPRECATED: Use ``DstackClientV0`` instead; see ``AsyncTappdClient``.
    """

    def __init__(self, endpoint: str | None = None, timeout: float = 3):
        """Initialize deprecated tappd client wrapper."""
        emit_deprecation_warning(
            "TappdClient is deprecated, please use DstackClientV0 instead"
        )
        endpoint = get_tappd_endpoint(endpoint)
        self.async_client = AsyncTappdClient(
            endpoint, use_sync_http=True, timeout=timeout
        )

    @call_async
    def derive_key(
        self,
        path: str | None = None,
        subject: str | None = None,
        alt_names: List[str] | None = None,
    ) -> GetTlsKeyResponse:
        """Use ``get_key`` instead (deprecated)."""
        raise NotImplementedError

    @call_async
    def tdx_quote(
        self,
        report_data: str | bytes,
        hash_algorithm: str | None = None,
    ) -> GetQuoteResponse:
        """Use ``get_quote`` instead (deprecated)."""
        raise NotImplementedError

    @call_async
    def info(self) -> InfoResponse[TcbInfo]:
        """Fetch service information including parsed TCB info."""
        raise NotImplementedError

    @call_async
    def __enter__(self):
        raise NotImplementedError

    @call_async
    def __exit__(self, exc_type, exc_val, exc_tb):
        raise NotImplementedError
