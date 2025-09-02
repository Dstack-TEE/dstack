# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import functools
import hashlib
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

__version__ = "0.2.0"


INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"


def replay_rtmr(history: list[str]) -> str:
    if len(history) == 0:
        return INIT_MR
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        # mr = sha384(concat(mr, content))
        # if content is shorter than 48 bytes, pad it with zeros
        content_bytes = bytes.fromhex(content)
        if len(content_bytes) < 48:
            content_bytes = content_bytes.ljust(48, b"\0")
        mr = hashlib.sha384(mr + content_bytes).digest()
    return mr.hex()


def get_endpoint(endpoint: str | None = None) -> str:
    if endpoint:
        return endpoint
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(
            f"Using simulator endpoint: {os.environ['DSTACK_SIMULATOR_ENDPOINT']}"
        )
        return os.environ["DSTACK_SIMULATOR_ENDPOINT"]
    return "/var/run/dstack.sock"


def get_tappd_endpoint(endpoint: str | None = None) -> str:
    if endpoint:
        return endpoint
    if "TAPPD_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(f"Using tappd endpoint: {os.environ['TAPPD_SIMULATOR_ENDPOINT']}")
        return os.environ["TAPPD_SIMULATOR_ENDPOINT"]
    return "/var/run/tappd.sock"


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

    def decode_quote(self) -> bytes:
        return bytes.fromhex(self.quote)

    def decode_event_log(self) -> "List[EventLog]":
        return [EventLog(**event) for event in json.loads(self.event_log)]

    def replay_rtmrs(self) -> Dict[int, str]:
        parsed_event_log = json.loads(self.event_log)
        rtmrs: Dict[int, str] = {}
        for idx in range(4):
            history = [
                event["digest"] for event in parsed_event_log if event.get("imr") == idx
            ]
            rtmrs[idx] = replay_rtmr(history)
        return rtmrs


class EventLog(BaseModel):
    imr: int
    event_type: int
    digest: str
    event: str
    event_payload: str


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

    rootfs_hash: str


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
    os_image_hash: str = ""
    key_provider_info: str
    compose_hash: str

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


class AsyncDstackClient(BaseClient):
    PATH_PREFIX = "/"

    def __init__(self, endpoint: str | None = None, use_sync_http: bool = False):
        """Initialize async client with HTTP or Unix-socket transport.

        Args:
            endpoint: HTTP/HTTPS URL or Unix socket path
            use_sync_http: If True, use sync HTTP client internally

        """
        endpoint = get_endpoint(endpoint)
        self.use_sync_http = use_sync_http
        self._client: Optional[httpx.AsyncClient] = None
        self._sync_client: Optional[httpx.Client] = None
        self._client_ref_count = 0

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
                transport=self.async_transport, base_url=self.base_url, timeout=0.5
            )
        return self._client

    def _get_sync_client(self) -> httpx.Client:
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                transport=self.sync_transport, base_url=self.base_url, timeout=0.5
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
            response.raise_for_status()
            return cast(Dict[str, Any], response.json())
        else:
            # Use async HTTP client - traditional async behavior
            async_client: httpx.AsyncClient = self._get_client()
            response = await async_client.post(path, json=payload, headers=headers)
            response.raise_for_status()
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

    async def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
    ) -> GetKeyResponse:
        """Derive a key from the given path and purpose."""
        data: Dict[str, Any] = {"path": path or "", "purpose": purpose or ""}
        result = await self._send_rpc_request("GetKey", data)
        return GetKeyResponse(**result)

    async def get_quote(
        self,
        report_data: str | bytes,
    ) -> GetQuoteResponse:
        """Request an attestation quote for the provided report data."""
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

    async def info(self) -> InfoResponse[TcbInfo]:
        """Fetch service information including parsed TCB info."""
        result = await self._send_rpc_request("Info", {})
        return InfoResponse.parse_response(result, TcbInfoV05x)

    async def emit_event(
        self,
        event: str,
        payload: str | bytes,
    ) -> None:
        """Emit an event that extends RTMR3 on TDX platforms."""
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
    ) -> GetTlsKeyResponse:
        """Request a TLS key from the service with optional parameters."""
        data: Dict[str, Any] = {
            "subject": subject or "",
            "usage_ra_tls": usage_ra_tls,
            "usage_server_auth": usage_server_auth,
            "usage_client_auth": usage_client_auth,
        }
        if alt_names:
            data["alt_names"] = list(alt_names)

        result = await self._send_rpc_request("GetTlsKey", data)
        return GetTlsKeyResponse(**result)

    async def is_reachable(self) -> bool:
        """Return True if the service responds to a quick health call."""
        try:
            await self._send_rpc_request("Info", {})
            return True
        except Exception:
            return False


class DstackClient(BaseClient):
    PATH_PREFIX = "/"

    def __init__(self, endpoint: str | None = None):
        """Initialize client with HTTP or Unix-socket transport.

        If a non-HTTP(S) endpoint is provided, it is treated as a Unix socket
        path and validated for existence.
        """
        self.async_client = AsyncDstackClient(endpoint, use_sync_http=True)

    @call_async
    def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
    ) -> GetKeyResponse:
        """Derive a key from the given path and purpose."""
        raise NotImplementedError

    @call_async
    def get_quote(
        self,
        report_data: str | bytes,
    ) -> GetQuoteResponse:
        """Request an attestation quote for the provided report data."""
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
        """Emit an event that extends RTMR3 on TDX platforms."""
        raise NotImplementedError

    @call_async
    def get_tls_key(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = True,
        usage_client_auth: bool = False,
    ) -> GetTlsKeyResponse:
        """Request a TLS key from the service with optional parameters."""
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


class AsyncTappdClient(AsyncDstackClient):
    """Deprecated async client kept for backward compatibility.

    DEPRECATED: Use ``AsyncDstackClient`` instead.
    """

    def __init__(self, endpoint: str | None = None, use_sync_http: bool = False):
        """Initialize deprecated async tappd client wrapper."""
        if not use_sync_http:
            # Already warned in TappdClient.__init__
            emit_deprecation_warning(
                "AsyncTappdClient is deprecated, please use AsyncDstackClient instead"
            )

        endpoint = get_tappd_endpoint(endpoint)
        super().__init__(endpoint, use_sync_http=use_sync_http)
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


class TappdClient(DstackClient):
    """Deprecated client kept for backward compatibility.

    DEPRECATED: Use ``DstackClient`` instead.
    """

    def __init__(self, endpoint: str | None = None):
        """Initialize deprecated tappd client wrapper."""
        emit_deprecation_warning(
            "TappdClient is deprecated, please use DstackClient instead"
        )
        endpoint = get_tappd_endpoint(endpoint)
        self.async_client = AsyncTappdClient(endpoint, use_sync_http=True)

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
