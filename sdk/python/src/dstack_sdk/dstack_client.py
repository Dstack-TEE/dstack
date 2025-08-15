# SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import hashlib
import json
import logging
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import httpx
from pydantic import BaseModel

logger = logging.getLogger("dstack_sdk")

# SDK version for User-Agent header
__version__ = "0.2.0"


INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"


def replay_rtmr(history: list[str]) -> str:
    """Replay RTMR history and return the final RTMR value as hex string."""
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
    """Return the dstack endpoint from argument or environment.

    If ``endpoint`` is not provided, check ``DSTACK_SIMULATOR_ENDPOINT`` in the
    environment; otherwise fall back to the default Unix socket path.
    """
    if endpoint:
        return endpoint
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(
            f"Using simulator endpoint: {os.environ['DSTACK_SIMULATOR_ENDPOINT']}"
        )
        return os.environ["DSTACK_SIMULATOR_ENDPOINT"]
    return "/var/run/dstack.sock"


def get_tappd_endpoint(endpoint: str | None = None) -> str:
    """Return the tappd endpoint from argument or environment.

    If ``endpoint`` is not provided, check ``TAPPD_SIMULATOR_ENDPOINT`` in the
    environment; otherwise fall back to the default Unix socket path.
    """
    if endpoint:
        return endpoint
    if "TAPPD_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(f"Using tappd endpoint: {os.environ['TAPPD_SIMULATOR_ENDPOINT']}")
        return os.environ["TAPPD_SIMULATOR_ENDPOINT"]
    return "/var/run/tappd.sock"


class GetTlsKeyResponse(BaseModel):
    """Response type for TLS key requests."""

    key: str
    certificate_chain: List[str]

    def as_uint8array(self, max_length: Optional[int] = None) -> bytes:
        """Return the TLS private key as DER bytes.

        If ``max_length`` is provided, the result is padded/truncated to that
        length.
        """
        # Remove PEM headers and decode
        content = self.key.replace("-----BEGIN PRIVATE KEY-----", "")
        content = content.replace("-----END PRIVATE KEY-----", "")
        content = content.replace("\n", "").replace(" ", "")

        binary_der = base64.b64decode(content)

        if max_length is None:
            return binary_der
        else:
            # Pad or truncate to max_length
            result = bytearray(max_length)
            copy_len = min(len(binary_der), max_length)
            result[:copy_len] = binary_der[:copy_len]
            return bytes(result)


class GetKeyResponse(BaseModel):
    """Response type for app key derivation requests."""

    key: str
    signature_chain: List[str]

    def decode_key(self) -> bytes:
        """Decode the hex key into raw bytes."""
        return bytes.fromhex(self.key)

    def decode_signature_chain(self) -> List[bytes]:
        """Decode the signature chain entries from hex to bytes."""
        return [bytes.fromhex(chain) for chain in self.signature_chain]


class GetQuoteResponse(BaseModel):
    """Response type for quote requests, including event log."""

    quote: str
    event_log: str

    def decode_quote(self) -> bytes:
        """Decode the quote from hex to bytes."""
        return bytes.fromhex(self.quote)

    def decode_event_log(self) -> "List[EventLog]":
        """Parse the event log JSON into a list of ``EventLog`` objects."""
        return [EventLog(**event) for event in json.loads(self.event_log)]

    def replay_rtmrs(self) -> Dict[int, str]:
        """Recompute RTMR registers (0-3) from the event log JSON."""
        parsed_event_log = json.loads(self.event_log)
        rtmrs: Dict[int, str] = {}
        for idx in range(4):
            history = [
                event["digest"] for event in parsed_event_log if event.get("imr") == idx
            ]
            rtmrs[idx] = replay_rtmr(history)
        return rtmrs


class EventLog(BaseModel):
    """Single event entry included in the quote event log."""

    imr: int
    event_type: int
    digest: str
    event: str
    event_payload: str


class TcbInfo(BaseModel):
    """Trusted computing base information returned by the service."""

    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    os_image_hash: str = ""  # Optional: empty if OS image is not measured by KMS
    compose_hash: str
    device_id: str
    app_compose: str
    event_log: List[EventLog]


class InfoResponse(BaseModel):
    """Service information response including TCB info and metadata."""

    app_id: str
    instance_id: str
    app_cert: str
    tcb_info: TcbInfo
    app_name: str
    device_id: str
    os_image_hash: str = ""  # Optional: empty if OS image is not measured by KMS
    key_provider_info: str
    compose_hash: str

    @classmethod
    def parse_response(cls, obj: Any) -> "InfoResponse":
        """Parse raw JSON into ``InfoResponse``, decoding nested ``tcb_info``."""
        if (
            isinstance(obj, dict)
            and "tcb_info" in obj
            and isinstance(obj["tcb_info"], str)
        ):
            obj = dict(obj)
            obj["tcb_info"] = TcbInfo(**json.loads(obj["tcb_info"]))
        return cls(**obj)


class BaseClient:
    """Marker base class for dstack clients."""


class DstackClient(BaseClient):
    """Synchronous client for dstack services."""

    PATH_PREFIX = "/"

    def __init__(self, endpoint: str | None = None):
        """Initialize client with HTTP or Unix-socket transport.

        If a non-HTTP(S) endpoint is provided, it is treated as a Unix socket
        path and validated for existence.
        """
        endpoint = get_endpoint(endpoint)
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            self.transport = httpx.HTTPTransport()
            self.base_url = endpoint
        else:
            # Check if Unix socket file exists
            if endpoint.startswith("/") and not os.path.exists(endpoint):
                raise FileNotFoundError(f"Unix socket file {endpoint} does not exist")
            self.transport = httpx.HTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    def _send_rpc_request(self, method: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send an RPC request and return the parsed JSON response."""
        path = self.PATH_PREFIX + method
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            response = client.post(
                path,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"dstack-sdk-python/{__version__}",
                },
            )
            response.raise_for_status()
            from typing import cast

            return cast(Dict[str, Any], response.json())

    def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
    ) -> GetKeyResponse:
        """Derive a key from the given path and purpose."""
        data: Dict[str, Any] = {"path": path or "", "purpose": purpose or ""}
        result = self._send_rpc_request("GetKey", data)
        return GetKeyResponse(**result)

    def get_quote(
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
        result = self._send_rpc_request("GetQuote", {"report_data": hex})
        return GetQuoteResponse(**result)

    def info(self) -> InfoResponse:
        """Fetch service information including parsed TCB info."""
        result = self._send_rpc_request("Info", {})
        return InfoResponse.parse_response(result)

    def emit_event(
        self,
        event: str,
        payload: str | bytes,
    ) -> None:
        """Emit an event that extends RTMR3 on TDX platforms."""
        if not event:
            raise ValueError("event name cannot be empty")

        payload_bytes: bytes = payload.encode() if isinstance(payload, str) else payload
        hex_payload = binascii.hexlify(payload_bytes).decode()
        self._send_rpc_request("EmitEvent", {"event": event, "payload": hex_payload})
        return None

    def get_tls_key(
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

        result = self._send_rpc_request("GetTlsKey", data)
        return GetTlsKeyResponse(**result)

    def is_reachable(self) -> bool:
        """Return True if the service responds to a quick health call."""
        try:
            with httpx.Client(
                transport=self.transport, base_url=self.base_url, timeout=0.5
            ) as client:
                response = client.post(
                    "/prpc/Tappd.Info",
                    json={},
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": f"dstack-sdk-python/{__version__}",
                    },
                )
                response.raise_for_status()
                return True
        except Exception:
            return False


class AsyncDstackClient(BaseClient):
    """Asynchronous client for dstack services."""

    PATH_PREFIX = "/"

    def __init__(self, endpoint: str | None = None):
        """Initialize async client with HTTP or Unix-socket transport."""
        endpoint = get_endpoint(endpoint)
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            self.transport = httpx.AsyncHTTPTransport()
            self.base_url = endpoint
        else:
            # Check if Unix socket file exists
            if endpoint.startswith("/") and not os.path.exists(endpoint):
                raise FileNotFoundError(f"Unix socket file {endpoint} does not exist")
            self.transport = httpx.AsyncHTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    async def _send_rpc_request(
        self, method: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send an RPC request asynchronously and return parsed JSON."""
        path = self.PATH_PREFIX + method
        async with httpx.AsyncClient(
            transport=self.transport, base_url=self.base_url
        ) as client:
            response = await client.post(
                path,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"dstack-sdk-python/{__version__}",
                },
            )
            response.raise_for_status()
            from typing import cast

            return cast(Dict[str, Any], response.json())

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

    async def info(self) -> InfoResponse:
        """Fetch service information including parsed TCB info."""
        result = await self._send_rpc_request("Info", {})
        return InfoResponse.parse_response(result)

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
            async with httpx.AsyncClient(
                transport=self.transport, base_url=self.base_url, timeout=0.5
            ) as client:
                response = await client.post(
                    "/prpc/Tappd.Info",
                    json={},
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": f"dstack-sdk-python/{__version__}",
                    },
                )
                response.raise_for_status()
                return True
        except Exception:
            return False


class TappdClient(DstackClient):
    """Deprecated client kept for backward compatibility.

    DEPRECATED: Use ``DstackClient`` instead.
    """
    PATH_PREFIX = "/prpc/Tappd."

    def __init__(self, endpoint: str | None = None):
        """Initialize deprecated tappd client wrapper."""
        import warnings

        warnings.warn(
            "TappdClient is deprecated, please use DstackClient instead",
            DeprecationWarning,
            stacklevel=2,
        )

        endpoint = get_tappd_endpoint(endpoint)
        super().__init__(endpoint)

    def derive_key(
        self,
        path: str | None = None,
        subject: str | None = None,
        alt_names: List[str] | None = None,
    ) -> GetTlsKeyResponse:
        """Use ``get_key`` instead (deprecated)."""
        import warnings

        warnings.warn(
            "derive_key is deprecated, please use get_key instead",
            DeprecationWarning,
            stacklevel=2,
        )

        data: Dict[str, Any] = {
            "path": path or "",
            "subject": subject or path or "",
        }
        if alt_names:
            data["alt_names"] = alt_names

        result = self._send_rpc_request("DeriveKey", data)
        return GetTlsKeyResponse(**result)

    def tdx_quote(
        self,
        report_data: str | bytes,
        hash_algorithm: str | None = None,
    ) -> GetQuoteResponse:
        """Use ``get_quote`` instead (deprecated)."""
        import warnings

        warnings.warn(
            "tdx_quote is deprecated, please use get_quote instead",
            DeprecationWarning,
            stacklevel=2,
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

        result = self._send_rpc_request("TdxQuote", payload)

        if "error" in result:
            raise RuntimeError(result["error"])

        return GetQuoteResponse(**result)


class AsyncTappdClient(AsyncDstackClient):
    """Deprecated async client kept for backward compatibility.

    DEPRECATED: Use ``AsyncDstackClient`` instead.
    """
    PATH_PREFIX = "/prpc/Tappd."

    def __init__(self, endpoint: str | None = None):
        """Initialize deprecated async tappd client wrapper."""
        import warnings

        warnings.warn(
            "AsyncTappdClient is deprecated, please use AsyncDstackClient instead",
            DeprecationWarning,
            stacklevel=2,
        )

        endpoint = get_tappd_endpoint(endpoint)
        super().__init__(endpoint)

    async def derive_key(
        self,
        path: str | None = None,
        subject: str | None = None,
        alt_names: List[str] | None = None,
    ) -> GetTlsKeyResponse:
        """Use ``get_key`` instead (deprecated)."""
        import warnings

        warnings.warn(
            "derive_key is deprecated, please use get_key instead",
            DeprecationWarning,
            stacklevel=2,
        )

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
        import warnings

        warnings.warn(
            "tdx_quote is deprecated, please use get_quote instead",
            DeprecationWarning,
            stacklevel=2,
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
