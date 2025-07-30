from typing import Literal, Optional, List, Dict, Any
import binascii
import json
import hashlib
import os
import logging
import base64

from pydantic import BaseModel
import httpx

logger = logging.getLogger('dstack_sdk')


INIT_MR = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"


def replay_rtmr(history: list[str]):
    """
    Replay the RTMR history to calculate the final RTMR value.
    """
    if len(history) == 0:
        return INIT_MR
    mr = bytes.fromhex(INIT_MR)
    for content in history:
        # mr = sha384(concat(mr, content))
        # if content is shorter than 48 bytes, pad it with zeros
        content = bytes.fromhex(content)
        if len(content) < 48:
            content = content.ljust(48, b'\0')
        mr = hashlib.sha384(mr + content).digest()
    return mr.hex()


def get_endpoint(endpoint: str | None = None) -> str:
    if endpoint:
        return endpoint
    if "DSTACK_SIMULATOR_ENDPOINT" in os.environ:
        logger.info(
            f"Using simulator endpoint: {os.environ['DSTACK_SIMULATOR_ENDPOINT']}")
        return os.environ["DSTACK_SIMULATOR_ENDPOINT"]
    return "/var/run/dstack.sock"


class GetTlsKeyResponse(BaseModel):
    key: str
    certificate_chain: List[str]


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

    def decode_event_log(self) -> 'List[EventLog]':
        return [EventLog(**event) for event in json.loads(self.event_log)]

    def replay_rtmrs(self) -> Dict[int, str]:
        # NOTE: before dstack-0.3.0, event log might not a JSON file.
        parsed_event_log = json.loads(self.event_log)
        rtmrs = {}
        for idx in range(4):
            history = []
            for event in parsed_event_log:
                if event.get('imr') == idx:
                    history.append(event['digest'])
            rtmrs[idx] = replay_rtmr(history)
        return rtmrs


class EventLog(BaseModel):
    imr: int
    event_type: int
    digest: str
    event: str
    event_payload: str


class TcbInfo(BaseModel):
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
    def model_validate(cls, obj: Any) -> 'InfoResponse':
        if isinstance(obj, dict) and 'tcb_info' in obj and isinstance(obj['tcb_info'], str):
            obj = dict(obj)
            obj['tcb_info'] = TcbInfo(**json.loads(obj['tcb_info']))
        return super().model_validate(obj)


class BaseClient:
    pass


class DstackClient(BaseClient):
    def __init__(self, endpoint: str | None = None):
        endpoint = get_endpoint(endpoint)
        if endpoint.startswith("http://") or endpoint.startswith('https://'):
            self.transport = httpx.HTTPTransport()
            self.base_url = endpoint
        else:
            self.transport = httpx.HTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    def _send_rpc_request(self, path, payload):
        with httpx.Client(transport=self.transport, base_url=self.base_url) as client:
            response = client.post(
                path,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

    def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
    ) -> GetKeyResponse:
        """
        Derives a key from the given path + app root key.

        Args:
            path: Path for key derivation (optional)
            purpose: Purpose for key derivation (optional)

        Returns:
            GetKeyResponse object containing key and signature chain

        The key derivation process works as follows:

        1. The app's root key is used as the base for derivation
        2. The provided path is used as context data for HKDF-SHA256 derivation
        3. A derived ECDSA key is created
        4. A message is formed by combining the purpose and the hex-encoded public key of the derived key
        5. The app's key signs this message using Keccak256 (Ethereum-style signing)
        6. The signature includes the recovery ID for verification
        7. A signature chain is returned containing:
           - First element: The app key's signature over the derived key's public key
           - Second element: The KMS root key's signature over the app's public key

        To verify the key:
        1. Verify the app's signature in the chain using the app's public key
        2. Verify the KMS root key's signature over the app's public key
        3. Verify that the message signed by the app key matches the derived key's public key
        4. Optionally, recover the app's public key from its signature and verify it matches
           the expected app public key
        """
        data: Dict[str, Any] = {"path": path or '', "purpose": purpose or ''}
        result = self._send_rpc_request("/GetKey", data)
        return GetKeyResponse(**result)

    def get_quote(
        self,
        report_data: str | bytes,
    ) -> GetQuoteResponse:
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        is_str = isinstance(report_data, str)
        if is_str:
            report_data = report_data.encode()
        if len(report_data) > 64:
            raise ValueError("report_data must be less than 64 bytes")
        hex = binascii.hexlify(report_data).decode()
        result = self._send_rpc_request("/GetQuote", {"report_data": hex})
        return GetQuoteResponse(**result)

    def info(self) -> InfoResponse:
        result = self._send_rpc_request("/Info", {})
        return InfoResponse.model_validate(result)

    def emit_event(
        self,
        event: str,
        payload: str | bytes,
    ) -> None:
        """
        Emit an event. This extends the event to RTMR3 on TDX platform.

        Requires dstack OS 0.5.0 or later.

        Args:
            event: The event name
            payload: The event data as string or bytes

        Returns:
            None
        """
        if not event:
            raise ValueError("event name cannot be empty")

        if isinstance(payload, str):
            payload = payload.encode()

        hex_payload = binascii.hexlify(payload).decode()
        self._send_rpc_request("/EmitEvent", {"event": event, "payload": hex_payload})
        return None

    def get_tls_key(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = False,
        usage_client_auth: bool = False,
    ) -> GetTlsKeyResponse:
        """
        Gets a TLS key from the dstack service with optional parameters.

        Args:
            subject: The subject for the TLS key
            alt_names: Alternative names for the TLS key
            usage_ra_tls: Whether to enable RA TLS usage
            usage_server_auth: Whether to enable server auth usage
            usage_client_auth: Whether to enable client auth usage

        Returns:
            GetTlsKeyResponse object containing the key and certificate chain
        """
        data: Dict[str, Any] = {
            "subject": subject or "",
            "usage_ra_tls": usage_ra_tls,
            "usage_server_auth": usage_server_auth,
            "usage_client_auth": usage_client_auth,
        }
        if alt_names:
            data["alt_names"] = alt_names

        result = self._send_rpc_request("/GetTlsKey", data)
        return GetTlsKeyResponse(**result)


class AsyncDstackClient(BaseClient):
    def __init__(self, endpoint=None):
        endpoint = get_endpoint(endpoint)
        if endpoint.startswith("http://") or endpoint.startswith('https://'):
            self.transport = httpx.AsyncHTTPTransport()
            self.base_url = endpoint
        else:
            self.transport = httpx.AsyncHTTPTransport(uds=endpoint)
            self.base_url = "http://localhost"

    async def _send_rpc_request(self, path, payload):
        async with httpx.AsyncClient(transport=self.transport, base_url=self.base_url) as client:
            response = await client.post(
                path,
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            response.raise_for_status()
            return response.json()

    async def get_key(
        self,
        path: str | None = None,
        purpose: str | None = None,
    ) -> GetKeyResponse:
        data: Dict[str, Any] = {"path": path or '', "purpose": purpose or ''}
        result = await self._send_rpc_request("/GetKey", data)
        return GetKeyResponse(**result)

    async def get_quote(
        self,
        report_data: str | bytes,
    ) -> GetQuoteResponse:
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        is_str = isinstance(report_data, str)
        if is_str:
            report_data = report_data.encode()
        if len(report_data) > 64:
            raise ValueError("report_data must be less than 64 bytes")
        hex = binascii.hexlify(report_data).decode()
        result = await self._send_rpc_request("/GetQuote", {"report_data": hex})
        return GetQuoteResponse(**result)

    async def info(self) -> InfoResponse:
        result = await self._send_rpc_request("/Info", {})
        return InfoResponse.model_validate(result)

    async def emit_event(
        self,
        event: str,
        payload: str | bytes,
    ) -> None:
        """
        Emit an event. This extends the event to RTMR3 on TDX platform.

        Requires dstack OS 0.5.0 or later.

        Args:
            event: The event name
            payload: The event data as string or bytes

        Returns:
            None
        """
        if not event:
            raise ValueError("event name cannot be empty")

        if isinstance(payload, str):
            payload = payload.encode()

        hex_payload = binascii.hexlify(payload).decode()
        await self._send_rpc_request("/EmitEvent", {"event": event, "payload": hex_payload})
        return None

    async def get_tls_key(
        self,
        subject: str | None = None,
        alt_names: List[str] | None = None,
        usage_ra_tls: bool = False,
        usage_server_auth: bool = False,
        usage_client_auth: bool = False,
    ) -> GetTlsKeyResponse:
        """
        Gets a TLS key from the dstack service with optional parameters.

        Args:
            subject: The subject for the TLS key
            alt_names: Alternative names for the TLS key
            usage_ra_tls: Whether to enable RA TLS usage
            usage_server_auth: Whether to enable server auth usage
            usage_client_auth: Whether to enable client auth usage

        Returns:
            GetTlsKeyResponse object containing the key and certificate chain
        """
        data: Dict[str, Any] = {
            "subject": subject or "",
            "usage_ra_tls": usage_ra_tls,
            "usage_server_auth": usage_server_auth,
            "usage_client_auth": usage_client_auth,
        }
        if alt_names:
            data["alt_names"] = alt_names

        result = await self._send_rpc_request("/GetTlsKey", data)
        return GetTlsKeyResponse(**result)
