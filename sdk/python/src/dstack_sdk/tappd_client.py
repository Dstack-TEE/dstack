from typing import Literal, Optional, List, Dict, Any
import binascii
import json
import hashlib
import os
import logging
import base64

from pydantic import BaseModel
import httpx

__version__ = "0.2.0"

logger = logging.getLogger('dstack_sdk')

QuoteHashAlgorithms = Literal[
  'sha256',
  'sha384',
  'sha512',
  'sha3-256',
  'sha3-384',
  'sha3-512',
  'keccak256',
  'keccak384',
  'keccak512',
  'raw',
  '', # Default value is sha512, so empty equals to sha512
]

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
        logger.info(f"Using simulator endpoint: {os.environ['DSTACK_SIMULATOR_ENDPOINT']}")
        return os.environ["DSTACK_SIMULATOR_ENDPOINT"]
    return "/var/run/tappd.sock"


class DeriveKeyResponse(BaseModel):
    key: str
    certificate_chain: List[str]

    def toBytes(self, max_length: Optional[int] = None) -> bytes:
        content = self.key.replace("-----BEGIN PRIVATE KEY-----", "") \
            .replace("-----END PRIVATE KEY-----", "") \
            .replace("\n", "")
        binary_der = base64.b64decode(content)
        if max_length is None:
            max_length = len(binary_der)
        return binary_der[:max_length]


class TdxQuoteResponse(BaseModel):
    quote: str
    event_log: str

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
    rootfs_hash: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    event_log: List[EventLog]


class TappdInfoResponse(BaseModel):
    app_id: str
    instance_id: str
    app_cert: str
    tcb_info: TcbInfo
    app_name: str
    public_logs: bool
    public_sysinfo: bool

    @classmethod
    def model_validate(cls, obj: Any) -> 'TappdInfoResponse':
        if isinstance(obj, dict) and 'tcb_info' in obj and isinstance(obj['tcb_info'], str):
            obj = dict(obj)
            obj['tcb_info'] = TcbInfo(**json.loads(obj['tcb_info']))
        return super().model_validate(obj)


class BaseClient:
    pass


class TappdClient(BaseClient):
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
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"dstack-sdk-python/{__version__}"
                }
            )
            response.raise_for_status()
            return response.json()

    def derive_key(
            self,
            path: str | None = None,
            subject: str | None = None,
            alt_names: List[str] | None = None
        ) -> DeriveKeyResponse:
        data: Dict[str, Any] = {"path": path or '', "subject": subject or path or ''}
        if alt_names:
            data["alt_names"] = alt_names
        result = self._send_rpc_request("/prpc/Tappd.DeriveKey", data)
        return DeriveKeyResponse(**result)

    def tdx_quote(
            self,
            report_data: str | bytes,
            hash_algorithm: QuoteHashAlgorithms = ''
        ) -> TdxQuoteResponse:
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        is_str = isinstance(report_data, str)
        if is_str:
            report_data = report_data.encode()
        hex = binascii.hexlify(report_data).decode()
        if hash_algorithm == "raw":
            if len(hex) < 128:
                hex = hex.rjust(128, '0')
            elif len(hex) > 128:
                hint = is_str and '64 characters' or '128 bytes'
                raise ValueError(f'Report data is too large, it should at most {hint} when hash_algorithm is raw.')
        result = self._send_rpc_request("/prpc/Tappd.TdxQuote", {"report_data": hex, "hash_algorithm": hash_algorithm})
        return TdxQuoteResponse(**result)

    def info(self) -> TappdInfoResponse:
        result = self._send_rpc_request("/prpc/Tappd.Info", {})
        return TappdInfoResponse.model_validate(result)


class AsyncTappdClient(BaseClient):
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
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": f"dstack-sdk-python/{__version__}"
                }
            )
            response.raise_for_status()
            return response.json()

    async def derive_key(
            self,
            path: str | None = None,
            subject: str | None = None,
            alt_names: List[str] | None = None
        ) -> DeriveKeyResponse:
        data: Dict[str, Any] = {"path": path or '', "subject": subject or path or ''}
        if alt_names:
            data["alt_names"] = alt_names
        result = await self._send_rpc_request("/prpc/Tappd.DeriveKey", data)
        return DeriveKeyResponse(**result)

    async def tdx_quote(
            self,
            report_data: str | bytes,
            hash_algorithm: QuoteHashAlgorithms = ''
        ) -> TdxQuoteResponse:
        if not report_data or not isinstance(report_data, (bytes, str)):
            raise ValueError("report_data can not be empty")
        is_str = isinstance(report_data, str)
        if is_str:
            report_data = report_data.encode()
        hex = binascii.hexlify(report_data).decode()
        if hash_algorithm == "raw":
            if len(hex) < 128:
                hex = hex.rjust(128, '0')
            elif len(hex) > 128:
                hint = is_str and '64 characters' or '128 bytes'
                raise ValueError(f'Report data is too large, it should at most {hint} when hash_algorithm is raw.')
        result = await self._send_rpc_request("/prpc/Tappd.TdxQuote", {"report_data": hex, "hash_algorithm": hash_algorithm})
        return TdxQuoteResponse(**result)

    async def info(self) -> TappdInfoResponse:
        result = await self._send_rpc_request("/prpc/Tappd.Info", {})
        return TappdInfoResponse.model_validate(result)