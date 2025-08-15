"""Type stubs for dstack_client module to fix sync method return types."""

from abc import abstractmethod
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

class GetTlsKeyResponse:
    key: str
    certificate_chain: List[str]
    def as_uint8array(self, max_length: Optional[int] = ...) -> bytes: ...

class GetKeyResponse:
    key: str
    signature_chain: List[str]
    def decode_key(self) -> bytes: ...
    def decode_signature_chain(self) -> List[bytes]: ...

class GetQuoteResponse:
    quote: str
    event_log: str
    def decode_quote(self) -> bytes: ...
    def decode_event_log(self) -> List[EventLog]: ...
    def replay_rtmrs(self) -> Dict[int, str]: ...

class EventLog:
    imr: int
    event_type: int
    digest: str
    event: str
    event_payload: str

class TcbInfo:
    mrtd: str
    rtmr0: str
    rtmr1: str
    rtmr2: str
    rtmr3: str
    os_image_hash: str
    compose_hash: str
    device_id: str
    app_compose: str
    event_log: List[EventLog]

class InfoResponse:
    app_id: str
    instance_id: str
    app_cert: str
    tcb_info: TcbInfo
    app_name: str
    device_id: str
    os_image_hash: str
    key_provider_info: str
    compose_hash: str
    @classmethod
    def parse_response(cls, obj: Any) -> InfoResponse: ...

class BusinessMethodsMixin:
    @abstractmethod
    async def _send_rpc_request(
        self, method: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]: ...

    # Async methods
    async def get_key(
        self, path: str | None = ..., purpose: str | None = ...
    ) -> GetKeyResponse: ...
    async def get_quote(self, report_data: str | bytes) -> GetQuoteResponse: ...
    async def info(self) -> InfoResponse: ...
    async def emit_event(self, event: str, payload: str | bytes) -> None: ...
    async def get_tls_key(
        self,
        subject: str | None = ...,
        alt_names: List[str] | None = ...,
        usage_ra_tls: bool = ...,
        usage_server_auth: bool = ...,
        usage_client_auth: bool = ...,
    ) -> GetTlsKeyResponse: ...
    async def is_reachable(self) -> bool: ...

class TappdMethodsMixin:
    @abstractmethod
    async def _send_rpc_request(
        self, method: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]: ...
    async def derive_key(
        self,
        path: str | None = ...,
        subject: str | None = ...,
        alt_names: List[str] | None = ...,
    ) -> GetTlsKeyResponse: ...
    async def tdx_quote(
        self, report_data: str | bytes, hash_algorithm: str | None = ...
    ) -> GetQuoteResponse: ...

class BaseClient: ...

class AsyncDstackClient(BaseClient, BusinessMethodsMixin):
    def __init__(self, endpoint: str | None = ...) -> None: ...
    async def _send_rpc_request(
        self, method: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]: ...

class DstackClient(BaseClient, BusinessMethodsMixin):
    def __init__(self, endpoint: str | None = ...) -> None: ...
    async def _send_rpc_request(
        self, method: str, payload: Dict[str, Any]
    ) -> Dict[str, Any]: ...

    # Sync methods - these should NOT return Coroutine
    def get_key(
        self, path: str | None = ..., purpose: str | None = ...
    ) -> GetKeyResponse: ...
    def get_quote(self, report_data: str | bytes) -> GetQuoteResponse: ...
    def info(self) -> InfoResponse: ...
    def emit_event(self, event: str, payload: str | bytes) -> None: ...
    def get_tls_key(
        self,
        subject: str | None = ...,
        alt_names: List[str] | None = ...,
        usage_ra_tls: bool = ...,
        usage_server_auth: bool = ...,
        usage_client_auth: bool = ...,
    ) -> GetTlsKeyResponse: ...
    def is_reachable(self) -> bool: ...

class AsyncTappdClient(AsyncDstackClient, TappdMethodsMixin):
    def __init__(self, endpoint: str | None = ...) -> None: ...

class TappdClient(DstackClient, TappdMethodsMixin):
    def __init__(self, endpoint: str | None = ...) -> None: ...

    # Sync deprecated methods
    def derive_key(
        self,
        path: str | None = ...,
        subject: str | None = ...,
        alt_names: List[str] | None = ...,
    ) -> GetTlsKeyResponse: ...
    def tdx_quote(
        self, report_data: str | bytes, hash_algorithm: str | None = ...
    ) -> GetQuoteResponse: ...
