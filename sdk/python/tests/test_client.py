# SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

from dstack_sdk.dstack_client import TcbInfo
from dstack_sdk.dstack_client import InfoResponse
import hashlib
import pytest

from evidence_api.tdx.quote import TdxQuote

from dstack_sdk import DstackClient, AsyncDstackClient, GetKeyResponse, GetQuoteResponse, GetTlsKeyResponse

def test_sync_client_get_key():
    client = DstackClient()
    result = client.get_key()
    assert isinstance(result, GetKeyResponse)
    assert isinstance(result.decode_key(), bytes)
    assert len(result.decode_key()) == 32

def test_sync_client_get_quote():
    client = DstackClient()
    result = client.get_quote('test')
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
    result = await client.get_quote('test')
    assert isinstance(result, GetQuoteResponse)

@pytest.mark.asyncio
async def test_async_client_get_tls_key():
    client = AsyncDstackClient()
    result = await client.get_tls_key()
    assert isinstance(result, GetTlsKeyResponse)
    assert isinstance(result.key, str)
    assert result.key.startswith('-----BEGIN PRIVATE KEY-----')
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
    result = await client.get_quote('test')
    # TODO evidence_api is a bit out-of-date, we need an up-to-date implementation.
    tdxQuote = TdxQuote(bytes.fromhex(result.quote))
    rtmrs = result.replay_rtmrs()
    assert rtmrs[0] == tdxQuote.body.rtmr0.hex()
    assert rtmrs[1] == tdxQuote.body.rtmr1.hex()
    assert rtmrs[2] == tdxQuote.body.rtmr2.hex()
    assert rtmrs[3] == tdxQuote.body.rtmr3.hex()

@pytest.mark.asyncio
async def test_get_quote_raw_hash_error():
    with pytest.raises(ValueError) as excinfo:
        client = AsyncDstackClient()
        await client.get_quote('0' * 65)
    assert '64 bytes' in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        client = AsyncDstackClient()
        await client.get_quote(b'0' * 129)
    assert '64 bytes' in str(excinfo.value)

@pytest.mark.asyncio
async def test_report_data():
    reportdata = 'test'
    client = AsyncDstackClient()
    result = await client.get_quote(reportdata)
    tdxQuote = TdxQuote(result.decode_quote())
    reportdata = reportdata.encode('utf-8') + b'\x00' * (64 - len(reportdata))
    assert reportdata == tdxQuote.body.reportdata
