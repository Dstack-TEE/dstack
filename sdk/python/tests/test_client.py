import hashlib
import pytest

from evidence_api.tdx.quote import TdxQuote

from dstack_sdk import TappdClient, AsyncTappdClient, DeriveKeyResponse, TdxQuoteResponse

# Test PEM key for cross-platform validation
TEST_PEM_KEY = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsxWvvkVZix6DYyFP
aS1yz5RZLOSiiHLx8mp7axE6Whuha0QDQgAED/3OrGv33eegcOrd8WYJWLMbDJQc
TJaeKpGauQSXugPjuwnq4a2mCUE221wXaGWAXBtH4eiHiumFe2eFzeDACA==
-----END PRIVATE KEY-----"""

def test_sync_client_derive_key():
    client = TappdClient()
    result = client.derive_key()
    assert isinstance(result, DeriveKeyResponse)
    asBytes = result.toBytes()
    assert isinstance(asBytes, bytes)
    asBytes = result.toBytes(32)
    assert isinstance(asBytes, bytes)
    assert len(asBytes) == 32

def test_toBytes_output_validation():
    """Test toBytes method with known PEM key for cross-platform validation"""
    # Create a mock DeriveKeyResponse with known PEM key
    response = DeriveKeyResponse(key=TEST_PEM_KEY, certificate_chain=[])
    
    # Test full length conversion
    result_full = response.toBytes()
    assert isinstance(result_full, bytes)
    assert len(result_full) == 139  # Expected length for this key
    
    # Test with specific length
    result_32 = response.toBytes(32)
    assert isinstance(result_32, bytes)
    assert len(result_32) == 32
    
    # Verify expected hex output (first 32 bytes should match JavaScript)
    expected_prefix = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
    assert result_32.hex() == expected_prefix
    
    # Test that longer result starts with the same prefix
    assert result_full[:32].hex() == expected_prefix
    
    # Expected full hex for this specific key
    expected_full_hex = ("308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02"
                        "01010420b315afbe45598b1e8363214f692d72cf94592ce4a28872f1f26a7b6b11"
                        "3a5a1ba16b44034200040ffdceac6bf7dde7a070eaddf1660958b31b0c941c4c96"
                        "9e2a919ab90497ba03e3bb09eae1ada6094136db5c176865805c1b47e1e8878ae9"
                        "857b6785cde0c008")
    assert result_full.hex() == expected_full_hex

def test_sync_client_tdx_quote():
    client = TappdClient()
    result = client.tdx_quote('test')
    assert isinstance(result, TdxQuoteResponse)

@pytest.mark.asyncio
async def test_async_client_derive_key():
    client = AsyncTappdClient()
    result = await client.derive_key()
    assert isinstance(result, DeriveKeyResponse)

@pytest.mark.asyncio
async def test_async_client_tdx_quote():
    client = AsyncTappdClient()
    result = await client.tdx_quote('test')
    assert isinstance(result, TdxQuoteResponse)

@pytest.mark.asyncio
async def test_replay_rtmr():
    client = AsyncTappdClient()
    result = await client.tdx_quote('test')
    # TODO evidence_api is a bit out-of-date, we need an up-to-date implementation.
    tdxQuote = TdxQuote(bytes.fromhex(result.quote[2:]))
    rtmrs = result.replay_rtmrs()
    assert rtmrs[0] == tdxQuote.body.rtmr0.hex()
    assert rtmrs[1] == tdxQuote.body.rtmr1.hex()
    assert rtmrs[2] == tdxQuote.body.rtmr2.hex()
    assert rtmrs[3] == tdxQuote.body.rtmr3.hex()

@pytest.mark.asyncio
async def test_tdx_quote_raw_hash_error():
    with pytest.raises(ValueError) as excinfo:
        client = AsyncTappdClient()
        await client.tdx_quote('0' * 65, 'raw')
    assert '64 characters' in str(excinfo.value)
    with pytest.raises(ValueError) as excinfo:
        client = AsyncTappdClient()
        await client.tdx_quote(b'0' * 129, 'raw')
    assert '128 bytes' in str(excinfo.value)

@pytest.mark.asyncio
async def test_report_data():
    reportdata = 'test'
    client = AsyncTappdClient()
    result = await client.tdx_quote(reportdata)
    tdxQuote = TdxQuote(bytes.fromhex(result.quote[2:]))
    assert hashlib.sha512(b"app-data:" + reportdata.encode("utf8")).hexdigest() == tdxQuote.body.reportdata.hex()
    # #2
    result = await client.tdx_quote(reportdata, 'raw')
    tdxQuote = TdxQuote(bytes.fromhex(result.quote[2:]))
    print(tdxQuote.body.reportdata.lstrip(b'\x00') == reportdata.encode('utf8'))
