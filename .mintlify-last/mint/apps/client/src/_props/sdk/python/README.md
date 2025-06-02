# DStack SDK

This SDK provides a Python client for communicating with the Dstack Guest Agent, which is available inside Dstack CVM.

## Installation

```bash
pip install dstack-sdk
```

## Basic Usage

```python
from dstack_sdk import DstackClient, AsyncDstackClient

# Synchronous client
client = DstackClient()

# Caution: You don't need to do this most of the time.
http_client = DstackClient('http://localhost:8000')

# Asynchronous client
async_client = AsyncDstackClient()

# Get the information of the Base Image.
info = client.info()  # or await async_client.info()
print(info.app_id)  # Application ID
print(info.tcb_info.mrtd)  # Access TCB info directly
print(info.tcb_info.event_log[0].event)  # Access event log entries

# Derive a key with optional path and subject
key_result = client.get_key('<unique-id>')  # or await async_client.get_key('<unique-id>')
print(key_result.key)  # X.509 private key in PEM format
print(key_result.certificate_chain)  # Certificate chain
key_bytes = key_result.toBytes()  # Get key as bytes

# Generate TDX quote
quote_result = client.get_quote(report_data='some-data')  # or await async_client.get_quote(report_data='some-data')
print(quote_result.quote)  # TDX quote in hex format
print(quote_result.event_log)  # Event log
rtmrs = quote_result.replay_rtmrs()  # Replay RTMRs
```

## Web3 Integration

The SDK provides integration with various blockchain ecosystems. You need to install the SDK with the appropriate optional dependencies:

```bash
# For Ethereum support
pip install "dstack-sdk[eth]"

# For Solana support
pip install "dstack-sdk[sol]"

# For both
pip install "dstack-sdk[all]"
```

### Ethereum

You can use derived keys with the built-in Ethereum integration:

```python
from dstack_sdk import DstackClient
from dstack_sdk.ethereum import to_account

# Derive a key
client = DstackClient()
key_result = client.get_key('eth-account')

# Convert to Ethereum account
account = to_account(key_result)
print(f"Ethereum address: {account.address}")

# Use with Web3
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('https://eth-mainnet.g.alchemy.com/v2/YOUR_API_KEY'))
# Sign transactions, etc.
```

### Solana

For Solana integration, use the built-in helper:

```python
from dstack_sdk import DstackClient
from dstack_sdk.solana import to_keypair

# Derive a key
client = DstackClient()
key_result = client.get_key('solana-account')

# Convert to Solana keypair
keypair = to_keypair(key_result)
print(f"Solana public key: {keypair.pubkey()}")

# Use with Solana transactions
# ... (sign transactions, etc.)
```

## API Reference

### Running the Simulator

For local development without TDX devices, you can use the simulator under `sdk/simulator`.

Run the simulator with:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

### DstackClient and AsyncDstackClient

#### Constructor

```python
DstackClient(endpoint: str | None = None)
AsyncDstackClient(endpoint: str | None = None)
```

* `endpoint`: Unix socket path or HTTP(S) URL. Defaults to '/var/run/dstack.sock'.
* Uses `DSTACK_SIMULATOR_ENDPOINT` environment variable if set

NOTE: Leave it empty in production. You only need to add `volumes` in your docker-compose file:

```yaml
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
```

#### Methods

##### `get_key(path: str | None = None, purpose: str | None = None) -> GetKeyResponse`

Derives a key for the given path and purpose.

* `path`: Path for key derivation (optional)
* `purpose`: Purpose for key derivation (optional)
* Returns: `GetKeyResponse` containing key and signature chain

##### `get_quote(report_data: str | bytes) -> GetQuoteResponse`

Generates a TDX quote with given report data.

* `report_data`: Data to include in the quote (must be less than 64 bytes)
* Returns: `GetQuoteResponse` containing the quote and event log

##### `info() -> InfoResponse`

Retrieves information about the CVM instance.

* Returns: `InfoResponse` containing app\_id, instance\_id, and tcb\_info

##### `get_tls_key(subject: str | None = None, alt_names: List[str] | None = None, usage_ra_tls: bool = False, usage_server_auth: bool = False, usage_client_auth: bool = False) -> GetTlsKeyResponse`

Gets a TLS key from the Dstack service with optional parameters.

* `subject`: The subject for the TLS key (optional)
* `alt_names`: Alternative names for the TLS key (optional)
* `usage_ra_tls`: Whether to enable RA TLS usage (default: False)
* `usage_server_auth`: Whether to enable server auth usage (default: False)
* `usage_client_auth`: Whether to enable client auth usage (default: False)
* Returns: `GetTlsKeyResponse` containing the key and certificate chain

## Development

We use [PDM](https://pdm-project.org/en/latest/) for local development and creating an isolated environment.

Just run the following command to initiate development:

```bash
pdm install -d
```

```bash
DSTACK_SIMULATOR_ENDPOINT=$(realpath ../simulator/dstack.sock) pdm run pytest
```

## License

Apache License
