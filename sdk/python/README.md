# dstack SDK for Python

Access TEE features from your Python application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

## Installation

```bash
pip install dstack-sdk
```

## Quick Start

```python
from dstack_sdk import DstackClient

client = DstackClient()

# Derive a deterministic key for your wallet
key = client.get_key('wallet/eth')
print(key.key)  # Same path always returns the same key

# Generate an attestation quote
quote = client.get_quote(b'my-app-state')
print(quote.quote)
```

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator, pass the endpoint explicitly:

```python
client = DstackClient('http://localhost:8090')
```

## Core API

### Derive Keys

`get_key()` derives deterministic keys bound to your application's identity (`app_id`). The same path always produces the same key for your app, but different apps get different keys even with the same path.

```python
# Derive keys by path
eth_key = client.get_key('wallet/ethereum')
btc_key = client.get_key('wallet/bitcoin')

# Use path to separate keys
mainnet_key = client.get_key('wallet/eth/mainnet')
testnet_key = client.get_key('wallet/eth/testnet')

# Different algorithm
ed_key = client.get_key('signing/key', algorithm='ed25519')
```

**Parameters:**
- `path`: Key derivation path (determines the key)
- `purpose` (optional): Included in signature chain message, does not affect the derived key
- `algorithm` (optional): `'secp256k1'` (default) or `'ed25519'`

**Returns:** `GetKeyResponse`
- `key`: Hex-encoded private key
- `signature_chain`: Signatures proving the key was derived in a genuine TEE

### Generate Attestation Quotes

`get_quote()` creates a TDX quote proving your code runs in a genuine TEE.

```python
quote = client.get_quote(b'user:alice:nonce123')

# Replay RTMRs from the event log
rtmrs = quote.replay_rtmrs()
print(rtmrs)
```

**Parameters:**
- `report_data`: Exactly 64 bytes recommended. If shorter, pad with zeros. If longer, hash it first (e.g., SHA-256).

**Returns:** `GetQuoteResponse`
- `quote`: Hex-encoded TDX quote
- `event_log`: JSON string of measured events
- `replay_rtmrs()`: Method to compute RTMR values from event log

### Get Instance Info

```python
info = client.info()
print(info.app_id)
print(info.instance_id)
print(info.tcb_info)
```

**Returns:** `InfoResponse`
- `app_id`: Application identifier
- `instance_id`: Instance identifier
- `app_name`: Application name
- `tcb_info`: TCB measurements (MRTD, RTMRs, event log)
- `compose_hash`: Hash of the app configuration
- `app_cert`: Application certificate (PEM)

### Generate TLS Certificates

`get_tls_key()` creates fresh TLS certificates. Unlike `get_key()`, each call generates a new random key.

```python
tls = client.get_tls_key(
    subject='api.example.com',
    alt_names=['localhost'],
    usage_ra_tls=True  # Embed attestation in certificate
)

print(tls.key)                # PEM private key
print(tls.certificate_chain)  # Certificate chain
```

**Parameters:**
- `subject` (optional): Certificate common name (e.g., domain name)
- `alt_names` (optional): List of subject alternative names
- `usage_ra_tls` (optional): Embed TDX quote in certificate extension
- `usage_server_auth` (optional): Enable for server authentication (default: `True`)
- `usage_client_auth` (optional): Enable for client authentication (default: `False`)

**Returns:** `GetTlsKeyResponse`
- `key`: PEM-encoded private key
- `certificate_chain`: List of PEM certificates

### Sign and Verify

Sign data using TEE-derived keys (not yet released):

```python
result = client.sign('ed25519', b'message to sign')
print(result.signature)
print(result.public_key)

# Verify the signature
valid = client.verify('ed25519', b'message to sign', result.signature, result.public_key)
print(valid.valid)  # True
```

**`sign()` Parameters:**
- `algorithm`: `'ed25519'`, `'secp256k1'`, or `'secp256k1_prehashed'`
- `data`: Data to sign (bytes or string)

**`sign()` Returns:** `SignResponse`
- `signature`: Hex-encoded signature
- `public_key`: Hex-encoded public key
- `signature_chain`: Signatures proving TEE origin

**`verify()` Parameters:**
- `algorithm`: Algorithm used for signing
- `data`: Original data
- `signature`: Signature to verify
- `public_key`: Public key to verify against

**`verify()` Returns:** `VerifyResponse`
- `valid`: Boolean indicating if signature is valid

### Emit Events

Extend RTMR3 with custom measurements for your application's boot sequence (requires dstack OS 0.5.0+). These measurements are append-only and become part of the attestation record.

```python
client.emit_event('config_loaded', 'production')
client.emit_event('plugin_initialized', 'auth-v2')
```

**Parameters:**
- `event`: Event name (string identifier)
- `payload`: Event value (bytes or string)

## Async Client

For async applications, use `AsyncDstackClient`:

```python
from dstack_sdk import AsyncDstackClient
import asyncio

async def main():
    client = AsyncDstackClient()

    info = await client.info()
    key = await client.get_key('wallet/eth')

    # Concurrent operations
    keys = await asyncio.gather(
        client.get_key('user/alice'),
        client.get_key('user/bob'),
    )

asyncio.run(main())
```

## Blockchain Integration

### Ethereum

```python
from dstack_sdk.ethereum import to_account

key = client.get_key('wallet/ethereum')
account = to_account(key)
print(account.address)
```

### Solana

```python
from dstack_sdk.solana import to_keypair

key = client.get_key('wallet/solana')
keypair = to_keypair(key)
print(keypair.public_key)
```

## Development

For local development without TDX hardware, use the simulator:

```bash
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator
```

Then set the endpoint:

```bash
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

Run tests with PDM:

```bash
pdm install -d
pdm run pytest -s
```

---

## Deployment Utilities

These utilities are for deployment scripts, not runtime SDK operations.

### Encrypt Environment Variables

Encrypt secrets before deploying to dstack:

```python
from dstack_sdk import encrypt_env_vars, verify_env_encrypt_public_key, EnvVar

# Get and verify the KMS public key
# (obtain public_key and signature from KMS API)
kms_identity = verify_env_encrypt_public_key(public_key_bytes, signature_bytes, app_id)
if not kms_identity:
    raise RuntimeError('Invalid KMS key')

# Encrypt variables
env_vars = [
    EnvVar(key='DATABASE_URL', value='postgresql://...'),
    EnvVar(key='API_KEY', value='secret'),
]
encrypted = encrypt_env_vars(env_vars, public_key)
```

### Calculate Compose Hash

```python
from dstack_sdk import get_compose_hash

hash_value = get_compose_hash(app_compose_dict)
```

---

## Migration from TappdClient

Replace `TappdClient` with `DstackClient`:

```python
# Before
from dstack_sdk import TappdClient
client = TappdClient()

# After
from dstack_sdk import DstackClient
client = DstackClient()
```

Method changes:
- `derive_key()` → `get_tls_key()` for TLS certificates
- `tdx_quote()` → `get_quote()`
- Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
