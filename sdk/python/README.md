# dstack SDK

The dstack SDK provides a Python client for secure communication with the dstack Trusted Execution Environment (TEE). This SDK enables applications to derive cryptographic keys, generate remote attestation quotes, and perform other security-critical operations within confidential computing environments.

## Installation

```bash
pip install dstack-sdk
```

## Overview

The dstack SDK enables secure communication with dstack Trusted Execution Environment (TEE) instances. dstack applications are defined using `app-compose.json` (based on the `AppCompose` structure) and deployed as containerized applications using Docker Compose.

### Client Types

The Python SDK provides both synchronous and asynchronous clients to accommodate different programming patterns:

#### Synchronous Clients
- **`DstackClient`**: Main synchronous client for dstack services
- **`TappdClient`**: Deprecated synchronous client (use `DstackClient` instead)

#### Asynchronous Clients  
- **`AsyncDstackClient`**: Async/await compatible client for dstack services
- **`AsyncTappdClient`**: Deprecated async client (use `AsyncDstackClient` instead)

**Key Differences:**
- **Synchronous clients** use regular method calls and block until completion
- **Asynchronous clients** use `async`/`await` syntax and allow concurrent operations
- **API compatibility**: Both client types provide identical methods and functionality
- **Performance**: Async clients excel in I/O-bound applications with multiple concurrent requests

### Application Architecture

dstack applications consist of:
- **App Configuration**: `app-compose.json` defining app metadata, security settings, and Docker Compose content
- **Container Deployment**: Docker Compose configuration embedded within the app definition
- **TEE Integration**: Access to TEE functionality via Unix socket (`/var/run/dstack.sock`)

### SDK Capabilities

- **Key Derivation**: Deterministic secp256k1 key generation for blockchain and Web3 applications
- **Remote Attestation**: TDX quote generation providing cryptographic proof of execution environment
- **TLS Certificate Management**: Fresh certificate generation with optional RA-TLS support for secure connections
- **Deployment Security**: Client-side encryption of sensitive environment variables ensuring secrets are only accessible to target TEE applications
- **Blockchain Integration**: Ready-to-use adapters for Ethereum and Solana ecosystems

### Socket Connection Requirements

To use the SDK, your Docker Compose configuration must bind-mount the dstack socket:

```yaml
# docker-compose.yml
services:
  your-app:
    image: your-app-image
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock  # dstack OS 0.5.x
      # For dstack OS 0.3.x compatibility (deprecated):
      # - /var/run/tappd.sock:/var/run/tappd.sock
```

## Basic Usage

### Application Setup

First, ensure your dstack application is properly configured:

**1. App Configuration (`app-compose.json`)**
```json
{
  "manifest_version": 1,
  "name": "my-secure-app",  
  "runner": "docker-compose",
  "docker_compose_file": "services:\\n  app:\\n    build: .\\n    volumes:\\n      - /var/run/dstack.sock:/var/run/dstack.sock\\n    environment:\\n      - NODE_ENV=production",
  "public_tcbinfo": true,
  "kms_enabled": false,
  "gateway_enabled": false
}
```

**Note**: The `docker_compose_file` field contains the actual Docker Compose YAML content as a string, not a file path.

### Synchronous Client Usage

```python
import json
import time
from dstack_sdk import DstackClient

# Create synchronous client - automatically connects to /var/run/dstack.sock
client = DstackClient()

# For local development with simulator
dev_client = DstackClient('http://localhost:8090')

# Get TEE instance information
info = client.info()
print('App ID:', info.app_id)
print('Instance ID:', info.instance_id)
print('App Name:', info.app_name)
print('TCB Info:', info.tcb_info)

# Derive deterministic keys for blockchain applications
wallet_key = client.get_key('wallet/ethereum', 'mainnet')
print('Derived key (32 bytes):', wallet_key.decode_key())        # secp256k1 private key bytes
print('Signature chain:', wallet_key.signature_chain)           # Authenticity proof

# Generate remote attestation quote
application_data = json.dumps({
    "version": "1.0.0",
    "timestamp": time.time(),
    "user_id": "alice"
})

quote = client.get_quote(application_data.encode())
print('TDX Quote:', quote.quote)
print('Event Log:', quote.event_log)

# Verify measurement registers
rtmrs = quote.replay_rtmrs()
print('RTMR0-3:', rtmrs)
```

### Asynchronous Client Usage

```python
import json
import time
import asyncio
from dstack_sdk import AsyncDstackClient

async def main():
    # Create asynchronous client
    async_client = AsyncDstackClient()
    
    # All methods must be awaited
    info = await async_client.info()
    print('App ID:', info.app_id)
    
    # Derive keys asynchronously
    wallet_key = await async_client.get_key('wallet/ethereum', 'mainnet')
    print('Derived key:', wallet_key.decode_key().hex())
    
    # Generate quote asynchronously
    quote = await async_client.get_quote(b'async-test-data')
    print('Quote length:', len(quote.quote))
    
    # Multiple concurrent operations
    tasks = [
        async_client.get_key('wallet/btc', 'mainnet'),
        async_client.get_key('wallet/eth', 'mainnet'),
        async_client.get_key('signing/key', 'production')
    ]
    
    # Execute concurrently
    keys = await asyncio.gather(*tasks)
    for i, key in enumerate(keys):
        print(f'Key {i}: {key.decode_key().hex()[:16]}...')

# Run async code
if __name__ == "__main__":
    asyncio.run(main())
```

### Choosing Between Sync and Async

**Use Synchronous Client (`DstackClient`) when:**
- Building simple scripts or CLI tools
- Making sequential API calls
- Working in synchronous codebases
- Learning or prototyping

**Use Asynchronous Client (`AsyncDstackClient`) when:**
- Building web applications (FastAPI, Starlette, etc.)
- Needing concurrent TEE operations
- Integrating with async frameworks
- Optimizing I/O-bound applications

```python
# Example: Concurrent key derivation (async advantage)
async def derive_multiple_keys():
    client = AsyncDstackClient()
    
    # This is much faster than sequential sync calls
    keys = await asyncio.gather(
        client.get_key('user/alice', 'eth'),
        client.get_key('user/bob', 'eth'),
        client.get_key('user/charlie', 'eth')
    )
    return keys
```

### Version Compatibility

- **dstack OS 0.5.x**: Use `/var/run/dstack.sock` (current)
- **dstack OS 0.3.x**: Use `/var/run/tappd.sock` (deprecated but supported)

The SDK automatically detects the correct socket path, but you must ensure the appropriate volume binding in your Docker Compose configuration.

## Advanced Features

### TLS Certificate Generation

Generate fresh TLS certificates with optional Remote Attestation support. **Important**: `get_tls_key()` generates random keys on each call - it's designed specifically for TLS/SSL scenarios where fresh keys are required.

```python
# Generate TLS certificate with different usage scenarios
tls_key = client.get_tls_key(
    subject='my-secure-service',              # Certificate common name
    alt_names=['localhost', '127.0.0.1'],     # Additional valid domains/IPs
    usage_ra_tls=True,                        # Include remote attestation
    usage_server_auth=True,                   # Enable server authentication (default)
    usage_client_auth=False                   # Disable client authentication
)

print('Private Key (PEM):', tls_key.key)
print('Certificate Chain:', tls_key.certificate_chain)

# ⚠️ WARNING: Each call generates a different key
tls_key1 = client.get_tls_key()
tls_key2 = client.get_tls_key()
# tls_key1.key != tls_key2.key (always different!)
```

### Event Logging

> [!NOTE]
> This feature isn't available in the simulator. We recommend sticking with `report_data` for most cases since it's simpler and safer to use. If you're not super familiar with SGX/TDX attestation quotes, it's best to avoid adding data directly into quotes as it could cause verification issues.

Extend RTMR3 with custom events for audit trails:

```python
# Emit custom events (requires dstack OS 0.5.0+)
client.emit_event('user-action', json.dumps({
    "action": "transfer",
    "amount": 1000,
    "timestamp": time.time()
}))

# Events are automatically included in subsequent quotes
quote = client.get_quote(b'audit-data')
events = json.loads(quote.event_log)
```

## Blockchain Integration

### Ethereum

```python
from dstack_sdk.ethereum import to_account

key_result = client.get_key('ethereum/main', 'wallet')

# Convert to Ethereum account
account = to_account(key_result)
print(f"Ethereum address: {account.address}")

# Use with Web3.py
from web3 import Web3
w3 = Web3(Web3.HTTPProvider('https://mainnet.infura.io/v3/YOUR-PROJECT-ID'))

# Sign transactions, etc.
```

### Solana

```python
from dstack_sdk.solana import to_keypair

key_result = client.get_key('solana/main', 'wallet')

# Convert to Solana keypair
keypair = to_keypair(key_result)
print(f"Solana public key: {keypair.public_key}")

# Use with solana-py
from solana.rpc.api import Client
from solana.transaction import Transaction
from solana.system_program import transfer, TransferParams

client_rpc = Client("https://api.mainnet-beta.solana.com")

# Create and send transaction
# ... (implement transaction logic)
```

## Environment Variables Encryption

**Important**: This feature is specifically for **deployment-time security**, not runtime SDK operations.

The SDK provides end-to-end encryption capabilities for securely transmitting sensitive environment variables during dstack application deployment. When deploying applications to TEE instances, sensitive configuration data (API keys, database credentials, private keys, etc.) needs to be securely transmitted from the deployment client to the TEE application.

### Deployment Security Problem

During application deployment, sensitive data must traverse:
1. **Client Environment** → Deployment infrastructure → **TEE Application**
2. **Risk**: Deployment infrastructure could potentially access plaintext secrets
3. **Solution**: Client-side encryption ensures only the target TEE application can decrypt secrets

### How It Works

1. **Pre-Deployment**: Client obtains encryption public key from KMS API
2. **Encryption**: Client encrypts environment variables using X25519 + AES-GCM
3. **Transmission**: Encrypted payload is sent through deployment infrastructure  
4. **Decryption**: TEE application automatically decrypts and loads environment variables
5. **Runtime**: Application accesses secrets via standard `os.environ`

This ensures **true end-to-end encryption** where deployment infrastructure never sees plaintext secrets.

### App Configuration for Encrypted Variables

Your `app-compose.json` should specify which environment variables are allowed:

```json
{
  "manifest_version": 1,
  "name": "secure-app",
  "runner": "docker-compose", 
  "docker_compose_file": "services:\\n  app:\\n    build: .\\n    volumes:\\n      - /var/run/dstack.sock:/var/run/dstack.sock\\n    environment:\\n      - API_KEY\\n      - DATABASE_URL\\n      - PRIVATE_KEY",
  "allowed_envs": ["API_KEY", "DATABASE_URL", "PRIVATE_KEY"],
  "kms_enabled": true
}
```

### Deployment Encryption Workflow

```python
from dstack_sdk import encrypt_env_vars, verify_env_encrypt_public_key, EnvVar
import requests
import json

# 1. Define sensitive environment variables
env_vars = [
    EnvVar(key='DATABASE_URL', value='postgresql://user:pass@host:5432/db'),
    EnvVar(key='API_SECRET_KEY', value='your-secret-key'),
    EnvVar(key='JWT_PRIVATE_KEY', value='-----BEGIN PRIVATE KEY-----\\n...'),
    EnvVar(key='WALLET_MNEMONIC', value='abandon abandon abandon...'),
]

# 2. Obtain encryption public key from KMS API (dstack-vmm or Phala Cloud)
response = requests.post('/prpc/GetAppEnvEncryptPubKey?json', 
                        headers={'Content-Type': 'application/json'},
                        json={'app_id': 'your-app-id-hex'})
data = response.json()
public_key, signature = data['public_key'], data['signature']

# 3. Verify KMS API authenticity to prevent man-in-the-middle attacks
public_key_bytes = bytes.fromhex(public_key)
signature_bytes = bytes.fromhex(signature)

trusted_pubkey = verify_env_encrypt_public_key(public_key_bytes, signature_bytes, 'your-app-id-hex')
if not trusted_pubkey:
    raise RuntimeError('KMS API provided untrusted encryption key')

print('Verified KMS public key:', trusted_pubkey.hex())

# 4. Encrypt environment variables for secure deployment
encrypted_data = encrypt_env_vars(env_vars, public_key)
print('Encrypted payload:', encrypted_data)

# 5. Deploy with encrypted configuration
# deploy_dstack_app({
#     'app_id': 'your-app-id-hex',
#     'encrypted_env': encrypted_data,
#     # ... other deployment parameters
# })
```

### Security Guarantees

The environment encryption system provides several security guarantees:

**End-to-End Encryption**: Environment variables are encrypted on the client side and can only be decrypted by the target dstack application inside the TEE. Even the deployment infrastructure cannot access the plaintext values.

**KMS Authenticity Verification**: The `verify_env_encrypt_public_key` function validates that the encryption public key comes from a trusted KMS (Key Management Service), preventing man-in-the-middle attacks during key exchange.

**Forward Secrecy**: Each encryption operation uses ephemeral X25519 keypairs, ensuring that compromising long-term keys cannot decrypt past communications.

**Authenticated Encryption**: AES-256-GCM provides both confidentiality and integrity protection, detecting any tampering with encrypted data.

## Cryptographic Security

### Key Derivation Security

The SDK implements secure key derivation using:

- **Deterministic Generation**: Keys are derived using HMAC-based Key Derivation Function (HKDF)
- **Application Isolation**: Each path produces unique keys, preventing cross-application access
- **Signature Verification**: All derived keys include cryptographic proof of origin
- **TEE Protection**: Master keys never leave the secure enclave

```python
# Each path generates a unique, deterministic key
wallet1 = client.get_key('app1/wallet', 'ethereum')
wallet2 = client.get_key('app2/wallet', 'ethereum')
# wallet1.key != wallet2.key (guaranteed different)

same_wallet = client.get_key('app1/wallet', 'ethereum')
# wallet1.key == same_wallet.key (guaranteed identical)
```

### Remote Attestation

TDX quotes provide cryptographic proof of:

- **Code Integrity**: Measurement of loaded application code
- **Data Integrity**: Inclusion of application-specific data in quote
- **Environment Authenticity**: Verification of TEE platform and configuration

```python
import json
import time

application_state = json.dumps({
    "version": "1.0.0",
    "config_hash": "sha256:...",
    "timestamp": time.time()
})

quote = client.get_quote(application_state.encode())

# Quote can be verified by external parties to confirm:
# 1. Application is running in genuine TEE
# 2. Application code matches expected measurements
# 3. Application state is authentic and unmodified
```

### Environment Encryption Protocol

The encryption scheme uses:

- **X25519 ECDH**: Elliptic curve key exchange for forward secrecy
- **AES-256-GCM**: Authenticated encryption with 256-bit keys
- **Ephemeral Keys**: New keypair generated for each encryption operation
- **Authenticated Data**: Prevents tampering and ensures integrity

## Development and Testing

### Local Development

For development without physical TDX hardware:

```bash
# Clone and build simulator
git clone https://github.com/Dstack-TEE/dstack.git
cd dstack/sdk/simulator
./build.sh
./dstack-simulator

# Set environment variable
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
```

### Testing Connectivity

```python
client = DstackClient()

# Check if dstack service is available
is_available = client.is_reachable()
if not is_available:
    print('dstack service is not reachable')
    exit(1)
```

## API Reference

### Client Classes Overview

The Python SDK provides four client classes with identical functionality but different execution models:

| Client Class | Type | Status | Use Case |
|-------------|------|--------|----------|
| `DstackClient` | Synchronous | ✅ Active | General use, scripts, synchronous code |
| `AsyncDstackClient` | Asynchronous | ✅ Active | Web apps, concurrent operations |
| `TappdClient` | Synchronous | ⚠️ Deprecated | Legacy compatibility only |
| `AsyncTappdClient` | Asynchronous | ⚠️ Deprecated | Legacy compatibility only |

### DstackClient (Synchronous)

#### Constructor

```python
DstackClient(endpoint: str | None = None)
```

**Parameters:**
- `endpoint` (optional): Connection endpoint
  - Unix socket path (production): `/var/run/dstack.sock`
  - HTTP/HTTPS URL (development): `http://localhost:8090`
  - Environment variable: `DSTACK_SIMULATOR_ENDPOINT`

### AsyncDstackClient (Asynchronous)

#### Constructor

```python
AsyncDstackClient(endpoint: str | None = None)
```

**Parameters:** Same as `DstackClient`

**Key Differences from Sync Client:**
- All methods are `async` and must be awaited
- Supports concurrent operations with `asyncio.gather()`
- Better performance for multiple I/O operations
- Integrates with async frameworks (FastAPI, aiohttp, etc.)

**Production App Configuration:**

The Docker Compose configuration is embedded in `app-compose.json`:

```json
{
  "manifest_version": 1,
  "name": "production-app",
  "runner": "docker-compose",
  "docker_compose_file": "services:\\n  app:\\n    image: your-app\\n    volumes:\\n      - /var/run/dstack.sock:/var/run/dstack.sock\\n    environment:\\n      - NODE_ENV=production",
  "public_tcbinfo": true
}
```

**Important**: The `docker_compose_file` contains YAML content as a string, ensuring the volume binding for `/var/run/dstack.sock` is included.

### Shared Methods

All methods below are available in both synchronous and asynchronous clients with identical signatures and functionality:

| Sync Method | Async Method | Description |
|------------|--------------|-------------|
| `client.info()` | `await async_client.info()` | Get TEE instance information |
| `client.get_key(...)` | `await async_client.get_key(...)` | Derive deterministic keys |
| `client.get_quote(...)` | `await async_client.get_quote(...)` | Generate attestation quote |
| `client.get_tls_key(...)` | `await async_client.get_tls_key(...)` | Generate TLS certificate |
| `client.emit_event(...)` | `await async_client.emit_event(...)` | Log custom events |
| `client.is_reachable()` | `await async_client.is_reachable()` | Test connectivity |

#### Methods

##### `info() -> InfoResponse` / `async info() -> InfoResponse`

Retrieves comprehensive information about the TEE instance.

**Returns:** `InfoResponse`
- `app_id`: Unique application identifier
- `instance_id`: Unique instance identifier  
- `app_name`: Application name from configuration
- `device_id`: TEE device identifier
- `tcb_info`: Trusted Computing Base information
  - `mrtd`: Measurement of TEE domain
  - `rtmr0-3`: Runtime Measurement Registers
  - `event_log`: Boot and runtime events
  - `os_image_hash`: Operating system measurement
  - `compose_hash`: Application configuration hash
- `app_cert`: Application certificate in PEM format
- `key_provider_info`: Key management configuration

##### `get_key(path: str | None = None, purpose: str | None = None) -> GetKeyResponse`

Derives a deterministic secp256k1/K256 private key for blockchain and Web3 applications. This is the primary method for obtaining cryptographic keys for wallets, signing, and other deterministic key scenarios.

**Parameters:**
- `path`: Unique identifier for key derivation (e.g., `"wallet/ethereum"`, `"signing/solana"`)
- `purpose` (optional): Additional context for key usage (default: `""`)

**Returns:** `GetKeyResponse`
- `key`: 32-byte secp256k1 private key as hex string (suitable for Ethereum, Bitcoin, Solana, etc.)
- `signature_chain`: Array of cryptographic signatures proving key authenticity

**Key Characteristics:**
- **Deterministic**: Same path + purpose always generates identical key
- **Isolated**: Different paths produce cryptographically independent keys  
- **Blockchain-Ready**: Compatible with secp256k1 curve (Ethereum, Bitcoin, Solana)
- **Verifiable**: Signature chain proves key was derived inside genuine TEE

**Use Cases:**
- Cryptocurrency wallets
- Transaction signing
- DeFi protocol interactions
- NFT operations
- Any scenario requiring consistent, reproducible keys

```python
# Examples of deterministic key derivation
eth_wallet = client.get_key('wallet/ethereum', 'mainnet')
btc_wallet = client.get_key('wallet/bitcoin', 'mainnet')
sol_wallet = client.get_key('wallet/solana', 'mainnet')

# Same path always returns same key
key1 = client.get_key('my-app/signing')
key2 = client.get_key('my-app/signing')
# key1.decode_key() == key2.decode_key() (guaranteed identical)

# Different paths return different keys
user_a = client.get_key('user/alice/wallet')
user_b = client.get_key('user/bob/wallet')  
# user_a.decode_key() != user_b.decode_key() (guaranteed different)
```

##### `get_quote(report_data: str | bytes) -> GetQuoteResponse`

Generates a TDX attestation quote containing the provided report data.

**Parameters:**
- `report_data`: Data to include in quote (max 64 bytes)

**Returns:** `GetQuoteResponse`
- `quote`: TDX quote as hex string
- `event_log`: JSON string of system events
- `replay_rtmrs()`: Method returning computed RTMR values

**Use Cases:**
- Remote attestation of application state
- Cryptographic proof of execution environment
- Audit trail generation

##### `get_tls_key(subject: str | None = None, alt_names: List[str] | None = None, usage_ra_tls: bool = False, usage_server_auth: bool = True, usage_client_auth: bool = False) -> GetTlsKeyResponse`

Generates a fresh, random TLS key pair with X.509 certificate for TLS/SSL connections. **Important**: This method generates different keys on each call - use `get_key()` for deterministic keys.

**Parameters:**
- `subject` (optional): Certificate subject (Common Name) - typically the domain name (default: `""`)
- `alt_names` (optional): Subject Alternative Names - additional domains/IPs for the certificate (default: `[]`)
- `usage_ra_tls` (optional): Include TDX attestation quote in certificate extension for remote verification (default: `False`)
- `usage_server_auth` (optional): Enable server authentication - allows certificate to authenticate servers (default: `True`)
- `usage_client_auth` (optional): Enable client authentication - allows certificate to authenticate clients (default: `False`)

**Returns:** `GetTlsKeyResponse`
- `key`: Private key in PEM format (X.509/PKCS#8)
- `certificate_chain`: Certificate chain list

**Key Characteristics:**
- **Random Generation**: Each call produces a completely different key
- **TLS-Optimized**: Keys and certificates designed for TLS/SSL scenarios
- **RA-TLS Support**: Optional remote attestation extension in certificates
- **TEE-Signed**: Certificates signed by TEE-resident Certificate Authority

##### `emit_event(event: str, payload: str | bytes) -> None`

Extends RTMR3 with a custom event for audit logging.

**Parameters:**
- `event`: Event identifier string
- `payload`: Event data

**Requirements:**
- dstack OS version 0.5.0 or later
- Events are permanently recorded in TEE measurements

##### `is_reachable() -> bool`

Tests connectivity to the dstack service.

**Returns:** `bool` indicating service availability

## Utility Functions

### Compose Hash Calculation

```python
from dstack_sdk import get_compose_hash

app_compose = {
    "manifest_version": 1,
    "name": "my-app",
    "runner": "docker-compose",
    "docker_compose_file": "docker-compose.yml"
}

hash_value = get_compose_hash(app_compose)
print('Configuration hash:', hash_value)
```

### KMS Public Key Verification

Verify the authenticity of encryption public keys provided by KMS APIs:

```python
from dstack_sdk import verify_env_encrypt_public_key

# Example: Verify KMS-provided encryption key
public_key = bytes.fromhex('e33a1832c6562067ff8f844a61e51ad051f1180b66ec2551fb0251735f3ee90a')
signature = bytes.fromhex('8542c49081fbf4e03f62034f13fbf70630bdf256a53032e38465a27c36fd6bed7a5e7111652004aef37f7fd92fbfc1285212c4ae6a6154203a48f5e16cad2cef00')
app_id = '0000000000000000000000000000000000000000'

kms_identity = verify_env_encrypt_public_key(public_key, signature, app_id)

if kms_identity:
    print('Trusted KMS identity:', kms_identity.hex())
    # Safe to use the public key for encryption
else:
    print('KMS signature verification failed')
    # Potential man-in-the-middle attack
```

## Security Best Practices

1. **Key Management**
   - Use descriptive, unique paths for key derivation
   - Never expose derived keys outside the TEE
   - Implement proper access controls in your application

2. **Remote Attestation**
   - Always verify quotes before trusting remote TEE instances
   - Include application-specific data in quote generation
   - Validate RTMR measurements against expected values

3. **TLS Configuration**
   - Enable RA-TLS for attestation-based authentication
   - Use appropriate certificate validity periods
   - Implement proper certificate validation

4. **Error Handling**
   - Handle cryptographic operation failures gracefully
   - Log security events for monitoring
   - Implement fallback mechanisms where appropriate

## Migration Guide

### Critical API Changes: Understanding the Separation

The legacy client mixed two different use cases that have now been properly separated:

1. **`get_key()`**: Deterministic key derivation for Web3/blockchain (secp256k1)
2. **`get_tls_key()`**: Random TLS certificate generation for HTTPS/SSL

### From TappdClient to DstackClient

**⚠️ BREAKING CHANGE**: `TappdClient` and `AsyncTappdClient` are deprecated and will be removed. All users must migrate to `DstackClient` and `AsyncDstackClient`.

### Complete Migration Reference

| Component | TappdClient (Old) | DstackClient (New) | Status |
|-----------|-------------------|-------------------|---------| 
| **Socket Path** | `/var/run/tappd.sock` | `/var/run/dstack.sock` | ✅ Updated |
| **HTTP URL Format** | `http://localhost/prpc/Tappd.<Method>` | `http://localhost/<Method>` | ✅ Simplified |
| **K256 Key Method** | `get_key(...)` | `get_key(...)` | ✅ Same |
| **TLS Certificate Method** | `derive_key(...)` | `get_tls_key(...)` | ✅ Separated |
| **TDX Quote (Raw)** | `tdx_quote(...)` | `get_quote(report_data)` | ✅ Renamed |

#### Migration Steps

**Step 1: Update Imports and Client**

```python
# Before
from dstack_sdk import TappdClient, AsyncTappdClient
client = TappdClient()
async_client = AsyncTappdClient()

# After  
from dstack_sdk import DstackClient, AsyncDstackClient
client = DstackClient()
async_client = AsyncDstackClient()
```

**Step 2: Update Method Calls**

```python
# For deterministic keys (most common)
# Before: TappdClient methods
key_result = client.get_key('wallet', 'ethereum')

# After: DstackClient methods (same!)
key_result = client.get_key('wallet', 'ethereum')

# For TLS certificates
# Before: derive_key with TLS options
tls_cert = client.derive_key('api', 'example.com', ['localhost'])

# After: get_tls_key with proper options
tls_cert = client.get_tls_key(
    subject='example.com',
    alt_names=['localhost']
)
```

### Migration Checklist

- [ ] **Infrastructure Updates:**
  - [ ] Update Docker volume binding to `/var/run/dstack.sock`
  - [ ] Change environment variables from `TAPPD_*` to `DSTACK_*`

- [ ] **Client Code Updates:**
  - [ ] Replace `TappdClient` with `DstackClient`
  - [ ] Replace `AsyncTappdClient` with `AsyncDstackClient`
  - [ ] Replace `derive_key()` calls with `get_tls_key()` for TLS certificates
  - [ ] Replace `tdx_quote()` calls with `get_quote()`

- [ ] **Testing:**
  - [ ] Test that deterministic keys still work as expected
  - [ ] Verify TLS certificate generation works
  - [ ] Test quote generation with new interface

## Development

We use [PDM](https://pdm-project.org/en/latest/) for local development and creating an isolated environment.

To initiate development:

```bash
pdm install -d
```

To run tests:

```bash
DSTACK_SIMULATOR_ENDPOINT=/path/to/dstack/sdk/simulator/dstack.sock pdm run pytest -s
```

## License

Apache License 2.0