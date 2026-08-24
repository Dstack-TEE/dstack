# dstack SDK for Python

Access TEE features from your Python application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

## Installation

```bash
pip install dstack-sdk
```

Blockchain helpers are optional extras:

| Extra | Pulls in | Use when |
|---|---|---|
| `dstack-sdk[ethereum]` | `eth-account` | You want `to_account` / `to_account_secure` for Ethereum signing |
| `dstack-sdk[solana]` | `solders` | You want `to_keypair` / `to_keypair_secure` for Solana signing |
| `dstack-sdk[all]` | both | You need both |

Aliases `[eth]` and `[sol]` are accepted for convenience.

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

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator:

```python
client = DstackClient('http://localhost:8090')
# or export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8090
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

# Use a different signature algorithm (requires dstack OS >= 0.5.7)
ed_key = client.get_key('signing/key', algorithm='ed25519')
```

**Parameters:**
- `path` (optional): Key derivation path. Defaults to `""` (root).
- `purpose` (optional): Included in the signature chain message; does not affect the derived key.
- `algorithm` (optional): `'secp256k1'` (default) or `'ed25519'`. For compatibility, this selects how the same derived 32-byte material is interpreted; it does not domain-separate the derivation. Use algorithm-specific paths when independent keys are required.

**Returns:** `GetKeyResponse`
- `key`: Hex-encoded private key
- `signature_chain`: Signatures proving the key was derived in a genuine TEE
- `decode_key()` / `decode_signature_chain()`: Helpers that return `bytes`

### Generate Attestation Quotes

`get_quote()` creates a TDX quote proving your code runs in a genuine TEE.
It needs Intel TDX: without it the call fails, and on GCP Confidential VMs it
returns the TDX quote alone, leaving out the vTPM quote GCP's verification also
binds. Call `attest()` in both cases.

```python
quote = client.get_quote(b'user:alice:nonce123')
print(quote.event_log)
```

**Parameters:**
- `report_data`: Up to 64 bytes (`bytes` or `str`). Shorter inputs are padded with zeros; longer inputs should be hashed first (e.g., SHA-256).

**Returns:** `GetQuoteResponse`
- `quote`: Hex-encoded TDX quote
- `event_log`: JSON string of measured events
- `decode_quote()` / `decode_event_log()`: Helpers

### Versioned Attestation

`attest()` returns a versioned attestation payload that newer verifier APIs can dispatch on without sniffing the quote format.

```python
result = client.attest(b'user:alice:nonce123')
print(result.attestation)        # hex string
print(result.decode_attestation())  # bytes
```

Pass `include_boottime_gpu_evidence=True` to also return the boot-time GPU attestation
evidence, so a verifier gets the quote and the GPU evidence in one round trip.

```python
result = client.attest(b'user:alice:nonce123', include_boottime_gpu_evidence=True)
print(result.boottime_gpu_evidence)
```

The evidence is the same bytes ``gpu_info()`` serves and is empty unless the flag was set
and boot-time GPU attestation output exists. It is not bound to `report_data`; verify
it with the measured `gpu-attestation` event digest as described under ``gpu_info()``.

### On-demand GPU Attestation

`attest_gpu(nonce)` collects vendor-native GPU evidence for a caller-chosen 32-byte
nonce.

```python
result = client.attest_gpu(os.urandom(32))
for bundle in result.bundles:
    print(bundle.vendor, bundle.format, bundle.evidence)
```

Select a verifier using each bundle's `vendor` and `format`. The verifier must check
the evidence signature, certificate chain, measurements, and embedded nonce. Evidence
is opaque and hex-encoded by the JSON RPC. It does not by itself bind the GPU to this
CVM.

### GPU Info

`gpu_info()` returns GPU information collected during boot. Currently, this
includes the complete NVIDIA `nvattest` JSON output.

```python
gpu = client.gpu_info()
print(gpu.attestation)
```

The `attestation` field is empty when no GPU attestation output is available.
The raw output is not trusted by itself; remote verifiers should compare its
digest with the measured `gpu-attestation` runtime event.

### Get Instance Info

```python
info = client.info()
print(info.app_id)
print(info.instance_id)
print(info.tcb_info)
print(info.cloud_vendor, info.cloud_product)  # 0.5.7+
```

**Returns:** `InfoResponse`
- `app_id`, `instance_id`, `app_name`, `device_id`
- `tcb_info`: TCB measurements (MRTD, RTMRs, event log, compose hash, ...)
- `compose_hash`: Hash of the app configuration
- `app_cert`: Application certificate (PEM)
- `key_provider_info`: Key management configuration
- `cloud_vendor` / `cloud_product`: Cloud provider strings (empty on older OS)

### Generate TLS Certificates

`get_tls_key()` creates fresh TLS certificates. Unlike `get_key()`, each call generates a new random key.

```python
tls = client.get_tls_key(
    subject='api.example.com',
    alt_names=['localhost'],
    usage_ra_tls=True,    # Embed attestation in certificate
    # 0.5.7+ options below:
    not_before=1700000000,   # seconds since UNIX epoch
    not_after=1800000000,
    with_app_info=True,
)
print(tls.key)                  # PEM private key
print(tls.certificate_chain)    # Certificate chain
```

**Parameters:**
- `subject` (optional): Certificate Common Name (e.g., domain name)
- `alt_names` (optional): Subject Alternative Names
- `usage_ra_tls` (optional): Embed TDX quote in a certificate extension (default `False`)
- `usage_server_auth` (optional): Enable for server authentication (default `True`)
- `usage_client_auth` (optional): Enable for client authentication (default `False`)
- `not_before` / `not_after` (optional, kw-only): Validity window in seconds since UNIX epoch. Requires dstack OS >= 0.5.7.
- `with_app_info` (optional, kw-only): Embed app identity into the certificate. Requires dstack OS >= 0.5.7.

When any of the 0.5.7-only options is set, the SDK probes `Version` first and raises `RuntimeError` on older guest agents that lack it.

**Returns:** `GetTlsKeyResponse`
- `key`: PEM-encoded private key
- `certificate_chain`: List of PEM certificates
- `as_uint8array(max_length=None)`: Returns the DER-encoded private key bytes (handy when feeding key material into low-level crypto libraries)

### Sign and Verify

Signing happens in the TEE, because it needs a key only the TEE holds. Verifying
does not, so it runs locally in this SDK — the guest agent's `Verify` RPC was
removed in v0.6.0. Its answer arrived over the socket unattested, so trusting it
was never better than checking the signature yourself.

```python
from dstack_sdk import verify_signature, verify_signature_chain

result = client.sign('ed25519', b'message to sign')

# Does this signature check out under this public key?
valid = verify_signature(
    'ed25519',
    b'message to sign',
    result.decode_signature(),
    result.decode_public_key(),
)
assert valid is True
```

**`sign()` Parameters:**
- `algorithm`: `'ed25519'`, `'secp256k1'` (alias `'k256'`), or `'secp256k1_prehashed'`
- `data`: Data to sign (`bytes` or `str`). For `secp256k1_prehashed`, must be a 32-byte digest.

**`sign()` Returns:** `SignResponse`
- `signature`: Hex-encoded signature
- `public_key`: Hex-encoded public key
- `signature_chain`: Three signatures linking the signing key back to the KMS root

**`verify_signature()` Returns:** `bool` — `False` when a well-formed signature
does not match, and it *raises* `ValueError` when an input is malformed (bad key
length, wrong signature length, unknown algorithm, non-canonical high-S
signature). A malformed input is a caller bug, not a verdict.

#### Verifying the whole chain

`verify_signature` alone proves only that whoever holds that public key signed
the data. It says nothing about *whose* key it is. `verify_signature_chain`
walks all three links back to a KMS root key you supply:

```python
# Both anchors come from you, not from the CVM being checked.
expected_app_id = bytes.fromhex('a9019d1b2c3d4e5f60718293a4b5c6d7e8f90a1b')
kms_root_pubkey = bytes.fromhex('03...')  # pinned, or read from DstackKms

app_root_pubkey = verify_signature_chain(
    'ed25519',
    b'message to sign',
    result.decode_public_key(),
    result.decode_signature_chain(),
    expected_app_id,
    kms_root_pubkey,
)
print(app_root_pubkey.hex())  # compressed SEC1, 33 bytes
```

Note what the example does *not* do: it never passes `client.info().app_id`
straight through. That value is reported by the very CVM being verified, so a
chain checked against it proves only that the CVM is self-consistent with
itself. Use the app id you registered on chain, and if you want `AppInfo` in the
picture, compare it against that value rather than trusting it.

It returns the app root public key and raises `ValueError` on any failure.

`kms_root_pubkey` must come from somewhere you already trust: the `DstackKms`
contract's `kmsInfo().k256Pubkey`, or a value you pinned. Reading it from the
same KMS you are checking against proves nothing — an attacker who can answer
that query can also mint a self-consistent chain. This comparison is the entire
point of the chain; skip it and the other two links establish nothing.

### Diagnostics

```python
client.version()        # VersionResponse(version, rev) — raises on OS < 0.5.7
client.is_reachable()   # Quick connectivity probe; never raises
```

## Async Client

For async applications, use `AsyncDstackClient`. The API surface is identical, but every method is a coroutine:

```python
import asyncio
from dstack_sdk import AsyncDstackClient

async def main():
    client = AsyncDstackClient()

    info = await client.info()
    key = await client.get_key('wallet/eth')

    # Run requests concurrently
    keys = await asyncio.gather(
        client.get_key('user/alice'),
        client.get_key('user/bob'),
    )

asyncio.run(main())
```

`AsyncDstackClient` accepts the same constructor as `DstackClient` plus `use_sync_http: bool = False` for callers that need to issue sync HTTP from within an async context.

## Blockchain Integration

### Ethereum

```python
from dstack_sdk.ethereum import to_account_secure

key = client.get_key('wallet/ethereum')
account = to_account_secure(key)
print(account.address)
```

`to_account_secure(key)` hashes the full key material with SHA-256 before deriving the Ethereum private key. The legacy `to_account()` is kept for backward compatibility but uses raw key bytes—prefer the secure variant for new code.

### Solana

```python
from dstack_sdk.solana import to_keypair_secure

key = client.get_key('wallet/solana', purpose='mainnet', algorithm='ed25519')
keypair = to_keypair_secure(key)
print(keypair.pubkey())
```

Same pattern: `to_keypair_secure(key)` SHA-256-hashes the key material; `to_keypair()` is the legacy raw-bytes variant.

---

## Deployment Utilities

These utilities are for deployment scripts, not runtime SDK operations.

### Encrypted Environment Variables

The KMS returns a fresh X25519 public key (with a secp256k1 signature) that you encrypt secrets against before submitting them with your deployment. Always verify the signer before trusting the key:

```python
from dstack_sdk import (
    encrypt_env_vars,
    verify_env_encrypt_public_key,
    EnvVar,
)

# `public_key`, `signature_v1`, `timestamp` come from KMS /GetAppEnvEncryptPubKey.
signer = verify_env_encrypt_public_key(
    public_key=public_key_bytes,
    signature=signature_v1_bytes,
    app_id=app_id_hex,
    timestamp=timestamp,
)
if signer is None:
    raise RuntimeError('invalid KMS env-encrypt public key')

# Always compare the recovered signer against a known-good KMS signer
# address, obtained out-of-band from the DstackKms contract or your
# deployment configuration. Without this check, an attacker could sign
# their own env-encrypt key and the verification above would still pass.
EXPECTED_KMS_SIGNER = '0x...'  # replace with your known KMS signer address
if signer != EXPECTED_KMS_SIGNER:
    raise RuntimeError(
        f'unexpected KMS signer: got {signer}, '
        f'expected {EXPECTED_KMS_SIGNER}'
    )

env_vars = [
    EnvVar(key='DATABASE_URL', value='postgresql://...'),
    EnvVar(key='API_KEY', value='secret'),
]
encrypted = await encrypt_env_vars(env_vars, public_key_hex)
# encrypt_env_vars_sync(...) is also available for non-async callers.
```

`verify_env_encrypt_public_key` returns the recovered compressed secp256k1 signer (`0x`-prefixed hex) on success, or `None` for any failure (bad length, expired/future timestamp, malformed `app_id`, invalid signature). The default `max_age_seconds` is 300; pass a larger value if your deployment workflow legitimately holds the response longer.

`verify_env_encrypt_public_key_legacy` remains available only for deployments that explicitly support older KMS builds without `signature_v1`. It does not provide timestamp replay protection and should not be used for new deployments.

### Calculate Compose Hash

```python
from dstack_sdk import get_compose_hash

hash_value = get_compose_hash(app_compose_dict)
```

---

## Compatibility

| Feature | Required dstack OS |
|---|---|
| `get_key`, `get_quote`, `get_tls_key` (legacy fields), `info` (legacy fields) | 0.3+ |
| `attest`, `sign`, `is_reachable` | 0.5.0+ (`sign` requires a server build with the feature) |
| `version`, `algorithm='ed25519'` on `get_key`, `info.cloud_vendor` / `cloud_product`, `not_before` / `not_after` / `with_app_info` on `get_tls_key` | 0.5.7+ |
| `verify_env_encrypt_public_key` (signature_v1 with timestamp) | Requires KMS build that emits `signature_v1`; legacy variant remains available |
| `verify_signature`, `verify_signature_chain` | Any — verification is local and needs no guest agent |

Calls that require 0.5.7-only fields probe the `Version` RPC first and raise a clear `RuntimeError` on older guest agents.

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

Install dev dependencies and run tests with PDM:

```bash
cd sdk/python
make install
make test
```

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
- `tdx_quote()` → `get_quote()` (raw data only, no hash algorithms)
- Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
