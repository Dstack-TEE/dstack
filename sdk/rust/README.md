# dstack SDK for Rust

Access TEE features from your Rust application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

This directory is a **standalone Cargo workspace** (`dstack-sdk`, `dstack-sdk-types`, and a `no_std` check crate). It does not join the `dstack/` core workspace.

## Installation

```toml
[dependencies]
dstack-sdk = { git = "https://github.com/Dstack-TEE/dstack.git" }
```

## Quick Start

```rust
use dstack_sdk::dstack_client::DstackClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DstackClient::new(None);

    // Derive a deterministic key for your wallet
    let key = client.get_key(Some("wallet/eth".to_string()), None).await?;
    println!("{}", key.key);  // Same path always returns the same key

    // Generate an attestation quote
    let resp = client.attest(b"my-app-state".to_vec()).await?;
    println!("{}", resp.attestation);

    Ok(())
}
```

The client automatically connects to `/var/run/dstack.sock`. For local development with the simulator:

```rust
let client = DstackClient::new(Some("http://localhost:8090".to_string()));
```

## Core API

### Derive Keys

`get_key()` derives deterministic keys bound to your application's identity (`app_id`). The same path always produces the same key for your app, but different apps get different keys even with the same path.

```rust
// Derive keys by path
let eth_key = client.get_key(Some("wallet/ethereum".to_string()), None).await?;
let btc_key = client.get_key(Some("wallet/bitcoin".to_string()), None).await?;

// Use path to separate keys
let mainnet_key = client.get_key(Some("wallet/eth/mainnet".to_string()), None).await?;
let testnet_key = client.get_key(Some("wallet/eth/testnet".to_string()), None).await?;
```

**Parameters:**
- `path`: Key derivation path (determines the key)
- `purpose` (optional): Included in signature chain message, does not affect the derived key

The Rust SDK currently requests the default `secp256k1` key material. Use distinct paths when keys must be independent.

**Returns:** `GetKeyResponse`
- `key`: Hex-encoded private key
- `signature_chain`: Signatures proving the key was derived in a genuine TEE

### Generate Attestation Quotes

`get_quote()` creates a TDX quote proving your code runs in a genuine TEE.
It needs Intel TDX: without it the call fails, and on GCP Confidential VMs it
returns the TDX quote alone, leaving out the vTPM quote GCP's verification also
binds. Call `attest()` in both cases.

```rust
let quote = client.get_quote(b"user:alice:nonce123".to_vec()).await?;
println!("{}", quote.event_log);
```

**Parameters:**
- `report_data`: Exactly 64 bytes recommended. If shorter, pad with zeros. If longer, hash it first (e.g., SHA-256).

**Returns:** `GetQuoteResponse`
- `quote`: Hex-encoded TDX quote
- `event_log`: JSON string of measured events

### Get Instance Info

```rust
let info = client.info().await?;
println!("{}", info.app_id);
println!("{}", info.instance_id);
println!("{}", info.tcb_info);
```

**Returns:** `InfoResponse`
- `app_id`: Application identifier
- `instance_id`: Instance identifier
- `app_name`: Application name
- `tcb_info`: TCB measurements (JSON string)
- `compose_hash`: Hash of the app configuration
- `app_cert`: Application certificate (PEM)

#### `attest(report_data: Vec<u8>) -> AttestResponse`
Generates a versioned attestation with a custom 64-byte payload.
- `attestation`: Hex-encoded attestation

#### `attest_gpu(nonce: Vec<u8>) -> AttestGpuResponse`

Runs NVIDIA GPU attestation now, against a 32-byte nonce you choose. Use it after
anything that may have reinitialised the GPU — a driver reload leaves a device that
answers NVML but can no longer attest.

```rust
let result = client.attest_gpu(nonce.to_vec()).await?;
println!("{}", result.evidence);
```

> [!IMPORTANT]
> `evidence` is GPU-signed and checkable by anyone — the base64 SPDM report and its
> certificate chain, over your nonce. `appraisal` is the local verifier's verdict on
> those same bytes and does **not** travel (`alg:none` EAT), so a remote party should
> appraise `evidence` itself and ignore `appraisal`.
>
> Neither binds the GPU to this CVM: an NVIDIA report binds the device and nonce and
> nothing else, so it is relayable until TDISP/TEE-IO. For TD-bound evidence use the
> boot-time `gpu-attestation` event. Calls are rate-limited to one per 10s.

#### `gpu_info() -> GpuInfoResponse`

Returns GPU information collected during boot. Currently, this includes the
complete NVIDIA `nvattest` JSON output.

```rust
let gpu = client.gpu_info().await?;
println!("{}", gpu.attestation);
```

The `attestation` field is empty when no GPU attestation output is available.
The raw output is not trusted by itself; remote verifiers should compare its
digest with the measured `gpu-attestation` runtime event.

### Generate TLS Certificates

`get_tls_key()` creates fresh TLS certificates. Unlike `get_key()`, each call generates a new random key.

```rust
use dstack_sdk_types::dstack::TlsKeyConfig;

let tls_config = TlsKeyConfig::builder()
    .subject("api.example.com")
    .alt_names(vec!["localhost".to_string()])
    .usage_ra_tls(true)  // Embed attestation in certificate
    .usage_server_auth(true)
    .build();

let tls = client.get_tls_key(tls_config).await?;

println!("{}", tls.key);                // PEM private key
println!("{:?}", tls.certificate_chain);  // Certificate chain
```

**TlsKeyConfig Options:**
- `.subject(name)`: Certificate common name (e.g., domain name)
- `.alt_names(names)`: List of subject alternative names
- `.usage_ra_tls(bool)`: Embed TDX quote in certificate extension
- `.usage_server_auth(bool)`: Enable for server authentication
- `.usage_client_auth(bool)`: Enable for client authentication

**Returns:** `GetTlsKeyResponse`
- `key`: PEM-encoded private key
- `certificate_chain`: List of PEM certificates

### Sign and Verify

Signing happens in the TEE, because it needs a key only the TEE holds. Verifying
does not, so it runs locally in this SDK -- the guest agent's `Verify` RPC was
removed in v0.6.0. Its answer arrived over the socket unattested, so trusting it
was never better than checking the signature yourself.

```rust
use dstack_sdk::verify::{verify_signature, verify_signature_chain, SignatureChain};

let result = client.sign("ed25519", b"message to sign".to_vec()).await?;

// Does this signature check out under this public key?
let valid = verify_signature(
    "ed25519",
    b"message to sign",
    &result.decode_signature()?,
    &result.decode_public_key()?,
)?;
assert!(valid);
```

**`sign()` Parameters:**
- `algorithm`: `"ed25519"`, `"secp256k1"` (alias `"k256"`), or `"secp256k1_prehashed"`
- `data`: Data to sign (a 32-byte digest for `secp256k1_prehashed`)

**`sign()` Returns:** `SignResponse`
- `signature`: Signature bytes
- `public_key`: Public key bytes
- `signature_chain`: Three signatures linking the signing key back to the KMS root

**`verify_signature()` Returns** `Result<bool>` -- `Ok(false)` when a well-formed
signature does not match, and `Err` when an input is malformed (bad key length,
unknown algorithm, non-canonical high-S signature). A malformed input is a caller
bug, not a verdict.

#### Verifying the whole chain

`verify_signature` alone proves only that whoever holds that public key signed the
data. It says nothing about *whose* key it is. `verify_signature_chain` walks all
three links back to a KMS root key you supply:

```rust
// Both anchors come from you, not from the CVM being checked.
let expected_app_id = hex::decode("a9019d1b2c3d4e5f60718293a4b5c6d7e8f90a1b")?;
let kms_root_pubkey = hex::decode("03...")?;  // pinned, or read from DstackKms

let verified = verify_signature_chain(&SignatureChain::from_sign_response(
    "ed25519",
    b"message to sign",
    &result.decode_public_key()?,
    &result.decode_signature_chain()?,
    &expected_app_id,
    &kms_root_pubkey,
)?;
println!("app root key: {}", hex::encode(verified.app_root_pubkey));
```

Note what the example does *not* do: it never passes `client.info().app_id`
straight through. That value is reported by the very CVM being verified, so a
chain checked against it proves only that the CVM is self-consistent with
itself. Use the app id you registered on chain, and if you want `AppInfo` in the
picture, compare it against that value rather than trusting it.

`kms_root_pubkey` must come from somewhere you already trust: the `DstackKms`
contract's `kmsInfo().k256Pubkey`, or a value you pinned. Reading it from the same
KMS you are checking against proves nothing -- an attacker who can answer that
query can also mint a self-consistent chain. This comparison is the entire point
of the chain; skip it and the other two links establish nothing.

## Blockchain Integration

### Ethereum with Alloy

```rust
use dstack_sdk::dstack_client::DstackClient;
use dstack_sdk::ethereum::to_account;

let key = client.get_key(Some("wallet/ethereum".to_string()), None).await?;
let signer = to_account(&key)?;
println!("Ethereum address: {}", signer.address());
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

Run examples:

```bash
cargo run --example dstack_client_usage
```

---

## Migration from TappdClient

Replace `TappdClient` with `DstackClient`:

```rust
// Before
use dstack_sdk::tappd_client::TappdClient;
let client = TappdClient::new(None);

// After
use dstack_sdk::dstack_client::DstackClient;
let client = DstackClient::new(None);
```

Method changes:
- `derive_key()` → `get_tls_key()` for TLS certificates
- Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
