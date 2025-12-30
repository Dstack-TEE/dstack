# dstack SDK for Rust

Access TEE features from your Rust application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

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
    let quote = client.get_quote(b"my-app-state".to_vec()).await?;
    println!("{}", quote.quote);

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

**Returns:** `GetKeyResponse`
- `key`: Hex-encoded private key
- `signature_chain`: Signatures proving the key was derived in a genuine TEE

### Generate Attestation Quotes

`get_quote()` creates a TDX quote proving your code runs in a genuine TEE.

```rust
let quote = client.get_quote(b"user:alice:nonce123".to_vec()).await?;

// Replay RTMRs from the event log
let rtmrs = quote.replay_rtmrs()?;
println!("{:?}", rtmrs);
```

**Parameters:**
- `report_data`: Exactly 64 bytes recommended. If shorter, pad with zeros. If longer, hash it first (e.g., SHA-256).

**Returns:** `GetQuoteResponse`
- `quote`: Hex-encoded TDX quote
- `event_log`: JSON string of measured events
- `replay_rtmrs()`: Method to compute RTMR values from event log

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

Sign data using TEE-derived keys (not yet released):

```rust
let result = client.sign("ed25519", b"message to sign".to_vec()).await?;
println!("{:?}", result.signature);
println!("{:?}", result.public_key);

// Verify the signature
let valid = client.verify(
    "ed25519",
    b"message to sign".to_vec(),
    result.signature.clone(),
    result.public_key.clone()
).await?;
println!("{}", valid.valid);  // true
```

**`sign()` Parameters:**
- `algorithm`: `"ed25519"`, `"secp256k1"`, or `"secp256k1_prehashed"`
- `data`: Data to sign

**`sign()` Returns:** `SignResponse`
- `signature`: Signature bytes
- `public_key`: Public key bytes
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

```rust
client.emit_event("config_loaded".to_string(), b"production".to_vec()).await?;
client.emit_event("plugin_initialized".to_string(), b"auth-v2".to_vec()).await?;
```

**Parameters:**
- `event`: Event name (string identifier)
- `payload`: Event value (bytes)

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
