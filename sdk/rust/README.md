# dstack SDK for Rust

Access TEE features from your Rust application running inside dstack. Derive deterministic keys, generate attestation quotes, create TLS certificates, and sign data—all backed by hardware security.

This directory is a **standalone Cargo workspace** (`dstack-sdk`, `dstack-sdk-types`, and a `no_std` check crate). It does not join the `dstack/` core workspace.

## Two clients, two API surfaces

The guest agent serves two surfaces on the same socket, selected by URL path,
and this SDK mirrors both:

| Client | Surface | Paths |
|---|---|---|
| `DstackClientV0` | the frozen v0.5.11 API | `/GetKey`, also served at `/v0/GetKey` |
| `DstackClientV1` | `dstack.guest.v1` | `/v1/GetKey` |

`DstackClientV0` is what a v0.5.x program already speaks; that surface is closed
and keeps working unchanged. `DstackClientV1` is where new work goes.

> **v1 keys are not v0 keys.** Deriving under the same name through
> `DstackClientV1` returns *different key material* than `DstackClientV0` does.
> This is deliberate -- the v0 KDF ignored the algorithm, so one secret served
> both curves -- and there is no compatibility mode. An application holding
> assets under a v0 key must migrate them with a transaction signed by the old
> key before cutting over. See [`docs/guest-api-v1.md`](../../docs/guest-api-v1.md).

The clients are transport mirrors, not a compatibility layer: neither translates
a call to the other, and each one's method set is exactly its surface's.

## Installation

```toml
[dependencies]
dstack-sdk = { git = "https://github.com/Dstack-TEE/dstack.git" }
```

## Quick Start

```rust
use dstack_sdk::dstack_client::DstackClientV0;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DstackClientV0::new(None);

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
let client = DstackClientV0::new(Some("http://localhost:8090".to_string()));
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
- `boottime_gpu_evidence`: Boot-time GPU attestation evidence, empty unless requested

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

### Sign and Verify (v0 only)

`Sign` and `Verify` are v0 RPCs. v1 has neither: any caller that can reach the
socket can ask `get_key` for the private key and do both locally, so an RPC for
them would add a round trip without adding a capability.

```rust
let sign_resp = client.sign("secp256k1", b"my message".to_vec()).await?;
let signature = sign_resp.decode_signature()?;
let public_key = sign_resp.decode_public_key()?;

let verified = client
    .verify("secp256k1", b"my message".to_vec(), signature, public_key)
    .await?;
assert!(verified.valid);
```

`verify()` needs no key material and no attestation, and the agent's answer
arrives over the socket unattested -- a caller gains nothing over checking the
signature itself. It is kept because it is part of the frozen v0 surface.

To verify a **v1 signature chain**, do it yourself.
[`docs/guest-api-v1.md`](../../docs/guest-api-v1.md) specifies the rules
normatively: the claim encoding, the recovery step, and the trust anchor the
chain has to terminate at. This SDK deliberately ships no verification helper --
it mirrors an API surface, and verifying is the relying party's job.

## The v1 client

```rust
use dstack_sdk::dstack_client_v1::{DstackClientV1, IssueCertConfig};

let client = DstackClientV1::new(None);
```

#### `get_key(domain: &str, algorithm: &str) -> GetKeyResponse`

```rust
let key = client.get_key("wallet", "secp256k1").await?;
let private_key = key.decode_key()?;      // 32 bytes
let public_key = key.decode_public_key()?; // SEC1 compressed, or 32 raw for ed25519
```

`domain` is a caller-chosen domain-separation string -- not a DNS name and not a
path. Derivation is **flat**: `a/b` is unrelated to `a`, and no key derives
another. `algorithm` is required and must be `secp256k1` or `ed25519`; there is
no default and no `k256` alias, so a typo is an error rather than a key of the
wrong type.

`signature_chain` has two links: the app root key's signature over the v1 key
claim, then the KMS root key's signature over the app root public key.

#### `attest(report_data: Vec<u8>, include_boottime_gpu_evidence: bool) -> AttestResponse`

v1's only CVM attestation entry point. The attestation already carries the TDX
quote and the event log, and unlike v0's `get_quote` it answers on every
supported platform.

```rust
let result = client.attest(b"custom data".to_vec(), true).await?;
let attestation = result.decode_attestation()?;
// `boottime_gpu_evidence` is the nvattest output captured at boot; empty when
// the flag was not set or the guest has no GPU output.
```

That evidence is **not** bound to `report_data` -- nvattest ran at boot against
its own nonce. Bind it by replaying the runtime event log and comparing sha256
of those exact UTF-8 bytes against `evidence_sha256` in the `gpu-attestation`
event.

#### `attest_gpu(nonce: Vec<u8>) -> AttestGpuResponse`

Collects GPU evidence *now*, against a caller-chosen 32-byte nonce -- which the
boot-time evidence cannot answer, since it is a record written at boot.

```rust
let result = client.attest_gpu(vec![0xab; 32]).await?;
for bundle in &result.bundles {
    println!("{} / {}", bundle.vendor, bundle.format);
}
```

Returns vendor-native evidence, not a verdict: select a verifier by `vendor` and
`format`, then check the signature, certificate chain, measurements, and the
nonce embedded in the evidence.

#### `issue_cert(config: IssueCertConfig) -> IssueCertResponse`

Certificate issuance -- what v0 called `get_tls_key`, which named the by-product
rather than the request.

```rust
let cert = client
    .issue_cert(
        IssueCertConfig::builder()
            .subject("example.com")
            .usage_server_auth(true)
            .build(),
    )
    .await?;
```

The returned private key is freshly generated per call and is **not** derived
from the app identity: two identical requests produce two unrelated keys.
`get_key` is the method that derives a stable, attestable key.

#### `info() -> InfoResponse`

Identity and configuration, never attestation. The measurement registers and the
event log are deliberately absent -- they are attestation data, and this
response arrives over a local socket with nothing vouching for it. Ask `attest`
and verify.

`app_compose` is served directly here, rather than nested inside a `tcb_info`
JSON string as v0 did, and `compose_hash` is sha256 over its verbatim bytes.

#### `version() -> VersionResponse`

Also the cheapest probe for whether an agent serves v1 at all.

## Blockchain Integration

### Ethereum with Alloy

```rust
use dstack_sdk::dstack_client::DstackClientV0;
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

Replace `TappdClient` with `DstackClientV0`:

```rust
// Before
use dstack_sdk::tappd_client::TappdClient;
let client = TappdClient::new(None);

// After
use dstack_sdk::dstack_client::DstackClientV0;
let client = DstackClientV0::new(None);
```

Method changes:
- `derive_key()` → `get_tls_key()` for TLS certificates
- Socket path: `/var/run/tappd.sock` → `/var/run/dstack.sock`

## License

Apache License 2.0
