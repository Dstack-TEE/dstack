# dstack Crate

This crate provides rust clients for communicating with both the current dstack server and the legacy tappd service, which are available inside dstack.

## Installation

```toml
[dependencies]
dstack-sdk = { git = "https://github.com/Dstack-TEE/dstack.git" }
```

## Basic Usage

### DstackClient (Current API)

```rust
use dstack_sdk::dstack_client::DstackClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = DstackClient::new(None); // Uses env var or default to Unix socket

    // Get system info
    let info = client.info().await?;
    println!("Instance ID: {}", info.instance_id);

    // Derive a key
    let key_resp = client.get_key(Some("my-app".to_string()), None).await?;
    println!("Key: {}", key_resp.key);
    println!("Signature Chain: {:?}", key_resp.signature_chain);

    // Generate TDX quote
    let quote_resp = client.get_quote(b"test-data".to_vec()).await?;
    println!("Quote: {}", quote_resp.quote);
    let rtmrs = quote_resp.replay_rtmrs()?;
    println!("Replayed RTMRs: {:?}", rtmrs);

    // Emit an event
    client.emit_event("BootComplete".to_string(), b"payload-data".to_vec()).await?;

    Ok(())
}
```

### TappdClient (Legacy API)

```rust
use dstack_sdk::tappd_client::TappdClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = TappdClient::new(None); // Uses env var or default to Unix socket

    // Get system info
    let info = client.info().await?;
    println!("Instance ID: {}", info.instance_id);
    println!("App Name: {}", info.app_name);

    // Derive a key
    let key_resp = client.derive_key("my-app").await?;
    println!("Key: {}", key_resp.key);
    println!("Certificate Chain: {:?}", key_resp.certificate_chain);

    // Decode the key to bytes (extracts raw ECDSA P-256 private key - 32 bytes)
    let key_bytes = key_resp.to_bytes()?;
    println!("ECDSA P-256 private key bytes (32 bytes): {:?}", key_bytes.len());

    // Generate quote (exactly 64 bytes of report data required)
    let mut report_data = b"test-data".to_vec();
    report_data.resize(64, 0); // Pad to 64 bytes
    let quote_resp = client.get_quote(report_data).await?;
    println!("Quote: {}", quote_resp.quote);
    let rtmrs = quote_resp.replay_rtmrs()?;
    println!("Replayed RTMRs: {:?}", rtmrs);

    Ok(())
}
```

## Features

### DstackClient Initialization

```rust
let client = DstackClient::new(Some("http://localhost:8000"));
```
- `endpoint`: Optional HTTP URL or Unix socket path (`/var/run/dstack.sock` by default)
- Will use the `DSTACK_SIMULATOR_ENDPOINT` environment variable if set

### TappdClient Initialization (Legacy API)

```rust
let client = TappdClient::new(Some("/var/run/tappd.sock"));
```
- `endpoint`: Optional HTTP URL or Unix socket path (`/var/run/tappd.sock` by default)
- Will use the `TAPPD_SIMULATOR_ENDPOINT` environment variable if set
- Supports the legacy tappd.sock API for backwards compatibility

## API Methods

### DstackClient Methods

#### `info(): InfoResponse`
Fetches metadata and measurements about the CVM instance.

#### `get_key(path: Option<String>, purpose: Option<String>) -> GetKeyResponse`
Derives a key for a specified path and optional purpose.
- `key`: Private key in hex format
- `signature_chain`: Vec of X.509 certificate chain entries

#### `get_quote(report_data: Vec<u8>) -> GetQuoteResponse`
Generates a TDX quote with a custom 64-byte payload.
- `quote`: Hex-encoded quote
- `event_log`: Serialized list of events
- `replay_rtmrs()`: Reconstructs RTMR values from the event log

#### `emit_event(event: String, payload: Vec<u8>)`
Sends an event log with associated binary payload to the runtime.

#### `get_tls_key(...) -> GetTlsKeyResponse`
Requests a key and X.509 certificate chain for RA-TLS or server/client authentication.

#### sign(algorithm: &str, data: Vec<u8>) -> SignResponse
Signs a payload using a derived key.

#### verify(algorithm: &str, data: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> VerifyResponse
Verifies a payload signature.

### TappdClient Methods (Legacy API)

#### `info(): TappdInfoResponse`
Fetches metadata and measurements about the CVM instance.

#### `derive_key(path: &str) -> DeriveKeyResponse`
Derives a key for a specified path.
- `key`: ECDSA P-256 private key in PEM format
- `certificate_chain`: Vec of X.509 certificate chain entries
- `to_bytes()`: Extracts and returns the raw ECDSA P-256 private key bytes (32 bytes)

#### `derive_key_with_subject(path: &str, subject: &str) -> DeriveKeyResponse`
Derives a key with a custom certificate subject.

#### `derive_key_with_subject_and_alt_names(path: &str, subject: Option<&str>, alt_names: Option<Vec<String>>) -> DeriveKeyResponse`
Derives a key with full certificate customization.

#### `get_quote(report_data: Vec<u8>) -> TdxQuoteResponse`
Generates a TDX quote with exactly 64 bytes of raw report data.

### Structures
- `GetKeyResponse`: Holds derived key and signature chain

- `GetQuoteResponse`: Contains the TDX quote and event log, with RTMR replay support

- `InfoResponse`: CVM instance metadata, including image and runtime measurements

- `SignResponse`: Holds a signature, signature chain, and public key

- `VerifyResponse`: Holds a boolean valid result

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
Set the endpoint in your environment:

```
export DSTACK_SIMULATOR_ENDPOINT=/path/to/dstack-simulator/dstack.sock
```

## Examples

See the `examples/` directory for comprehensive usage examples:

- `examples/dstack_client_usage.rs` - Complete example using the current DstackClient API
- `examples/tappd_client_usage.rs` - Complete example using the legacy TappdClient API

Run examples with:
```bash
cargo run --example dstack_client_usage
cargo run --example tappd_client_usage
```

## License

Apache License
