# Dstack Crate

This crate provides a rust client for communicating with the dstack server, which is available inside dstack.

## Installation

```toml
[dependencies]
dstack-rust = { git = "https://github.com/Dstack-TEE/dstack.git", package = "dstack-rust" }
```

## Basic Usage

```rust
use dstack_sdk::DstackClient;

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

## Features

### Initialization

```rust
let client = DstackClient::new(Some("http://localhost:8000"));
```

* `endpoint`: Optional HTTP URL or Unix socket path (`/var/run/dstack.sock` by default)

* Will use the `DSTACK_SIMULATOR_ENDPOINT` environment variable if set

## Methods

### `info(): InfoResponse`

Fetches metadata and measurements about the CVM instance.

### `get_key(path: Option<String>, purpose: Option<String>) -> GetKeyResponse`

Derives a key for a specified path and optional purpose.

* `key`: Private key in hex format

* `signature_chain`: Vec of X.509 certificate chain entries

### `get_quote(report_data: Vec<u8>) -> GetQuoteResponse`

Generates a TDX quote with a custom 64-byte payload.

* `quote`: Hex-encoded quote

* `event_log`: Serialized list of events

* `replay_rtmrs()`: Reconstructs RTMR values from the event log

### `emit_event(event: String, payload: Vec<u8>)`

Sends an event log with associated binary payload to the runtime.

### `get_tls_key(...) -> GetTlsKeyResponse`

Requests a key and X.509 certificate chain for RA-TLS or server/client authentication.

### Structures

* `GetKeyResponse`: Holds derived key and signature chain

* `GetQuoteResponse`: Contains the TDX quote and event log, with RTMR replay support

* `InfoResponse`: CVM instance metadata, including image and runtime measurements

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
export DSTACK_SIMULATOR_ENDPOINT=http://localhost:8000
```

## License

Apache License
