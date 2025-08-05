# dstack SDK Types

This crate provides Rust type definitions for communication with both the current dstack server and the legacy tappd service. It contains serializable structures and response types used by the dstack SDK clients.

## Installation

```toml
[dependencies]
dstack-sdk-types = { git = "https://github.com/Dstack-TEE/dstack.git" }
```

## Overview

This crate is `#![no_std]` compatible and provides two main modules:

- `dstack` - Types for the current dstack API
- `tappd` - Types for the legacy tappd API

## Basic Usage

```rust
use dstack_sdk_types::dstack::{GetKeyResponse, GetQuoteResponse, InfoResponse};
use dstack_sdk_types::tappd::{DeriveKeyResponse, TdxQuoteResponse, TappdInfoResponse};

// Parse a response from the dstack API
let key_response: GetKeyResponse = serde_json::from_str(&json_data)?;
let key_bytes = key_response.decode_key()?;

// Parse a quote response and replay RTMRs
let quote_response: GetQuoteResponse = serde_json::from_str(&json_data)?;
let rtmrs = quote_response.replay_rtmrs()?;

// Work with legacy tappd types
let derive_response: DeriveKeyResponse = serde_json::from_str(&json_data)?;
let private_key_bytes = derive_response.decode_key()?; // Extracts 32-byte ECDSA P-256 key
```

## License

Apache License
