// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
//
// SPDX-License-Identifier: Apache-2.0

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use anyhow::{Context as _, Result};
use hex::{encode as hex_encode, FromHexError};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, Value};
use sha2::Digest;

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

const INIT_MR: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

fn replay_rtmr(history: Vec<String>) -> Result<String, FromHexError> {
    if history.is_empty() {
        return Ok(INIT_MR.to_string());
    }
    let mut mr = hex::decode(INIT_MR)?;
    for content in history {
        let mut content_bytes = hex::decode(content)?;
        if content_bytes.len() < 48 {
            content_bytes.resize(48, 0);
        }
        mr.extend_from_slice(&content_bytes);
        mr = sha2::Sha384::digest(&mr).to_vec();
    }
    Ok(hex_encode(mr))
}

/// Represents an event log entry in the system
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct EventLog {
    /// The index of the IMR (Integrity Measurement Register)
    pub imr: u32,
    /// The type of event being logged
    pub event_type: u32,
    /// The cryptographic digest of the event
    pub digest: String,
    /// The type of event as a string
    pub event: String,
    /// The payload data associated with the event
    pub event_payload: String,
}

/// Configuration for TLS key generation
#[derive(Debug, bon::Builder, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TlsKeyConfig {
    /// The subject name for the certificate
    #[builder(into, default = String::new())]
    pub subject: String,
    /// Alternative names for the certificate
    #[builder(default = Vec::new())]
    pub alt_names: Vec<String>,
    /// Whether the key should be used for remote attestation TLS
    #[builder(default = false)]
    pub usage_ra_tls: bool,
    /// Whether the key should be used for server authentication
    #[builder(default = true)]
    pub usage_server_auth: bool,
    /// Whether the key should be used for client authentication
    #[builder(default = false)]
    pub usage_client_auth: bool,
}

/// Response containing a key and its signature chain
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct GetKeyResponse {
    /// The key in hexadecimal format
    pub key: String,
    /// The chain of signatures verifying the key
    pub signature_chain: Vec<String>,
}

impl GetKeyResponse {
    pub fn decode_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.key)
    }

    pub fn decode_signature_chain(&self) -> Result<Vec<Vec<u8>>, FromHexError> {
        self.signature_chain.iter().map(hex::decode).collect()
    }
}

/// Response containing a quote and associated event log
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct GetQuoteResponse {
    /// The attestation quote in hexadecimal format
    pub quote: String,
    /// The event log associated with the quote
    pub event_log: String,
    /// The report data
    #[serde(default)]
    pub report_data: String,
    /// VM configuration
    #[serde(default)]
    pub vm_config: String,
}

/// Response containing a versioned attestation
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct AttestResponse {
    /// The attestation in hexadecimal format
    pub attestation: String,
}

impl AttestResponse {
    pub fn decode_attestation(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.attestation)
    }
}

impl GetQuoteResponse {
    pub fn decode_quote(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.quote)
    }

    pub fn decode_event_log(&self) -> Result<Vec<EventLog>, serde_json::Error> {
        serde_json::from_str(&self.event_log)
    }

    pub fn replay_rtmrs(&self) -> Result<BTreeMap<u8, String>> {
        let parsed_event_log: Vec<EventLog> = self.decode_event_log()?;
        let mut rtmrs = BTreeMap::new();
        for idx in 0..4 {
            let mut history = Vec::new();
            for event in &parsed_event_log {
                if event.imr == idx {
                    history.push(event.digest.clone());
                }
            }
            rtmrs.insert(
                idx as u8,
                replay_rtmr(history)
                    .ok()
                    .context("Invalid digest in event log")?,
            );
        }
        Ok(rtmrs)
    }
}

/// Response containing instance information and attestation data
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct InfoResponse {
    /// The application identifier
    pub app_id: String,
    /// The instance identifier
    pub instance_id: String,
    /// The application certificate
    pub app_cert: String,
    /// Trusted Computing Base information
    pub tcb_info: TcbInfo,
    /// The name of the application
    pub app_name: String,
    /// The device identifier
    pub device_id: String,
    /// The aggregated measurement register
    #[serde(default)]
    pub mr_aggregated: String,
    /// The hash of the OS image
    /// Optional: empty if OS image is not measured by KMS
    #[serde(default)]
    pub os_image_hash: String,
    /// Information about the key provider
    pub key_provider_info: String,
    /// The hash of the compose configuration
    pub compose_hash: String,
    /// VM configuration
    #[serde(default)]
    pub vm_config: String,
}

impl InfoResponse {
    pub fn validated_from_value(mut obj: Value) -> Result<Self, serde_json::Error> {
        if let Some(tcb_info_str) = obj.get("tcb_info").and_then(Value::as_str) {
            let parsed_tcb_info: TcbInfo = from_str(tcb_info_str)?;
            obj["tcb_info"] = serde_json::to_value(parsed_tcb_info)?;
        }
        serde_json::from_value(obj)
    }
}

/// Trusted Computing Base information structure
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TcbInfo {
    /// The measurement root of trust
    pub mrtd: String,
    /// The value of RTMR0 (Runtime Measurement Register 0)
    pub rtmr0: String,
    /// The value of RTMR1 (Runtime Measurement Register 1)
    pub rtmr1: String,
    /// The value of RTMR2 (Runtime Measurement Register 2)
    pub rtmr2: String,
    /// The value of RTMR3 (Runtime Measurement Register 3)
    pub rtmr3: String,
    /// The hash of the OS image. This is empty if the OS image is not measured by KMS.
    #[serde(default)]
    pub os_image_hash: String,
    /// The hash of the compose configuration
    pub compose_hash: String,
    /// The device identifier
    pub device_id: String,
    /// The app compose
    pub app_compose: String,
    /// The event log entries
    pub event_log: Vec<EventLog>,
}

/// Response containing TLS key and certificate chain
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct GetTlsKeyResponse {
    /// The TLS key in hexadecimal format
    pub key: String,
    /// The chain of certificates
    pub certificate_chain: Vec<String>,
}

/// Response from a Sign request
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct SignResponse {
    /// The signature in hexadecimal format
    pub signature: String,
    /// The chain of signatures in hexadecimal format
    pub signature_chain: Vec<String>,
    /// The public key in hexadecimal format
    pub public_key: String,
}

impl SignResponse {
    /// Decodes the signature from hex to bytes
    pub fn decode_signature(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.signature)
    }

    /// Decodes the public key from hex to bytes
    pub fn decode_public_key(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.public_key)
    }

    /// Decodes the signature chain from hex to bytes
    pub fn decode_signature_chain(&self) -> Result<Vec<Vec<u8>>, FromHexError> {
        self.signature_chain.iter().map(hex::decode).collect()
    }
}

/// Response from a Verify request
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct VerifyResponse {
    /// Whether the signature is valid
    pub valid: bool,
}
