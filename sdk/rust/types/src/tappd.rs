// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <danielsharifi@outlook.com>
//
// SPDX-License-Identifier: Apache-2.0

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use anyhow::{bail, Context as _, Result};
use hex::{encode as hex_encode, FromHexError};
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[cfg(feature = "borsh_schema")]
use borsh::BorshSchema;
#[cfg(feature = "borsh")]
use borsh::{BorshDeserialize, BorshSerialize};

use crate::dstack::EventLog;

const INIT_MR: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

/// Hash algorithms supported by the TDX quote generation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub enum QuoteHashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Keccak256,
    Keccak384,
    Keccak512,
    Raw,
}

impl QuoteHashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha3_256 => "sha3-256",
            Self::Sha3_384 => "sha3-384",
            Self::Sha3_512 => "sha3-512",
            Self::Keccak256 => "keccak256",
            Self::Keccak384 => "keccak384",
            Self::Keccak512 => "keccak512",
            Self::Raw => "raw",
        }
    }
}

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

/// Response from a key derivation request
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct DeriveKeyResponse {
    /// The derived key (PEM format for certificates, hex for raw keys)
    pub key: String,
    /// The certificate chain
    pub certificate_chain: Vec<String>,
}

impl DeriveKeyResponse {
    /// Decodes the key from PEM format and extracts the raw ECDSA P-256 private key bytes
    pub fn decode_key(&self) -> Result<Vec<u8>, anyhow::Error> {
        use pkcs8::der::asn1::{Int, OctetString};
        use pkcs8::der::{Decode, Document, Reader, SliceReader};
        use pkcs8::PrivateKeyInfo;

        let key_content = self.key.trim();

        // Parse PEM to DER using der's Document
        let (label, doc) = Document::from_pem(key_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse PEM: {:?}", e))?;

        // Verify it's a private key
        if label != "PRIVATE KEY" {
            bail!("Expected PRIVATE KEY PEM label, got: {}", label);
        }

        // Parse as PKCS#8 PrivateKeyInfo
        let private_key_info = PrivateKeyInfo::from_der(doc.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to parse PKCS#8 private key: {:?}", e))?;

        // Extract the private key bytes from the PKCS#8 structure
        // For ECDSA P-256 keys, the private key data contains a DER-encoded ECPrivateKey
        let private_key_data = private_key_info.private_key;

        // Parse the ECPrivateKey structure to extract the raw key bytes
        // ECPrivateKey ::= SEQUENCE {
        //   version INTEGER,
        //   privateKey OCTET STRING,
        //   parameters [0] EXPLICIT ECParameters OPTIONAL,
        //   publicKey [1] EXPLICIT BIT STRING OPTIONAL
        // }
        let mut reader = SliceReader::new(private_key_data)
            .map_err(|e| anyhow::anyhow!("Failed to create reader: {:?}", e))?;
        let key_bytes = reader
            .sequence(|reader| {
                // Skip version (INTEGER)
                let _version: Int = reader.decode()?;
                // Get the private key (OCTET STRING)
                let private_key: OctetString = reader.decode()?;
                // Skip optional fields (parameters and publicKey)
                // We don't need to parse them, just consume remaining data
                while !reader.is_finished() {
                    let _: pkcs8::der::Any = reader.decode()?;
                }
                Ok(private_key.as_bytes().to_vec())
            })
            .map_err(|e| anyhow::anyhow!("Failed to parse ECPrivateKey structure: {:?}", e))?;

        if key_bytes.len() != 32 {
            bail!(
                "Expected 32-byte ECDSA P-256 private key, got {} bytes",
                key_bytes.len()
            );
        }

        Ok(key_bytes)
    }
}

/// Response from a TDX quote request
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TdxQuoteResponse {
    /// The TDX quote in hexadecimal format
    pub quote: String,
    /// The event log associated with the quote
    pub event_log: String,
    /// The hash algorithm used (if returned by server)
    #[serde(default)]
    pub hash_algorithm: Option<String>,
    /// The prefix used (if returned by server)
    #[serde(default)]
    pub prefix: Option<String>,
}

impl TdxQuoteResponse {
    pub fn decode_quote(&self) -> Result<Vec<u8>, FromHexError> {
        hex::decode(&self.quote)
    }

    pub fn decode_event_log(&self) -> Result<Vec<EventLog>, serde_json::Error> {
        serde_json::from_str(&self.event_log)
    }

    /// Replays RTMR history to calculate final RTMR values
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

/// TCB (Trusted Computing Base) information
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TappdTcbInfo {
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
    /// The event log entries
    pub event_log: Vec<EventLog>,
    /// The application compose file
    pub app_compose: String,
}

/// Response from a Tappd info request
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "borsh_schema", derive(BorshSchema))]
pub struct TappdInfoResponse {
    /// The application identifier
    pub app_id: String,
    /// The instance identifier
    pub instance_id: String,
    /// The application certificate
    pub app_cert: String,
    /// Trusted Computing Base information
    pub tcb_info: TappdTcbInfo,
    /// The name of the application
    pub app_name: String,
}
