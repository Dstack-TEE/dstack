// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM Types - Common TPM-related type definitions
//!
//! This crate contains type definitions shared across TPM-related crates:
//! - tpm-attest (device side - generates quotes)
//! - tpm-qvl (verifier side - verifies quotes)
//! - ra-tls (uses TPM quotes in attestation)

use dstack_types::Platform;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

/// TPM Quote structure containing attestation data
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct TpmQuote {
    /// TPMS_ATTEST message
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,

    /// Quote signature
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,

    /// PCR values included in the quote
    pub pcr_values: Vec<PcrValue>,

    /// Attestation Key (AK) certificate (DER format)
    #[serde(with = "hex_bytes")]
    pub ak_cert: Vec<u8>,

    /// Platform where quote was generated
    pub platform: Platform,

    /// Event Log (optional, used for PCR replay verification)
    pub event_log: Vec<TpmEvent>,
}

impl TpmQuote {
    pub fn from_scale(mut input: &[u8]) -> Result<Self, scale::Error> {
        Self::decode(&mut input)
    }

    pub fn to_scale(&self) -> Vec<u8> {
        self.encode()
    }
}

/// PCR (Platform Configuration Register) value
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode)]
pub struct PcrValue {
    /// PCR index (0-23)
    pub index: u32,

    /// Hash algorithm (e.g., "sha256", "sha384")
    pub algorithm: String,

    /// PCR value (hash)
    #[serde(with = "hex_bytes")]
    pub value: Vec<u8>,
}

/// PCR selection specifying which PCRs to include
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrSelection {
    /// Hash bank (e.g., "sha256")
    pub bank: String,

    /// List of PCR indices
    pub pcrs: Vec<u32>,
}

impl PcrSelection {
    pub fn new(bank: &str, pcrs: &[u32]) -> Self {
        Self {
            bank: bank.to_string(),
            pcrs: pcrs.to_vec(),
        }
    }

    pub fn sha256(pcrs: &[u32]) -> Self {
        Self::new("sha256", pcrs)
    }

    pub fn to_arg(&self) -> String {
        let pcr_list: Vec<String> = self.pcrs.iter().map(|p| p.to_string()).collect();
        format!(
            "{}:{pcr_list_joined}",
            self.bank,
            pcr_list_joined = pcr_list.join(",")
        )
    }
}

impl Default for PcrSelection {
    fn default() -> Self {
        Self::sha256(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    }
}

// Re-export TPM Event types from cc-eventlog
pub use cc_eventlog::tpm::{TpmEvent, TpmEventLog};
