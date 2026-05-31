// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! NSM types for attestation document parsing

use anyhow::Context;
use serde::Deserialize;

/// NSM Description
#[derive(Debug, Clone)]
pub struct NsmDescription {
    /// Version major
    pub version_major: u16,
    /// Version minor
    pub version_minor: u16,
    /// Version patch
    pub version_patch: u16,
    /// Module ID
    pub module_id: String,
    /// Maximum number of PCRs
    pub max_pcrs: u16,
    /// Locked PCRs bitmap
    pub locked_pcrs: Vec<u16>,
    /// Digest algorithm
    pub digest: String,
}

/// Attestation document structure (COSE Sign1)
///
/// The attestation document is a COSE Sign1 structure containing:
/// - Protected header with algorithm
/// - Unprotected header (empty)
/// - Payload (CBOR-encoded attestation claims)
/// - Signature
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationDocument {
    /// Module ID
    pub module_id: String,
    /// Digest algorithm used
    pub digest: String,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,
    /// PCR values
    pub pcrs: std::collections::BTreeMap<u16, Vec<u8>>,
    /// Certificate (DER-encoded)
    pub certificate: Vec<u8>,
    /// CA bundle (list of DER-encoded certificates)
    pub cabundle: Vec<Vec<u8>>,
    /// Optional public key
    #[serde(default)]
    pub public_key: Option<Vec<u8>>,
    /// Optional user data
    #[serde(default)]
    pub user_data: Option<Vec<u8>>,
    /// Optional nonce
    #[serde(default)]
    pub nonce: Option<Vec<u8>>,
}

impl AttestationDocument {
    /// Parse attestation document from COSE Sign1 bytes
    pub fn from_cose(data: &[u8]) -> anyhow::Result<Self> {
        // COSE Sign1 structure is a CBOR array: [protected, unprotected, payload, signature]
        let (_protected, _unprotected, payload, _signature): (
            Vec<u8>,
            std::collections::BTreeMap<i32, ciborium::Value>,
            Vec<u8>,
            Vec<u8>,
        ) = ciborium::from_reader(data).context("Failed to parse COSE Sign1")?;

        // Parse the payload
        let doc: AttestationDocument = ciborium::from_reader(&payload[..])
            .map_err(|e| anyhow::anyhow!("Failed to parse attestation payload: {}", e))?;

        Ok(doc)
    }
}
