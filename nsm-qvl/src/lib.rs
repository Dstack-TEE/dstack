// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! AWS Nitro Enclave NSM Quote Verification Library (QVL)
//!
//! This module provides quote verification for AWS Nitro Enclave attestation documents.
//! It verifies:
//! - COSE Sign1 signature using ECDSA P-384 with SHA-384
//! - Certificate chain from the attestation document to the AWS Nitro root CA
//!
//! # Architecture
//! The verification follows AWS Nitro Enclave attestation document specification:
//! 1. Decode CBOR/COSE Sign1 structure
//! 2. Extract attestation document payload
//! 3. Verify certificate chain (cabundle + certificate against root CA)
//! 4. Verify COSE signature using the certificate's public key
//!
//! # References
//! - https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
//! - https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::{collections::BTreeMap, io::Cursor};

pub use collateral::{get_collateral, get_collateral_and_verify};

mod verify;

pub use verify::{
    verify_attestation, verify_attestation_with_ca, verify_attestation_with_collateral,
    verify_attestation_with_crl, NsmVerifiedReport,
};

#[derive(Debug, Clone)]
pub struct NsmCollateral {
    /// All CRLs extracted from device-provided cert chain
    pub crls: Vec<Vec<u8>>,
    /// Root CA CRL extracted from verifier-provided root CA
    pub root_ca_crl: Option<Vec<u8>>,
}

/// AWS Nitro Enclaves Root CA certificate (G1)
///
/// Subject: CN=aws.nitro-enclaves, C=US, O=Amazon, OU=AWS
/// Valid: 2019-10-28 to 2049-10-28 (30 years)
/// Fingerprint: 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
pub const AWS_NITRO_ENCLAVES_ROOT_G1: &str = include_str!("../certs/AWS_NitroEnclaves_Root-G1.pem");

/// Parsed COSE Sign1 structure for NSM attestation
#[derive(Debug)]
pub struct CoseSign1 {
    /// Protected header (contains algorithm)
    pub protected: Vec<u8>,
    /// Unprotected header (usually empty for NSM)
    pub unprotected: BTreeMap<i64, ciborium::Value>,
    /// Payload (CBOR-encoded attestation document)
    pub payload: Vec<u8>,
    /// Signature (ECDSA P-384)
    pub signature: Vec<u8>,
}

impl CoseSign1 {
    /// Parse COSE Sign1 from raw bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        // COSE Sign1 structure is a CBOR array: [protected, unprotected, payload, signature]
        let mut reader = Cursor::new(data);
        let value: ciborium::Value =
            ciborium::from_reader(&mut reader).context("Failed to parse COSE Sign1 CBOR")?;
        if reader.position() != data.len() as u64 {
            bail!("Trailing bytes after COSE Sign1");
        }

        let array = match value {
            ciborium::Value::Array(arr) => arr,
            ciborium::Value::Tag(18, inner) => {
                // COSE_Sign1 tag is 18
                match *inner {
                    ciborium::Value::Array(arr) => arr,
                    _ => bail!("COSE Sign1 tag content is not an array"),
                }
            }
            _ => bail!("COSE Sign1 is not an array"),
        };

        if array.len() != 4 {
            bail!("COSE Sign1 array must have 4 elements, got {}", array.len());
        }

        let protected = match &array[0] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => bail!("COSE Sign1 protected header is not bytes"),
        };

        let unprotected = match &array[1] {
            ciborium::Value::Map(m) => {
                let mut map = BTreeMap::new();
                for (k, v) in m {
                    if let ciborium::Value::Integer(i) = k {
                        let key: i128 = (*i).into();
                        map.insert(key as i64, v.clone());
                    }
                }
                map
            }
            _ => BTreeMap::new(),
        };

        let payload = match &array[2] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => bail!("COSE Sign1 payload is not bytes"),
        };

        let signature = match &array[3] {
            ciborium::Value::Bytes(b) => b.clone(),
            _ => bail!("COSE Sign1 signature is not bytes"),
        };

        Ok(Self {
            protected,
            unprotected,
            payload,
            signature,
        })
    }

    /// Get the algorithm from protected header
    pub fn algorithm(&self) -> Result<i64> {
        let protected_map = self.protected_map()?;

        // Algorithm is key 1 in COSE
        let alg = protected_map
            .get(&1)
            .context("No algorithm in protected header")?;

        match alg {
            ciborium::Value::Integer(i) => {
                let val: i128 = (*i).into();
                Ok(val as i64)
            }
            _ => bail!("Algorithm is not an integer"),
        }
    }

    /// Validate critical headers (crit) per COSE rules.
    pub fn validate_critical_headers(&self) -> Result<()> {
        let protected_map = self.protected_map()?;
        let Some(crit) = protected_map.get(&2) else {
            return Ok(());
        };

        let crit_list = match crit {
            ciborium::Value::Array(arr) => arr,
            _ => bail!("COSE crit header is not an array"),
        };

        for item in crit_list {
            match item {
                ciborium::Value::Integer(i) => {
                    let val: i128 = (*i).into();
                    if val as i64 != 1 {
                        bail!("Unsupported critical header parameter: {val}");
                    }
                }
                ciborium::Value::Text(name) => {
                    if name != "alg" {
                        bail!("Unsupported critical header parameter: {name}");
                    }
                }
                _ => bail!("Invalid critical header parameter type"),
            }
        }

        Ok(())
    }

    /// Build the Sig_structure for verification
    /// Sig_structure = ["Signature1", protected, external_aad, payload]
    pub fn sig_structure(&self) -> Result<Vec<u8>> {
        let sig_structure = ciborium::Value::Array(vec![
            ciborium::Value::Text("Signature1".to_string()),
            ciborium::Value::Bytes(self.protected.clone()),
            ciborium::Value::Bytes(vec![]), // external_aad is empty
            ciborium::Value::Bytes(self.payload.clone()),
        ]);

        let mut buf = Vec::new();
        ciborium::into_writer(&sig_structure, &mut buf)
            .context("Failed to encode Sig_structure")?;
        Ok(buf)
    }

    fn protected_map(&self) -> Result<BTreeMap<i64, ciborium::Value>> {
        let mut reader = Cursor::new(&self.protected);
        let map = ciborium::from_reader(&mut reader).context("Failed to parse protected header")?;
        if reader.position() != self.protected.len() as u64 {
            bail!("Trailing bytes after protected header");
        }
        Ok(map)
    }
}

/// Attestation document structure (parsed from COSE payload)
#[derive(Debug, Clone, Deserialize)]
pub struct AttestationDocument {
    /// Module ID
    pub module_id: String,
    /// Digest algorithm used
    pub digest: String,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,
    /// PCR values
    pub pcrs: BTreeMap<u16, Vec<u8>>,
    /// Certificate (DER-encoded) - the signing certificate
    pub certificate: Vec<u8>,
    /// CA bundle (list of DER-encoded certificates)
    /// Order: [ROOT_CERT, INTERM_1, INTERM_2, ..., INTERM_N]
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
    /// Parse attestation document from CBOR payload
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        let mut reader = Cursor::new(data);
        let doc = ciborium::from_reader(&mut reader)
            .context("Failed to parse attestation document CBOR")?;
        if reader.position() != data.len() as u64 {
            bail!("Trailing bytes after attestation document CBOR");
        }
        Ok(doc)
    }
}

pub mod collateral;
