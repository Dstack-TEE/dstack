// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM Quote Verification Library (QVL)
//!
//! This module provides quote verification and collateral management for TPM attestation.
//! It follows the dcap-qvl architecture for Intel TDX verification.
//!
//! # Architecture
//! - **Step 1**: `get_collateral()` - Extract cert chain and download CRLs
//! - **Step 2**: `verify_quote()` - Verify quote with collateral
//!
//! This crate is designed to run on the verifier side, while tpm-attest runs on the device side.

use anyhow::{bail, Result};
use dstack_types::Platform;
use serde::{Deserialize, Serialize};

/// GCP TPM Root CA certificate (embedded, valid 2022-2122)
///
/// Subject: CN=EK/AK CA Root, OU=Google Cloud, O=Google LLC, L=Mountain View, ST=California, C=US
/// Valid: 2022-07-08 to 2122-07-08 (100 years)
pub const GCP_ROOT_CA: &str = include_str!("../certs/gcp-root-ca.pem");

/// Get TPM root CA certificate for the given platform
pub fn get_root_ca(platform: Platform) -> Result<&'static str> {
    match platform {
        Platform::Gcp => Ok(GCP_ROOT_CA),
        Platform::NitroEnclave => {
            bail!("Nitro Enclave uses NSM attestation, not TPM. Use nsm-qvl instead.")
        }
        Platform::Dstack => bail!("dstack platform does not use TPM attestation"),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuoteCollateral {
    /// Intermediate certificate chain (PEM format) from device
    /// Does NOT include root CA (which must be provided independently by verifier)
    pub cert_chain_pem: String,
    /// All CRLs extracted from device-provided cert chain
    pub crls: Vec<Vec<u8>>,
    /// Root CA CRL extracted from verifier-provided root CA
    pub root_ca_crl: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct VerificationError {
    pub status: VerificationStatus,
    pub error: anyhow::Error,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "verification failed: {}", self.error)
    }
}

impl std::error::Error for VerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.error.source()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VerificationStatus {
    pub ak_verified: bool,
    pub signature_verified: bool,
    pub pcr_verified: bool,
}

#[cfg(feature = "crl-download")]
pub use collateral::{get_collateral, get_collateral_and_verify};

pub use verify::verify_quote;

pub mod verify;

#[cfg(feature = "crl-download")]
pub mod collateral;
