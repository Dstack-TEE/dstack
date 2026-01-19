// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Embedding and extracting attestation from/to TLS certificate

pub use dstack_attest::attestation::*;

use crate::{oids, traits::CertExt};
use anyhow::{Context, Result};

/// Extract attestation from x509 certificate
pub fn from_der(cert: &[u8]) -> Result<Option<Attestation>> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert).context("Failed to parse certificate")?;
    from_cert(&cert)
}

/// Extract attestation from a certificate
pub fn from_cert(cert: &impl CertExt) -> Result<Option<Attestation>> {
    from_ext_getter(|oid| cert.get_extension_bytes(oid))
}

/// Extract attestation from a certificate extension getter
pub fn from_ext_getter(
    get_ext: impl Fn(&[u64]) -> Result<Option<Vec<u8>>>,
) -> Result<Option<Attestation>> {
    // Try to detect attestation mode from certificate extension
    if let Some(attestation_bytes) = get_ext(oids::PHALA_RATLS_ATTESTATION)? {
        let VersionedAttestation::V0 { attestation } =
            VersionedAttestation::from_scale(&attestation_bytes)
                .context("Failed to decode attestation from cert extension")?;
        return Ok(Some(attestation));
    }
    // Backward compatibility: if PHALA_RATLS_ATTESTATION
    let Some(tdx_quote) = get_ext(oids::PHALA_RATLS_TDX_QUOTE)? else {
        return Ok(None);
    };
    let raw_event_log = get_ext(oids::PHALA_RATLS_EVENT_LOG)?.context("TDX event log missing")?;
    Ok(Some(
        Attestation::from_tdx_quote(tdx_quote, &raw_event_log)
            .context("Failed to create attestation from TDX quote")?,
    ))
}
