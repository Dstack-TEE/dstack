// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Embedding and extracting attestation from/to TLS certificate

pub use dstack_attest::attestation::*;

use crate::{oids, traits::CertExt};
use anyhow::{bail, Context, Result};

/// Verified RA-TLS certificate evidence.
///
/// This is the certificate-level endpoint identity proof: the embedded dstack
/// attestation has been cryptographically verified and its `report_data` is
/// bound to the certificate SubjectPublicKeyInfo.
pub struct VerifiedRaTlsCert {
    /// DER-encoded SubjectPublicKeyInfo from the verified certificate.
    pub public_key_der: Vec<u8>,
    /// Verified dstack attestation embedded in the certificate.
    pub attestation: VerifiedAttestation,
    /// Optional app id certificate extension.
    pub app_id: Option<Vec<u8>>,
    /// Optional app info certificate extension.
    pub app_info: Option<AppInfo>,
    /// Optional dstack certificate usage extension.
    pub special_usage: Option<String>,
}

/// Extract attestation from x509 certificate
pub fn from_der(cert: &[u8]) -> Result<Option<VersionedAttestation>> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert).context("Failed to parse certificate")?;
    from_cert(&cert)
}

/// Verify the RA-TLS attestation embedded in a DER-encoded X.509 certificate.
///
/// This verifies the platform evidence and checks that the attestation
/// `report_data` equals `QuoteContentType::RaTlsCert` over the certificate's
/// DER SubjectPublicKeyInfo. That binding prevents an operator-controlled
/// network endpoint from reusing valid attestation evidence with a different
/// TLS key.
pub async fn verify_der(cert: &[u8], pccs_url: Option<&str>) -> Result<VerifiedRaTlsCert> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert).context("failed to parse certificate")?;
    verify_cert(&cert, pccs_url).await
}

/// Verify the RA-TLS attestation embedded in a PEM-encoded X.509 certificate.
pub async fn verify_pem(cert: &[u8], pccs_url: Option<&str>) -> Result<VerifiedRaTlsCert> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert).context("failed to parse PEM")?;
    verify_der(&pem.contents, pccs_url).await
}

/// Verify the RA-TLS attestation embedded in a parsed X.509 certificate.
async fn verify_cert(
    cert: &x509_parser::prelude::X509Certificate<'_>,
    pccs_url: Option<&str>,
) -> Result<VerifiedRaTlsCert> {
    let attestation = from_cert(cert)?.context("RA-TLS attestation extension missing")?;
    let public_key_der = cert.tbs_certificate.public_key().raw.to_vec();
    if public_key_der.is_empty() {
        bail!("certificate SubjectPublicKeyInfo is empty");
    }
    let app_id = cert.get_app_id()?;
    let app_info = cert.get_app_info()?;
    let special_usage = cert.get_special_usage()?;
    let attestation = attestation
        .into_v1()
        .verify_with_ra_pubkey(&public_key_der, pccs_url)
        .await
        .context("RA-TLS attestation verification failed")?;

    Ok(VerifiedRaTlsCert {
        public_key_der,
        attestation,
        app_id,
        app_info,
        special_usage,
    })
}

/// Extract attestation from a certificate
pub fn from_cert(cert: &impl CertExt) -> Result<Option<VersionedAttestation>> {
    from_ext_getter(|oid| cert.get_extension_bytes(oid))
}

/// Extract attestation from a certificate extension getter
pub fn from_ext_getter(
    get_ext: impl Fn(&[u64]) -> Result<Option<Vec<u8>>>,
) -> Result<Option<VersionedAttestation>> {
    // Try to detect attestation mode from certificate extension
    if let Some(attestation_bytes) = get_ext(oids::PHALA_RATLS_ATTESTATION)? {
        let attestation = VersionedAttestation::from_bytes(&attestation_bytes)
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
            .context("Failed to create attestation from TDX quote")?
            .into_versioned(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cert::CertRequest;
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    fn fake_tdx_attestation(report_data: [u8; 64]) -> VersionedAttestation {
        Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote: Vec::new(),
                event_log: Vec::new(),
            }),
            runtime_events: Vec::new(),
            report_data,
            config: String::new(),
            report: (),
        }
        .into_versioned()
    }

    #[tokio::test]
    async fn verify_der_rejects_missing_attestation_extension() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertRequest::builder()
            .key(&key)
            .subject("missing-attestation.example")
            .usage_server_auth(true)
            .build()
            .self_signed()
            .unwrap();

        let result = verify_der(cert.der().as_ref(), None).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("attestation extension missing"));
    }

    #[tokio::test]
    async fn verify_der_rejects_attestation_not_bound_to_cert_key() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let attestation = fake_tdx_attestation([0u8; 64]);
        let cert = CertRequest::builder()
            .key(&key)
            .subject("mismatched-attestation.example")
            .usage_server_auth(true)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();

        let result = verify_der(cert.der().as_ref(), None).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err:#}").contains("report data mismatch"));
    }
}
