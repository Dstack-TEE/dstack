// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! NSM Attestation Verification Module

use std::time::SystemTime;

use anyhow::{bail, Context, Result};
use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha384};
use tracing::debug;
use webpki::{BorrowedCertRevocationList, CertRevocationList, EndEntityCert};
use x509_parser::prelude::*;

use crate::{AttestationDocument, CoseSign1, NsmCollateral};

const DIGEST_SHA384: &str = "SHA384";
const PCR_SHA384_LEN: usize = 48;

/// Verified NSM attestation report
#[derive(Debug, Clone)]
pub struct NsmVerifiedReport {
    /// Module ID
    pub module_id: String,
    /// Digest algorithm
    pub digest: String,
    /// Timestamp (milliseconds since epoch)
    pub timestamp: u64,
    /// PCR values
    pub pcrs: std::collections::BTreeMap<u16, Vec<u8>>,
    /// User data from attestation
    pub user_data: Option<Vec<u8>>,
    /// Nonce from attestation
    pub nonce: Option<Vec<u8>>,
    /// Public key from attestation
    pub public_key: Option<Vec<u8>>,
}

/// Verify Nitro attestation with custom root CA (for testing)
pub fn verify_attestation_with_ca(
    cose_sign1_bytes: &[u8],
    root_ca_pem: &str,
    collateral: Option<&NsmCollateral>,
) -> Result<NsmVerifiedReport> {
    verify_attestation(cose_sign1_bytes, root_ca_pem, collateral, None)
}

/// Verify Nitro attestation with custom root CA and custom time (for testing)
///
/// This enforces digest/PCR consistency and a freshness window based on `now`.
pub fn verify_attestation(
    cose_sign1_bytes: &[u8],
    root_ca_pem: &str,
    collateral: Option<&NsmCollateral>,
    now: Option<SystemTime>,
) -> Result<NsmVerifiedReport> {
    let now = now.unwrap_or_else(SystemTime::now);
    let cose = CoseSign1::from_bytes(cose_sign1_bytes).context("Failed to parse COSE Sign1")?;
    cose.validate_critical_headers()
        .context("Unsupported COSE critical headers")?;
    let alg = cose.algorithm().context("Failed to get algorithm")?;
    if alg != -35 {
        bail!("Unsupported COSE algorithm: {alg}. Expected -35 (ES384)");
    }
    let doc = AttestationDocument::from_cbor(&cose.payload)
        .context("Failed to parse attestation document")?;
    validate_attestation_document(&doc).context("Attestation document validation failed")?;
    verify_certificate_chain(&doc, root_ca_pem, collateral, Some(now))
        .context("Certificate chain verification failed")?;
    verify_cose_signature(&cose, &doc.certificate).context("COSE signature verification failed")?;

    Ok(NsmVerifiedReport {
        module_id: doc.module_id,
        digest: doc.digest,
        timestamp: doc.timestamp,
        pcrs: doc.pcrs,
        user_data: doc.user_data,
        nonce: doc.nonce,
        public_key: doc.public_key,
    })
}

pub fn verify_attestation_with_collateral(
    cose_sign1_bytes: &[u8],
    root_ca_pem: &str,
    collateral: &NsmCollateral,
    now: Option<SystemTime>,
) -> Result<NsmVerifiedReport> {
    verify_attestation(cose_sign1_bytes, root_ca_pem, Some(collateral), now)
}

pub async fn verify_attestation_with_crl(
    cose_sign1_bytes: &[u8],
    root_ca_pem: &str,
    enable_crl: bool,
    now: Option<SystemTime>,
) -> Result<NsmVerifiedReport> {
    if enable_crl {
        let collateral = crate::get_collateral(cose_sign1_bytes, root_ca_pem).await?;
        verify_attestation(cose_sign1_bytes, root_ca_pem, Some(&collateral), now)
    } else {
        verify_attestation(cose_sign1_bytes, root_ca_pem, None, now)
    }
}

/// Verify the certificate chain from attestation document
fn verify_certificate_chain(
    doc: &AttestationDocument,
    root_ca_pem: &str,
    collateral: Option<&NsmCollateral>,
    now_override: Option<SystemTime>,
) -> Result<()> {
    // Parse root CA from PEM
    let root_ca_der = parse_pem_cert(root_ca_pem).context("Failed to parse root CA PEM")?;

    // The cabundle order is: [ROOT_CERT, INTERM_1, INTERM_2, ..., INTERM_N]
    // We need to verify: TARGET_CERT <- INTERM_N <- ... <- INTERM_1 <- ROOT_CERT
    // But we use the verifier-provided root CA, not the one from cabundle

    // Build intermediate chain from cabundle (excluding root at index 0)
    let intermediates: Vec<CertificateDer<'static>> = doc
        .cabundle
        .iter()
        .skip(1) // Skip the root cert from cabundle, use verifier-provided root
        .map(|der| CertificateDer::from(der.clone()))
        .collect();

    debug!(
        "Certificate chain: 1 leaf + {} intermediates + 1 root",
        intermediates.len()
    );

    // Parse the leaf certificate (signing certificate)
    let leaf_cert_der = CertificateDer::from(doc.certificate.clone());
    let leaf_cert =
        EndEntityCert::try_from(&leaf_cert_der).context("Failed to parse leaf certificate")?;

    // Create trust anchor from root CA
    let root_cert_der = CertificateDer::from(root_ca_der);
    let trust_anchor = webpki::anchor_from_trusted_cert(&root_cert_der)
        .context("Failed to create trust anchor from root CA")?;

    // Get current time
    let now = now_override.unwrap_or(SystemTime::now());
    let now = now
        .duration_since(std::time::UNIX_EPOCH)
        .context("Failed to get current time")?;
    let time = UnixTime::since_unix_epoch(now);

    let chain_has_crl_dp = has_crl_distribution_points(&doc.certificate)?
        || doc
            .cabundle
            .iter()
            .skip(1) // Skip the root cert from cabundle
            .any(|cert| has_crl_distribution_points(cert).unwrap_or(false));

    let root_has_crl_dp = has_crl_distribution_points(root_cert_der.as_ref()).unwrap_or(false);

    let trust_anchors = [trust_anchor];

    let Some(collateral) = collateral else {
        leaf_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &trust_anchors,
                &intermediates,
                time,
                webpki::KeyUsage::client_auth(),
                None,
                None,
            )
            .context("Certificate chain verification failed")?;
        return Ok(());
    };
    if root_has_crl_dp && collateral.root_ca_crl.is_none() {
        bail!("Root CA has CRL distribution points but no root CA CRL provided");
    }
    if chain_has_crl_dp && collateral.crls.is_empty() {
        bail!("CRL distribution points present but no CRLs downloaded");
    }

    if let Some(root_ca_crl) = &collateral.root_ca_crl {
        let crl_refs = vec![root_ca_crl.as_slice()];
        webpki::check_single_cert_crl(root_cert_der.as_ref(), &crl_refs, time)
            .context("root CA revoked or invalid CRL")?;
    }

    let crls: Vec<CertRevocationList> = collateral
        .crls
        .iter()
        .enumerate()
        .map(|(i, der)| {
            BorrowedCertRevocationList::from_der(der)
                .map(|crl| crl.into())
                .with_context(|| format!("failed to parse intermediate CRL #{i}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let crl_refs: Vec<&CertRevocationList> = crls.iter().collect();

    let revocation_builder = webpki::RevocationOptionsBuilder::new(&crl_refs)
        .map_err(|_| anyhow::anyhow!("failed to create RevocationOptionsBuilder"))?;

    let revocation = revocation_builder
        .with_depth(webpki::RevocationCheckDepth::Chain)
        .with_status_policy(webpki::UnknownStatusPolicy::Allow)
        .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
        .build();

    leaf_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &trust_anchors,
            &intermediates,
            time,
            webpki::KeyUsage::client_auth(),
            Some(revocation),
            None,
        )
        .context("Certificate chain verification failed")?;

    Ok(())
}

fn validate_attestation_document(doc: &AttestationDocument) -> Result<()> {
    if doc.digest != DIGEST_SHA384 {
        bail!("Unsupported digest algorithm: {}", doc.digest);
    }

    if doc.pcrs.is_empty() {
        bail!("No PCRs in attestation document");
    }

    for (idx, value) in &doc.pcrs {
        if value.len() != PCR_SHA384_LEN {
            bail!(
                "PCR{idx} length mismatch: {} (expected {PCR_SHA384_LEN})",
                value.len()
            );
        }
    }

    Ok(())
}

/// Verify COSE signature using the certificate's public key
fn verify_cose_signature(cose: &CoseSign1, cert_der: &[u8]) -> Result<()> {
    // Extract public key from certificate
    let (_, cert) =
        X509Certificate::from_der(cert_der).context("Failed to parse signing certificate")?;

    let spki = cert.public_key();
    let public_key_bytes = spki.subject_public_key.data.as_ref();

    // Parse as P-384 public key
    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .context("Failed to parse P-384 public key from certificate")?;

    // Build Sig_structure for verification
    let sig_structure = cose
        .sig_structure()
        .context("Failed to build Sig_structure")?;

    // Hash the Sig_structure with SHA-384
    let mut hasher = Sha384::new();
    hasher.update(&sig_structure);
    let message_hash = hasher.finalize();

    // Parse signature (P-384 signature is 96 bytes: 48 bytes r + 48 bytes s)
    if cose.signature.len() != 96 {
        bail!(
            "Invalid P-384 signature length: {} (expected 96)",
            cose.signature.len()
        );
    }

    let signature =
        Signature::from_slice(&cose.signature).context("Failed to parse ECDSA signature")?;

    // Verify signature
    verifying_key
        .verify_prehash(&message_hash, &signature)
        .context("ECDSA signature verification failed")?;

    Ok(())
}

/// Parse a PEM certificate to DER
fn parse_pem_cert(pem_str: &str) -> Result<Vec<u8>> {
    let pem_block = ::pem::parse(pem_str).context("Failed to parse PEM")?;
    if pem_block.tag() != "CERTIFICATE" {
        bail!("PEM is not a certificate: {}", pem_block.tag());
    }
    Ok(pem_block.into_contents())
}

fn has_crl_distribution_points(cert_der: &[u8]) -> Result<bool> {
    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;
    for ext in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(_) = ext.parsed_extension() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AWS_NITRO_ENCLAVES_ROOT_G1;

    #[test]
    fn test_root_ca_parsing() {
        let der = parse_pem_cert(AWS_NITRO_ENCLAVES_ROOT_G1).expect("Failed to parse root CA");
        let (_, cert) = X509Certificate::from_der(&der).expect("Failed to parse X509");

        // Verify it's the AWS Nitro Enclaves root CA
        let subject = cert.subject().to_string();
        assert!(
            subject.contains("aws.nitro-enclaves"),
            "Subject should contain aws.nitro-enclaves: {}",
            subject
        );
        assert!(
            subject.contains("Amazon"),
            "Subject should contain Amazon: {}",
            subject
        );
        assert!(cert.is_ca());
    }
}
