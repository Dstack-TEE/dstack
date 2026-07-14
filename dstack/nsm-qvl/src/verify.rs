// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! NSM Attestation Verification Module

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Maximum age of an attestation document relative to `now`. NSM certificates
/// are short-lived, but this additionally bounds replay of an old-but-still-in-
/// cert-validity document.
const MAX_ATTESTATION_AGE: Duration = Duration::from_secs(3600);
/// Tolerated clock skew when rejecting future-dated documents.
const CLOCK_SKEW: Duration = Duration::from_secs(300);

use anyhow::{bail, Context, Result};
use p384::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
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
/// This enforces digest/PCR consistency, certificate-chain validity at `now`,
/// and a freshness window (`MAX_ATTESTATION_AGE`) on the document timestamp.
/// Callers must still bind the attestation to a challenge via `nonce`/`user_data`
/// for full replay protection.
pub fn verify_attestation(
    cose_sign1_bytes: &[u8],
    root_ca_pem: &str,
    collateral: Option<&NsmCollateral>,
    now: Option<SystemTime>,
) -> Result<NsmVerifiedReport> {
    let now = now.unwrap_or_else(SystemTime::now);
    let cose = CoseSign1::from_bytes(cose_sign1_bytes).context("failed to parse COSE Sign1")?;
    cose.validate_critical_headers()
        .context("unsupported COSE critical headers")?;
    let alg = cose.algorithm().context("failed to get algorithm")?;
    if alg != -35 {
        bail!("unsupported COSE algorithm: {alg}. Expected -35 (ES384)");
    }
    let doc = AttestationDocument::from_cbor(&cose.payload)
        .context("failed to parse attestation document")?;
    validate_attestation_document(&doc).context("attestation document validation failed")?;

    // Freshness: NSM stamps the document (ms since epoch) at generation time.
    let doc_time = UNIX_EPOCH + Duration::from_millis(doc.timestamp);
    match now.duration_since(doc_time) {
        Ok(age) if age > MAX_ATTESTATION_AGE => {
            bail!("attestation document is stale: {age:?} old (max {MAX_ATTESTATION_AGE:?})");
        }
        Err(future) if future.duration() > CLOCK_SKEW => {
            bail!(
                "attestation document timestamp is in the future by {:?}",
                future.duration()
            );
        }
        _ => {}
    }

    verify_certificate_chain(&doc, root_ca_pem, collateral, Some(now))
        .context("certificate chain verification failed")?;
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

/// Verify the leaf signing certificate chains to the verifier-provided root.
///
/// The cabundle is ordered `[ROOT_CERT, INTERM_1, ..., INTERM_N]`; we validate
/// `TARGET_CERT <- INTERM_N <- ... <- INTERM_1 <- ROOT`. The root embedded in
/// the cabundle is deliberately dropped (index 0) — trust is anchored on the
/// verifier-provided root CA, not on anything the attesting device supplied.
fn verify_certificate_chain(
    doc: &AttestationDocument,
    root_ca_pem: &str,
    collateral: Option<&NsmCollateral>,
    now_override: Option<SystemTime>,
) -> Result<()> {
    let root_ca_der = parse_pem_cert(root_ca_pem).context("failed to parse root CA PEM")?;
    let root_cert_der = CertificateDer::from(root_ca_der);

    let intermediates: Vec<CertificateDer<'static>> = doc
        .cabundle
        .iter()
        .skip(1)
        .map(|der| CertificateDer::from(der.clone()))
        .collect();
    debug!(
        "certificate chain: 1 leaf + {} intermediates + 1 root",
        intermediates.len()
    );

    let leaf_cert_der = CertificateDer::from(doc.certificate.clone());
    let leaf_cert =
        EndEntityCert::try_from(&leaf_cert_der).context("failed to parse leaf certificate")?;
    let trust_anchor = webpki::anchor_from_trusted_cert(&root_cert_der)
        .context("failed to create trust anchor from root CA")?;
    let trust_anchors = [trust_anchor];

    let now = now_override.unwrap_or_else(SystemTime::now);
    let now = now
        .duration_since(std::time::UNIX_EPOCH)
        .context("failed to get current time")?;
    let time = UnixTime::since_unix_epoch(now);

    let Some(collateral) = collateral else {
        return verify_chain(&leaf_cert, &trust_anchors, &intermediates, time, None);
    };
    verify_chain_with_crl(
        doc,
        &leaf_cert,
        &root_cert_der,
        &trust_anchors,
        &intermediates,
        time,
        collateral,
    )
}

/// Run webpki path validation with an optional CRL-based revocation policy.
fn verify_chain(
    leaf_cert: &EndEntityCert,
    trust_anchors: &[TrustAnchor],
    intermediates: &[CertificateDer<'static>],
    time: UnixTime,
    revocation: Option<webpki::RevocationOptions>,
) -> Result<()> {
    leaf_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            trust_anchors,
            intermediates,
            time,
            webpki::KeyUsage::client_auth(),
            revocation,
            None,
        )
        .context("certificate chain verification failed")?;
    Ok(())
}

/// Validate the chain with CRL-based revocation checking.
///
/// The Nitro chain and root publish CRL distribution points. If a certificate
/// advertises one but the collateral didn't supply the matching CRL, fail
/// closed rather than silently skipping the revocation check.
fn verify_chain_with_crl(
    doc: &AttestationDocument,
    leaf_cert: &EndEntityCert,
    root_cert_der: &CertificateDer,
    trust_anchors: &[TrustAnchor],
    intermediates: &[CertificateDer<'static>],
    time: UnixTime,
    collateral: &NsmCollateral,
) -> Result<()> {
    ensure_crls_present(doc, root_cert_der, collateral)?;

    if let Some(root_ca_crl) = &collateral.root_ca_crl {
        let crl_refs = vec![root_ca_crl.as_slice()];
        webpki::check_single_cert_crl(root_cert_der.as_ref(), &crl_refs, time)
            .context("root CA revoked or invalid CRL")?;
    }

    let crls = parse_intermediate_crls(collateral)?;
    let crl_refs: Vec<&CertRevocationList> = crls.iter().collect();
    let revocation = webpki::RevocationOptionsBuilder::new(&crl_refs)
        .map_err(|_| anyhow::anyhow!("failed to create RevocationOptionsBuilder"))?
        .with_depth(webpki::RevocationCheckDepth::Chain)
        .with_status_policy(webpki::UnknownStatusPolicy::Allow)
        .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
        .build();

    verify_chain(
        leaf_cert,
        trust_anchors,
        intermediates,
        time,
        Some(revocation),
    )
}

/// Fail closed when a certificate advertises a CRL distribution point but the
/// collateral didn't supply the matching CRL — otherwise revocation checking
/// would be silently skipped.
fn ensure_crls_present(
    doc: &AttestationDocument,
    root_cert_der: &CertificateDer,
    collateral: &NsmCollateral,
) -> Result<()> {
    let root_has_crl_dp = has_crl_distribution_points(root_cert_der.as_ref()).unwrap_or(false);
    if root_has_crl_dp && collateral.root_ca_crl.is_none() {
        bail!("root CA has CRL distribution points but no root CA CRL provided");
    }

    let chain_has_crl_dp = has_crl_distribution_points(&doc.certificate)?
        || doc
            .cabundle
            .iter()
            .skip(1)
            .any(|cert| has_crl_distribution_points(cert).unwrap_or(false));
    if chain_has_crl_dp && collateral.crls.is_empty() {
        bail!("CRL distribution points present but no CRLs downloaded");
    }

    Ok(())
}

fn parse_intermediate_crls(collateral: &NsmCollateral) -> Result<Vec<CertRevocationList<'_>>> {
    collateral
        .crls
        .iter()
        .enumerate()
        .map(|(i, der)| {
            BorrowedCertRevocationList::from_der(der)
                .map(|crl| crl.into())
                .with_context(|| format!("failed to parse intermediate CRL #{i}"))
        })
        .collect()
}

fn validate_attestation_document(doc: &AttestationDocument) -> Result<()> {
    if doc.digest != DIGEST_SHA384 {
        bail!("unsupported digest algorithm: {}", doc.digest);
    }

    if doc.pcrs.is_empty() {
        bail!("no PCRs in attestation document");
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
    let (_, cert) =
        X509Certificate::from_der(cert_der).context("failed to parse signing certificate")?;

    let spki = cert.public_key();
    let public_key_bytes = spki.subject_public_key.data.as_ref();

    let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
        .context("failed to parse P-384 public key from certificate")?;

    let sig_structure = cose
        .sig_structure()
        .context("failed to build Sig_structure")?;

    let mut hasher = Sha384::new();
    hasher.update(&sig_structure);
    let message_hash = hasher.finalize();

    // P-384 signature is fixed-width 96 bytes (48-byte r || 48-byte s).
    if cose.signature.len() != 96 {
        bail!(
            "invalid P-384 signature length: {} (expected 96)",
            cose.signature.len()
        );
    }

    let signature =
        Signature::from_slice(&cose.signature).context("failed to parse ECDSA signature")?;

    verifying_key
        .verify_prehash(&message_hash, &signature)
        .context("ECDSA signature verification failed")?;

    Ok(())
}

/// Parse a PEM certificate to DER
fn parse_pem_cert(pem_str: &str) -> Result<Vec<u8>> {
    let pem_block = ::pem::parse(pem_str).context("failed to parse PEM")?;
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
    fn parses_root_ca() {
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
