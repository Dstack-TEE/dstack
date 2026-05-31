// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM Quote Verification Module

use ::pem::parse_many;
use anyhow::{anyhow, bail, Context, Result};
use dstack_types::Platform;
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};
use x509_parser::prelude::*;

use rustls_pki_types::{CertificateDer, UnixTime};
use webpki::{BorrowedCertRevocationList, CertRevocationList, EndEntityCert};

use tpm_types::{PcrValue, TpmEvent, TpmQuote};

use crate::{get_root_ca, QuoteCollateral, VerificationError, VerificationStatus};

#[derive(Clone)]
pub struct VerifiedReport {
    pub attest: TpmAttest,
    pub platform: Platform,
    pub pcr_values: Vec<PcrValue>,
}

impl VerifiedReport {
    pub fn get_pcr(&self, index: u32) -> Result<Vec<u8>> {
        self.pcr_values
            .iter()
            .find(|p| p.index == index)
            .map(|p| p.value.clone())
            .ok_or(anyhow!("PCR {} not found", index))
    }
}

#[derive(Debug)]
enum PublicKey {
    Rsa(RsaPublicKey),
    Ecc(VerifyingKey),
}

/// Verify quote with collateral and library-bundled root CA
pub fn verify_quote(
    quote: &TpmQuote,
    collateral: &QuoteCollateral,
) -> Result<VerifiedReport, VerificationError> {
    let ca = get_root_ca(quote.platform).map_err(|e| VerificationError {
        status: VerificationStatus::default(),
        error: e,
    })?;
    verify_quote_with_ca(quote, collateral, ca)
}

/// Verify quote with collateral and user-provided root CA (recommended for security)
///
/// The root CA is provided by the verifier as an independent trust anchor,
/// not derived from device-provided collateral. This prevents attacks where
/// a malicious device provides a fake certificate chain including a fake root CA.
pub fn verify_quote_with_ca(
    quote: &TpmQuote,
    collateral: &QuoteCollateral,
    root_ca_pem: &str,
) -> Result<VerifiedReport, VerificationError> {
    let mut status = VerificationStatus::default();

    let attest = match parse_tpm_attest(&quote.message) {
        Ok(a) => a,
        Err(e) => {
            return Err(VerificationError {
                status,
                error: e.context("failed to parse TPMS_ATTEST"),
            });
        }
    };

    let attested_pcr_indices: Vec<u32> = attest
        .attested_quote_info
        .pcr_selections
        .iter()
        .flat_map(|s| s.pcr_indices.iter().copied())
        .collect();
    let provided_pcr_indices: Vec<u32> = quote.pcr_values.iter().map(|p| p.index).collect();

    if attested_pcr_indices != provided_pcr_indices {
        return Err(VerificationError {
            status,
            error: anyhow!(
                "PCR selection mismatch: TPMS_ATTEST has {:?}, but pcr_values has {:?}",
                attested_pcr_indices,
                provided_pcr_indices
            ),
        });
    }

    let computed_pcr_digest =
        compute_pcr_digest(&quote.pcr_values).map_err(|e| VerificationError {
            status: status.clone(),
            error: e,
        })?;
    if attest.attested_quote_info.pcr_digest != computed_pcr_digest {
        return Err(VerificationError {
            status,
            error: anyhow!("PCR digest mismatch"),
        });
    }

    verify_event_log(&quote.pcr_values, &quote.event_log).map_err(|e| VerificationError {
        status: status.clone(),
        error: e.context("event log verification failed"),
    })?;
    debug!("✓ Event Log replay verification successful");

    status.pcr_verified = true;

    let ak_public_key = match extract_ak_public_key_from_cert(&quote.ak_cert) {
        Ok(key) => {
            debug!("extracted AK public key from certificate");
            key
        }
        Err(e) => {
            return Err(VerificationError {
                status,
                error: e.context("failed to extract AK public key from certificate"),
            });
        }
    };

    match verify_signature_with_key(&quote.message, &quote.signature, &ak_public_key) {
        Ok(true) => status.signature_verified = true,
        Ok(false) => {
            return Err(VerificationError {
                status,
                error: anyhow!("signature verification failed"),
            });
        }
        Err(e) => {
            return Err(VerificationError {
                status,
                error: e.context("signature verification error"),
            });
        }
    }

    match verify_ak_chain_with_collateral(&quote.ak_cert, collateral, root_ca_pem) {
        Ok(()) => {}
        Err(e) => {
            return Err(VerificationError {
                status,
                error: e.context("AK certificate chain verification error"),
            });
        }
    }

    Ok(VerifiedReport {
        attest,
        platform: quote.platform,
        pcr_values: quote.pcr_values.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct TpmAttest {
    pub magic: u32,
    pub type_: u16,
    pub qualified_signer: Vec<u8>,
    pub qualified_data: Vec<u8>,
    pub clock_info: ClockInfo,
    pub firmware_version: u64,
    pub attested_quote_info: QuoteInfo,
}

#[derive(Debug, Clone)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: u8,
}

/// PCR selection entry from TPM quote
#[derive(Debug, Clone)]
pub struct PcrSelection {
    /// Hash algorithm (e.g., 0x000B for SHA-256)
    pub hash_alg: u16,
    /// Selected PCR indices
    pub pcr_indices: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct QuoteInfo {
    /// PCR selections from the quote
    pub pcr_selections: Vec<PcrSelection>,
    /// PCR digest
    pub pcr_digest: Vec<u8>,
}

fn parse_tpm_attest(data: &[u8]) -> Result<TpmAttest> {
    use nom::bytes::complete::take;
    use nom::number::complete::{be_u16, be_u32, be_u64, be_u8};
    use nom::IResult;

    fn parse_sized_buffer(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
        let (input, size) = be_u16(input)?;
        let (input, data) = take(size)(input)?;
        Ok((input, data.to_vec()))
    }

    fn parse_attest(input: &[u8]) -> IResult<&[u8], TpmAttest> {
        let (input, magic) = be_u32(input)?;
        let (input, type_) = be_u16(input)?;
        let (input, qualified_signer) = parse_sized_buffer(input)?;
        let (input, qualified_data) = parse_sized_buffer(input)?;

        let (input, clock) = be_u64(input)?;
        let (input, reset_count) = be_u32(input)?;
        let (input, restart_count) = be_u32(input)?;
        let (input, safe) = be_u8(input)?;

        let (input, firmware_version) = be_u64(input)?;

        let (input, pcr_select_count) = be_u32(input)?;

        let mut pcr_selections = Vec::new();
        let mut current_input = input;
        for _ in 0..pcr_select_count {
            let (input, hash_alg) = be_u16(current_input)?;
            let (input, sizeof_select) = be_u8(input)?;
            let (input, pcr_bitmap) = take(sizeof_select)(input)?;

            // Parse PCR bitmap into indices
            let mut pcr_indices = Vec::new();
            for (byte_idx, &byte) in pcr_bitmap.iter().enumerate() {
                for bit_idx in 0..8 {
                    if (byte & (1 << bit_idx)) != 0 {
                        pcr_indices.push((byte_idx * 8 + bit_idx) as u32);
                    }
                }
            }

            pcr_selections.push(PcrSelection {
                hash_alg,
                pcr_indices,
            });

            current_input = input;
        }

        let input = current_input;
        let (input, pcr_digest) = parse_sized_buffer(input)?;

        Ok((
            input,
            TpmAttest {
                magic,
                type_,
                qualified_signer,
                qualified_data,
                clock_info: ClockInfo {
                    clock,
                    reset_count,
                    restart_count,
                    safe,
                },
                firmware_version,
                attested_quote_info: QuoteInfo {
                    pcr_selections,
                    pcr_digest,
                },
            },
        ))
    }

    let (_, attest) = parse_attest(data).map_err(|e| anyhow!("parse error: {e}"))?;

    if attest.magic != 0xff544347 {
        bail!("invalid magic number: 0x{magic:08x}", magic = attest.magic);
    }

    if attest.type_ != 0x8018 {
        bail!("invalid attest type: 0x{type_:04x}", type_ = attest.type_);
    }

    Ok(attest)
}

fn compute_pcr_digest(pcr_values: &[PcrValue]) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    for pcr in pcr_values {
        hasher.update(&pcr.value);
    }
    Ok(hasher.finalize().to_vec())
}

fn verify_event_log(pcr_values: &[PcrValue], event_log: &[TpmEvent]) -> Result<()> {
    for pcr in pcr_values {
        let pcr_events: Vec<&TpmEvent> = event_log
            .iter()
            .filter(|e| e.pcr_index == pcr.index)
            .collect();

        if pcr_events.is_empty() {
            continue;
        }

        // Replay PCR extension to verify Event Log matches quote
        let mut replayed_pcr = vec![0u8; 32];
        for event in &pcr_events {
            let mut hasher = Sha256::new();
            hasher.update(&replayed_pcr);
            hasher.update(&event.digest);
            replayed_pcr = hasher.finalize().to_vec();
        }

        if replayed_pcr != pcr.value {
            bail!(
                "PCR {} replay mismatch: expected {}, got {}",
                pcr.index,
                hex::encode(&pcr.value),
                hex::encode(&replayed_pcr)
            );
        }

        debug!(
            "✓ PCR {} replay verification successful ({} events)",
            pcr.index,
            pcr_events.len()
        );

        // For PCR 2: Extract Event 28 (UKI measurement) for image verification
        // NOTE: Extracting the 3rd event (index 2) is GCP OVMF-specific behavior.
        // On GCP, PCR 2 events are: [0]=EV_SEPARATOR, [1]=EV_EFI_GPT_EVENT,
        // [2]=UKI (Event 28), [3]=Linux kernel (Event 41)
        // Other platforms may have different event ordering.
        if pcr.index == 2 && pcr_events.len() >= 3 {
            let uki_digest = hex::encode(&pcr_events[2].digest);
            debug!("Event 28 (UKI hash): {}", uki_digest);
            debug!("To verify image: compare this against expected UKI Authenticode hash");
        }
    }

    Ok(())
}

fn extract_ak_public_key_from_cert(ak_cert_der: &[u8]) -> Result<PublicKey> {
    let (_, cert) =
        X509Certificate::from_der(ak_cert_der).context("failed to parse AK certificate")?;

    let spki = cert.public_key();

    let algo_oid = &spki.algorithm.algorithm;

    const OID_RSA_ENCRYPTION: &[u64] = &[1, 2, 840, 113549, 1, 1, 1];
    const OID_EC_PUBLIC_KEY: &[u64] = &[1, 2, 840, 10045, 2, 1];

    let oid_bytes: Vec<u64> = algo_oid
        .iter()
        .ok_or_else(|| anyhow::anyhow!("invalid OID"))?
        .collect();

    if oid_bytes == OID_RSA_ENCRYPTION {
        use rsa::pkcs1::DecodeRsaPublicKey;
        use rsa::traits::PublicKeyParts;

        let public_key = RsaPublicKey::from_pkcs1_der(spki.subject_public_key.data.as_ref())
            .context("failed to decode RSA public key from certificate")?;

        debug!(
            "extracted RSA AK public key from certificate ({} bits)",
            public_key.size() * 8
        );

        Ok(PublicKey::Rsa(public_key))
    } else if oid_bytes == OID_EC_PUBLIC_KEY {
        let public_key_bytes = spki.subject_public_key.data.as_ref();

        let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes)
            .context("failed to decode ECC public key from certificate")?;

        debug!("extracted ECC P-256 AK public key from certificate");

        Ok(PublicKey::Ecc(verifying_key))
    } else {
        bail!("unsupported public key algorithm: {:?}", oid_bytes);
    }
}

fn verify_signature_with_key(
    message: &[u8],
    signature: &[u8],
    public_key: &PublicKey,
) -> Result<bool> {
    if signature.len() < 4 {
        bail!("signature too short: {} bytes", signature.len());
    }

    let sig_alg = u16::from_be_bytes([signature[0], signature[1]]);
    let hash_alg = u16::from_be_bytes([signature[2], signature[3]]);

    if hash_alg != 0x000B {
        bail!("unsupported hash algorithm: 0x{hash_alg:04x}");
    }

    let actual_signature = &signature[4..];

    debug!(
        "message ({} bytes): {}",
        message.len(),
        hex::encode(message)
    );
    debug!(
        "signature ({} bytes): {}",
        actual_signature.len(),
        hex::encode(actual_signature)
    );

    let mut hasher = Sha256::new();
    hasher.update(message);
    let message_hash = hasher.finalize();

    debug!("message hash: {}", hex::encode(message_hash));

    match public_key {
        PublicKey::Rsa(rsa_key) => {
            if sig_alg != 0x0014 {
                bail!("expected RSASSA (0x0014), got 0x{sig_alg:04x}");
            }

            if actual_signature.len() < 2 {
                bail!("RSA signature too short for size field");
            }
            let rsa_sig_size =
                u16::from_be_bytes([actual_signature[0], actual_signature[1]]) as usize;
            if actual_signature.len() < 2 + rsa_sig_size {
                bail!("RSA signature too short for signature data");
            }
            let rsa_sig_data = &actual_signature[2..2 + rsa_sig_size];

            debug!("RSA signature parsed: {rsa_sig_size} bytes");

            let padding = rsa::Pkcs1v15Sign::new::<Sha256>();
            match rsa_key.verify(padding, &message_hash, rsa_sig_data) {
                Ok(_) => {
                    debug!("✓ RSA signature verification successful");
                    Ok(true)
                }
                Err(e) => {
                    warn!("RSA signature verification failed: {e}");
                    Ok(false)
                }
            }
        }
        PublicKey::Ecc(ecc_key) => {
            if sig_alg != 0x0018 {
                bail!("expected ECDSA (0x0018), got 0x{sig_alg:04x}");
            }

            if actual_signature.len() < 2 {
                bail!("ECDSA signature too short for signatureR size");
            }
            let r_size = u16::from_be_bytes([actual_signature[0], actual_signature[1]]) as usize;
            if actual_signature.len() < 2 + r_size {
                bail!("ECDSA signature too short for signatureR data");
            }
            let r_data = &actual_signature[2..2 + r_size];

            let s_offset = 2 + r_size;
            if actual_signature.len() < s_offset + 2 {
                bail!("ECDSA signature too short for signatureS size");
            }
            let s_size =
                u16::from_be_bytes([actual_signature[s_offset], actual_signature[s_offset + 1]])
                    as usize;
            if actual_signature.len() < s_offset + 2 + s_size {
                bail!("ECDSA signature too short for signatureS data");
            }
            let s_data = &actual_signature[s_offset + 2..s_offset + 2 + s_size];

            let mut sig_bytes = Vec::with_capacity(r_size + s_size);
            sig_bytes.extend_from_slice(r_data);
            sig_bytes.extend_from_slice(s_data);

            debug!("ECDSA signature parsed: r={r_size} bytes, s={s_size} bytes",);

            let signature =
                Signature::from_slice(&sig_bytes).context("failed to parse ECDSA signature")?;

            match ecc_key.verify_prehash(&message_hash, &signature) {
                Ok(_) => {
                    debug!("✓ ECC signature verification successful");
                    Ok(true)
                }
                Err(e) => {
                    warn!("ECC signature verification failed: {e}");
                    Ok(false)
                }
            }
        }
    }
}

fn extract_certs_webpki(cert_pem: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let pem_items = parse_many(cert_pem).context("failed to parse PEM")?;

    let certs = pem_items
        .into_iter()
        .map(|pem| CertificateDer::from(pem.into_contents()))
        .collect();

    Ok(certs)
}

fn verify_ak_chain_with_collateral(
    ak_cert_der: &[u8],
    collateral: &QuoteCollateral,
    root_ca_pem: &str,
) -> Result<()> {
    debug!(
        "verifying AK certificate chain with webpki ({} bytes leaf, {} intermediate CRLs, root CRL: {})",
        ak_cert_der.len(),
        collateral.crls.len(),
        if collateral.root_ca_crl.is_some() { "yes" } else { "no" }
    );

    let ak_cert_der_owned = CertificateDer::from(ak_cert_der.to_vec());
    let ak_cert =
        EndEntityCert::try_from(&ak_cert_der_owned).context("failed to parse AK certificate")?;

    // Load intermediate certs from device-provided collateral
    let intermediate_certs = extract_certs_webpki(collateral.cert_chain_pem.as_bytes())?;

    debug!(
        "loaded {} intermediate certificate(s) from collateral",
        intermediate_certs.len()
    );
    for (i, cert_der) in intermediate_certs.iter().enumerate() {
        if let Ok((_, cert)) = X509Certificate::from_der(cert_der.as_ref()) {
            debug!(
                "  intermediate[{i}]: subject={}, issuer={}",
                cert.subject(),
                cert.issuer()
            );
        }
    }

    // Load root CA from verifier-provided trust anchor (CRITICAL: independent from device)
    let root_ca_certs = extract_certs_webpki(root_ca_pem.as_bytes())?;
    if root_ca_certs.is_empty() {
        bail!("failed to parse root CA PEM - no certificates found");
    }
    let root_cert_der = &root_ca_certs[0];

    if let Ok((_, cert)) = X509Certificate::from_der(root_cert_der.as_ref()) {
        debug!(
            "trust anchor (verifier-provided): subject={}, issuer={}",
            cert.subject(),
            cert.issuer()
        );
    }

    let trust_anchor = webpki::anchor_from_trusted_cert(root_cert_der)
        .context("failed to create trust anchor from verifier root CA")?;

    debug!(
        "trust anchor created, {} intermediate(s)",
        intermediate_certs.len()
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("failed to get current time")?;
    let time = UnixTime::since_unix_epoch(now);

    let trust_anchors = [trust_anchor];

    // Check root CA against CRL if CRL was provided
    if let Some(root_ca_crl) = &collateral.root_ca_crl {
        debug!("checking root CA against its CRL (dcap-qvl-webpki)");
        let crl_refs = vec![root_ca_crl.as_slice()];
        webpki::check_single_cert_crl(root_cert_der.as_ref(), &crl_refs, time)
            .context("root CA revoked or invalid CRL")?;
        debug!("✓ root CA CRL check passed");
    } else {
        debug!("root CA has no CRL - skipping root CA CRL check");
    }

    let result = if !collateral.crls.is_empty() {
        debug!(
            "parsing {} intermediate CRL(s) for revocation checking",
            collateral.crls.len()
        );
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

        debug!("creating revocation options (CRL enforcement)");
        let revocation_builder = webpki::RevocationOptionsBuilder::new(&crl_refs)
            .map_err(|_| anyhow::anyhow!("failed to create RevocationOptionsBuilder"))?;

        let revocation = revocation_builder
            .with_depth(webpki::RevocationCheckDepth::Chain)
            .with_status_policy(webpki::UnknownStatusPolicy::Allow)
            .with_expiration_policy(webpki::ExpirationPolicy::Enforce)
            .build();

        debug!("verifying certificate chain with CRL revocation checking");

        const TCG_KP_AIK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];
        let key_usage = webpki::KeyUsage::required_if_present(TCG_KP_AIK_CERTIFICATE);

        ak_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &trust_anchors,
                &intermediate_certs,
                time,
                key_usage,
                Some(revocation),
                None,
            )
            .context("certificate chain verification failed")
    } else {
        debug!("no CRLs available (no certificates have CRL Distribution Points)");
        debug!("verifying certificate chain WITHOUT CRL checking");

        const TCG_KP_AIK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];
        let key_usage = webpki::KeyUsage::required_if_present(TCG_KP_AIK_CERTIFICATE);

        ak_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &trust_anchors,
                &intermediate_certs,
                time,
                key_usage,
                None,
                None,
            )
            .context("certificate chain verification failed")
    };

    match result {
        Ok(_) => {
            if collateral.crls.is_empty() {
                debug!("✓ AK certificate chain verification successful (webpki, no CRLs)");
            } else {
                debug!(
                    "✓ AK certificate chain verification successful (webpki + {} intermediate CRL(s))",
                    collateral.crls.len()
                );
            }
            Ok(())
        }
        Err(e) => {
            warn!("✗ AK certificate chain verification failed: {e:?}");
            Err(e)
        }
    }
}
