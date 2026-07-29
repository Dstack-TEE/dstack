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
pub async fn verify_der(cert: &[u8], verifier: &AttestationVerifier) -> Result<VerifiedRaTlsCert> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(cert).context("failed to parse certificate")?;
    verify_cert(&cert, verifier).await
}

/// Verify the RA-TLS attestation embedded in a PEM-encoded X.509 certificate.
pub async fn verify_pem(cert: &[u8], verifier: &AttestationVerifier) -> Result<VerifiedRaTlsCert> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert).context("failed to parse PEM")?;
    verify_der(&pem.contents, verifier).await
}

fn verify_certificate_profile(cert: &x509_parser::prelude::X509Certificate<'_>) -> Result<()> {
    cert.verify_signature(None)
        .context("certificate self-signature verification failed")?;
    if !cert.validity().is_valid() {
        bail!("certificate is outside its validity period");
    }
    let key_usage = cert
        .key_usage()
        .context("failed to decode certificate key usage")?
        .context("certificate key usage extension missing")?;
    if !key_usage.value.digital_signature() {
        bail!("certificate key usage does not permit digital signatures");
    }
    let extended = cert
        .extended_key_usage()
        .context("failed to decode certificate extended key usage")?
        .context("certificate extended key usage extension missing")?;
    if !extended.value.server_auth && !extended.value.client_auth {
        bail!("certificate extended key usage permits neither server nor client authentication");
    }
    let san = cert
        .subject_alternative_name()
        .context("failed to decode certificate SAN")?
        .context("certificate SAN extension missing")?;
    if san.value.general_names.is_empty() {
        bail!("certificate SAN extension is empty");
    }
    Ok(())
}

/// Verify the RA-TLS attestation embedded in a parsed X.509 certificate.
async fn verify_cert(
    cert: &x509_parser::prelude::X509Certificate<'_>,
    verifier: &AttestationVerifier,
) -> Result<VerifiedRaTlsCert> {
    verify_certificate_profile(cert)?;
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
        .verify_with_ra_pubkey(&public_key_der, verifier)
        .await
        .context("RA-TLS attestation verification failed")?;
    if app_id.is_some() || app_info.is_some() {
        let attested = attestation
            .decode_app_info(false)
            .context("certificate identity extensions require attested app info")?;
        if let Some(extension) = &app_id {
            if extension != &attested.app_id {
                bail!("certificate app-id extension does not match attested app id");
            }
        }
        if let Some(extension) = &app_info {
            let matches = extension.app_id == attested.app_id
                && extension.compose_hash == attested.compose_hash
                && extension.instance_id == attested.instance_id
                && extension.device_id == attested.device_id
                && extension.mr_system == attested.mr_system
                && extension.mr_aggregated == attested.mr_aggregated
                && extension.os_image_hash == attested.os_image_hash
                && extension.key_provider_info == attested.key_provider_info;
            if !matches {
                bail!("certificate app-info extension does not match attested app info");
            }
        }
    }
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
    async fn ra_certificate_profile_quote_key_and_app_mutation_matrix() {
        use std::{sync::Arc, time::Duration};

        use cc_eventlog::{EventLogVersion, RuntimeEvent};
        use mock_attestation::server::{serve_listener, MockCollateralState};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let pccs = format!("http://{address}");
        let state = Arc::new(MockCollateralState::from_seed([0x74; 32], &pccs).unwrap());
        let server = tokio::spawn(serve_listener(listener, state.clone()));
        let verifier = AttestationVerifier::new_with_tdx_root(
            Some(&dstack_types::CollateralUrls {
                pccs: Some(pccs),
                ..Default::default()
            }),
            state.tdx.root_ca_pem().as_bytes(),
        )
        .unwrap();

        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let report_data = QuoteContentType::RaTlsCert.to_report_data(&key.public_key_der());
        let events = vec![
            RuntimeEvent::new("app-id".into(), vec![0x11; 20], EventLogVersion::V1),
            RuntimeEvent::new("compose-hash".into(), vec![0x22; 32], EventLogVersion::V1),
            RuntimeEvent::new("instance-id".into(), vec![0x33; 20], EventLogVersion::V1),
            RuntimeEvent::new(
                "key-provider".into(),
                b"fixture-provider".to_vec(),
                EventLogVersion::V1,
            ),
        ];
        let replayed = cc_eventlog::replay_events::<ez_hash::Sha384>(&events, None);
        let mut rtmrs = [[0u8; 48]; 4];
        rtmrs[3].copy_from_slice(&replayed);
        let evidence = state.tdx.attest_with_rtmrs(report_data, rtmrs).unwrap();
        let attestation = Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote: evidence.quote,
                event_log: events.iter().cloned().map(Into::into).collect(),
            }),
            runtime_events: events,
            report_data,
            config: format!(r#"{{"os_image_hash":"{}"}}"#, "44".repeat(32)),
            report: (),
        }
        .into_versioned();
        let verified_attestation = attestation
            .clone()
            .into_v1()
            .verify(&verifier)
            .await
            .unwrap();
        let app_info = verified_attestation.decode_app_info(false).unwrap();
        let alt_names = vec!["guest.example".to_string()];
        let cert = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .app_id(&app_info.app_id)
            .app_info(&app_info)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        let valid = verify_der(cert.der().as_ref(), &verifier).await.unwrap();
        assert_eq!(valid.app_id.as_deref(), Some(app_info.app_id.as_slice()));

        let mut changed_app_info = app_info.clone();
        changed_app_info.os_image_hash[0] ^= 1;
        let cert = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .app_id(&app_info.app_id)
            .app_info(&changed_app_info)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        let error = verify_der(cert.der().as_ref(), &verifier)
            .await
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("app-info extension does not match"));

        let mut changed_app_id = app_info.app_id.clone();
        changed_app_id[0] ^= 1;
        let cert = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .app_id(&changed_app_id)
            .app_info(&app_info)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        let error = verify_der(cert.der().as_ref(), &verifier)
            .await
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("app-id extension does not match"));

        let mut changed_quote = attestation.clone();
        let VersionedAttestation::V0 {
            attestation: changed,
        } = &mut changed_quote
        else {
            unreachable!("V1 runtime events must use the legacy-compatible container")
        };
        let AttestationQuote::DstackTdx(tdx_quote) = &mut changed.quote else {
            unreachable!()
        };
        tdx_quote.quote[100] ^= 1;
        let cert = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .attestation(&changed_quote)
            .build()
            .self_signed()
            .unwrap();
        assert!(verify_der(cert.der().as_ref(), &verifier).await.is_err());

        let wrong_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertRequest::builder()
            .key(&wrong_key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        assert!(format!(
            "{:#}",
            verify_der(cert.der().as_ref(), &verifier)
                .await
                .err()
                .unwrap()
        )
        .contains("report data mismatch"));

        let no_san = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .usage_server_auth(true)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        assert!(format!(
            "{:#}",
            verify_der(no_san.der().as_ref(), &verifier)
                .await
                .err()
                .unwrap()
        )
        .contains("SAN extension missing"));

        let no_eku = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        assert!(format!(
            "{:#}",
            verify_der(no_eku.der().as_ref(), &verifier)
                .await
                .err()
                .unwrap()
        )
        .contains("extended key usage extension missing"));

        let profile_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(alt_names.clone()).unwrap();
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyEncipherment];
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ServerAuth);
        let bad_usage = params.self_signed(&profile_key).unwrap();
        let (_, parsed) = x509_parser::parse_x509_certificate(bad_usage.der()).unwrap();
        assert!(verify_certificate_profile(&parsed)
            .unwrap_err()
            .to_string()
            .contains("does not permit digital signatures"));

        let now = std::time::SystemTime::now();
        let expired = CertRequest::builder()
            .key(&key)
            .subject("guest.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .not_before(now - Duration::from_secs(2 * 86400))
            .not_after(now - Duration::from_secs(86400))
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();
        assert!(format!(
            "{:#}",
            verify_der(expired.der().as_ref(), &verifier)
                .await
                .err()
                .unwrap()
        )
        .contains("outside its validity period"));

        let mut bad_signature = valid_cert_bytes(&key, &alt_names, &attestation);
        let last = bad_signature.len() - 1;
        bad_signature[last] ^= 1;
        assert!(format!(
            "{:#}",
            verify_der(&bad_signature, &verifier).await.err().unwrap()
        )
        .contains("self-signature verification failed"));
        server.abort();
    }

    fn valid_cert_bytes(
        key: &KeyPair,
        alt_names: &[String],
        attestation: &VersionedAttestation,
    ) -> Vec<u8> {
        CertRequest::builder()
            .key(key)
            .subject("guest.example")
            .alt_names(alt_names)
            .usage_server_auth(true)
            .attestation(attestation)
            .build()
            .self_signed()
            .unwrap()
            .der()
            .to_vec()
    }

    #[tokio::test]
    async fn verify_der_rejects_missing_attestation_extension() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let alt_names = vec!["missing-attestation.example".to_string()];
        let cert = CertRequest::builder()
            .key(&key)
            .subject("missing-attestation.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .build()
            .self_signed()
            .unwrap();

        let verifier = AttestationVerifier::new_prod(None).unwrap();
        let result = verify_der(cert.der().as_ref(), &verifier).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("attestation extension missing"));
    }

    #[tokio::test]
    async fn verify_der_rejects_attestation_not_bound_to_cert_key() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let attestation = fake_tdx_attestation([0u8; 64]);
        let alt_names = vec!["mismatched-attestation.example".to_string()];
        let cert = CertRequest::builder()
            .key(&key)
            .subject("mismatched-attestation.example")
            .alt_names(&alt_names)
            .usage_server_auth(true)
            .attestation(&attestation)
            .build()
            .self_signed()
            .unwrap();

        let verifier = AttestationVerifier::new_prod(None).unwrap();
        let result = verify_der(cert.der().as_ref(), &verifier).await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(format!("{err:#}").contains("report data mismatch"));
    }
}
