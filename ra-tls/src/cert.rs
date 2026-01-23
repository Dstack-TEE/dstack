// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Certificate creation functions.

use std::time::{SystemTime, UNIX_EPOCH};
use std::{path::Path, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use fs_err as fs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
};
use scale::{Decode, Encode};
use x509_parser::der_parser::Oid;
use x509_parser::prelude::{FromDer as _, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::oids::{
    PHALA_RATLS_APP_ID, PHALA_RATLS_APP_INFO, PHALA_RATLS_ATTESTATION, PHALA_RATLS_CERT_USAGE,
    PHALA_RATLS_EVENT_LOG, PHALA_RATLS_TDX_QUOTE,
};
use crate::traits::CertExt;
#[cfg(feature = "quote")]
use dstack_attest::attestation::QuoteContentType;
use dstack_attest::attestation::{AppInfo, Attestation, AttestationQuote, VersionedAttestation};

/// A CA certificate and private key.
pub struct CaCert {
    /// The original PEM certificate.
    pub pem_cert: String,
    /// CA certificate
    cert: Certificate,
    /// CA private key
    pub key: KeyPair,
}

impl CaCert {
    /// Instantiate a new CA certificate with a given private key and pem cert.
    pub fn new(pem_cert: String, pem_key: String) -> Result<Self> {
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert =
            CertificateParams::from_ca_cert_pem(&pem_cert).context("Failed to parse cert")?;
        // TODO: load the cert from the file directly, blocked by https://github.com/rustls/rcgen/issues/274
        let cert = cert.self_signed(&key).context("Failed to self-sign cert")?;
        Ok(Self {
            pem_cert,
            cert,
            key,
        })
    }

    /// Instantiate a new CA certificate with a given private key and pem cert.
    pub fn from_parts(key: KeyPair, cert: Certificate) -> Self {
        Self {
            pem_cert: cert.pem(),
            cert,
            key,
        }
    }

    /// Load a CA certificate and private key from files.
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let pem_key = fs::read_to_string(key_path).context("Failed to read key file")?;
        let pem_cert = fs::read_to_string(cert_path).context("Failed to read cert file")?;
        Self::new(pem_cert, pem_key)
    }

    /// Sign a certificate request.
    pub fn sign(&self, req: CertRequest<impl PublicKeyData>) -> Result<Certificate> {
        req.signed_by(&self.cert, &self.key)
    }

    /// Sign a remote certificate signing request.
    pub fn sign_csr(
        &self,
        csr: &CertSigningRequestV2,
        app_id: Option<&[u8]>,
        usage: &str,
    ) -> Result<Certificate> {
        let pki = rcgen::SubjectPublicKeyInfo::from_der(&csr.pubkey)
            .context("Failed to parse signature")?;
        let cfg = &csr.config;
        let app_info = if cfg.ext_app_info {
            Some(csr.attestation.decode_app_info(false)?)
        } else {
            None
        };
        let attestation = cfg.ext_quote.then_some(&csr.attestation);
        let req = CertRequest::builder()
            .key(&pki)
            .subject(&cfg.subject)
            .maybe_org_name(cfg.org_name.as_deref())
            .alt_names(&cfg.subject_alt_names)
            .usage_server_auth(cfg.usage_server_auth)
            .usage_client_auth(cfg.usage_client_auth)
            .maybe_attestation(attestation)
            .maybe_app_id(app_id)
            .maybe_app_info(app_info.as_ref())
            .special_usage(usage)
            .maybe_not_before(cfg.not_before.map(unix_time_to_system_time))
            .maybe_not_after(cfg.not_after.map(unix_time_to_system_time))
            .build();
        self.sign(req).context("Failed to sign certificate")
    }
}

/// The configuration of the certificate.
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct CertConfig {
    /// The organization name of the certificate.
    pub org_name: Option<String>,
    /// The subject of the certificate.
    pub subject: String,
    /// The subject alternative names of the certificate.
    pub subject_alt_names: Vec<String>,
    /// The purpose of the certificate.
    pub usage_server_auth: bool,
    /// The purpose of the certificate.
    pub usage_client_auth: bool,
    /// Whether the certificate is quoted.
    pub ext_quote: bool,
}

/// The configuration of the certificate with optional validity overrides.
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct CertConfigV2 {
    /// The organization name of the certificate.
    pub org_name: Option<String>,
    /// The subject of the certificate.
    pub subject: String,
    /// The subject alternative names of the certificate.
    pub subject_alt_names: Vec<String>,
    /// The purpose of the certificate.
    pub usage_server_auth: bool,
    /// The purpose of the certificate.
    pub usage_client_auth: bool,
    /// Whether the certificate is quoted.
    pub ext_quote: bool,
    /// Whether embed app info.
    pub ext_app_info: bool,
    /// The certificate validity start time as seconds since UNIX epoch.
    pub not_before: Option<u64>,
    /// The certificate validity end time as seconds since UNIX epoch.
    pub not_after: Option<u64>,
}

impl From<CertConfig> for CertConfigV2 {
    fn from(config: CertConfig) -> Self {
        Self {
            org_name: config.org_name,
            subject: config.subject,
            subject_alt_names: config.subject_alt_names,
            usage_server_auth: config.usage_server_auth,
            usage_client_auth: config.usage_client_auth,
            ext_quote: config.ext_quote,
            ext_app_info: false,
            not_before: None,
            not_after: None,
        }
    }
}

/// A certificate signing request.
#[derive(Encode, Decode, Clone)]
pub struct CertSigningRequestV1 {
    /// The confirm word, need to be "please sign cert:"
    pub confirm: String,
    /// The public key of the certificate.
    pub pubkey: Vec<u8>,
    /// The certificate configuration.
    pub config: CertConfig,
    /// The quote of the certificate.
    pub quote: Vec<u8>,
    /// The event log of the certificate.
    pub event_log: Vec<u8>,
}

/// A trait for Certificate Signing Request (CSR) operations.
///
/// This trait provides methods for signing and verifying CSRs using ECDSA P-256 keys.
/// Implementors must provide the data to sign, the public key, and a magic string for validation.
pub trait Csr {
    /// Signs the CSR data using the provided key pair.
    ///
    /// # Arguments
    /// * `key` - The ECDSA key pair used to sign the CSR.
    ///
    /// # Returns
    /// The DER-encoded ECDSA signature as a byte vector.
    ///
    /// # Errors
    /// Returns an error if key pair creation or signing fails.
    fn signed_by(&self, key: &KeyPair) -> Result<Vec<u8>> {
        let encoded = self.data_to_sign();
        let rng = SystemRandom::new();
        // Extract the DER-encoded private key and create an ECDSA key pair
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng)
                .context("Failed to create key pair from DER")?;

        // Sign the encoded CSR
        let signature = key_pair
            .sign(&rng, &encoded)
            .context("Failed to sign CSR")?
            .as_ref()
            .to_vec();
        Ok(signature)
    }

    /// Verifies the signature of the CSR.
    ///
    /// # Arguments
    /// * `signature` - The signature bytes to verify against the CSR data.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid and the magic string matches.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The public key cannot be parsed
    /// - The algorithm is not ECDSA P-256
    /// - The signature is invalid
    /// - The magic string does not match "please sign cert:"
    fn verify(&self, signature: &[u8]) -> Result<()> {
        let encoded = self.data_to_sign();
        let (_rem, pki) =
            SubjectPublicKeyInfo::from_der(self.pubkey()).context("Failed to parse pubkey")?;
        let parsed_pki = pki.parsed().context("Failed to parse pki")?;
        if !matches!(parsed_pki, PublicKey::EC(_)) {
            bail!("Unsupported algorithm");
        }
        let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pki.subject_public_key.data);
        // verify signature
        key.verify(&encoded, signature)
            .ok()
            .context("Invalid signature")?;
        if self.magic() != "please sign cert:" {
            bail!("Invalid confirm word");
        }
        Ok(())
    }

    /// Returns the data that should be signed or verified.
    ///
    /// Implementors should return the encoded CSR data as a byte vector.
    fn data_to_sign(&self) -> Vec<u8>;

    /// Returns the public key associated with this CSR.
    ///
    /// The public key should be in DER-encoded SubjectPublicKeyInfo format.
    fn pubkey(&self) -> &[u8];

    /// Returns the magic string used for validation.
    ///
    /// This string is checked during verification to ensure the CSR is valid.
    /// Expected value: "please sign cert:"
    fn magic(&self) -> &str;
}

impl Csr for CertSigningRequestV1 {
    fn data_to_sign(&self) -> Vec<u8> {
        self.encode()
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn magic(&self) -> &str {
        &self.confirm
    }
}

/// A certificate signing request.
#[derive(Encode, Decode, Clone)]
pub struct CertSigningRequestV2 {
    /// The confirm word, need to be "please sign cert:"
    pub confirm: String,
    /// The public key of the certificate.
    pub pubkey: Vec<u8>,
    /// The certificate configuration.
    pub config: CertConfigV2,
    /// The attestation.
    pub attestation: VersionedAttestation,
}

impl TryFrom<CertSigningRequestV1> for CertSigningRequestV2 {
    type Error = anyhow::Error;
    fn try_from(v0: CertSigningRequestV1) -> Result<Self, Self::Error> {
        Ok(Self {
            confirm: v0.confirm,
            pubkey: v0.pubkey,
            config: v0.config.into(),
            attestation: Attestation::from_tdx_quote(v0.quote, &v0.event_log)?.into_versioned(),
        })
    }
}

impl Csr for CertSigningRequestV2 {
    fn data_to_sign(&self) -> Vec<u8> {
        self.encode()
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    fn magic(&self) -> &str {
        &self.confirm
    }
}

impl CertSigningRequestV2 {
    /// Encodes the certificate signing request into a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.encode()
    }

    /// To attestation
    pub fn to_attestation(&self) -> Result<VersionedAttestation> {
        Ok(self.attestation.clone())
    }
}

/// Information required to create a certificate.
#[derive(bon::Builder)]
pub struct CertRequest<'a, Key> {
    key: &'a Key,
    org_name: Option<&'a str>,
    subject: &'a str,
    alt_names: Option<&'a [String]>,
    ca_level: Option<u8>,
    app_id: Option<&'a [u8]>,
    app_info: Option<&'a AppInfo>,
    special_usage: Option<&'a str>,
    attestation: Option<&'a VersionedAttestation>,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
    #[builder(default = false)]
    usage_server_auth: bool,
    #[builder(default = false)]
    usage_client_auth: bool,
}

impl<Key> CertRequest<'_, Key> {
    fn into_cert_params(self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        if let Some(org_name) = self.org_name {
            dn.push(DnType::OrganizationName, org_name);
        }
        dn.push(DnType::CommonName, self.subject);
        params.distinguished_name = dn;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        if self.usage_server_auth {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ServerAuth);
        }
        if self.usage_client_auth {
            params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
        }
        if let Some(alt_names) = self.alt_names {
            for alt_name in alt_names {
                params
                    .subject_alt_names
                    .push(SanType::DnsName(alt_name.clone().try_into()?));
            }
        }
        if let Some(app_id) = self.app_id {
            add_ext(&mut params, PHALA_RATLS_APP_ID, app_id);
        }
        if let Some(app_info) = self.app_info {
            let app_info_bytes =
                rmp_serde::to_vec(&app_info).context("Failed to serialize app info")?;
            add_ext(&mut params, PHALA_RATLS_APP_INFO, app_info_bytes);
        }
        if let Some(usage) = self.special_usage {
            add_ext(&mut params, PHALA_RATLS_CERT_USAGE, usage);
        }
        if let Some(ver_att) = self.attestation {
            let VersionedAttestation::V0 { attestation } = &ver_att;
            match &attestation.quote {
                AttestationQuote::DstackTdx(tdx_quote) => {
                    // For backward compatibility, we serialize the quote to the classic oids.
                    let event_log = serde_json::to_vec(&tdx_quote.event_log)
                        .context("Failed to serialize event log")?;
                    add_ext(&mut params, PHALA_RATLS_TDX_QUOTE, &tdx_quote.quote);
                    add_ext(&mut params, PHALA_RATLS_EVENT_LOG, &event_log);
                }
                _ => {
                    // The event logs are too large on GCP TDX to put in the certificate, so we strip them
                    let attestation_bytes = ver_att.clone().into_stripped().to_scale();
                    add_ext(&mut params, PHALA_RATLS_ATTESTATION, &attestation_bytes);
                }
            }
        }
        if let Some(ca_level) = self.ca_level {
            params.is_ca = IsCa::Ca(BasicConstraints::Constrained(ca_level));
            params.key_usages.push(KeyUsagePurpose::KeyCertSign);
            params.key_usages.push(KeyUsagePurpose::CrlSign);
        }
        if let Some(not_before) = self.not_before {
            params.not_before = not_before.into();
        }
        params.not_after = self
            .not_after
            .unwrap_or_else(|| {
                let now = SystemTime::now();
                let day = Duration::from_secs(86400);
                now + day * 365 * 10
            })
            .into();
        Ok(params)
    }
}

fn add_ext(params: &mut CertificateParams, oid: &[u64], content: impl AsRef<[u8]>) {
    let content = yasna::construct_der(|writer| {
        writer.write_bytes(content.as_ref());
    });
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(oid, content));
}

fn unix_time_to_system_time(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

impl CertRequest<'_, KeyPair> {
    /// Create a self-signed certificate.
    pub fn self_signed(self) -> Result<Certificate> {
        let key = self.key;
        let cert = self.into_cert_params()?.self_signed(key)?;
        Ok(cert)
    }
}

impl<Key: PublicKeyData> CertRequest<'_, Key> {
    /// Create a certificate signed by a given issuer.
    pub fn signed_by(self, issuer: &Certificate, issuer_key: &KeyPair) -> Result<Certificate> {
        let key = self.key;
        let cert = self
            .into_cert_params()?
            .signed_by(key, issuer, issuer_key)?;
        Ok(cert)
    }
}

impl CertExt for Certificate {
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let found = self
            .params()
            .custom_extensions
            .iter()
            .find(|ext| ext.oid_components().collect::<Vec<_>>() == oid)
            .map(|ext| ext.content().to_vec());
        Ok(found)
    }
}

impl CertExt for X509Certificate<'_> {
    fn get_extension_der(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid).or(Err(anyhow!("Invalid oid")))?;
        let found = self
            .get_extension_unique(&oid)
            .context("failt to decode der")?
            .map(|ext| ext.value.to_vec());
        Ok(found)
    }
}

/// A key and certificate pair.
pub struct CertPair {
    /// The certificate in PEM format.
    pub cert_pem: String,
    /// The key in PEM format.
    pub key_pem: String,
}

/// Magic prefix for gzip-compressed event log (version 1)
pub const EVENTLOG_GZIP_MAGIC: &[u8] = b"ELGZv1";

/// Compress a certificate extension value
pub fn compress_ext_value(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(data)
        .context("failed to write to gzip encoder")?;
    let compressed = encoder
        .finish()
        .context("failed to finish gzip compression")?;

    // Prepend magic prefix
    let mut result = Vec::with_capacity(EVENTLOG_GZIP_MAGIC.len() + compressed.len());
    result.extend_from_slice(EVENTLOG_GZIP_MAGIC);
    result.extend_from_slice(&compressed);
    Ok(result)
}

/// Decompress a certificate extension value
pub fn decompress_ext_value(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    if data.starts_with(EVENTLOG_GZIP_MAGIC) {
        // Compressed format
        let compressed = &data[EVENTLOG_GZIP_MAGIC.len()..];
        let mut decoder = GzDecoder::new(compressed);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .context("failed to decompress event log")?;
        Ok(decompressed)
    } else {
        // Uncompressed format (backwards compatibility)
        Ok(data.to_vec())
    }
}

/// Generate a certificate with RA-TLS quote and event log.
#[cfg(feature = "quote")]
pub fn generate_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<CertPair> {
    generate_ra_cert_with_app_id(ca_cert_pem, ca_key_pem, None)
}

/// Generate a certificate with RA-TLS quote and event log.
/// If app_id is provided, it will be included in the quote.
#[cfg(feature = "quote")]
pub fn generate_ra_cert_with_app_id(
    ca_cert_pem: String,
    ca_key_pem: String,
    app_id: Option<[u8; 20]>,
) -> Result<CertPair> {
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();

    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);

    let attestation = Attestation::quote_with_app_id(&report_data, app_id)
        .context("Failed to get quote for cert pubkey")?
        .into_versioned();

    // Build certificate request with all extensions
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .key(&key)
        .attestation(&attestation)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok(CertPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dstack_attest::attestation::TdxQuote;
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use scale::Encode;

    #[test]
    fn test_csr_signing_and_verification() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pubkey = key_pair.public_key_der();

        let csr = CertSigningRequestV1 {
            confirm: "please sign cert:".to_string(),
            pubkey: pubkey.clone(),
            config: CertConfig {
                org_name: Some("Test Org".to_string()),
                subject: "test.example.com".to_string(),
                subject_alt_names: vec!["alt.example.com".to_string()],
                usage_server_auth: true,
                usage_client_auth: false,
                ext_quote: false,
            },
            quote: Vec::new(),
            event_log: Vec::new(),
        };

        let signature = csr.signed_by(&key_pair).unwrap();
        assert!(csr.verify(&signature).is_ok());

        let mut invalid_signature = signature.clone();
        invalid_signature[0] ^= 0xff;
        assert!(csr.verify(&invalid_signature).is_err());
    }

    #[test]
    fn test_invalid_confirm_word() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pubkey = key_pair.public_key_der();

        let csr = CertSigningRequestV1 {
            confirm: "wrong confirm word".to_string(),
            pubkey: pubkey.clone(),
            config: CertConfig {
                org_name: Some("Test Org".to_string()),
                subject: "test.example.com".to_string(),
                subject_alt_names: vec![],
                usage_server_auth: true,
                usage_client_auth: false,
                ext_quote: false,
            },
            quote: Vec::new(),
            event_log: Vec::new(),
        };

        let signature = csr.signed_by(&key_pair).unwrap();
        assert!(csr.verify(&signature).is_err());
    }

    #[test]
    fn test_event_log_compression() {
        // Test with typical event log JSON data
        let event_log = r#"[{"imr":0,"event_type":1,"digest":"abc123","event":"test","event_payload":"deadbeef"}]"#;
        let original = event_log.as_bytes();

        // Compress
        let compressed = compress_ext_value(original).unwrap();
        assert!(compressed.starts_with(EVENTLOG_GZIP_MAGIC));

        // Decompress
        let decompressed = decompress_ext_value(&compressed).unwrap();
        assert_eq!(decompressed, original);

        // Test backwards compatibility with uncompressed data
        let decompressed_uncompressed = decompress_ext_value(original).unwrap();
        assert_eq!(decompressed_uncompressed, original);
    }

    #[test]
    fn test_event_log_compression_ratio() {
        // Simulate a large event log with repetitive data (like certificates)
        let mut large_data = Vec::new();
        for i in 0..100 {
            large_data.extend_from_slice(format!(
                r#"{{"imr":{},"event_type":1,"digest":"{}","event":"test{}","event_payload":"{}"}},"#,
                i % 4,
                "a".repeat(96),
                i,
                "deadbeef".repeat(100)
            ).as_bytes());
        }

        let compressed = compress_ext_value(&large_data).unwrap();
        let ratio = compressed.len() as f64 / large_data.len() as f64;

        // Compression should achieve at least 50% reduction for repetitive data
        assert!(ratio < 0.5, "compression ratio {} should be < 0.5", ratio);

        // Verify decompression works
        let decompressed = decompress_ext_value(&compressed).unwrap();
        assert_eq!(decompressed, large_data);
    }

    #[test]
    fn test_csr_v2_scale_encoding_stable() {
        let csr = CertSigningRequestV2 {
            confirm: "please sign cert:".to_string(),
            pubkey: vec![1, 2, 3],
            config: CertConfigV2 {
                org_name: None,
                subject: "test.example.com".to_string(),
                subject_alt_names: vec![],
                usage_server_auth: true,
                usage_client_auth: false,
                ext_quote: false,
                ext_app_info: false,
                not_before: None,
                not_after: None,
            },
            attestation: Attestation {
                quote: AttestationQuote::DstackTdx(TdxQuote {
                    quote: vec![],
                    event_log: vec![],
                }),
                runtime_events: vec![],
                report_data: [0u8; 64],
                config: "".into(),
                report: (),
            }
            .into_versioned(),
        };

        let actual = hex::encode(csr.encode());
        let expected = "44706c65617365207369676e20636572743a0c0102030040746573742e6578616d706c652e636f6d00010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_csr_v2_scale_encoding_stable_with_tdx_quote() {
        let csr = CertSigningRequestV2 {
            confirm: "please sign cert:".to_string(),
            pubkey: vec![1, 2, 3],
            config: CertConfigV2 {
                org_name: None,
                subject: "test.example.com".to_string(),
                subject_alt_names: vec![],
                usage_server_auth: true,
                usage_client_auth: false,
                ext_quote: true,
                ext_app_info: false,
                not_before: None,
                not_after: None,
            },
            attestation: Attestation {
                quote: AttestationQuote::DstackTdx(TdxQuote {
                    quote: vec![9],
                    event_log: vec![],
                }),
                runtime_events: vec![],
                report_data: [0u8; 64],
                config: "".into(),
                report: (),
            }
            .into_versioned(),
        };

        let actual = hex::encode(csr.encode());
        let expected = "44706c65617365207369676e20636572743a0c0102030040746573742e6578616d706c652e636f6d0001000100000000040900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(actual, expected);
    }
}
