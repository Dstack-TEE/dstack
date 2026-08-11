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
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData,
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
};
use crate::traits::CertExt;
#[cfg(feature = "quote")]
use dstack_attest::attestation::QuoteContentType;
use dstack_attest::attestation::{AppInfo, Attestation, VersionedAttestation};

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
        let (_, parsed_pem) = x509_parser::pem::parse_x509_pem(pem_cert.as_bytes())
            .context("Failed to parse cert PEM")?;
        let parsed_cert = parsed_pem
            .parse_x509()
            .context("Failed to parse cert DER")?;
        anyhow::ensure!(
            parsed_cert.public_key().raw == key.public_key_der(),
            "CA certificate does not match private key"
        );
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
            Some(csr.attestation.clone().into_v1().decode_app_info(false)?)
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
        let mut params = CertificateParams::new(self.alt_names.unwrap_or_default().to_vec())?;
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
        if let Some(app_id) = self.app_id {
            add_ext(&mut params, PHALA_RATLS_APP_ID, app_id);
        }
        if let Some(app_info) = self.app_info {
            // Encode as a MessagePack map keyed by field name rather than a positional
            // array. Field-name keys let readers tolerate fields they do not know, so
            // appending a field to `AppInfo` no longer breaks peers built against an
            // older definition. Decoding accepts both forms, so certificates issued by
            // older releases (positional) stay readable.
            let app_info_bytes =
                rmp_serde::to_vec_named(&app_info).context("failed to serialize app info")?;
            add_ext(&mut params, PHALA_RATLS_APP_INFO, app_info_bytes);
        }
        if let Some(usage) = self.special_usage {
            add_ext(&mut params, PHALA_RATLS_CERT_USAGE, usage);
        }
        if let Some(ver_att) = self.attestation {
            let attestation_bytes = ver_att.clone().into_stripped().to_bytes()?;
            add_ext(&mut params, PHALA_RATLS_ATTESTATION, &attestation_bytes);
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

/// Maximum allowed decompressed size of the event log extension (in bytes).
///
/// This protects against gzip decompression bombs in RA-TLS certificate
/// extensions by bounding the amount of memory we are willing to allocate.
/// 16 KiB is sufficient for typical event logs we embed in certs.
pub const MAX_EVENTLOG_EXT_SIZE: u64 = 16 * 1024;

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
        let decoder = GzDecoder::new(compressed);
        // Limit the total amount of decompressed data to avoid gzip bombs.
        let mut limited = decoder.take(MAX_EVENTLOG_EXT_SIZE + 1);
        let mut decompressed = Vec::new();
        limited
            .read_to_end(&mut decompressed)
            .context("failed to decompress event log")?;
        if decompressed.len() as u64 > MAX_EVENTLOG_EXT_SIZE {
            bail!(
                "event log extension too large (>{} bytes)",
                MAX_EVENTLOG_EXT_SIZE
            );
        }
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
    use dstack_attest::attestation::{AttestationQuote, TdxQuote};
    use rcgen::{SanType, PKCS_ECDSA_P256_SHA256};
    use scale::Encode;
    use std::net::IpAddr;

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
    fn test_cert_request_parses_ip_alt_names_as_ip_sans() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ip = "203.0.113.10".parse::<IpAddr>().unwrap();
        let alt_names = vec!["203.0.113.10".to_string(), "test.example.com".to_string()];

        let params = CertRequest::builder()
            .key(&key_pair)
            .subject("test.example.com")
            .alt_names(&alt_names)
            .build()
            .into_cert_params()
            .unwrap();

        assert!(params.subject_alt_names.contains(&SanType::IpAddress(ip)));
        assert!(params.subject_alt_names.iter().any(
            |san| matches!(san, SanType::DnsName(name) if name.as_str() == "test.example.com")
        ));
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
        // Simulate a reasonably large, highly repetitive event log payload.
        // Keep it well below MAX_EVENTLOG_EXT_SIZE so decompression succeeds.
        let large_data = vec![b'a'; (MAX_EVENTLOG_EXT_SIZE / 2) as usize];

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
        let expected = "44706c65617365207369676e20636572743a0c0102030040746573742e6578616d706c652e636f6d0001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
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
        let expected = "44706c65617365207369676e20636572743a0c0102030040746573742e6578616d706c652e636f6d000100010000000000040900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(actual, expected);
    }

    /// `AppInfo` travels inside RA-TLS certificates, so its MessagePack encoding is a
    /// cross-release wire contract: a certificate issued by one build gets parsed by
    /// peers built from another, and certificates outlive the process that issued them.
    ///
    /// Positional (array) encoding made that contract the *field order and count*, so
    /// appending a field broke every peer that had not been rebuilt. Encoding as a map
    /// keyed by field name makes it the *field names*, which readers can skip when
    /// unknown. These tests pin both directions across the v0.5.11 boundary.
    mod app_info_encoding {
        use super::*;
        use serde::{Deserialize, Serialize};
        use serde_human_bytes as hex_bytes;

        /// The exact `AppInfo` layout shipped in v0.5.6 through v0.5.11: eight fields,
        /// no `init_script_hashes`. Stands in for a peer built against those releases.
        #[derive(Debug, Serialize, Deserialize)]
        struct LegacyAppInfo {
            #[serde(with = "hex_bytes")]
            app_id: Vec<u8>,
            #[serde(with = "hex_bytes")]
            compose_hash: Vec<u8>,
            #[serde(with = "hex_bytes")]
            instance_id: Vec<u8>,
            #[serde(with = "hex_bytes")]
            device_id: Vec<u8>,
            #[serde(with = "hex_bytes")]
            mr_system: [u8; 32],
            #[serde(with = "hex_bytes")]
            mr_aggregated: [u8; 32],
            #[serde(with = "hex_bytes")]
            os_image_hash: Vec<u8>,
            #[serde(with = "hex_bytes")]
            key_provider_info: Vec<u8>,
        }

        /// A v0.5.11 app-info extension body: `LegacyAppInfo` in positional MessagePack,
        /// exactly as `rmp_serde::to_vec` emitted it. Leading `0x98` is a fixarray of 8.
        const LEGACY_POSITIONAL_APP_INFO: &str = concat!(
            "98c403a1a2a3c402b1b2c402c1c2c401d1c42051515151515151515151515151",
            "51515151515151515151515151515151515151c4206262626262626262626262",
            "626262626262626262626262626262626262626262c402e1e2c4036b6d73",
        );

        /// True when `bytes` opens with a MessagePack map header of any width. The
        /// header widens from fixmap to map16 at 16 entries, so matching on the fixmap
        /// range alone would start failing precisely when `AppInfo` grows past 15
        /// fields — the case this encoding exists to support.
        fn starts_with_msgpack_map(bytes: &[u8]) -> bool {
            matches!(bytes.first().copied(), Some(0x80..=0x8f | 0xde | 0xdf))
        }

        fn sample_app_info() -> AppInfo {
            AppInfo {
                app_id: vec![0xa1, 0xa2, 0xa3],
                compose_hash: vec![0xb1, 0xb2],
                instance_id: vec![0xc1, 0xc2],
                device_id: vec![0xd1],
                mr_system: [0x51; 32],
                mr_aggregated: [0x62; 32],
                os_image_hash: vec![0xe1, 0xe2],
                key_provider_info: b"kms".to_vec(),
                init_script_hashes: Some(vec![[0xf1; 32].to_vec(), [0xf2; 32].to_vec()]),
            }
        }

        /// Old certificate, new reader. Certificates issued before this change carry a
        /// positional array and must keep parsing; fields added since default in.
        #[test]
        fn legacy_positional_app_info_still_decodes() {
            let bytes = hex::decode(LEGACY_POSITIONAL_APP_INFO).unwrap();
            let decoded: AppInfo = rmp_serde::from_slice(&bytes).unwrap();

            assert_eq!(decoded.app_id, vec![0xa1, 0xa2, 0xa3]);
            assert_eq!(decoded.compose_hash, vec![0xb1, 0xb2]);
            assert_eq!(decoded.instance_id, vec![0xc1, 0xc2]);
            assert_eq!(decoded.device_id, vec![0xd1]);
            assert_eq!(decoded.mr_system, [0x51; 32]);
            assert_eq!(decoded.mr_aggregated, [0x62; 32]);
            assert_eq!(decoded.os_image_hash, vec![0xe1, 0xe2]);
            assert_eq!(decoded.key_provider_info, b"kms".to_vec());
            assert_eq!(
                decoded.init_script_hashes, None,
                "a field absent from the legacy layout must decode as unbound, not fail"
            );
        }

        /// New certificate, old reader. This is the direction positional encoding broke:
        /// a v0.5.11 peer decoding a certificate issued by this build.
        #[test]
        fn named_app_info_decodes_against_legacy_field_set() {
            let encoded = rmp_serde::to_vec_named(&sample_app_info()).unwrap();

            assert!(
                starts_with_msgpack_map(&encoded),
                "app info must encode as a MessagePack map, not a positional array"
            );

            let legacy: LegacyAppInfo = rmp_serde::from_slice(&encoded)
                .expect("a reader without init_script_hashes must skip it, not fail");
            assert_eq!(legacy.app_id, vec![0xa1, 0xa2, 0xa3]);
            assert_eq!(legacy.mr_system, [0x51; 32]);
            assert_eq!(legacy.key_provider_info, b"kms".to_vec());
        }

        /// The encoding change must not drop or reshape any field on the way through a
        /// real certificate extension.
        #[test]
        fn app_info_survives_a_certificate_round_trip() {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let app_info = sample_app_info();
            let cert = CertRequest::builder()
                .key(&key)
                .subject("test.example.com")
                .app_info(&app_info)
                .build()
                .self_signed()
                .unwrap();

            let decoded = cert.get_app_info().unwrap().expect("app info extension");
            assert_eq!(decoded.app_id, app_info.app_id);
            assert_eq!(decoded.compose_hash, app_info.compose_hash);
            assert_eq!(decoded.instance_id, app_info.instance_id);
            assert_eq!(decoded.device_id, app_info.device_id);
            assert_eq!(decoded.mr_system, app_info.mr_system);
            assert_eq!(decoded.mr_aggregated, app_info.mr_aggregated);
            assert_eq!(decoded.os_image_hash, app_info.os_image_hash);
            assert_eq!(decoded.key_provider_info, app_info.key_provider_info);
            assert_eq!(decoded.init_script_hashes, app_info.init_script_hashes);
        }
    }
}
