// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Certificate creation functions.

use std::time::SystemTime;
use std::{path::Path, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use fs_err as fs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType,
};
use ring::rand::SystemRandom;
use tdx_attest::eventlog::read_event_logs;
use tdx_attest::get_quote;
use x509_parser::der_parser::Oid;
use x509_parser::prelude::{FromDer as _, X509Certificate};
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::attestation::QuoteContentType;
use crate::oids::{PHALA_RATLS_APP_ID, PHALA_RATLS_CERT_USAGE};
use crate::{
    oids::{PHALA_RATLS_EVENT_LOG, PHALA_RATLS_QUOTE},
    traits::CertExt,
};
use ring::signature::{
    EcdsaKeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_ASN1, ECDSA_P256_SHA256_ASN1_SIGNING,
};
use scale::{Decode, Encode};

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
        csr: &CertSigningRequest,
        app_id: Option<&[u8]>,
        usage: &str,
    ) -> Result<Certificate> {
        let pki = rcgen::SubjectPublicKeyInfo::from_der(&csr.pubkey)
            .context("Failed to parse signature")?;
        let cfg = &csr.config;
        let req = CertRequest::builder()
            .key(&pki)
            .subject(&cfg.subject)
            .maybe_org_name(cfg.org_name.as_deref())
            .alt_names(&cfg.subject_alt_names)
            .usage_server_auth(cfg.usage_server_auth)
            .usage_client_auth(cfg.usage_client_auth)
            .maybe_quote(cfg.ext_quote.then_some(&csr.quote))
            .maybe_event_log(cfg.ext_quote.then_some(&csr.event_log))
            .maybe_app_id(app_id)
            .special_usage(usage)
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

/// A certificate signing request.
#[derive(Encode, Decode, Clone, PartialEq)]
pub struct CertSigningRequest {
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

impl CertSigningRequest {
    /// Sign the certificate signing request.
    pub fn signed_by(&self, key: &KeyPair) -> Result<Vec<u8>> {
        let encoded = self.encode();
        let rng = SystemRandom::new();
        // Extract the DER-encoded private key and create an ECDSA key pair
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &key.serialize_der(), &rng)
                .context("Failed to create key pair from DER")?;

        // Sign the encoded CSR
        let signature = key_pair
            .sign(&rng, &encoded)
            .expect("Failed to sign CSR")
            .as_ref()
            .to_vec();
        Ok(signature)
    }

    /// Verify the signature of the certificate signing request.
    pub fn verify(&self, signature: &[u8]) -> Result<()> {
        let encoded = self.encode();
        let (_rem, pki) =
            SubjectPublicKeyInfo::from_der(&self.pubkey).context("Failed to parse pubkey")?;
        let parsed_pki = pki.parsed().context("Failed to parse pki")?;
        if !matches!(parsed_pki, PublicKey::EC(_)) {
            bail!("Unsupported algorithm");
        }
        let key = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &pki.subject_public_key.data);
        // verify signature
        key.verify(&encoded, signature)
            .ok()
            .context("Invalid signature")?;
        if self.confirm != "please sign cert:" {
            bail!("Invalid confirm word");
        }
        Ok(())
    }

    /// Encode the certificate signing request to a vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.encode()
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
    special_usage: Option<&'a str>,
    quote: Option<&'a [u8]>,
    event_log: Option<&'a [u8]>,
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
        if let Some(quote) = self.quote {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(quote);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_QUOTE, content);
            params.custom_extensions.push(ext);
        }
        if let Some(event_log) = self.event_log {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(event_log);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_EVENT_LOG, content);
            params.custom_extensions.push(ext);
        }
        if let Some(app_id) = self.app_id {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(app_id);
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_APP_ID, content);
            params.custom_extensions.push(ext);
        }
        if let Some(special_usage) = self.special_usage {
            let content = yasna::construct_der(|writer| {
                writer.write_bytes(special_usage.as_bytes());
            });
            let ext = CustomExtension::from_oid_content(PHALA_RATLS_CERT_USAGE, content);
            params.custom_extensions.push(ext);
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

/// Generate a certificate with RA-TLS quote and event log.
pub fn generate_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<CertPair> {
    use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let (_, quote) = get_quote(&report_data, None).context("Failed to get quote")?;
    let event_logs = read_event_logs().context("Failed to read event logs")?;
    let event_log = serde_json::to_vec(&event_logs).context("Failed to serialize event logs")?;
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .quote(&quote)
        .event_log(&event_log)
        .key(&key)
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
    use rcgen::PKCS_ECDSA_P256_SHA256;

    #[test]
    fn test_csr_signing_and_verification() {
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let pubkey = key_pair.public_key_der();

        let csr = CertSigningRequest {
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

        let csr = CertSigningRequest {
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
}
