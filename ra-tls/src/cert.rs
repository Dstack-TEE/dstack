//! Certificate creation functions.

use std::time::SystemTime;
use std::{path::Path, time::Duration};

use anyhow::{anyhow, Context, Result};
use fs_err as fs;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, SanType,
};
use x509_parser::der_parser::Oid;

use crate::{
    attestation::Attestation,
    oids::{PHALA_RATLS_EVENT_LOG, PHALA_RATLS_QUOTE},
    traits::CertExt,
};

/// A CA certificate and private key.
pub struct CaCert {
    /// The original PEM certificate.
    pub pem_cert: String,
    /// CA certificate
    pub cert: Certificate,
    /// CA private key
    pub key: KeyPair,
}

impl CaCert {
    /// Instantiate a new CA certificate with a given private key and pem cert.
    pub fn new(pem_cert: String, pem_key: String) -> Result<Self> {
        let key = KeyPair::from_pem(&pem_key).context("Failed to parse key")?;
        let cert =
            CertificateParams::from_ca_cert_pem(&pem_cert).context("Failed to parse cert")?;
        let todo = "load the cert from the file directly: blocked by https://github.com/rustls/rcgen/issues/274";
        let cert = cert.self_signed(&key).context("Failed to self-sign cert")?;
        Ok(Self {
            pem_cert,
            cert,
            key,
        })
    }

    /// Load a CA certificate and private key from files.
    pub fn load(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Result<Self> {
        let pem_key = fs::read_to_string(key_path).context("Failed to read key file")?;
        let pem_cert = fs::read_to_string(cert_path).context("Failed to read cert file")?;
        Self::new(pem_cert, pem_key)
    }

    /// Sign a certificate request.
    pub fn sign(&self, req: CertRequest) -> Result<Certificate> {
        let key = req.key;
        let params = req.into_cert_params()?;
        let cert = params.signed_by(key, &self.cert, &self.key)?;
        Ok(cert)
    }

    /// Decode the attestation extension if present.
    pub fn decode_attestation(&self) -> Result<Option<Attestation>> {
        use x509_parser::pem::Pem;
        let Some(pem) = Pem::iter_from_buffer(self.pem_cert.as_bytes())
            .next()
            .transpose()
            .context("Invalid pem")?
        else {
            return Ok(None);
        };
        let cert = pem.parse_x509().context("Invalid x509 certificate")?;
        let externsions = cert.tbs_certificate.extensions();
        let attestation = Attestation::from_ext_getter(|oid| {
            let oid = Oid::from(oid).or(Err(anyhow!("Invalid oid")))?;
            let Some(ext) = externsions.iter().find(|ext| ext.oid == oid) else {
                return Ok(None);
            };
            Ok(Some(ext.value.to_vec()))
        })?;
        Ok(attestation)
    }
}

/// Information required to create a certificate.
#[derive(bon::Builder)]
pub struct CertRequest<'a> {
    key: &'a KeyPair,
    org_name: Option<&'a str>,
    subject: &'a str,
    alt_names: Option<&'a [String]>,
    ca_level: Option<u8>,
    quote: Option<&'a [u8]>,
    event_log: Option<&'a [u8]>,
    not_before: Option<SystemTime>,
    not_after: Option<SystemTime>,
}

impl CertRequest<'_> {
    fn into_cert_params(self) -> Result<CertificateParams> {
        let mut params = CertificateParams::new(vec![])?;
        let mut dn = DistinguishedName::new();
        if let Some(org_name) = self.org_name {
            dn.push(DnType::OrganizationName, org_name);
        }
        dn.push(DnType::CommonName, self.subject);
        params.distinguished_name = dn;
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
        if let Some(ca_level) = self.ca_level {
            if ca_level > 0 {
                params.is_ca = IsCa::Ca(BasicConstraints::Constrained(ca_level));
            }
        }
        if let Some(not_before) = self.not_before {
            params.not_before = not_before.into();
        }
        params.not_after = self
            .not_after
            .unwrap_or_else(|| {
                let now = SystemTime::now();
                let day = Duration::from_secs(86400);
                now + day * 365
            })
            .into();
        Ok(params)
    }

    /// Create a self-signed certificate.
    pub fn self_signed(self) -> Result<Certificate> {
        let key = self.key;
        let cert = self.into_cert_params()?.self_signed(key)?;
        Ok(cert)
    }

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
    fn get_extension(&self, oid: &[u64]) -> Result<Option<Vec<u8>>> {
        let found = self
            .params()
            .custom_extensions
            .iter()
            .find(|ext| ext.oid_components().collect::<Vec<_>>() == oid)
            .map(|ext| ext.content().to_vec());
        Ok(found)
    }
}
