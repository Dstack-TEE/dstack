// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Test-only PKI: a self-signed CA and the leaves it signs.
//!
//! Every crate that needs a certificate to drive a TLS test used to build one out of
//! raw `rcgen` -- generate a key, set `IsCa::Ca(BasicConstraints::Unconstrained)`,
//! self-sign, write three PEM files -- which is how the same twenty lines ended up in
//! `gateway`'s sync tests, its HTTPS client tests, and `ra-rpc`'s client-auth tests,
//! each subtly different.
//!
//! Nothing here needs a TEE. `PHALA_RATLS_APP_ID` is an ordinary X.509 extension that
//! [`CertRequest`] writes unconditionally, and a peer check that compares app ids never
//! looks at a quote. For material that *does* carry attestation, use
//! [`generate_ra_cert_with_app_id`](crate::cert::generate_ra_cert_with_app_id), which
//! needs the `quote` feature and a real or simulated platform.
//!
//! Private keys produced here are test material and must never reach a production
//! image, which is why this module is behind the off-by-default `test-pki` feature.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rcgen::{Certificate, KeyPair};

use crate::attestation::AppInfo;
use crate::cert::CertRequest;

/// A certificate and the key that signs for it.
pub struct TestCertKey {
    /// The certificate.
    pub cert: Certificate,
    /// Its private key.
    pub key: KeyPair,
}

impl TestCertKey {
    /// The certificate, PEM-encoded.
    pub fn cert_pem(&self) -> String {
        self.cert.pem()
    }

    /// The private key, PEM-encoded.
    pub fn key_pem(&self) -> String {
        self.key.serialize_pem()
    }

    /// The certificate, DER-encoded.
    pub fn cert_der(&self) -> Vec<u8> {
        self.cert.der().to_vec()
    }

    /// The private key, DER-encoded.
    pub fn key_der(&self) -> Vec<u8> {
        self.key.serialize_der()
    }
}

/// A self-signed CA that exists to sign test leaves.
///
/// `ca_level(0)` rather than an unconstrained CA: a test CA has no reason to be allowed
/// to mint intermediates, and a root store that only accepts `CA:TRUE` is satisfied
/// either way.
pub struct TestCa(TestCertKey);

impl TestCa {
    /// Mint a new CA.
    pub fn new() -> Result<Self> {
        Self::named("dstack Test CA")
    }

    /// Mint a new CA with a chosen subject.
    pub fn named(subject: &str) -> Result<Self> {
        let key = KeyPair::generate().context("failed to generate CA key")?;
        let cert = CertRequest::builder()
            .subject(subject)
            .key(&key)
            .ca_level(0)
            .build()
            .self_signed()
            .context("failed to self-sign CA")?;
        Ok(Self(TestCertKey { cert, key }))
    }

    /// The CA certificate and key.
    pub fn cert_key(&self) -> &TestCertKey {
        &self.0
    }

    /// The CA certificate, PEM-encoded -- what a client's root store loads.
    pub fn cert_pem(&self) -> String {
        self.0.cert_pem()
    }
}

/// A leaf to mint, self-signed or signed by a [`TestCa`].
#[derive(Default)]
pub struct TestCert {
    subject: String,
    alt_names: Vec<String>,
    app_id: Option<Vec<u8>>,
    app_info: Option<AppInfo>,
    server_auth: bool,
    client_auth: bool,
}

impl TestCert {
    /// A leaf with the given subject and no extensions beyond the defaults.
    pub fn new(subject: &str) -> Self {
        Self {
            subject: subject.to_string(),
            ..Default::default()
        }
    }

    /// A leaf valid for `127.0.0.1`, usable for both ends of an mTLS connection.
    ///
    /// The shape almost every local TLS test wants: Rocket and `rustls` both check the
    /// SAN against the address dialled, and a test that reuses one leaf for the server
    /// and the client needs both usages.
    pub fn localhost() -> Self {
        Self::new("localhost")
            .alt_name("127.0.0.1")
            .server_auth(true)
            .client_auth(true)
    }

    /// Add a subject alternative name.
    pub fn alt_name(mut self, name: &str) -> Self {
        self.alt_names.push(name.to_string());
        self
    }

    /// Stamp `PHALA_RATLS_APP_ID`, which is what a peer identity check reads.
    pub fn app_id(mut self, app_id: &[u8]) -> Self {
        self.app_id = Some(app_id.to_vec());
        self
    }

    /// Stamp `PHALA_RATLS_APP_INFO`, the fuller identity a KMS-issued certificate
    /// carries alongside the app id.
    ///
    /// Separate from [`Self::app_id`] on purpose, so a test can mint the shape that
    /// used to be accepted by a fallback -- app info present, app id absent -- and pin
    /// that it no longer is.
    pub fn app_info(mut self, app_id: &[u8]) -> Self {
        self.app_info = Some(AppInfo {
            app_id: app_id.to_vec(),
            compose_hash: Vec::new(),
            instance_id: Vec::new(),
            device_id: Vec::new(),
            mr_system: [0u8; 32],
            mr_aggregated: [0u8; 32],
            os_image_hash: Vec::new(),
            key_provider_info: Vec::new(),
            init_script_hashes: None,
        });
        self
    }

    /// Mark the leaf usable for server authentication.
    pub fn server_auth(mut self, yes: bool) -> Self {
        self.server_auth = yes;
        self
    }

    /// Mark the leaf usable for client authentication.
    pub fn client_auth(mut self, yes: bool) -> Self {
        self.client_auth = yes;
        self
    }

    fn request<'a>(&'a self, key: &'a KeyPair) -> crate::cert::CertRequest<'a, KeyPair> {
        CertRequest::builder()
            .subject(&self.subject)
            .key(key)
            .alt_names(&self.alt_names)
            .maybe_app_id(self.app_id.as_deref())
            .maybe_app_info(self.app_info.as_ref())
            .usage_server_auth(self.server_auth)
            .usage_client_auth(self.client_auth)
            .build()
    }

    /// Mint the leaf, signed by itself.
    pub fn self_signed(self) -> Result<TestCertKey> {
        let key = KeyPair::generate().context("failed to generate leaf key")?;
        let cert = self
            .request(&key)
            .self_signed()
            .context("failed to self-sign leaf")?;
        Ok(TestCertKey { cert, key })
    }

    /// Mint the leaf, signed by `ca`.
    pub fn signed_by(self, ca: &TestCa) -> Result<TestCertKey> {
        let key = KeyPair::generate().context("failed to generate leaf key")?;
        let ca = ca.cert_key();
        let cert = self
            .request(&key)
            .signed_by(&ca.cert, &ca.key)
            .context("failed to sign leaf")?;
        Ok(TestCertKey { cert, key })
    }

    /// Mint the leaf DER only, signed by itself.
    ///
    /// For a check that parses a certificate and reads an extension, where the key is
    /// never used to complete a handshake.
    pub fn self_signed_der(self) -> Result<Vec<u8>> {
        Ok(self.self_signed()?.cert_der())
    }
}

/// Where [`write_mtls_pki`] put the PEM files.
pub struct TestPkiFiles {
    /// The leaf certificate, at `<dir>/node.crt`.
    pub cert_path: PathBuf,
    /// The leaf private key, at `<dir>/node.key`.
    pub key_path: PathBuf,
    /// The CA certificate, at `<dir>/ca.crt`.
    pub ca_cert_path: PathBuf,
    /// The leaf, for a test that also needs to serve with it.
    pub leaf: TestCertKey,
    /// The CA, for a test that signs a second leaf to play the other end.
    pub ca: TestCa,
}

/// Mint a CA and one leaf it signed, and write all three PEM files under `dir`.
///
/// The layout clients expect: a config that names a cert, a key and a CA bundle can
/// point straight at the three paths returned. Both the leaf and the CA come back, so a
/// test that needs a second peer -- a different app id, an expired leaf -- can sign one
/// under the same CA rather than starting over.
pub fn write_mtls_pki(dir: &Path, leaf: TestCert) -> Result<TestPkiFiles> {
    let ca = TestCa::new()?;
    let leaf = leaf.signed_by(&ca)?;

    let cert_path = dir.join("node.crt");
    let key_path = dir.join("node.key");
    let ca_cert_path = dir.join("ca.crt");

    std::fs::write(&cert_path, leaf.cert_pem()).context("failed to write leaf cert")?;
    std::fs::write(&key_path, leaf.key_pem()).context("failed to write leaf key")?;
    std::fs::write(&ca_cert_path, ca.cert_pem()).context("failed to write CA cert")?;

    Ok(TestPkiFiles {
        cert_path,
        key_path,
        ca_cert_path,
        leaf,
        ca,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::CertExt;

    #[test]
    fn a_leaf_carries_the_app_id_it_was_stamped_with() {
        let leaf = TestCert::localhost()
            .app_id(b"an-app-id")
            .self_signed()
            .expect("leaf");
        assert_eq!(
            leaf.cert.get_app_id().expect("read app id"),
            Some(b"an-app-id".to_vec())
        );
    }

    #[test]
    fn a_leaf_without_an_app_id_reads_back_as_absent() {
        let leaf = TestCert::localhost().self_signed().expect("leaf");
        assert_eq!(leaf.cert.get_app_id().expect("read app id"), None);
    }

    /// A root store built from the CA only accepts a trust anchor with `CA:TRUE`, so a
    /// CA that did not come back as one would fail every handshake rather than an
    /// assertion here.
    #[test]
    fn the_ca_is_a_ca_and_signs_leaves_that_chain_to_it() {
        use x509_parser::prelude::FromDer;

        let ca = TestCa::new().expect("ca");
        let leaf = TestCert::localhost().signed_by(&ca).expect("leaf");

        let ca_der = ca.cert_key().cert_der();
        let (_, parsed_ca) =
            x509_parser::certificate::X509Certificate::from_der(&ca_der).expect("parse ca");
        assert!(parsed_ca.is_ca(), "the test CA must be usable as one");

        let leaf_der = leaf.cert_der();
        let (_, parsed_leaf) =
            x509_parser::certificate::X509Certificate::from_der(&leaf_der).expect("parse leaf");
        assert_eq!(
            parsed_leaf.issuer(),
            parsed_ca.subject(),
            "a leaf signed by the CA must name it as issuer"
        );
    }

    #[test]
    fn the_three_pem_files_land_where_a_client_config_points() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pki = write_mtls_pki(dir.path(), TestCert::localhost().app_id(b"an-app-id"))
            .expect("write pki");

        for path in [&pki.cert_path, &pki.key_path, &pki.ca_cert_path] {
            let pem = std::fs::read_to_string(path).expect("read pem");
            assert!(pem.contains("-----BEGIN"), "{path:?} is not PEM");
        }
    }
}
