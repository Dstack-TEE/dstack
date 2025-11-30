// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! HTTPS client with mTLS and custom certificate verification during TLS handshake.

use std::fmt::Debug;
use std::sync::Arc;

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde::{de::DeserializeOwned, Serialize};
use tracing::info;

/// Custom certificate validator trait for TLS handshake verification.
///
/// Implementations can perform additional validation on the peer certificate
/// during the TLS handshake, before any application data is sent.
pub trait CertValidator: Debug + Send + Sync + 'static {
    /// Validate the peer certificate.
    ///
    /// Called after standard X.509 chain verification succeeds.
    /// Return `Ok(())` to accept the certificate, or `Err` to reject.
    fn validate(&self, cert_der: &[u8]) -> Result<(), String>;
}

/// TLS configuration for mTLS with optional custom certificate validation
#[derive(Clone)]
pub struct HttpsClientConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: String,
    /// Optional custom certificate validator (checked during TLS handshake)
    pub cert_validator: Option<Arc<dyn CertValidator>>,
}

/// Wrapper that adapts a CertValidator to rustls ServerCertVerifier
#[derive(Debug)]
struct CustomCertVerifier {
    validator: Arc<dyn CertValidator>,
    root_store: Arc<rustls::RootCertStore>,
}

impl CustomCertVerifier {
    fn new(
        validator: Arc<dyn CertValidator>,
        ca_cert_der: CertificateDer<'static>,
    ) -> Result<Self> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(ca_cert_der)
            .context("failed to add CA cert to root store")?;
        Ok(Self {
            validator,
            root_store: Arc::new(root_store),
        })
    }
}

impl ServerCertVerifier for CustomCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // First, do standard certificate verification
        let verifier = rustls::client::WebPkiServerVerifier::builder(self.root_store.clone())
            .build()
            .map_err(|e| rustls::Error::General(format!("failed to build verifier: {e}")))?;

        verifier.verify_server_cert(end_entity, intermediates, server_name, &[], now)?;

        // Then run custom validation
        self.validator
            .validate(end_entity.as_ref())
            .map_err(rustls::Error::General)?;

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

type HyperClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;

/// HTTPS client with mTLS and optional custom certificate validation.
///
/// When a `cert_validator` is set in `TlsConfig`, the client runs the validator
/// during the TLS handshake, before any application data is sent.
#[derive(Clone)]
pub struct HttpsClient {
    client: HyperClient,
}

impl HttpsClient {
    /// Create a new HTTPS client with mTLS configuration
    pub fn new(tls: &HttpsClientConfig) -> Result<Self> {
        // Load client certificate and key
        let cert_pem = std::fs::read(&tls.cert_path)
            .with_context(|| format!("failed to read TLS cert from {}", tls.cert_path))?;
        let key_pem = std::fs::read(&tls.key_path)
            .with_context(|| format!("failed to read TLS key from {}", tls.key_path))?;

        let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&cert_pem)
            .collect::<Result<_, _>>()
            .context("failed to parse client certs")?;

        let key = PrivateKeyDer::from_pem_slice(&key_pem).context("failed to parse private key")?;

        // Load CA certificate
        let ca_cert_pem = std::fs::read(&tls.ca_cert_path)
            .with_context(|| format!("failed to read CA cert from {}", tls.ca_cert_path))?;
        let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&ca_cert_pem)
            .collect::<Result<_, _>>()
            .context("failed to parse CA certs")?;
        let ca_cert = ca_certs
            .into_iter()
            .next()
            .context("no CA certificate found")?;

        // Build rustls config with custom verifier if validator is provided
        let tls_config_builder = rustls::ClientConfig::builder();

        let tls_config = if let Some(ref validator) = tls.cert_validator {
            let verifier = CustomCertVerifier::new(validator.clone(), ca_cert)?;
            tls_config_builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
        } else {
            // Standard verification without custom validator
            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(ca_cert).context("failed to add CA cert")?;
            tls_config_builder.with_root_certificates(root_store)
        }
        .with_client_auth_cert(certs, key)
        .context("failed to set client auth cert")?;

        info!(
            "HTTPS client: mTLS enabled with cert={}, ca={}, custom_validator={}",
            tls.cert_path,
            tls.ca_cert_path,
            tls.cert_validator.is_some()
        );

        let https = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http1()
            .build();

        let client = Client::builder(TokioExecutor::new()).build(https);
        Ok(Self { client })
    }

    /// Send a POST request with JSON body and receive JSON response
    pub async fn post_json<T: Serialize, R: DeserializeOwned>(
        &self,
        url: &str,
        body: &T,
    ) -> Result<R> {
        let body = serde_json::to_vec(body).context("failed to serialize request body")?;

        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(url)
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .context("failed to build request")?;

        let response = self
            .client
            .request(request)
            .await
            .with_context(|| format!("failed to send request to {url}"))?;

        if !response.status().is_success() {
            anyhow::bail!("request failed: {}", response.status());
        }

        let body = response
            .into_body()
            .collect()
            .await
            .context("failed to read response body")?
            .to_bytes();

        serde_json::from_slice(&body).context("failed to parse response")
    }
}

// ============================================================================
// Built-in validators
// ============================================================================

/// Validator that checks the peer certificate contains a specific app_id.
#[derive(Debug)]
pub struct AppIdValidator {
    expected_app_id: Vec<u8>,
}

impl AppIdValidator {
    pub fn new(expected_app_id: Vec<u8>) -> Self {
        Self { expected_app_id }
    }
}

impl CertValidator for AppIdValidator {
    fn validate(&self, cert_der: &[u8]) -> Result<(), String> {
        use ra_tls::traits::CertExt;

        let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
            .map_err(|e| format!("failed to parse certificate: {e}"))?;

        let peer_app_id = cert
            .get_app_id()
            .map_err(|e| format!("failed to get app_id: {e}"))?;

        let Some(peer_app_id) = peer_app_id else {
            return Err("peer certificate does not contain app_id".into());
        };

        if peer_app_id != self.expected_app_id {
            return Err(format!(
                "app_id mismatch: expected {}, got {}",
                hex::encode(&self.expected_app_id),
                hex::encode(&peer_app_id)
            ));
        }

        Ok(())
    }
}
