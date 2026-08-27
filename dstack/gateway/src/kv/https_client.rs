// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! HTTPS client with mTLS and custom certificate verification during TLS handshake.

use std::fmt::Debug;
use std::io::Write;
use std::sync::Arc;

use anyhow::{Context, Result};
use flate2::{write::GzEncoder, Compression};
use http_body_util::{BodyExt, Full, Limited};
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

/// Read a peer's response body, refusing one larger than the routes accept on a request.
///
/// `Body::collect` reads to completion, so without this a peer could stream an unbounded
/// response and the decompression limit downstream would never be reached — the memory
/// is already gone by then.
async fn read_body_bounded(body: hyper::body::Incoming) -> Result<Bytes> {
    Limited::new(body, super::MAX_COMPRESSED_SYNC_BYTES)
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to read response body (limit {} bytes): {err}",
                super::MAX_COMPRESSED_SYNC_BYTES
            )
        })
}

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

/// TLS configuration for mTLS with custom certificate validation
#[derive(Clone)]
pub struct HttpsClientConfig {
    pub cert_path: String,
    pub key_path: String,
    pub ca_cert_path: String,
    /// Custom certificate validator, checked against the peer's certificate
    /// during the handshake.
    ///
    /// Not optional: this is the only thing that distinguishes a gateway in our own
    /// cluster from any other holder of a certificate the shared CA signed, and CA-path
    /// validation alone does not make that distinction.
    pub cert_validator: Arc<dyn CertValidator>,
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

/// HTTPS client with mTLS and peer identity validation.
///
/// The `cert_validator` runs during the TLS handshake, before any application data is
/// sent, on top of the chain verification against the configured CA.
#[derive(Clone)]
pub struct HttpsClient {
    client: HyperClient,
}

/// A non-success HTTP status, kept as a typed error in the chain so a caller
/// can react to a specific code. The sync path needs to tell an HTTP 403
/// rejection apart from a peer that is down or broken without string-matching
/// a formatted error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpStatusError(pub u16);

impl std::fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "request failed with HTTP status {}", self.0)
    }
}

impl std::error::Error for HttpStatusError {}

impl HttpsClient {
    async fn post_gzipped(
        &self,
        url: &str,
        body: Vec<u8>,
    ) -> Result<hyper::Response<hyper::body::Incoming>> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder
            .write_all(&body)
            .context("failed to compress request")?;
        let compressed = encoder.finish().context("failed to finish compression")?;

        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(url)
            .header("content-type", "application/x-msgpack-gz")
            .body(Full::new(Bytes::from(compressed)))
            .context("failed to build request")?;

        self.client
            .request(request)
            .await
            .with_context(|| format!("failed to send request to {url}"))
    }

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

        // `CustomCertVerifier` runs the validator *after* rustls has verified the chain
        // against `ca_cert`, so this is the CA path plus an identity check, never a
        // replacement for it. There is deliberately no validator-less branch: it would
        // accept any certificate the CA signed, which is every gateway in every cluster
        // that shares the CA.
        let verifier = CustomCertVerifier::new(tls.cert_validator.clone(), ca_cert)?;
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_client_auth_cert(certs, key)
            .context("failed to set client auth cert")?;

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
            return Err(HttpStatusError(response.status().as_u16()).into());
        }

        // Bounded like every other response: this is the bootnode GetPeers path, and
        // the threat model does not assume a bootnode is honest.
        let body = read_body_bounded(response.into_body()).await?;

        serde_json::from_slice(&body).context("failed to parse response")
    }

    /// Send an already-encoded body and return the decompressed response bytes.
    pub async fn post_bytes_response(&self, url: &str, body: Vec<u8>) -> Result<Vec<u8>> {
        let response = self.post_gzipped(url, body).await?;

        let status = response.status();
        if !status.is_success() {
            return Err(HttpStatusError(status.as_u16()).into());
        }

        let body = read_body_bounded(response.into_body()).await?;
        crate::kv::gunzip_bounded(&body, crate::kv::MAX_DECOMPRESSED_SYNC_BYTES)
    }

    /// Send an already-encoded body to an endpoint whose successful response has no body.
    pub async fn post_bytes_no_response(&self, url: &str, body: Vec<u8>) -> Result<()> {
        let response = self.post_gzipped(url, body).await?;
        if !response.status().is_success() {
            return Err(HttpStatusError(response.status().as_u16()).into());
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::KeyPair;

    /// A certificate carrying `PHALA_RATLS_APP_ID`, minted in process.
    ///
    /// No TEE is involved: `CertRequest` writes the extension unconditionally, and the
    /// validator below never looks at a quote — it parses DER and compares bytes.
    fn cert_with_app_id(app_id: &[u8]) -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        CertRequest::builder()
            .key(&key)
            .subject("peer.test")
            .app_id(app_id)
            .build()
            .self_signed()
            .expect("self-signed cert")
            .der()
            .to_vec()
    }

    fn cert_without_app_id() -> Vec<u8> {
        let key = KeyPair::generate().expect("key");
        CertRequest::builder()
            .key(&key)
            .subject("peer.test")
            .build()
            .self_signed()
            .expect("self-signed cert")
            .der()
            .to_vec()
    }

    /// The client half of the same rule the sync routes enforce on inbound requests.
    ///
    /// This runs during the TLS handshake, so a validator that always returns `Ok(())`
    /// means this gateway will complete a mutually-authenticated connection to any peer
    /// presenting any certificate our CA signed — and then send it our state. Replacing
    /// the whole body with `Ok(())`, or inverting the comparison, left the suite green.
    #[test]
    fn a_peer_certificate_is_accepted_only_when_its_app_id_matches() {
        let ours = b"app-id-of-this-cluster".to_vec();
        let validator = AppIdValidator::new(ours.clone());

        assert_eq!(validator.validate(&cert_with_app_id(&ours)), Ok(()));
        assert!(
            validator
                .validate(&cert_with_app_id(b"a-different-app"))
                .is_err(),
            "a certificate from another app must not complete the handshake"
        );
    }

    /// A certificate that says nothing about which app holds it proves nothing, and must
    /// be refused rather than treated as unconstrained.
    #[test]
    fn a_peer_certificate_without_an_app_id_is_refused() {
        let validator = AppIdValidator::new(b"app-id-of-this-cluster".to_vec());
        let err = validator
            .validate(&cert_without_app_id())
            .expect_err("a certificate with no app identity must be refused");
        assert!(err.contains("app_id"), "{err}");
    }

    /// Anything that is not a certificate is a parse failure, not a pass.
    #[test]
    fn a_malformed_certificate_is_refused() {
        let validator = AppIdValidator::new(b"whatever".to_vec());
        assert!(validator.validate(b"not a certificate at all").is_err());
    }
}

/// Response handling tested against a real TLS peer.
///
/// No container and no TEE: a local listener with a certificate minted in process.
#[cfg(test)]
mod transport_tests {
    use super::*;
    use hyper::service::service_fn;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// The app id the HTTP-level tests below run under. They are not about identity,
    /// but the validator is not optional, so their server and client agree on one.
    const TEST_APP_ID: &[u8] = b"app-id-of-this-cluster";

    /// A CA plus a leaf valid for 127.0.0.1, written where `HttpsClient::new` expects.
    fn tls_material(dir: &std::path::Path) -> (HttpsClientConfig, Vec<u8>, Vec<u8>) {
        app_id_server_cert(dir, TEST_APP_ID)
    }

    /// Serve one fixed response over TLS and return the URL to reach it.
    async fn serve(status: StatusCode, body: Vec<u8>, cert: Vec<u8>, key: Vec<u8>) -> String {
        let certs = vec![rustls::pki_types::CertificateDer::from(cert)];
        let key = rustls::pki_types::PrivateKeyDer::try_from(key).expect("server key");
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(tls),
                            service_fn(move |_req| {
                                let body = body.clone();
                                async move {
                                    Ok::<_, Infallible>(
                                        Response::builder()
                                            .status(status)
                                            .body(Full::new(Bytes::from(body)))
                                            .expect("response"),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });

        format!("https://127.0.0.1:{}/wavekv/sync/persistent", addr.port())
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(bytes).expect("gzip");
        encoder.finish().expect("gzip finish")
    }

    async fn request(status: StatusCode, body: Vec<u8>) -> Result<Vec<u8>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let (config, cert, key) = tls_material(dir.path());
        let url = serve(status, body, cert, key).await;
        HttpsClient::new(&config)
            .expect("client")
            .post_bytes_response(&url, b"request".to_vec())
            .await
    }

    /// The status code survives into the error chain as a typed value: the
    /// sync path tells an HTTP 403 rejection apart from a peer that is down or
    /// broken, and string-matching a Display line is not a contract.
    #[tokio::test]
    async fn a_refusal_status_is_readable_from_the_error_chain() {
        let err = request(StatusCode::FORBIDDEN, Vec::new())
            .await
            .expect_err("403 must not read as success");
        let status = err
            .chain()
            .filter_map(|cause| cause.downcast_ref::<HttpStatusError>())
            .next()
            .expect("the status must be present as a typed error");
        assert_eq!(*status, HttpStatusError(403));
    }

    /// A non-success status must never be decoded as a successful sync response.
    #[tokio::test]
    async fn a_server_error_is_rejected() {
        assert!(request(StatusCode::INTERNAL_SERVER_ERROR, Vec::new())
            .await
            .is_err());
        assert!(request(StatusCode::BAD_REQUEST, Vec::new()).await.is_err());
    }

    /// A peer that answers gets its body decompressed and returned.
    #[tokio::test]
    async fn an_upgraded_peer_returns_its_decoded_body() {
        let payload = b"the-envelope-bytes".to_vec();
        let got = request(StatusCode::OK, gzip(&payload)).await.unwrap();
        assert_eq!(got, payload);
    }

    /// Push responses intentionally have no body. A successful delivery must not be
    /// passed through the sync-response gunzip path.
    #[tokio::test]
    async fn an_empty_success_response_is_accepted_for_a_push() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let (config, cert, key) = tls_material(dir.path());
        let url = serve(StatusCode::OK, Vec::new(), cert, key).await;

        HttpsClient::new(&config)
            .expect("client")
            .post_bytes_no_response(&url, b"push-envelope".to_vec())
            .await
            .expect("an empty 200 response is a successful push");
    }

    #[tokio::test]
    async fn a_failed_push_status_is_rejected() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let (config, cert, key) = tls_material(dir.path());
        let url = serve(StatusCode::NOT_FOUND, Vec::new(), cert, key).await;

        assert!(HttpsClient::new(&config)
            .expect("client")
            .post_bytes_no_response(&url, b"push-envelope".to_vec())
            .await
            .is_err());
    }

    /// A server certificate carrying an app id, signed by the same test CA.
    ///
    /// The client config that comes back validates against that same app id, which is
    /// what the HTTP-level tests want. `a_peer_from_another_app_cannot_complete_the_handshake`
    /// overrides `cert_validator` to make the two disagree.
    fn app_id_server_cert(
        dir: &std::path::Path,
        app_id: &[u8],
    ) -> (HttpsClientConfig, Vec<u8>, Vec<u8>) {
        let pki = ra_tls::test_pki::write_mtls_pki(
            dir,
            ra_tls::test_pki::TestCert::new("peer.test")
                .alt_name("127.0.0.1")
                .app_id(app_id)
                .server_auth(true),
        )
        .expect("write test PKI");

        (
            HttpsClientConfig {
                cert_path: pki.cert_path.to_string_lossy().into_owned(),
                key_path: pki.key_path.to_string_lossy().into_owned(),
                ca_cert_path: pki.ca_cert_path.to_string_lossy().into_owned(),
                cert_validator: Arc::new(AppIdValidator::new(app_id.to_vec())),
            },
            pki.leaf.cert_der(),
            pki.leaf.key_der(),
        )
    }

    /// The client-side identity check, over a real handshake rather than a direct call.
    ///
    /// `AppIdValidator` runs inside `CustomCertVerifier`, which rustls only reaches once
    /// standard chain verification passes — so unit-testing the validator alone leaves
    /// the wiring untested. A peer from another app must fail to connect at all, before
    /// any application bytes move.
    #[tokio::test]
    async fn a_peer_from_another_app_cannot_complete_the_handshake() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ours = b"app-id-of-this-cluster".to_vec();

        for (server_app_id, expect_ok) in
            [(ours.clone(), true), (b"a-different-app".to_vec(), false)]
        {
            let dir = tempfile::tempdir().expect("tempdir");
            let (mut config, cert, key) = app_id_server_cert(dir.path(), &server_app_id);
            config.cert_validator = Arc::new(AppIdValidator::new(ours.clone()));
            let url = serve(StatusCode::OK, gzip(b"response"), cert, key).await;

            let got = HttpsClient::new(&config)
                .expect("client")
                .post_bytes_response(&url, b"x".to_vec())
                .await;

            if expect_ok {
                assert_eq!(
                    got.expect("a peer from our own app must connect"),
                    b"response"
                );
            } else {
                assert!(
                    got.is_err(),
                    "a peer from another app completed the handshake"
                );
            }
        }
    }

    /// `post_json` is the bootnode GetPeers path, and the threat model does not assume a
    /// bootnode is honest — so a failure status must not be parsed as a peer list.
    #[tokio::test]
    async fn a_failed_bootnode_fetch_is_not_parsed_as_peers() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().expect("tempdir");
        let (config, cert, key) = tls_material(dir.path());
        let url = serve(StatusCode::FORBIDDEN, b"null".to_vec(), cert, key).await;
        let client = HttpsClient::new(&config).expect("client");
        let out: Result<Option<u32>> = client.post_json(&url, &()).await;
        assert!(
            out.is_err(),
            "a 403 from a bootnode must not parse as a body"
        );
    }

    /// The response body is bounded before it is decompressed, so a peer cannot spend
    /// our memory ahead of any decoding limit.
    ///
    /// The body must be *valid* gzip that merely exceeds the compressed ceiling. A
    /// malformed one is rejected by `gunzip_bounded` whatever the ceiling says, so it
    /// would pass this test with the bound removed entirely — which is exactly what the
    /// first version of it did. Stored-mode gzip keeps the encoded size at roughly the
    /// input size, so the payload clears the ceiling while decompressing well inside it.
    #[tokio::test]
    async fn an_oversized_response_body_is_refused() {
        let stored = {
            let mut encoder = GzEncoder::new(Vec::new(), Compression::none());
            encoder
                .write_all(&vec![0u8; super::super::MAX_COMPRESSED_SYNC_BYTES + 1])
                .expect("gzip");
            encoder.finish().expect("gzip finish")
        };
        assert!(
            stored.len() > super::super::MAX_COMPRESSED_SYNC_BYTES,
            "the fixture depends on the compressed body clearing the ceiling"
        );
        assert!(request(StatusCode::OK, stored).await.is_err());
    }
}
