// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! End-to-end check that a Rocket server using [`RaTlsClientAuth`] authenticates
//! clients by the attestation in their certificate rather than by its issuer.
//!
//! The cases that matter:
//!   * a certificate minted from a temp CA is accepted (what guests and KMS-to-KMS
//!     onboarding send today, and what used to be the only accepted shape);
//!   * a self-issued RA-TLS certificate is accepted too, which is what lets clients
//!     stop fetching CA material;
//!   * a certificate with no attestation is rejected during the handshake;
//!   * an anonymous connection still reaches the handler, so the unauthenticated
//!     RPCs stay reachable.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use ra_rpc::ratls_client_verifier::RaTlsClientAuth;
use ra_tls::attestation::{Attestation, AttestationQuote, TdxQuote, VersionedAttestation};
use ra_tls::cert::CertRequest;
use ra_tls::rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256};
use rocket::tls::Resolver as _;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CertPair {
    cert_pem: String,
    key_pem: String,
}

fn attestation() -> VersionedAttestation {
    Attestation {
        quote: AttestationQuote::DstackTdx(TdxQuote {
            quote: vec![1, 2, 3],
            event_log: vec![],
        }),
        runtime_events: vec![],
        report_data: [0u8; 64],
        config: "".into(),
        report: (),
    }
    .into_versioned()
}

fn server_cert() -> CertPair {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let alt_names = vec!["localhost".to_string()];
    let cert = CertRequest::builder()
        .subject("test server")
        .key(&key)
        .alt_names(&alt_names)
        .usage_server_auth(true)
        .build()
        .self_signed()
        .unwrap();
    CertPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

fn client_cert(with_attestation: bool, issuer: Option<(&Certificate, &KeyPair)>) -> CertPair {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let att = attestation();
    let req = CertRequest::builder()
        .subject("test client")
        .key(&key)
        .maybe_attestation(with_attestation.then_some(&att))
        .usage_client_auth(true)
        .build();
    let cert = match issuer {
        Some((ca_cert, ca_key)) => req.signed_by(ca_cert, ca_key).unwrap(),
        None => req.self_signed().unwrap(),
    };
    CertPair {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    }
}

fn temp_ca() -> (Certificate, KeyPair) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = CertRequest::builder()
        .subject("Dstack Client Temp CA")
        .key(&key)
        .ca_level(0)
        .build()
        .self_signed()
        .unwrap();
    (cert, key)
}

#[rocket::get("/whoami")]
fn whoami(cert: Option<rocket::mtls::Certificate<'_>>) -> String {
    match cert {
        None => "anonymous".to_string(),
        Some(c) => format!("cn={}", c.subject().common_name().unwrap_or("<none>")),
    }
}

#[derive(Debug)]
struct AcceptAnyServer(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyServer {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

async fn probe(port: u16, client: Option<&CertPair>) -> Result<String> {
    use rustls::pki_types::pem::PemObject as _;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServer(provider)));
    let mut config = match client {
        Some(pair) => {
            let certs: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(pair.cert_pem.as_bytes())
                    .collect::<Result<_, _>>()?;
            let key = PrivateKeyDer::from_pem_slice(pair.key_pem.as_bytes())?;
            builder.with_client_auth_cert(certs, key)?
        }
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .context("tcp connect")?;
    let mut tls = connector
        .connect(ServerName::try_from("localhost")?, tcp)
        .await
        .context("tls handshake")?;
    tls.write_all(b"GET /whoami HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    tls.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let body = text
        .rsplit("\r\n\r\n")
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    if body.is_empty() {
        bail!(
            "empty body, status line: {}",
            text.lines().next().unwrap_or("")
        );
    }
    Ok(body)
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certs_are_authenticated_by_attestation_not_issuer() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let dir = tempdir();
    let server = server_cert();
    let certs_path = dir.join("server.crt");
    let key_path = dir.join("server.key");
    std::fs::write(&certs_path, &server.cert_pem).unwrap();
    std::fs::write(&key_path, &server.key_pem).unwrap();

    let port = free_port();
    // Note: no `[tls.mutual]` section at all — the resolver supplies the verifier.
    let figment = rocket::Config::figment()
        .merge(("port", port))
        .merge(("address", "127.0.0.1"))
        .merge(("log_level", "off"))
        .merge(("shutdown.ctrlc", false))
        .merge(("tls.certs", certs_path.to_str().unwrap()))
        .merge(("tls.key", key_path.to_str().unwrap()));
    let rocket = rocket::custom(figment)
        .attach(RaTlsClientAuth::fairing())
        .mount("/", rocket::routes![whoami]);
    let server_task = tokio::spawn(async move { rocket.launch().await });

    let mut up = false;
    for _ in 0..100 {
        assert!(!server_task.is_finished(), "rocket exited during launch");
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            up = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(up, "server never came up on port {port}");

    // A self-issued RA-TLS cert is accepted and reaches the handler. No client sends
    // one yet; this is the shape the CA pin used to reject.
    let self_signed = client_cert(true, None);
    assert_eq!(
        probe(port, Some(&self_signed)).await.unwrap(),
        "cn=test client"
    );

    // A cert minted from the temp CA — what guests and KMS-to-KMS onboarding present
    // today — keeps working.
    let (ca_cert, ca_key) = temp_ca();
    let ca_signed = client_cert(true, Some((&ca_cert, &ca_key)));
    assert_eq!(
        probe(port, Some(&ca_signed)).await.unwrap(),
        "cn=test client"
    );

    // A cert with no attestation is refused during the handshake.
    let no_attestation = client_cert(false, None);
    let err = probe(port, Some(&no_attestation))
        .await
        .expect_err("cert without attestation must be rejected");
    assert!(
        format!("{err:#}").contains("HandshakeFailure"),
        "expected the handshake to be refused, got: {err:#}"
    );

    // Anonymous connections still work, so unauthenticated RPCs stay reachable.
    assert_eq!(probe(port, None).await.unwrap(), "anonymous");

    server_task.abort();
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ra-rpc-ratls-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
