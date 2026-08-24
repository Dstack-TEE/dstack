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

use anyhow::{Context, Result};
use ra_rpc::ratls_client_verifier::RaTlsClientAuth;
use ra_tls::attestation::{Attestation, AttestationQuote, TdxQuote, VersionedAttestation};
use ra_tls::cert::CertRequest;
use ra_tls::rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256};
use rocket::tls::Resolver as _;

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

/// Drive the server the way a real caller does: an HTTPS client that presents (or
/// withholds) a client certificate. Server-cert checking is off because the test
/// server is self-issued; the client certificate is the subject here.
async fn probe(port: u16, client: Option<&CertPair>) -> Result<String> {
    let mut builder = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(10));
    if let Some(pair) = client {
        let identity_pem = format!("{}\n{}", pair.cert_pem, pair.key_pem);
        builder = builder.identity(reqwest::Identity::from_pem(identity_pem.as_bytes())?);
    }
    let response = builder
        .build()?
        .get(format!("https://127.0.0.1:{port}/whoami"))
        .send()
        .await
        .context("request failed")?
        .error_for_status()?;
    response.text().await.context("failed to read body")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.local_addr().unwrap().port()
}

#[tokio::test(flavor = "multi_thread")]
async fn client_certs_are_authenticated_by_attestation_not_issuer() {
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

/// A `tls` section that exists but does not parse must stop the launch. Degrading to
/// "no resolver" would leave rocket serving a listener that never asks for a client
/// certificate, so every attested RPC would fail somewhere far from the cause.
#[tokio::test]
async fn a_half_written_tls_section_fails_init() {
    let figment = rocket::Config::figment().merge(("tls.certs", "/nonexistent.pem"));
    let rocket = rocket::custom(figment);
    let err = RaTlsClientAuth::init(&rocket)
        .await
        .err()
        .expect("a tls section without a key must not be ignored");
    assert!(
        format!("{err}").contains("key"),
        "expected the missing key to be named, got: {err}"
    );
}

/// No `tls` section at all is the plain-HTTP dev case: init must succeed and stay
/// inactive rather than fail the launch. (`resolve` is unreachable here - rocket only
/// calls it once a handshake is in flight, and there is no TLS listener to have one.)
#[tokio::test]
async fn no_tls_section_still_launches() {
    let rocket = rocket::custom(rocket::Config::figment());
    RaTlsClientAuth::init(&rocket)
        .await
        .expect("a plain-HTTP server must still launch");
}

/// Inline PEM bytes are what rocket's own listener accepts alongside paths. The
/// resolver reads through rocket's readers, so both shapes work.
#[tokio::test]
async fn inline_pem_bytes_are_accepted() {
    let server = server_cert();
    let figment = rocket::Config::figment()
        .merge(("tls.certs", server.cert_pem.as_bytes().to_vec()))
        .merge(("tls.key", server.key_pem.as_bytes().to_vec()));
    let rocket = rocket::custom(figment);
    RaTlsClientAuth::init(&rocket)
        .await
        .expect("inline PEM must be accepted, as it is by the stock listener");
}
