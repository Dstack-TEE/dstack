// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "client")]

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use prpc::client::RequestClient;
use ra_rpc::client::{PinnedIssuer, RaClientConfig};
use ra_tls::cert::CertRequest;
use ra_tls::rcgen::KeyPair;
use ra_tls::test_pki::TestCa;
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A pinned issuer is checked at the handshake, so a server it did not sign,
/// or a certificate it signed that is a CA, expired or of another usage, never
/// receives the request, nor the bearer token in it.
#[tokio::test]
async fn nothing_is_sent_to_a_server_failing_the_pin() {
    let registered = TestCa::new().unwrap();
    let other = TestCa::new().unwrap();
    let expired = SystemTime::now() - Duration::from_secs(60);
    for (issuer, usage, ca, not_after, reached) in [
        (&registered, "kms:rpc", false, None, true),
        (&registered, "app:ca", false, None, false),
        (&registered, "kms:rpc", true, None, false),
        (&registered, "kms:rpc", false, Some(expired), false),
        (&other, "kms:rpc", false, None, false),
    ] {
        let key = KeyPair::generate().unwrap();
        let cert = CertRequest::builder()
            .subject("localhost")
            .alt_names(&["localhost".to_string()])
            .special_usage(usage)
            .maybe_ca_level(ca.then_some(0))
            .maybe_not_after(not_after)
            .key(&key)
            .build()
            .signed_by(&issuer.cert_key().cert, &issuer.cert_key().key)
            .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
            else {
                return false;
            };
            let mut request = [0; 4096];
            if !matches!(stream.read(&mut request).await, Ok(n) if n > 0) {
                return false;
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull")
                .await
                .unwrap();
            true
        });
        let client = RaClientConfig::builder()
            .remote_uri(format!("https://{address}"))
            .tls_pinned_issuer(PinnedIssuer {
                pubkey: registered.cert_key().key.public_key_der(),
                usage: "kms:rpc".into(),
            })
            .bearer_token("secret".into())
            .verify_server_attestation(false)
            .build()
            .into_client()
            .unwrap();
        let result = client.request::<(), ()>("Probe", ()).await;
        assert_eq!(result.is_ok(), reached, "{usage}: {result:?}");
        assert_eq!(server.await.unwrap(), reached);
    }
}

#[test]
fn a_pinned_issuer_requires_https() {
    let client = |uri: &str| {
        RaClientConfig::builder()
            .remote_uri(uri.into())
            .tls_pinned_issuer(PinnedIssuer {
                pubkey: vec![0],
                usage: "kms:rpc".into(),
            })
            .build()
            .into_client()
    };
    assert!(client("https://kms").is_ok());
    assert!(client("http://kms").is_err());
}
