// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "client")]

use std::sync::Arc;

use prpc::client::RequestClient;
use ra_rpc::client::RaClientConfig;
use ra_tls::test_pki::{TestCa, TestCert};
use rustls::{
    pki_types::PrivatePkcs8KeyDer,
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct FixedCertificate(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[tokio::test]
async fn tls12_requires_the_server_certificate_key_even_without_ca_validation() {
    check_key_possession(&rustls::version::TLS12).await;
}

#[tokio::test]
async fn tls13_requires_the_server_certificate_key_even_without_ca_validation() {
    check_key_possession(&rustls::version::TLS13).await;
}

async fn check_key_possession(version: &'static rustls::SupportedProtocolVersion) {
    for correct_key in [true, false] {
        let server_cert = TestCert::localhost().self_signed().unwrap();
        let signing_key = if correct_key {
            server_cert.key_der()
        } else {
            TestCert::localhost().self_signed().unwrap().key_der()
        };
        let ca = TestCa::new().unwrap();
        let client_cert = TestCert::localhost().signed_by(&ca).unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_key().cert.der().clone()).unwrap();
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let signing_key = provider
            .key_provider
            .load_private_key(PrivatePkcs8KeyDer::from(signing_key).into())
            .unwrap();
        // A resolver permits deliberately pairing a stolen certificate with
        // another key, unlike with_single_cert which rejects it up front.
        let pinned_cert = server_cert.cert_der();
        let certified = CertifiedKey::new(vec![server_cert.cert.der().clone()], signing_key);
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .unwrap()
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(Arc::new(FixedCertificate(Arc::new(certified))));
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
            .tls_no_check(true)
            .tls_client_cert(client_cert.cert_pem())
            .tls_client_key(client_cert.key_pem())
            .verify_server_attestation(false)
            .cert_validator(Box::new(move |info| {
                let info = info.ok_or_else(|| anyhow::anyhow!("missing server certificate"))?;
                anyhow::ensure!(info.cert_der == pinned_cert, "server certificate changed");
                Ok(())
            }))
            .build()
            .into_client()
            .unwrap();
        let result = client.request::<(), ()>("Probe", ()).await;
        assert_eq!(result.is_ok(), correct_key, "{version:?}: {result:?}");
        assert_eq!(server.await.unwrap(), correct_key);
    }
}
