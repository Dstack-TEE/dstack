// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "client")]

use std::sync::Arc;

use prpc::client::RequestClient;
use ra_rpc::client::RaClient;
use ra_tls::{
    cert::CertRequest,
    rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256},
};
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
async fn skipping_ca_validation_still_requires_the_server_certificate_key() {
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for correct_key in [true, false] {
            let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
            let cert = CertRequest::builder()
                .subject("test server")
                .key(&key)
                .usage_server_auth(true)
                .build()
                .self_signed()
                .unwrap();
            let signing_key = if correct_key {
                key
            } else {
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap()
            };
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let signing_key = provider
                .key_provider
                .load_private_key(PrivatePkcs8KeyDer::from(signing_key.serialize_der()).into())
                .unwrap();
            // A resolver permits deliberately pairing a stolen certificate with
            // another key, unlike with_single_cert which rejects it up front.
            let certified = CertifiedKey::new(vec![cert.der().clone()], signing_key);
            let config = rustls::ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(&[version])
                .unwrap()
                .with_no_client_auth()
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
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnull",
                    )
                    .await
                    .unwrap();
                true
            });
            let client = RaClient::new(format!("https://{address}"), true).unwrap();
            let result = client.request::<(), ()>("Probe", ()).await;
            assert_eq!(result.is_ok(), correct_key, "{version:?}: {result:?}");
            assert_eq!(server.await.unwrap(), correct_key);
        }
    }
}
