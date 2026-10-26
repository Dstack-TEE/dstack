// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

use super::*;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn mock_kds(
    responses: Vec<(&'static str, &'static [u8])>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut headers = Vec::new();
            let mut buffer = [0; 1024];
            while !headers.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.unwrap();
                assert!(count > 0);
                headers.extend_from_slice(&buffer[..count]);
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        }
    });
    (url, task)
}

#[tokio::test]
async fn concurrent_vcek_misses_share_one_request_and_cache() {
    let (url, server) = mock_kds(vec![("200 OK", b"certificate")]).await;
    let client = AmdKdsClient::with_base_url(url).unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(64));
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let client = client.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            client
                .fetch_vcek(AmdSnpProduct::Milan, &[7; 64], AmdSnpTcbVersion::default())
                .await
                .unwrap()
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().bytes, b"certificate");
    }
    server.await.unwrap();
    // The listener is now closed: another request could not succeed.
    assert_eq!(
        client
            .fetch_vcek(AmdSnpProduct::Milan, &[7; 64], AmdSnpTcbVersion::default())
            .await
            .unwrap()
            .bytes,
        b"certificate"
    );
}

#[tokio::test]
async fn rate_limit_is_typed_and_not_cached_as_invalid_or_success() {
    let (url, server) = mock_kds(vec![
        ("429 Too Many Requests", b"limited"),
        ("200 OK", b"certificate"),
    ])
    .await;
    let client = AmdKdsClient::with_base_url(url).unwrap();
    let error = client
        .fetch_vcek(AmdSnpProduct::Milan, &[7; 64], AmdSnpTcbVersion::default())
        .await
        .unwrap_err();
    assert!(collateral_unavailable(&error), "{error:#}");
    assert!(error.chain().any(|cause| cause
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|error| error.status() == Some(reqwest::StatusCode::TOO_MANY_REQUESTS))));
    assert_eq!(
        client
            .fetch_vcek(AmdSnpProduct::Milan, &[7; 64], AmdSnpTcbVersion::default())
            .await
            .unwrap()
            .bytes,
        b"certificate"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn malformed_certificate_is_not_a_dependency_outage() {
    let (url, server) = mock_kds(vec![("200 OK", b"not a certificate")]).await;
    let client = AmdKdsClient::with_base_url(url).unwrap();
    let error = client
        .fetch_ca_chain(AmdSnpProduct::Milan)
        .await
        .unwrap_err();
    assert!(!collateral_unavailable(&error), "{error:#}");
    server.await.unwrap();
}
