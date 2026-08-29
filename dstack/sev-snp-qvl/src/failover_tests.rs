// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Failover behaviour of [`AmdKdsClient`] against real sockets.
//!
//! These cover the part that matters operationally and cannot be established
//! by reading the code: that a rate-limited, broken or absent endpoint really
//! does hand off to the next one, and that a decisive answer does not.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use crate::{AmdKdsClient, AmdSnpProduct};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

/// A single-purpose HTTP origin that always answers the same way and counts
/// the requests it saw.
struct FakeKds {
    base_url: String,
    hits: Arc<AtomicUsize>,
}

impl FakeKds {
    async fn serving(status_line: &'static str, body: &'static str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::SeqCst);
                let mut discard = [0u8; 1024];
                let _ = socket.read(&mut discard).await;
                let response = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        Self {
            base_url: format!("http://127.0.0.1:{port}/vcek/v1"),
            hits,
        }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

const BODY: &str = "collateral-bytes";

fn cert_chain_path() -> String {
    format!("{}/cert_chain", AmdSnpProduct::Milan.kds_name())
}

#[tokio::test]
async fn a_rate_limited_endpoint_hands_off_to_the_next_one() {
    let rate_limited = FakeKds::serving("429 Too Many Requests", "slow down").await;
    let healthy = FakeKds::serving("200 OK", BODY).await;

    let client = AmdKdsClient::with_base_urls([&rate_limited.base_url, &healthy.base_url]).unwrap();
    let bytes = client
        .fetch_path(&cert_chain_path(), "cert_chain")
        .await
        .expect("the healthy endpoint should have answered");

    assert_eq!(bytes, BODY.as_bytes());
    assert_eq!(rate_limited.hits(), 1, "the first endpoint should be tried");
    assert_eq!(healthy.hits(), 1, "and the second should serve the answer");
}

#[tokio::test]
async fn a_refused_connection_hands_off_to_the_next_one() {
    // Nothing listens on port 1, so the connection is refused outright.
    let dead = "http://127.0.0.1:1/vcek/v1".to_string();
    let healthy = FakeKds::serving("200 OK", BODY).await;

    let client = AmdKdsClient::with_base_urls([&dead, &healthy.base_url]).unwrap();
    let bytes = client
        .fetch_path(&cert_chain_path(), "cert_chain")
        .await
        .expect("a refused connection should fail over");

    assert_eq!(bytes, BODY.as_bytes());
    assert_eq!(healthy.hits(), 1);
}

/// A 404 is an answer about the chip, not about the endpoint. Every mirror
/// repeats it, so failing over would multiply load and bury the real error
/// under a list of identical ones.
#[tokio::test]
async fn a_not_found_stops_rather_than_asking_everyone_else() {
    let not_found = FakeKds::serving("404 Not Found", "no such chip").await;
    let healthy = FakeKds::serving("200 OK", BODY).await;

    let client = AmdKdsClient::with_base_urls([&not_found.base_url, &healthy.base_url]).unwrap();
    let err = client
        .fetch_path(&cert_chain_path(), "cert_chain")
        .await
        .expect_err("a 404 should surface, not be retried away");

    assert!(
        format!("{err:#}").contains("404"),
        "the original status should survive: {err:#}"
    );
    assert_eq!(not_found.hits(), 1);
    assert_eq!(
        healthy.hits(),
        0,
        "the second endpoint should never have been contacted"
    );
}

#[tokio::test]
async fn every_endpoint_failing_reports_every_endpoint() {
    let first = FakeKds::serving("503 Service Unavailable", "down").await;
    let second = FakeKds::serving("500 Internal Server Error", "boom").await;

    let client = AmdKdsClient::with_base_urls([&first.base_url, &second.base_url]).unwrap();
    let err = client
        .fetch_path(&cert_chain_path(), "cert_chain")
        .await
        .expect_err("both endpoints failed");

    let rendered = format!("{err:#}");
    assert!(rendered.contains("2 endpoints"), "{rendered}");
    assert!(rendered.contains("503"), "{rendered}");
    assert!(rendered.contains("500"), "{rendered}");
    assert_eq!(first.hits(), 1);
    assert_eq!(second.hits(), 1);
}
