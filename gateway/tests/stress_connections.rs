// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Stress test for concurrent TCP connections.
//!
//! Verifies that a TCP accept loop (like the gateway proxy's) can handle
//! thousands of concurrent connections with SNI-like payloads without dropping.
//!
//! Run: cargo test -p dstack-gateway --test stress_connections -- --nocapture

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

/// Build a minimal TLS ClientHello with the given SNI hostname.
fn build_client_hello(hostname: &str) -> Vec<u8> {
    let sni_hostname = hostname.as_bytes();
    let sni_list_len = (sni_hostname.len() + 5) as u16;
    let ext_data_len = (sni_hostname.len() + 7) as u16;
    let extensions_len = ext_data_len + 4;
    let client_hello_body_len = 2 + 32 + 1 + 2 + 1 + 2 + extensions_len;
    let handshake_len = client_hello_body_len + 4;
    let mut hello = Vec::with_capacity(handshake_len as usize + 5);
    hello.push(0x16);
    hello.extend_from_slice(&[0x03, 0x01]);
    hello.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    hello.push(0x01);
    hello.push(0x00);
    hello.extend_from_slice(&(client_hello_body_len as u16).to_be_bytes());
    hello.extend_from_slice(&[0x03, 0x03]);
    hello.extend_from_slice(&[0u8; 32]);
    hello.push(0x00);
    hello.extend_from_slice(&[0x00, 0x02]);
    hello.extend_from_slice(&[0x00, 0x2f]);
    hello.push(0x01);
    hello.push(0x00);
    hello.extend_from_slice(&extensions_len.to_be_bytes());
    hello.extend_from_slice(&[0x00, 0x00]);
    hello.extend_from_slice(&ext_data_len.to_be_bytes());
    hello.extend_from_slice(&sni_list_len.to_be_bytes());
    hello.push(0x00);
    hello.extend_from_slice(&(sni_hostname.len() as u16).to_be_bytes());
    hello.extend_from_slice(sni_hostname);
    hello
}

#[tokio::test]
async fn test_5000_concurrent_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let total: u64 = 5000;
    let accepted = Arc::new(AtomicU64::new(0));
    let accepted_clone = accepted.clone();

    // Server: accept, read payload, echo back
    let server = tokio::spawn(async move {
        let mut handlers = JoinSet::new();
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => break,
            };
            let n = accepted_clone.fetch_add(1, Ordering::Relaxed);
            handlers.spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]).await;
                }
            });
            if n + 1 >= total {
                break;
            }
        }
        while handlers.join_next().await.is_some() {}
    });

    // Clients
    let success = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let hello = Arc::new(build_client_hello("stress.example.com"));
    let mut clients = JoinSet::new();

    for _ in 0..total {
        let s = success.clone();
        let f = failed.clone();
        let h = hello.clone();
        clients.spawn(async move {
            match TcpStream::connect(addr).await {
                Ok(mut stream) => {
                    if stream.write_all(&h).await.is_ok() {
                        let mut buf = vec![0u8; 4096];
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            stream.read(&mut buf),
                        )
                        .await
                        {
                            Ok(Ok(n)) if n > 0 => {
                                s.fetch_add(1, Ordering::Relaxed);
                            }
                            _ => {
                                f.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    } else {
                        f.fetch_add(1, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    f.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
    }

    while clients.join_next().await.is_some() {}
    let _ = server.await;

    let s = success.load(Ordering::Relaxed);
    let f = failed.load(Ordering::Relaxed);
    let a = accepted.load(Ordering::Relaxed);
    eprintln!("target={total} accepted={a} success={s} failed={f}");
    // Allow up to 5% failure due to timing
    assert!(
        s >= total * 95 / 100,
        "success rate too low: {s}/{total} (failed={f})"
    );
}
