// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Custom HTTP client for instant_acme that supports both HTTP and HTTPS.

use anyhow::{Context, Result};
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Full};
use instant_acme::{BodyWrapper, BytesResponse, HttpClient};
use reqwest::Client;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// How long one call to the ACME directory may take.
///
/// `reqwest`'s async client has no default timeout -- unlike its blocking one,
/// which defaults to 30 s -- so without this a directory that accepts the
/// connection and then says nothing holds the call open indefinitely.
///
/// It matters here because `acme_url` is operator-settable and two callers run
/// under the cluster-wide ACME lock with no outer bound of their own: account
/// registration and credential rotation. An order is already capped by
/// `renew_timeout`; those are not, so a silent directory would park the lock
/// -- and with it every renewal in the cluster -- until the lock's own 600 s
/// expiry, and the task waiting on it forever.
const ACME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn acme_client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .user_agent("dstack-certbot/0.1")
        .timeout(timeout)
        .build()
        .context("failed to build reqwest client")
}

/// A HTTP client that supports both HTTP and HTTPS connections.
/// This is needed because the default instant_acme client only supports HTTPS.
#[derive(Clone)]
pub struct ReqwestHttpClient {
    client: Client,
}

impl ReqwestHttpClient {
    /// Create a new HTTP client.
    pub fn new() -> Result<Self> {
        Self::with_timeout(ACME_REQUEST_TIMEOUT)
    }

    /// Create a new HTTP client bounding each request by `timeout`.
    pub fn with_timeout(timeout: Duration) -> Result<Self> {
        Ok(Self {
            client: acme_client(timeout)?,
        })
    }
}

impl HttpClient for ReqwestHttpClient {
    fn request(
        &self,
        req: Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let uri = parts.uri.to_string();
            let method = parts.method.clone();
            let body_bytes = body
                .collect()
                .await
                .map_err(|e| {
                    instant_acme::Error::Other(Box::new(e) as Box<dyn StdError + Send + Sync>)
                })?
                .to_bytes();

            tracing::debug!(
                target: "certbot::http_client",
                %uri,
                %method,
                request_body_len = body_bytes.len(),
                "sending ACME request"
            );

            let mut builder = client.request(parts.method, uri.clone());
            for (name, value) in &parts.headers {
                builder = builder.header(name, value);
            }

            let response = builder
                .body(body_bytes.to_vec())
                .send()
                .await
                .map_err(|e| {
                    instant_acme::Error::Other(Box::new(e) as Box<dyn StdError + Send + Sync>)
                })?;

            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.map_err(|e| {
                instant_acme::Error::Other(Box::new(e) as Box<dyn StdError + Send + Sync>)
            })?;

            tracing::debug!(
                target: "certbot::http_client",
                %uri,
                %status,
                response_body = %String::from_utf8_lossy(&body),
                "received ACME response"
            );

            let mut http_response = http::Response::builder().status(status);
            for (name, value) in headers {
                if let Some(name) = name {
                    http_response = http_response.header(name, value);
                }
            }
            let http_response = http_response
                .body(Full::new(body))
                .map_err(|e| instant_acme::Error::Other(Box::new(e)))?;

            Ok(BytesResponse::from(http_response))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use instant_acme::BodyWrapper;
    use tokio::net::TcpListener;

    /// `ensure_acme_account` and `rotate_acme_credentials` hold the shared ACME
    /// lock across their directory calls with no timeout of their own, so a
    /// directory that accepts the connection and then answers nothing has to be
    /// given up on here or nowhere.
    #[tokio::test]
    async fn a_directory_that_never_answers_does_not_hold_the_acme_lock() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _accepted = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let client = ReqwestHttpClient::with_timeout(Duration::from_millis(200)).unwrap();
        let request = Request::builder()
            .method("POST")
            .uri(format!("http://{address}/acme/new-acct"))
            .body(BodyWrapper::from(b"{}".to_vec()))
            .unwrap();
        let out = tokio::time::timeout(Duration::from_secs(10), client.request(request)).await;
        let out = out.expect("a silent directory must not hold the call open");
        assert!(
            out.is_err(),
            "a silent directory must not read as an answer"
        );
    }
}
