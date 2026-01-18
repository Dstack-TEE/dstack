// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Custom HTTP client for instant_acme that supports both HTTP and HTTPS.

use bytes::Bytes;
use tracing;
use http::Request;
use http_body_util::{BodyExt, Full};
use instant_acme::{BytesResponse, HttpClient};
use reqwest::Client;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;

/// A HTTP client that supports both HTTP and HTTPS connections.
/// This is needed because the default instant_acme client only supports HTTPS.
#[derive(Clone)]
pub struct ReqwestHttpClient {
    client: Client,
}

impl ReqwestHttpClient {
    /// Create a new HTTP client.
    pub fn new() -> Self {
        let client = Client::builder()
            .user_agent("dstack-certbot/0.1")
            .build()
            .expect("failed to build reqwest client");
        Self { client }
    }
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient for ReqwestHttpClient {
    fn request(
        &self,
        req: Request<Full<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.client.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let uri = parts.uri.to_string();
            let method = parts.method.clone();
            let body_bytes = body
                .collect()
                .await
                .map_err(|e| instant_acme::Error::Other(Box::new(e) as Box<dyn StdError + Send + Sync>))?
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

            let response = builder.body(body_bytes.to_vec()).send().await.map_err(|e| {
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
