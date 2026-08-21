// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use prpc::{
    client::{Error, RequestClient},
    serde_json, Message,
};
use serde::{de::DeserializeOwned, Serialize};
use std::time::Duration;

pub struct PrpcClient {
    base_url: String,
    path_append: String,
    auth_token: Option<String>,
    request_timeout: Option<Duration>,
}

impl PrpcClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            path_append: String::new(),
            auth_token: None,
            request_timeout: None,
        }
    }

    pub fn new_unix(socket_path: String, mut path: String) -> Self {
        if !path.ends_with('/') {
            path.push('/');
        }
        Self {
            base_url: format!("unix:{socket_path}"),
            path_append: path,
            auth_token: None,
            request_timeout: None,
        }
    }

    /// Send `Authorization: Bearer <token>` with every request.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.auth_token = (!token.is_empty()).then_some(token);
        self
    }

    /// Bound the complete request, including connection establishment, request
    /// upload, response headers, and response body.
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }
}

fn normalize_json_response_body(body: &[u8]) -> &[u8] {
    if body.is_empty() {
        b"null"
    } else {
        body
    }
}

impl RequestClient for PrpcClient {
    async fn request<T, R>(&self, path: &str, body: T) -> Result<R, Error>
    where
        T: Message + Serialize,
        R: Message + DeserializeOwned,
    {
        let body = serde_json::to_vec(&body).context("Failed to serialize body")?;
        let path = format!("{}{path}?json", self.path_append);
        let auth_header;
        let mut headers: Vec<(&str, &str)> = Vec::new();
        if let Some(token) = &self.auth_token {
            auth_header = format!("Bearer {token}");
            headers.push(("Authorization", auth_header.as_str()));
        }
        let request =
            super::http_request_with_headers("POST", &self.base_url, &path, &body, &headers);
        let (status, body) = match self.request_timeout {
            Some(timeout) => tokio::time::timeout(timeout, request)
                .await
                .context("pRPC request timed out")??,
            None => request.await?,
        };
        if status != 200 {
            anyhow::bail!("Invalid status code: {status}, path={path}");
        }
        let response = serde_json::from_slice(normalize_json_response_body(&body))
            .context("Failed to deserialize response")?;
        Ok(response)
    }
}

#[cfg(test)]
mod response_tests {
    use super::{normalize_json_response_body, serde_json, PrpcClient};
    use prpc::client::RequestClient;
    use std::{future::pending, time::Duration};
    use tokio::net::TcpListener;

    #[derive(Clone, PartialEq, prpc::Message, serde::Serialize, serde::Deserialize)]
    struct Empty {}

    #[test]
    fn empty_json_response_decodes_as_unit() {
        let value: () = serde_json::from_slice(normalize_json_response_body(b""))
            .expect("empty response should decode as unit");
        assert_eq!(value, ());
    }

    #[test]
    fn non_empty_json_response_is_unchanged() {
        assert_eq!(
            normalize_json_response_body(br#"{"value":1}"#),
            br#"{"value":1}"#
        );
    }

    #[tokio::test]
    async fn request_timeout_covers_waiting_for_the_response() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            pending::<()>().await;
        });
        let client = PrpcClient::new(format!("http://{addr}"))
            .with_request_timeout(Duration::from_millis(50));

        let error = client
            .request::<Empty, Empty>("Test.Hang", Empty {})
            .await
            .unwrap_err();

        assert!(error.to_string().contains("pRPC request timed out"));
        server.abort();
    }
}
