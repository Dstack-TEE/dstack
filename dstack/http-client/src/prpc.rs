// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use prpc::{
    client::{Error, RequestClient},
    serde_json, Message,
};
use serde::{de::DeserializeOwned, Serialize};

pub struct PrpcClient {
    base_url: String,
    path_append: String,
    auth_token: Option<String>,
    max_response_bytes: Option<usize>,
}

impl PrpcClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            path_append: String::new(),
            auth_token: None,
            max_response_bytes: None,
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
            max_response_bytes: None,
        }
    }

    /// Refuse a response larger than `max_bytes`.
    ///
    /// For callers whose peer is not trusted -- anything talking to a CVM's
    /// guest agent. Unbounded otherwise, because most peers here are local or
    /// operator-run and return as much as the caller asked for.
    pub fn with_max_response_bytes(mut self, max_bytes: usize) -> Self {
        self.max_response_bytes = Some(max_bytes);
        self
    }

    /// Send `Authorization: Bearer <token>` with every request.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.auth_token = (!token.is_empty()).then_some(token);
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
        let (status, body) = super::http_request_bounded(
            "POST",
            &self.base_url,
            &path,
            &body,
            &headers,
            self.max_response_bytes,
        )
        .await?;
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
    use super::{normalize_json_response_body, serde_json};

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
}
