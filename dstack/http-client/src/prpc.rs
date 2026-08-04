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
}

impl PrpcClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            path_append: String::new(),
            auth_token: None,
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
        }
    }

    /// Send `Authorization: Bearer <token>` with every request.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        let token = token.into();
        self.auth_token = (!token.is_empty()).then_some(token);
        self
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
        let (status, body) =
            super::http_request_with_headers("POST", &self.base_url, &path, &body, &headers)
                .await?;
        if status != 200 {
            anyhow::bail!("Invalid status code: {status}, path={path}");
        }
        // Not serde_json::from_slice: a unit response arrives as an empty body, which
        // is not valid JSON. Every RequestClient impl has to decode through this.
        let response =
            prpc::codec::decode_json_from_slice(&body).context("Failed to deserialize response")?;
        Ok(response)
    }
}
