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
}

impl PrpcClient {
    pub fn new(base_url: String) -> Self {
        Self {
            base_url,
            path_append: String::new(),
        }
    }

    pub fn new_unix(socket_path: String, mut path: String) -> Self {
        if !path.ends_with('/') {
            path.push('/');
        }
        Self {
            base_url: format!("unix:{socket_path}"),
            path_append: path,
        }
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
        let (status, body) = super::http_request("POST", &self.base_url, &path, &body).await?;
        if status != 200 {
            anyhow::bail!("Invalid status code: {status}, path={path}");
        }
        let response = serde_json::from_slice(&body).context("Failed to deserialize response")?;
        Ok(response)
    }
}
