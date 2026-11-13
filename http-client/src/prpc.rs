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

/// A pRPC server answered with a status other than 200.
///
/// Carried in the returned `anyhow::Error`, so callers can tell, say, a method
/// the server does not implement from other failures without parsing text.
#[derive(Debug)]
pub struct StatusError {
    pub path: String,
    pub status: u16,
    /// The reason the server gave, if it gave one.
    pub message: Option<String>,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            path,
            status,
            message,
        } = self;
        match message {
            Some(message) => write!(f, "{path} failed with status {status}: {message}"),
            None => write!(f, "Invalid status code: {status}, path={path}"),
        }
    }
}

impl std::error::Error for StatusError {}

/// The reason a pRPC server gave for failing a JSON request, if it gave one.
fn server_error_message(body: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct ErrorBody {
        error: String,
    }
    serde_json::from_slice::<ErrorBody>(body)
        .ok()
        .map(|body| body.error)
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
        let (status, body) = super::http_request("POST", &self.base_url, &path, &body).await?;
        if status != 200 {
            return Err(StatusError {
                path,
                status,
                message: server_error_message(&body),
            }
            .into());
        }
        let response = serde_json::from_slice(normalize_json_response_body(&body))
            .context("Failed to deserialize response")?;
        Ok(response)
    }
}
