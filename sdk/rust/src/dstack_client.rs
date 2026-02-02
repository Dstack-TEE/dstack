// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 tuddman <tuddman@users.noreply.github.com>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use hex::encode as hex_encode;
use http_client_unix_domain_socket::{ClientUnix, Method};
use reqwest::Client;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Value};
use std::env;

pub use dstack_sdk_types::dstack::*;

// Internal request structs for hex encoding
#[derive(Debug, Serialize)]
struct SignRequest<'a> {
    algorithm: &'a str,
    data: String,
}

#[derive(Debug, Serialize)]
struct VerifyRequest<'a> {
    algorithm: &'a str,
    data: String,
    signature: String,
    public_key: String,
}

fn get_endpoint(endpoint: Option<&str>) -> String {
    if let Some(e) = endpoint {
        return e.to_string();
    }
    if let Ok(sim_endpoint) = env::var("DSTACK_SIMULATOR_ENDPOINT") {
        return sim_endpoint;
    }
    // Try paths in order: legacy paths first, then namespaced paths
    const SOCKET_PATHS: &[&str] = &[
        "/var/run/dstack.sock",
        "/run/dstack.sock",
        "/var/run/dstack/dstack.sock",
        "/run/dstack/dstack.sock",
    ];
    for path in SOCKET_PATHS {
        if std::path::Path::new(path).exists() {
            return path.to_string();
        }
    }
    // Default to new path even if not exists (will fail with clear error)
    SOCKET_PATHS[0].to_string()
}

#[derive(Debug)]
pub enum ClientKind {
    Http,
    Unix,
}

pub trait BaseClient {}

/// The main client for interacting with the dstack service
pub struct DstackClient {
    /// The base URL for HTTP requests
    base_url: String,
    /// The endpoint for Unix domain socket communication
    endpoint: String,
    /// The type of client (HTTP or Unix domain socket)
    client: ClientKind,
}

impl BaseClient for DstackClient {}

impl DstackClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        let endpoint = get_endpoint(endpoint);
        let (base_url, client) = match endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), ClientKind::Http)
            }
            _ => ("http://localhost".to_string(), ClientKind::Unix),
        };

        DstackClient {
            base_url,
            endpoint,
            client,
        }
    }

    async fn send_rpc_request<S: Serialize, D: DeserializeOwned>(
        &self,
        path: &str,
        payload: &S,
    ) -> anyhow::Result<D> {
        match &self.client {
            ClientKind::Http => {
                let client = Client::new();
                let url = format!(
                    "{}/{}",
                    self.base_url.trim_end_matches('/'),
                    path.trim_start_matches('/')
                );
                let res = client
                    .post(&url)
                    .json(payload)
                    .header("Content-Type", "application/json")
                    .send()
                    .await?
                    .error_for_status()?;
                Ok(res.json().await?)
            }
            ClientKind::Unix => {
                let mut unix_client = ClientUnix::try_new(&self.endpoint).await?;
                let res = unix_client
                    .send_request_json::<_, _, Value>(
                        path,
                        Method::POST,
                        &[("Content-Type", "application/json"), ("Host", "dstack")],
                        Some(&payload),
                    )
                    .await?;
                Ok(res.1)
            }
        }
    }

    pub async fn get_key(
        &self,
        path: Option<String>,
        purpose: Option<String>,
    ) -> Result<GetKeyResponse> {
        let data = json!({
            "path": path.unwrap_or_default(),
            "purpose": purpose.unwrap_or_default(),
            "algorithm": "secp256k1", // Default or specify as needed
        });
        let response = self.send_rpc_request("/GetKey", &data).await?;
        let response = serde_json::from_value::<GetKeyResponse>(response)?;

        Ok(response)
    }

    pub async fn get_quote(&self, report_data: Vec<u8>) -> Result<GetQuoteResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            anyhow::bail!("Invalid report data length")
        }
        let hex_data = hex_encode(report_data);
        let data = json!({ "report_data": hex_data });
        let response = self.send_rpc_request("/GetQuote", &data).await?;
        let response = serde_json::from_value::<GetQuoteResponse>(response)?;

        Ok(response)
    }

    pub async fn attest(&self, report_data: Vec<u8>) -> Result<AttestResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            anyhow::bail!("Invalid report data length")
        }
        let hex_data = hex_encode(report_data);
        let data = json!({ "report_data": hex_data });
        let response = self.send_rpc_request("/Attest", &data).await?;
        let response = serde_json::from_value::<AttestResponse>(response)?;

        Ok(response)
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let response = self.send_rpc_request("/Info", &json!({})).await?;
        Ok(InfoResponse::validated_from_value(response)?)
    }

    pub async fn emit_event(&self, event: String, payload: Vec<u8>) -> Result<()> {
        if event.is_empty() {
            anyhow::bail!("Event name cannot be empty")
        }
        let hex_payload = hex_encode(payload);
        let data = json!({ "event": event, "payload": hex_payload });
        self.send_rpc_request::<_, ()>("/EmitEvent", &data).await?;
        Ok(())
    }

    pub async fn get_tls_key(&self, tls_key_config: TlsKeyConfig) -> Result<GetTlsKeyResponse> {
        let response = self.send_rpc_request("/GetTlsKey", &tls_key_config).await?;
        let response = serde_json::from_value::<GetTlsKeyResponse>(response)?;

        Ok(response)
    }

    /// Signs a payload using a derived key.
    pub async fn sign(&self, algorithm: &str, data: Vec<u8>) -> Result<SignResponse> {
        let payload = SignRequest {
            algorithm,
            data: hex_encode(data),
        };
        let response = self.send_rpc_request("/Sign", &payload).await?;
        let response = serde_json::from_value::<SignResponse>(response)?;
        Ok(response)
    }

    /// Verifies a payload signature.
    pub async fn verify(
        &self,
        algorithm: &str,
        data: Vec<u8>,
        signature: Vec<u8>,
        public_key: Vec<u8>,
    ) -> Result<VerifyResponse> {
        let payload = VerifyRequest {
            algorithm,
            data: hex_encode(data),
            signature: hex_encode(signature),
            public_key: hex_encode(public_key),
        };
        let response = self.send_rpc_request("/Verify", &payload).await?;
        let response = serde_json::from_value::<VerifyResponse>(response)?;
        Ok(response)
    }
}
