use crate::dstack_client::BaseClient;
use anyhow::{bail, Result};
use hex::encode as hex_encode;
use http_client_unix_domain_socket::{ClientUnix, Method};
use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;

pub use dstack_sdk_types::tappd::*;

fn get_tappd_endpoint(endpoint: Option<&str>) -> String {
    if let Some(e) = endpoint {
        return e.to_string();
    }
    if let Ok(sim_endpoint) = env::var("TAPPD_SIMULATOR_ENDPOINT") {
        return sim_endpoint;
    }
    "/var/run/tappd.sock".to_string()
}

#[derive(Debug)]
pub enum TappdClientKind {
    Http,
    Unix,
}

/// The main client for interacting with the legacy Tappd service
pub struct TappdClient {
    /// The base URL for HTTP requests
    base_url: String,
    /// The endpoint for Unix domain socket communication
    endpoint: String,
    /// The type of client (HTTP or Unix domain socket)
    client: TappdClientKind,
}

impl BaseClient for TappdClient {}

impl TappdClient {
    pub fn new(endpoint: Option<&str>) -> Self {
        let endpoint = get_tappd_endpoint(endpoint);
        let (base_url, client) = match endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), TappdClientKind::Http)
            }
            _ => ("http://localhost".to_string(), TappdClientKind::Unix),
        };

        TappdClient {
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
            TappdClientKind::Http => {
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
            TappdClientKind::Unix => {
                let mut unix_client = ClientUnix::try_new(&self.endpoint).await?;
                let res = unix_client
                    .send_request_json::<_, _, Value>(
                        path,
                        Method::POST,
                        &[("Content-Type", "application/json")],
                        Some(&payload),
                    )
                    .await?;
                Ok(res.1)
            }
        }
    }

    /// Derives a key from the Tappd service using the path as both path and subject
    pub async fn derive_key(&self, path: &str) -> Result<DeriveKeyResponse> {
        self.derive_key_with_subject_and_alt_names(path, Some(path), None)
            .await
    }

    /// Derives a key from the Tappd service with a specific subject
    pub async fn derive_key_with_subject(
        &self,
        path: &str,
        subject: &str,
    ) -> Result<DeriveKeyResponse> {
        self.derive_key_with_subject_and_alt_names(path, Some(subject), None)
            .await
    }

    /// Derives a key from the Tappd service with full configuration
    pub async fn derive_key_with_subject_and_alt_names(
        &self,
        path: &str,
        subject: Option<&str>,
        alt_names: Option<Vec<String>>,
    ) -> Result<DeriveKeyResponse> {
        let subject = subject.unwrap_or(path);

        let mut payload = json!({
            "path": path,
            "subject": subject,
        });

        if let Some(alt_names) = alt_names {
            if !alt_names.is_empty() {
                payload["alt_names"] = json!(alt_names);
            }
        }

        let response = self
            .send_rpc_request("/prpc/Tappd.DeriveKey", &payload)
            .await?;
        Ok(response)
    }

    /// Sends a raw quote request with 64 bytes of report data
    pub async fn get_quote(&self, report_data: Vec<u8>) -> Result<TdxQuoteResponse> {
        if report_data.len() != 64 {
            bail!("Report data must be exactly 64 bytes for raw quote");
        }

        let payload = json!({
            "report_data": hex_encode(report_data),
        });

        let response = self
            .send_rpc_request("/prpc/Tappd.RawQuote", &payload)
            .await?;
        Ok(response)
    }

    /// Retrieves information about the Tappd instance
    pub async fn info(&self) -> Result<TappdInfoResponse> {
        #[derive(Deserialize)]
        struct RawInfoResponse {
            app_id: String,
            instance_id: String,
            app_cert: String,
            tcb_info: String,
            app_name: String,
        }

        let raw_response: RawInfoResponse = self
            .send_rpc_request("/prpc/Tappd.Info", &json!({}))
            .await?;

        let tcb_info: TappdTcbInfo = serde_json::from_str(&raw_response.tcb_info)?;

        Ok(TappdInfoResponse {
            app_id: raw_response.app_id,
            instance_id: raw_response.instance_id,
            app_cert: raw_response.app_cert,
            tcb_info,
            app_name: raw_response.app_name,
        })
    }
}
