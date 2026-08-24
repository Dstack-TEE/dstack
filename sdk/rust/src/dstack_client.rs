// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
// SPDX-FileCopyrightText: © 2025 tuddman <tuddman@users.noreply.github.com>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use hex::encode as hex_encode;
use http_client_unix_domain_socket::{Body, ClientUnix, ErrorAndResponse, Method};
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

pub(crate) fn get_endpoint(endpoint: Option<&str>) -> String {
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

/// How much of a server response an error may quote.
///
/// An agent with no route for the path answers with an HTML page, and pasting a
/// whole page into an error helps nobody.
const MAX_ERROR_BODY: usize = 512;

fn truncate(text: &str) -> String {
    match text.char_indices().nth(MAX_ERROR_BODY) {
        Some((end, _)) => format!("{}...", &text[..end]),
        None => text.to_string(),
    }
}

/// What the server said, as far as it can be made out.
///
/// A prpc handler that refuses answers `{"error": "..."}` with a 4xx, and that
/// field is the only part worth showing. A request that never reached a handler
/// -- a `/v1` call against a pre-0.6 agent -- comes back as an HTML error page
/// instead, and then the raw body is the only clue there is.
fn server_error_text(body: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(body) else {
        return "(non-utf8 response body)".to_string();
    };
    let text = text.trim();
    if text.is_empty() {
        return "(empty response body)".to_string();
    }
    if let Ok(Value::Object(fields)) = serde_json::from_str::<Value>(text) {
        if let Some(Value::String(message)) = fields.get("error") {
            return truncate(message);
        }
    }
    truncate(text)
}

/// Turn a non-2xx response into an error naming both the status and the reason.
pub(crate) fn http_error(status: u16, body: &[u8]) -> anyhow::Error {
    anyhow!("HTTP {status}: {}", server_error_text(body))
}

/// POST `payload` as JSON over TCP and return the raw response body.
pub(crate) async fn http_post<S: Serialize>(
    base_url: &str,
    path: &str,
    payload: &S,
) -> Result<Vec<u8>> {
    let url = format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        path.trim_start_matches('/')
    );
    let res = Client::new()
        .post(&url)
        .json(payload)
        .header("Content-Type", "application/json")
        .send()
        .await?;
    // Deliberately not `error_for_status()`: that discards the response body,
    // which is exactly where the agent puts the reason it refused.
    let status = res.status();
    let body = res.bytes().await?;
    if !status.is_success() {
        return Err(http_error(status.as_u16(), &body));
    }
    Ok(body.to_vec())
}

/// POST `payload` as JSON over the guest-agent socket and return the raw body.
pub(crate) async fn unix_post<S: Serialize>(
    endpoint: &str,
    path: &str,
    payload: &S,
) -> Result<Vec<u8>> {
    let mut unix_client = ClientUnix::try_new(endpoint).await?;
    // `send_request` rather than `send_request_json`: the JSON helper insists on
    // deserializing the *error* body as well, so an HTML 404 from an agent that
    // does not serve this path surfaces as a JSON parse failure rather than as
    // the status that explains it.
    let request = Body::from(serde_json::to_vec(payload)?);
    match unix_client
        .send_request(
            path,
            Method::POST,
            &[("Content-Type", "application/json"), ("Host", "dstack")],
            Some(request),
        )
        .await
    {
        Ok((_status, body)) => Ok(body),
        Err(ErrorAndResponse::ResponseUnsuccessful(status, body)) => {
            Err(http_error(status.as_u16(), &body))
        }
        Err(ErrorAndResponse::InternalError(err)) => Err(err.into()),
    }
}

/// Client for the frozen v0 guest-agent surface.
///
/// **Legacy.** New code should use [`crate::dstack_client_v1::DstackClientV1`],
/// which is what the unsuffixed `DstackClient` now names. This client stays for
/// applications that need the v0.5.11 surface -- `sign`, `verify`,
/// `emit_event`, `get_quote` -- which v1 does not carry.
///
/// Speaks the unversioned paths (`/GetKey`), which the agent also serves at
/// `/v0`. That surface is closed at exactly what dstack v0.5.11 shipped: it
/// gains no methods and changes no behaviour, so this client keeps working
/// against a 0.6 agent unchanged.
///
/// For anything new, use [`crate::dstack_client_v1::DstackClientV1`]. Note that
/// **v1 derives different key material than v0 for the same inputs** -- see
/// `docs/guest-api-v1.md` for the migration.
pub struct DstackClientV0 {
    /// The base URL for HTTP requests
    base_url: String,
    /// The endpoint for Unix domain socket communication
    endpoint: String,
    /// The type of client (HTTP or Unix domain socket)
    client: ClientKind,
}

impl BaseClient for DstackClientV0 {}

impl DstackClientV0 {
    pub fn new(endpoint: Option<&str>) -> Self {
        let endpoint = get_endpoint(endpoint);
        let (base_url, client) = match endpoint {
            ref e if e.starts_with("http://") || e.starts_with("https://") => {
                (e.to_string(), ClientKind::Http)
            }
            _ => ("http://localhost".to_string(), ClientKind::Unix),
        };

        DstackClientV0 {
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
        let body = match &self.client {
            ClientKind::Http => http_post(&self.base_url, path, payload).await?,
            ClientKind::Unix => unix_post(&self.endpoint, path, payload).await?,
        };
        serde_json::from_slice(&body).context("failed to parse the response")
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

    /// Request a TDX quote for the provided report data.
    ///
    /// Needs Intel TDX. Without it the guest agent returns an error, and on GCP
    /// Confidential VMs it answers with the TDX quote alone, leaving out the
    /// vTPM quote GCP's verification also binds. Use [`Self::attest`] in both
    /// cases.
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

    /// Requests a versioned attestation for the given report data.
    ///
    /// No GPU-evidence flag: that field is reserved on this surface and only
    /// `/v1/Attest` honours it.
    pub async fn attest(&self, report_data: Vec<u8>) -> Result<AttestResponse> {
        if report_data.is_empty() || report_data.len() > 64 {
            anyhow::bail!("Invalid report data length")
        }
        let data = json!({ "report_data": hex_encode(report_data) });
        let response = self.send_rpc_request("/Attest", &data).await?;
        Ok(serde_json::from_value::<AttestResponse>(response)?)
    }

    pub async fn info(&self) -> Result<InfoResponse> {
        let response = self.send_rpc_request("/Info", &json!({})).await?;
        Ok(InfoResponse::validated_from_value(response)?)
    }

    /// Query the guest-agent version.
    ///
    /// Returns `Ok(VersionResponse)` on OS >= 0.5.7.
    /// Returns an error on older OS versions that lack the Version RPC.
    pub async fn version(&self) -> Result<VersionResponse> {
        let response = self.send_rpc_request("/Version", &json!({})).await?;
        let response = serde_json::from_value::<VersionResponse>(response)?;
        Ok(response)
    }

    /// Emit a runtime event.
    ///
    /// Always fails against a 0.6 agent: runtime RTMR3 events became
    /// system-owned, and the method is kept only so a caller learns that from
    /// the error rather than from an unexplained failure. The agent's message
    /// is surfaced verbatim.
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

    /// Verifies a payload signature through the agent.
    ///
    /// Part of the v0 surface and kept for callers that already depend on it.
    /// It needs no key material and no attestation, and the answer arrives over
    /// the socket unattested, so a caller gains nothing over checking the
    /// signature itself. v1 has no counterpart; `docs/guest-api-v1.md`
    /// specifies verification for relying parties.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_the_error_field_of_a_prpc_failure() {
        let err = http_error(400, br#"{"error":"algorithm is not supported"}"#);
        assert_eq!(err.to_string(), "HTTP 400: algorithm is not supported");
    }

    #[test]
    fn quotes_the_body_when_it_is_not_a_prpc_failure() {
        // What a pre-0.6 agent answers a `/v1` call with.
        let err = http_error(404, b"<!DOCTYPE html>\n<html>404</html>");
        assert_eq!(
            err.to_string(),
            "HTTP 404: <!DOCTYPE html>\n<html>404</html>"
        );
    }

    #[test]
    fn bounds_the_quoted_body() {
        let err = http_error(500, "x".repeat(MAX_ERROR_BODY * 2).as_bytes());
        // An HTML error page must not become the whole error message.
        assert_eq!(
            err.to_string().len(),
            "HTTP 500: ".len() + MAX_ERROR_BODY + 3
        );
        assert!(err.to_string().ends_with("..."));
    }

    #[test]
    fn names_an_unreadable_body_rather_than_dropping_the_status() {
        assert_eq!(
            http_error(502, b"").to_string(),
            "HTTP 502: (empty response body)"
        );
        assert_eq!(
            http_error(502, &[0xff, 0xfe]).to_string(),
            "HTTP 502: (non-utf8 response body)"
        );
    }
}
