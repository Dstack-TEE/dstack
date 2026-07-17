// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! HTTP surface: the two endpoints NVIDIA's attestation SDK talks to, plus
//! health/info endpoints for operators.

use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use rocket::figment::Figment;
use rocket::http::{ContentType, Status};
use rocket::response::{self, Responder, Response};
use rocket::{get, post, routes, Build, Rocket, State};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::cache::{Cache, CacheEntry};
use crate::der;

/// How long before nominal expiry an entry stops being served and starts
/// being refreshed. Covers clock skew between proxy and guests plus the
/// guest-side validity check.
const SERVING_SKEW_SECS: i64 = 300;
/// Matches the SDK's fallback (NvHttpOcspClient::DEFAULT_NEXT_UPDATE_TTL_SECONDS)
/// when a response carries no nextUpdate.
const DEFAULT_OCSP_TTL_SECS: i64 = 3600;
const OCSP_REQUEST_TYPE: &str = "application/ocsp-request";
const OCSP_RESPONSE_TYPE: &str = "application/ocsp-response";

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub upstream_ocsp_url: String,
    pub upstream_rim_url: String,
    pub cache_dir: String,
    /// RIM documents are re-fetched after this long.
    #[serde(with = "serde_duration")]
    pub rim_ttl: Duration,
    /// A stale RIM document is served (when the upstream cannot provide a
    /// fresh copy) for this long after `rim_ttl` elapsed.
    #[serde(with = "serde_duration")]
    pub rim_max_stale: Duration,
    /// Upper bound on OCSP caching, applied on top of the response's own
    /// nextUpdate.
    #[serde(with = "serde_duration")]
    pub ocsp_max_ttl: Duration,
    /// Entries expiring within this window are refreshed in the background.
    #[serde(with = "serde_duration")]
    pub refresh_margin: Duration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream_ocsp_url: "https://ocsp.ndis.nvidia.com".into(),
            upstream_rim_url: "https://rim.attestation.nvidia.com".into(),
            cache_dir: "/var/lib/dstack/gpu-attest-proxy".into(),
            rim_ttl: Duration::from_secs(24 * 3600),
            rim_max_stale: Duration::from_secs(7 * 24 * 3600),
            ocsp_max_ttl: Duration::from_secs(7 * 24 * 3600),
            refresh_margin: Duration::from_secs(24 * 3600),
        }
    }
}

pub struct ProxyState {
    pub config: ProxyConfig,
    pub cache: Cache,
    pub http: reqwest::Client,
}

struct RawResponse {
    status: Status,
    content_type: ContentType,
    body: Vec<u8>,
}

impl<'r> Responder<'r, 'static> for RawResponse {
    fn respond_to(self, _request: &'r rocket::Request<'_>) -> response::Result<'static> {
        Response::build()
            .status(self.status)
            .header(self.content_type)
            .sized_body(self.body.len(), Cursor::new(self.body))
            .ok()
    }
}

fn plain(status: Status, text: &'static str) -> RawResponse {
    RawResponse {
        status,
        content_type: ContentType::Plain,
        body: text.as_bytes().to_vec(),
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn content_type_or(saved: &str, default: &str) -> ContentType {
    saved
        .parse::<ContentType>()
        .unwrap_or_else(|_| default.parse().expect("default content types parse"))
}

/// POST endpoint for OCSP requests. Successful responses are cached keyed by
/// CertID until their nextUpdate; everything else is relayed untouched.
#[post("/ocsp", data = "<body>")]
async fn ocsp(state: &State<Arc<ProxyState>>, body: Vec<u8>) -> RawResponse {
    let cert_ids = match der::ocsp_request_cert_ids(&body) {
        Ok(ids) => ids,
        Err(err) => {
            warn!("rejecting malformed OCSP request: {err:#}");
            return plain(Status::BadRequest, "malformed OCSP request");
        }
    };
    // NVIDIA's SDK queries one certificate per request.
    let key = hex::encode(&cert_ids[0]);
    let now = unix_now();
    if let Some(entry) = state.cache.get("ocsp", &key) {
        if entry.expires_at > now + SERVING_SKEW_SECS {
            debug!("OCSP cache hit for {key}");
            return RawResponse {
                status: Status::Ok,
                content_type: content_type_or(&entry.content_type, OCSP_RESPONSE_TYPE),
                body: entry.body,
            };
        }
    }
    match fetch_and_cache_ocsp(state, &body, &key, &cert_ids[0]).await {
        Ok((status, content_type, upstream_body)) => RawResponse {
            status,
            content_type,
            body: upstream_body,
        },
        Err(err) => {
            warn!("OCSP upstream request failed: {err:#}");
            plain(Status::BadGateway, "OCSP upstream unavailable")
        }
    }
}

/// Relay one OCSP request upstream, caching successful, parseable responses.
/// Errors mean the upstream could not be reached at all; HTTP error statuses
/// are relayed (and deliberately not cached).
async fn fetch_and_cache_ocsp(
    state: &ProxyState,
    request_body: &[u8],
    key: &str,
    cert_id: &[u8],
) -> Result<(Status, ContentType, Vec<u8>)> {
    let resp = state
        .http
        .post(&state.config.upstream_ocsp_url)
        .header(reqwest::header::CONTENT_TYPE, OCSP_REQUEST_TYPE)
        .header(reqwest::header::ACCEPT, OCSP_RESPONSE_TYPE)
        .body(request_body.to_vec())
        .send()
        .await
        .context("OCSP upstream POST failed")?;
    let status = Status::from_code(resp.status().as_u16()).unwrap_or(Status::BadGateway);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<ContentType>().ok())
        .unwrap_or(ContentType::Binary);
    let body = resp
        .bytes()
        .await
        .context("failed to read OCSP upstream body")?;
    if status == Status::Ok {
        let validity = der::ocsp_response_validity(&body, cert_id);
        if let Ok(Some((this_update, next_update))) = validity {
            let now = unix_now();
            let nominal = next_update.unwrap_or(this_update + DEFAULT_OCSP_TTL_SECS);
            let expires_at = nominal.min(now + state.config.ocsp_max_ttl.as_secs() as i64);
            state.cache.put(CacheEntry {
                kind: "ocsp".into(),
                key: key.to_string(),
                content_type: OCSP_RESPONSE_TYPE.into(),
                body: body.to_vec(),
                refresh_body: Some(request_body.to_vec()),
                fetched_at: now,
                expires_at,
            });
        }
    }
    Ok((status, content_type, body.to_vec()))
}

/// GET endpoint mirroring NVIDIA's RIM service path layout, so the proxy base
/// URL can be handed to the SDK as-is (`{base}/v1/rim/{rim_id}`). RIM
/// documents are signed and version-pinned, so staleness is far less
/// sensitive than OCSP: fresh entries are served directly, and on upstream
/// failure a stale entry is served within `rim_max_stale`.
#[get("/v1/rim/<rim_id>")]
async fn rim(state: &State<Arc<ProxyState>>, rim_id: &str) -> RawResponse {
    if !valid_rim_id(rim_id) {
        return plain(Status::BadRequest, "invalid RIM id");
    }
    let now = unix_now();
    let cached = state.cache.get("rim", rim_id);
    if let Some(entry) = &cached {
        if entry.is_fresh(now) {
            debug!("RIM cache hit for {rim_id}");
            return RawResponse {
                status: Status::Ok,
                content_type: content_type_or(&entry.content_type, "application/xml"),
                body: entry.body.clone(),
            };
        }
    }
    match fetch_and_cache_rim(state, rim_id).await {
        Ok((status, content_type, body)) => RawResponse {
            status,
            content_type,
            body,
        },
        Err(err) => {
            warn!("RIM upstream request failed for {rim_id}: {err:#}");
            if let Some(entry) = cached {
                if entry.is_usable_stale(now, state.config.rim_max_stale.as_secs()) {
                    warn!(
                        "serving stale RIM {rim_id} (fetched at {})",
                        entry.fetched_at
                    );
                    return RawResponse {
                        status: Status::Ok,
                        content_type: content_type_or(&entry.content_type, "application/xml"),
                        body: entry.body,
                    };
                }
            }
            plain(
                Status::BadGateway,
                "RIM upstream unavailable and no usable cache",
            )
        }
    }
}

fn valid_rim_id(rim_id: &str) -> bool {
    !rim_id.is_empty()
        && rim_id.len() <= 256
        && rim_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'='))
}

async fn fetch_and_cache_rim(
    state: &ProxyState,
    rim_id: &str,
) -> Result<(Status, ContentType, Vec<u8>)> {
    let url = format!(
        "{}/v1/rim/{rim_id}",
        state.config.upstream_rim_url.trim_end_matches('/')
    );
    let resp = state
        .http
        .get(&url)
        .send()
        .await
        .context("RIM upstream GET failed")?;
    let status = Status::from_code(resp.status().as_u16()).unwrap_or(Status::BadGateway);
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<ContentType>().ok())
        .unwrap_or(ContentType::XML);
    let body = resp
        .bytes()
        .await
        .context("failed to read RIM upstream body")?;
    if status == Status::Ok {
        let now = unix_now();
        state.cache.put(CacheEntry {
            kind: "rim".into(),
            key: rim_id.into(),
            content_type: content_type.to_string(),
            body: body.to_vec(),
            refresh_body: None,
            fetched_at: now,
            expires_at: now + state.config.rim_ttl.as_secs() as i64,
        });
    }
    Ok((status, content_type, body.to_vec()))
}

#[get("/health")]
fn health() -> &'static str {
    "ok"
}

#[get("/info")]
fn info(state: &State<Arc<ProxyState>>) -> String {
    let (fresh, stale) = state.cache.stats();
    format!("cache entries: {fresh} fresh, {stale} stale\n")
}

/// Refresh entries nearing expiry so a warm cache rides through upstream
/// outages with close to a full validity window. Failures are retried on the
/// next tick; the existing entry keeps serving until it expires.
pub async fn refresh_loop(state: Arc<ProxyState>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(600));
    loop {
        ticker.tick().await;
        let margin = state.config.refresh_margin.as_secs();
        for entry in state.cache.expiring_soon(margin) {
            let result = match entry.kind.as_str() {
                "ocsp" => match &entry.refresh_body {
                    Some(body) => {
                        let key = entry.key.clone();
                        match hex::decode(&key) {
                            Ok(cert_id) => fetch_and_cache_ocsp(&state, body, &key, &cert_id).await,
                            Err(_) => continue,
                        }
                    }
                    None => continue,
                },
                "rim" => fetch_and_cache_rim(&state, &entry.key).await,
                _ => continue,
            };
            match result {
                Ok((status, _, _)) if status == Status::Ok => {
                    debug!("refreshed {} {}", entry.kind, entry.key)
                }
                Ok((status, _, _)) => {
                    debug!(
                        "refresh of {} {} got HTTP {}",
                        entry.kind, entry.key, status.code
                    )
                }
                Err(err) => debug!("refresh of {} {} failed: {err:#}", entry.kind, entry.key),
            }
        }
    }
}

pub fn rocket(figment: Figment, state: Arc<ProxyState>) -> Rocket<Build> {
    rocket::custom(figment)
        .manage(state)
        .mount("/", routes![ocsp, rim, health, info])
}
