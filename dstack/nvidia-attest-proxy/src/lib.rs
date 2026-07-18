// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

mod cache;
mod ocsp;

use std::{
    convert::Infallible,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::Bytes;
use cache::{CacheEntry, CacheStore, EntrySource};
use dashmap::DashMap;
use futures::StreamExt;
use http::{
    header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    HeaderValue, Method, Request, Response, StatusCode,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::Mutex, time::MissedTickBehavior};
use tracing::{debug, info, warn};
use url::Url;

const MAX_OCSP_REQUEST_BYTES: usize = 64 * 1024;
const MAX_OCSP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RIM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const OCSP_CONTENT_TYPE: &str = "application/ocsp-response";
const JSON_CONTENT_TYPE: &str = "application/json";
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// Concurrent upstream requests per background refresh sweep.
const REFRESH_CONCURRENCY: usize = 4;

#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub cache_dir: PathBuf,
    pub ocsp_url: Url,
    pub rim_url: Url,
    pub service_key: Option<String>,
    pub request_timeout: Duration,
    pub connect_timeout: Duration,
    pub ocsp_max_ttl: Duration,
    pub ocsp_default_ttl: Duration,
    pub ocsp_refresh_before: Duration,
    pub rim_ttl: Duration,
    /// How long an expired RIM document may still be served when the upstream
    /// cannot provide a fresh copy. RIM documents are signed and
    /// version-addressed, so staleness is an availability trade-off, not a
    /// security one. Zero disables stale serving.
    pub rim_max_stale: Duration,
    /// Interval between background refresh sweeps. Entries past half their
    /// lifetime are renewed so a warm cache rides through upstream outages
    /// with close to a full validity window. Zero disables the refresher.
    pub refresh_interval: Duration,
    pub max_cache_entries_per_kind: usize,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<()> {
        validate_upstream_url("OCSP", &self.ocsp_url)?;
        validate_upstream_url("RIM", &self.rim_url)?;
        for (name, value) in [
            ("request timeout", self.request_timeout),
            ("connect timeout", self.connect_timeout),
            ("OCSP maximum TTL", self.ocsp_max_ttl),
            ("OCSP default TTL", self.ocsp_default_ttl),
            ("OCSP refresh window", self.ocsp_refresh_before),
            ("RIM TTL", self.rim_ttl),
        ] {
            if value.is_zero() {
                bail!("{name} must be greater than zero");
            }
            if value.as_secs() > i64::MAX as u64 {
                bail!("{name} is too large");
            }
        }
        // These two may be zero, meaning the feature is disabled.
        for (name, value) in [
            ("RIM maximum staleness", self.rim_max_stale),
            ("refresh interval", self.refresh_interval),
        ] {
            if value.as_secs() > i64::MAX as u64 {
                bail!("{name} is too large");
            }
        }
        if self.max_cache_entries_per_kind == 0 {
            bail!("maximum cache entries per kind must be greater than zero");
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct Proxy {
    client: Client,
    cache: CacheStore,
    config: Arc<ProxyConfig>,
    fills: Arc<DashMap<String, Arc<Mutex<()>>>>,
}

#[derive(Debug)]
struct UpstreamResponse {
    status: StatusCode,
    content_type: String,
    body: Bytes,
}

pub async fn run(config: ProxyConfig) -> Result<()> {
    config.validate()?;
    let listen_addr = config.listen_addr;
    let proxy = Proxy::new(config).await?;
    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("failed to bind {listen_addr}"))?;
    info!(%listen_addr, "GPU attestation collateral proxy listening");
    tokio::spawn(proxy.clone().refresh_loop());

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept connection")?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(error) = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(HEADER_READ_TIMEOUT)
                .serve_connection(
                    io,
                    service_fn(move |request| {
                        let proxy = proxy.clone();
                        async move { Ok::<_, Infallible>(proxy.handle(request).await) }
                    }),
                )
                .await
            {
                tracing::debug!(%peer_addr, %error, "HTTP connection failed");
            }
        });
    }
}

impl Proxy {
    async fn new(config: ProxyConfig) -> Result<Self> {
        config.validate()?;
        let cache = CacheStore::new(&config.cache_dir, config.max_cache_entries_per_kind).await?;
        let client = Client::builder()
            .connect_timeout(config.connect_timeout)
            .timeout(config.request_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!(
                "dstack-nvidia-attest-proxy/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .context("failed to create upstream HTTP client")?;
        Ok(Self {
            client,
            cache,
            config: Arc::new(config),
            fills: Arc::new(DashMap::new()),
        })
    }

    fn rim_max_stale_secs(&self) -> i64 {
        self.config.rim_max_stale.as_secs().min(i64::MAX as u64) as i64
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/healthz") => text_response(StatusCode::OK, "ok\n"),
            (&Method::GET, "/info") => self.handle_info().await,
            (&Method::POST, "/ocsp") => {
                if !request
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .is_some_and(|value| {
                        value.split(';').next().is_some_and(|value| {
                            value
                                .trim()
                                .eq_ignore_ascii_case("application/ocsp-request")
                        })
                    })
                {
                    return text_response(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        "expected application/ocsp-request\n",
                    );
                }
                let body = match Limited::new(request.into_body(), MAX_OCSP_REQUEST_BYTES)
                    .collect()
                    .await
                {
                    Ok(body) => body.to_bytes(),
                    Err(error) => {
                        tracing::debug!(%error, "failed to read OCSP request");
                        return text_response(
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "invalid or oversized OCSP request\n",
                        );
                    }
                };
                self.handle_ocsp(body).await
            }
            (&Method::GET, path) if path.starts_with("/v1/rim/") => {
                let rim_id = &path["/v1/rim/".len()..];
                if !valid_rim_id(rim_id) || request.uri().query().is_some() {
                    return text_response(StatusCode::BAD_REQUEST, "invalid RIM ID\n");
                }
                self.handle_rim(rim_id).await
            }
            (&Method::GET, "/ocsp") | (&Method::POST, "/healthz") | (&Method::POST, "/info") => {
                text_response(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n")
            }
            _ => text_response(StatusCode::NOT_FOUND, "not found\n"),
        }
    }

    async fn handle_ocsp(&self, body: Bytes) -> Response<Full<Bytes>> {
        let key = match ocsp::request_cache_key(&body) {
            Ok(key) => key,
            Err(error) => {
                tracing::debug!(%error, "rejected malformed OCSP request");
                return text_response(StatusCode::BAD_REQUEST, "invalid OCSP request\n");
            }
        };
        // `cache_get(.., 0)` only ever returns entries that have not yet hit
        // their hard expiry (max_stale_secs=0 for OCSP). An entry can still
        // be fresh but close enough to expiry to need a synchronous renewal
        // (`ocsp_needs_refresh`) before it is served again.
        if let Some(entry) = self.cache_get("ocsp", &key, 0).await {
            if !self.ocsp_needs_refresh(&entry) {
                return cached_response(entry, "HIT");
            }
        }

        let (fill_key, fill) = self.fill_lock("ocsp", &key);
        let response = {
            let _guard = fill.lock().await;
            self.fill_ocsp(&key, body).await
        };
        drop(fill);
        self.release_fill(&fill_key);
        response
    }

    /// Resolve an OCSP request, synchronously renewing a cached entry once it
    /// enters its refresh window. A failed renewal falls back to the still-
    /// valid cached response instead of failing the request — the goal is to
    /// avoid the *next* request finding a hard-expired cache, not to punish
    /// this one for a transient upstream hiccup.
    async fn fill_ocsp(&self, key: &str, body: Bytes) -> Response<Full<Bytes>> {
        let cached = self.cache_get("ocsp", key, 0).await;
        if let Some(entry) = &cached {
            if !self.ocsp_needs_refresh(entry) {
                // A concurrent request already renewed this entry while we
                // were waiting for the fill lock.
                return cached_response(entry.clone(), "HIT");
            }
        }
        let upstream = match self.fetch_ocsp(body.clone()).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, "OCSP upstream request failed");
                if let Some(entry) = cached {
                    return cached_response(entry, "HIT");
                }
                return text_response(StatusCode::BAD_GATEWAY, "OCSP upstream unavailable\n");
            }
        };
        if upstream.status != StatusCode::OK {
            if let Some(entry) = &cached {
                warn!(status = %upstream.status, "OCSP refresh returned an error; using valid cached response");
                return cached_response(entry.clone(), "HIT");
            }
        }
        let cache_state = if cached.is_some() { "REFRESH" } else { "MISS" };
        if upstream.status == StatusCode::OK {
            let now = now_epoch();
            match ocsp::response_cache_expiry(
                &upstream.body,
                now,
                self.config.ocsp_max_ttl.as_secs(),
                self.config.ocsp_default_ttl.as_secs(),
            ) {
                Ok(expires_at) => {
                    let source = EntrySource::OcspRequestB64(BASE64.encode(&body));
                    if let Err(error) = self
                        .cache
                        .put(
                            "ocsp",
                            key,
                            &upstream.body,
                            &upstream.content_type,
                            now,
                            expires_at,
                            Some(source),
                        )
                        .await
                    {
                        warn!(%error, "failed to persist OCSP cache entry");
                    }
                }
                Err(error) => {
                    warn!(%error, "OCSP response is not cacheable; returning it without caching");
                }
            }
        }
        upstream_response(upstream, cache_state)
    }

    async fn handle_rim(&self, rim_id: &str) -> Response<Full<Bytes>> {
        let key = hex::encode(Sha256::digest(rim_id.as_bytes()));
        let max_stale = self.rim_max_stale_secs();
        if let Some(entry) = self.cache_get("rim", &key, max_stale).await {
            if entry.is_fresh(now_epoch()) {
                return cached_response(entry, "HIT");
            }
        }

        let (fill_key, fill) = self.fill_lock("rim", &key);
        let response = {
            let _guard = fill.lock().await;
            self.fill_rim(&key, rim_id).await
        };
        drop(fill);
        self.release_fill(&fill_key);
        response
    }

    /// Fetch a RIM document, falling back to a stale cache entry (bounded by
    /// `rim_max_stale`) when the upstream is unreachable or failing. RIM
    /// documents are signed and version-addressed, so a stale copy is
    /// verifiable and identical to a fresh one; expired OCSP entries are
    /// deliberately never served this way.
    async fn fill_rim(&self, key: &str, rim_id: &str) -> Response<Full<Bytes>> {
        let cached = self.cache_get("rim", key, self.rim_max_stale_secs()).await;
        if let Some(entry) = &cached {
            if entry.is_fresh(now_epoch()) {
                return cached_response(entry.clone(), "HIT");
            }
        }
        let upstream = match self.fetch_rim(rim_id).await {
            Ok(upstream) => {
                if upstream.status.is_server_error() {
                    if let Some(entry) = cached {
                        warn!(%rim_id, status = %upstream.status, "RIM upstream failing; serving stale document");
                        return cached_response(entry, "STALE");
                    }
                }
                upstream
            }
            Err(error) => {
                warn!(%error, %rim_id, "RIM upstream request failed");
                if let Some(entry) = cached {
                    warn!(%rim_id, "serving stale RIM document while the upstream is unreachable");
                    return cached_response(entry, "STALE");
                }
                return text_response(StatusCode::BAD_GATEWAY, "RIM upstream unavailable\n");
            }
        };
        if upstream.status == StatusCode::OK {
            let now = now_epoch();
            let expires_at = now.saturating_add(self.config.rim_ttl.as_secs() as i64);
            if let Err(error) = self
                .cache
                .put(
                    "rim",
                    key,
                    &upstream.body,
                    &upstream.content_type,
                    now,
                    expires_at,
                    Some(EntrySource::RimId(rim_id.to_string())),
                )
                .await
            {
                warn!(%error, "failed to persist RIM cache entry");
            }
        }
        upstream_response(upstream, "MISS")
    }

    async fn handle_info(&self) -> Response<Full<Bytes>> {
        let now = now_epoch();
        let mut report = String::new();
        for namespace in ["ocsp", "rim"] {
            match self.cache.list(namespace).await {
                Ok(entries) => {
                    let fresh = entries
                        .iter()
                        .filter(|(_, metadata)| metadata.expires_at > now)
                        .count();
                    let stale = entries.len() - fresh;
                    report.push_str(&format!("{namespace}: {fresh} fresh, {stale} stale\n"));
                }
                Err(error) => {
                    report.push_str(&format!("{namespace}: unavailable ({error:#})\n"));
                }
            }
        }
        binary_response(
            StatusCode::OK,
            "text/plain; charset=utf-8",
            Bytes::from(report),
        )
    }

    /// Renew entries past half their lifetime so a warm cache approaches a
    /// full validity window of outage tolerance. The half-life trigger keeps
    /// short-lived entries from being polled on every sweep, and entries past
    /// their usefulness (OCSP: expiry; RIM: expiry plus the stale window) are
    /// dropped instead of being retried forever.
    async fn refresh_loop(self) {
        let interval = self.config.refresh_interval;
        if interval.is_zero() {
            info!("background refresh is disabled");
            return;
        }
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            self.refresh_once().await;
        }
    }

    async fn refresh_once(&self) {
        for namespace in ["ocsp", "rim"] {
            let entries = match self.cache.list(namespace).await {
                Ok(entries) => entries,
                Err(error) => {
                    warn!(%error, %namespace, "failed to list cache entries for refresh");
                    continue;
                }
            };
            let now = now_epoch();
            let due = entries
                .into_iter()
                .filter(|(_, metadata)| {
                    should_refresh(metadata.fetched_at, metadata.expires_at, now)
                })
                .collect::<Vec<_>>();
            futures::stream::iter(due)
                .for_each_concurrent(REFRESH_CONCURRENCY, |(key, metadata)| async move {
                    self.refresh_entry(namespace, key, metadata.source).await;
                })
                .await;
        }
    }

    async fn refresh_entry(
        &self,
        namespace: &'static str,
        key: String,
        source: Option<EntrySource>,
    ) {
        let (fill_key, fill) = self.fill_lock(namespace, &key);
        {
            let _guard = fill.lock().await;
            self.refresh_locked(namespace, &key, source).await;
        }
        drop(fill);
        self.release_fill(&fill_key);
    }

    async fn refresh_locked(&self, namespace: &str, key: &str, source: Option<EntrySource>) {
        let max_stale = match namespace {
            "rim" => self.rim_max_stale_secs(),
            _ => 0,
        };
        // This get drops entries past their usefulness as a side effect, so
        // dead entries are cleaned up instead of being retried forever.
        let Some(entry) = self.cache_get(namespace, key, max_stale).await else {
            return;
        };
        if !should_refresh(entry.fetched_at, entry.expires_at, now_epoch()) {
            // A concurrent miss already renewed this entry.
            return;
        }
        // Entries from a pre-source cache format cannot be refreshed; they
        // serve until they expire naturally.
        match &source {
            None => {}
            Some(EntrySource::RimId(rim_id)) => match self.fetch_rim(rim_id).await {
                Ok(upstream) if upstream.status == StatusCode::OK => {
                    let now = now_epoch();
                    let expires_at = now.saturating_add(self.config.rim_ttl.as_secs() as i64);
                    match self
                        .cache
                        .put(
                            namespace,
                            key,
                            &upstream.body,
                            &upstream.content_type,
                            now,
                            expires_at,
                            source.clone(),
                        )
                        .await
                    {
                        Ok(()) => debug!(%rim_id, "refreshed RIM document"),
                        Err(error) => warn!(%error, "failed to persist refreshed RIM entry"),
                    }
                }
                Ok(upstream) => {
                    debug!(%rim_id, status = %upstream.status, "RIM refresh got an error status")
                }
                Err(error) => debug!(%rim_id, %error, "RIM refresh failed"),
            },
            Some(EntrySource::OcspRequestB64(encoded)) => {
                let Ok(request) = BASE64.decode(encoded) else {
                    debug!(%key, "cache entry has an undecodable OCSP refresh request");
                    return;
                };
                match self.fetch_ocsp(Bytes::from(request)).await {
                    Ok(upstream) if upstream.status == StatusCode::OK => {
                        let now = now_epoch();
                        match ocsp::response_cache_expiry(
                            &upstream.body,
                            now,
                            self.config.ocsp_max_ttl.as_secs(),
                            self.config.ocsp_default_ttl.as_secs(),
                        ) {
                            Ok(expires_at) => {
                                match self
                                    .cache
                                    .put(
                                        namespace,
                                        key,
                                        &upstream.body,
                                        &upstream.content_type,
                                        now,
                                        expires_at,
                                        source.clone(),
                                    )
                                    .await
                                {
                                    Ok(()) => debug!(%key, "refreshed OCSP response"),
                                    Err(error) => {
                                        warn!(%error, "failed to persist refreshed OCSP entry")
                                    }
                                }
                            }
                            Err(error) => {
                                debug!(%error, "refreshed OCSP response is not cacheable")
                            }
                        }
                    }
                    Ok(upstream) => {
                        debug!(%key, status = %upstream.status, "OCSP refresh got an error status")
                    }
                    Err(error) => debug!(%key, %error, "OCSP refresh failed"),
                }
            }
        }
    }

    async fn fetch_ocsp(&self, body: Bytes) -> Result<UpstreamResponse> {
        let mut request = self
            .client
            .post(self.config.ocsp_url.clone())
            .header(CONTENT_TYPE, "application/ocsp-request")
            .header(ACCEPT, OCSP_CONTENT_TYPE)
            .body(body);
        if let Some(service_key) = self.config.service_key.as_deref() {
            request = request.bearer_auth(service_key);
        }
        collect_upstream(
            request
                .send()
                .await
                .context("failed to query OCSP upstream")?,
            MAX_OCSP_RESPONSE_BYTES,
        )
        .await
    }

    async fn fetch_rim(&self, rim_id: &str) -> Result<UpstreamResponse> {
        let mut url = self.config.rim_url.clone();
        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow::anyhow!("RIM upstream URL cannot be a base URL"))?;
            segments.pop_if_empty().extend(["v1", "rim", rim_id]);
        }
        let mut request = self.client.get(url).header(ACCEPT, JSON_CONTENT_TYPE);
        if let Some(service_key) = self.config.service_key.as_deref() {
            request = request.bearer_auth(service_key);
        }
        collect_upstream(
            request
                .send()
                .await
                .context("failed to query RIM upstream")?,
            MAX_RIM_RESPONSE_BYTES,
        )
        .await
    }

    async fn cache_get(
        &self,
        namespace: &str,
        key: &str,
        max_stale_secs: i64,
    ) -> Option<CacheEntry> {
        match self
            .cache
            .get(namespace, key, now_epoch(), max_stale_secs)
            .await
        {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, %namespace, "failed to read cache entry");
                None
            }
        }
    }

    /// Whether an OCSP entry has entered its synchronous refresh window
    /// (`ocsp_refresh_before` of its signed expiry). This is a softer signal
    /// than hard freshness: an entry that fails this check is still valid
    /// and safe to serve as a fallback if renewal fails.
    fn ocsp_needs_refresh(&self, entry: &CacheEntry) -> bool {
        entry.expires_at.saturating_sub(now_epoch())
            <= self.config.ocsp_refresh_before.as_secs() as i64
    }

    fn fill_lock(&self, namespace: &str, key: &str) -> (String, Arc<Mutex<()>>) {
        let fill_key = format!("{namespace}:{key}");
        let lock = self
            .fills
            .entry(fill_key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        (fill_key, lock)
    }

    /// Drop a fill lock nobody is holding, so `fills` does not grow with every
    /// distinct key ever requested. Waiters hold their own `Arc` clone, which
    /// keeps the strong count above one until they are done.
    fn release_fill(&self, fill_key: &str) {
        self.fills
            .remove_if(fill_key, |_, lock| Arc::strong_count(lock) == 1);
    }
}

/// Refresh once an entry has consumed half its lifetime. This both renews
/// long-lived entries well before expiry and avoids polling upstream on every
/// sweep for entries with short validity windows.
fn should_refresh(fetched_at: i64, expires_at: i64, now: i64) -> bool {
    let lifetime = expires_at.saturating_sub(fetched_at);
    lifetime > 0 && now.saturating_sub(fetched_at) >= lifetime / 2
}

async fn collect_upstream(response: reqwest::Response, limit: usize) -> Result<UpstreamResponse> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        bail!("upstream response exceeds {limit} bytes");
    }
    let status = response.status();
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = response
        .bytes()
        .await
        .context("failed to read upstream response")?;
    if body.len() > limit {
        bail!("upstream response exceeds {limit} bytes");
    }
    Ok(UpstreamResponse {
        status,
        content_type,
        body,
    })
}

fn validate_upstream_url(name: &str, url: &Url) -> Result<()> {
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("{name} upstream URL must be an absolute HTTP(S) URL");
    }
    if url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        bail!("{name} upstream URL must not contain credentials, query, or fragment");
    }
    Ok(())
}

fn valid_rim_id(rim_id: &str) -> bool {
    !rim_id.is_empty()
        && rim_id.len() <= 256
        && rim_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

fn cached_response(entry: CacheEntry, state: &'static str) -> Response<Full<Bytes>> {
    let age = now_epoch().saturating_sub(entry.fetched_at);
    let mut response = binary_response(StatusCode::OK, &entry.content_type, entry.body);
    response
        .headers_mut()
        .insert("x-dstack-cache", HeaderValue::from_static(state));
    if let Ok(age) = HeaderValue::from_str(&age.to_string()) {
        response.headers_mut().insert("age", age);
    }
    if let Ok(expires_at) = HeaderValue::from_str(&entry.expires_at.to_string()) {
        response
            .headers_mut()
            .insert("x-dstack-cache-expires", expires_at);
    }
    response
}

fn upstream_response(
    upstream: UpstreamResponse,
    cache_state: &'static str,
) -> Response<Full<Bytes>> {
    let mut response = binary_response(upstream.status, &upstream.content_type, upstream.body);
    response
        .headers_mut()
        .insert("x-dstack-cache", HeaderValue::from_static(cache_state));
    response
}

fn binary_response(status: StatusCode, content_type: &str, body: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(content_type) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(CONTENT_TYPE, content_type);
    }
    response
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Full<Bytes>> {
    binary_response(
        status,
        "text/plain; charset=utf-8",
        Bytes::from_static(body.as_bytes()),
    )
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::{TimeZone, Utc};

    use super::*;

    fn der(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut result = vec![tag];
        if value.len() < 128 {
            result.push(value.len() as u8);
        } else {
            let bytes = value.len().to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap();
            result.push(0x80 | (bytes.len() - first) as u8);
            result.extend_from_slice(&bytes[first..]);
        }
        result.extend_from_slice(value);
        result
    }

    fn sequence(parts: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &parts.concat())
    }

    fn ocsp_request(nonce: u8) -> Bytes {
        let algorithm = sequence(&[der(0x06, &[0x2b, 0x0e, 0x03, 0x02, 0x1a])]);
        let cert_id = sequence(&[
            algorithm,
            der(0x04, &[1; 20]),
            der(0x04, &[2; 20]),
            der(0x02, &[3]),
        ]);
        let request_list = sequence(&[sequence(&[cert_id])]);
        let extensions = der(0xa2, &sequence(&[der(0x04, &[nonce; 16])]));
        Bytes::from(sequence(&[sequence(&[request_list, extensions])]))
    }

    fn ocsp_response(now: i64) -> Bytes {
        ocsp_response_with_ttl(now, 3600)
    }

    fn ocsp_response_with_ttl(now: i64, ttl: i64) -> Bytes {
        let format = |timestamp| {
            Utc.timestamp_opt(timestamp, 0)
                .unwrap()
                .format("%Y%m%d%H%M%SZ")
                .to_string()
        };
        let cert_id = sequence(&[der(0x02, &[1])]);
        let single = sequence(&[
            cert_id,
            der(0x80, &[]),
            der(0x18, format(now - 60).as_bytes()),
            der(0xa0, &der(0x18, format(now + ttl).as_bytes())),
        ]);
        let response_data = sequence(&[
            der(0x82, &[7; 20]),
            der(0x18, format(now).as_bytes()),
            sequence(&[single]),
        ]);
        let basic = sequence(&[
            response_data,
            sequence(&[der(0x06, &[0x2a, 0x03])]),
            der(0x03, &[0]),
        ]);
        let response_bytes = sequence(&[
            der(
                0x06,
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01],
            ),
            der(0x04, &basic),
        ]);
        Bytes::from(sequence(&[der(0x0a, &[0]), der(0xa0, &response_bytes)]))
    }

    async fn mock_upstream(
        response: Bytes,
        content_type: &'static str,
    ) -> (Url, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let response = response.clone();
                let request_counter = request_counter.clone();
                tokio::spawn(async move {
                    http1::Builder::new()
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |_request| {
                                let response = response.clone();
                                let request_counter = request_counter.clone();
                                async move {
                                    request_counter.fetch_add(1, Ordering::SeqCst);
                                    Ok::<_, Infallible>(binary_response(
                                        StatusCode::OK,
                                        content_type,
                                        response,
                                    ))
                                }
                            }),
                        )
                        .await
                        .unwrap();
                });
            }
        });
        (
            Url::parse(&format!("http://{address}/ocsp")).unwrap(),
            requests,
            task,
        )
    }

    /// A URL that refuses connections: bind an ephemeral port, then drop it.
    async fn dead_upstream() -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        Url::parse(&format!("http://{address}/")).unwrap()
    }

    fn test_config(cache_dir: PathBuf, ocsp_url: Url, rim_url: Url) -> ProxyConfig {
        ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cache_dir,
            ocsp_url,
            rim_url,
            service_key: None,
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(1),
            ocsp_max_ttl: Duration::from_secs(86_400),
            ocsp_default_ttl: Duration::from_secs(3600),
            ocsp_refresh_before: Duration::from_secs(300),
            rim_ttl: Duration::from_secs(86_400),
            rim_max_stale: Duration::from_secs(7 * 86_400),
            refresh_interval: Duration::from_secs(600),
            max_cache_entries_per_kind: 10,
        }
    }

    #[tokio::test]
    async fn ocsp_cache_reuses_response_across_nonces_and_restarts() {
        let now = now_epoch();
        let response = ocsp_response(now);
        let (upstream_url, requests, upstream) =
            mock_upstream(response.clone(), OCSP_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let config = test_config(
            cache_dir.path().to_path_buf(),
            upstream_url.clone(),
            Url::parse("https://rim.attestation.nvidia.com").unwrap(),
        );

        let proxy = Proxy::new(config.clone()).await.unwrap();
        let nonce = std::process::id() as u8;
        let miss = proxy.handle_ocsp(ocsp_request(nonce)).await;
        assert_eq!(miss.headers()["x-dstack-cache"], "MISS");
        assert_eq!(
            miss.into_body().collect().await.unwrap().to_bytes(),
            response
        );
        let hit = proxy.handle_ocsp(ocsp_request(nonce.wrapping_add(1))).await;
        assert_eq!(hit.headers()["x-dstack-cache"], "HIT");
        assert_eq!(requests.load(Ordering::SeqCst), 1);

        drop(proxy);
        let reopened = Proxy::new(config).await.unwrap();
        let hit = reopened
            .handle_ocsp(ocsp_request(nonce.wrapping_add(2)))
            .await;
        assert_eq!(hit.headers()["x-dstack-cache"], "HIT");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        upstream.abort();
    }

    #[tokio::test]
    async fn ocsp_cache_refreshes_before_expiry() {
        let now = now_epoch();
        let response = ocsp_response_with_ttl(now, 60);
        let (upstream_url, requests, upstream) = mock_upstream(response, OCSP_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cache_dir: cache_dir.path().to_path_buf(),
            ocsp_url: upstream_url,
            rim_url: Url::parse("https://rim.attestation.nvidia.com").unwrap(),
            service_key: None,
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(1),
            ocsp_max_ttl: Duration::from_secs(86_400),
            ocsp_default_ttl: Duration::from_secs(3600),
            ocsp_refresh_before: Duration::from_secs(300),
            rim_ttl: Duration::from_secs(86_400),
            rim_max_stale: Duration::from_secs(7 * 86_400),
            refresh_interval: Duration::from_secs(600),
            max_cache_entries_per_kind: 10,
        })
        .await
        .unwrap();

        let nonce = std::process::id() as u8;
        assert_eq!(
            proxy.handle_ocsp(ocsp_request(nonce)).await.headers()["x-dstack-cache"],
            "MISS"
        );
        assert_eq!(
            proxy
                .handle_ocsp(ocsp_request(nonce.wrapping_add(1)))
                .await
                .headers()["x-dstack-cache"],
            "REFRESH"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 2);
        upstream.abort();
    }

    #[tokio::test]
    async fn rim_cache_uses_versioned_id() {
        let response = Bytes::from_static(br#"{"id":"NV_GPU_DRIVER_GH100_580.1","rim":"test"}"#);
        let (upstream_url, requests, upstream) =
            mock_upstream(response.clone(), JSON_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(test_config(
            cache_dir.path().to_path_buf(),
            upstream_url.clone(),
            upstream_url,
        ))
        .await
        .unwrap();

        let miss = proxy.handle_rim("NV_GPU_DRIVER_GH100_580.1").await;
        assert_eq!(miss.headers()["x-dstack-cache"], "MISS");
        assert_eq!(
            miss.into_body().collect().await.unwrap().to_bytes(),
            response
        );
        let hit = proxy.handle_rim("NV_GPU_DRIVER_GH100_580.1").await;
        assert_eq!(hit.headers()["x-dstack-cache"], "HIT");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        upstream.abort();
    }

    #[tokio::test]
    async fn stale_rim_is_served_when_upstream_is_unreachable() {
        let dead = dead_upstream().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(test_config(
            cache_dir.path().to_path_buf(),
            dead.clone(),
            dead,
        ))
        .await
        .unwrap();

        let rim_id = "NV_GPU_DRIVER_GH100_580.1";
        let key = hex::encode(Sha256::digest(rim_id.as_bytes()));
        let now = now_epoch();
        proxy
            .cache
            .put(
                "rim",
                &key,
                b"stale-but-signed",
                JSON_CONTENT_TYPE,
                now - 1000,
                now - 10,
                Some(EntrySource::RimId(rim_id.to_string())),
            )
            .await
            .unwrap();

        let response = proxy.handle_rim(rim_id).await;
        assert_eq!(response.headers()["x-dstack-cache"], "STALE");
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            &b"stale-but-signed"[..]
        );
    }

    #[tokio::test]
    async fn expired_ocsp_is_never_served() {
        let dead = dead_upstream().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(test_config(
            cache_dir.path().to_path_buf(),
            dead.clone(),
            dead,
        ))
        .await
        .unwrap();

        let request = ocsp_request(1);
        let key = ocsp::request_cache_key(&request).unwrap();
        let now = now_epoch();
        proxy
            .cache
            .put(
                "ocsp",
                &key,
                b"expired-response",
                OCSP_CONTENT_TYPE,
                now - 1000,
                now - 10,
                Some(EntrySource::OcspRequestB64(BASE64.encode(&request))),
            )
            .await
            .unwrap();

        let response = proxy.handle_ocsp(request).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn refresher_renews_entries_past_half_life() {
        let now = now_epoch();
        let response = ocsp_response(now);
        let (upstream_url, requests, upstream) =
            mock_upstream(response.clone(), OCSP_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(test_config(
            cache_dir.path().to_path_buf(),
            upstream_url,
            Url::parse("https://rim.attestation.nvidia.com").unwrap(),
        ))
        .await
        .unwrap();

        let request = ocsp_request(1);
        let key = ocsp::request_cache_key(&request).unwrap();
        // Past half-life (age 1000 of a 1010-second lifetime), close to expiry.
        proxy
            .cache
            .put(
                "ocsp",
                &key,
                b"old-response",
                OCSP_CONTENT_TYPE,
                now - 1000,
                now + 10,
                Some(EntrySource::OcspRequestB64(BASE64.encode(&request))),
            )
            .await
            .unwrap();

        proxy.refresh_once().await;
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        let entry = proxy.cache_get("ocsp", &key, 0).await.unwrap();
        assert!(entry.expires_at > now + 10);
        assert_eq!(entry.body, response);

        // A freshly renewed entry is not refreshed again on the next sweep.
        proxy.refresh_once().await;
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        // Clients now hit the refreshed entry without touching upstream.
        let hit = proxy.handle_ocsp(ocsp_request(2)).await;
        assert_eq!(hit.headers()["x-dstack-cache"], "HIT");
        assert_eq!(requests.load(Ordering::SeqCst), 1);
        upstream.abort();
    }

    #[tokio::test]
    async fn refresher_drops_entries_past_usefulness() {
        let dead = dead_upstream().await;
        let cache_dir = tempfile::tempdir().unwrap();
        let config = test_config(cache_dir.path().to_path_buf(), dead.clone(), dead);
        let max_stale = config.rim_max_stale.as_secs() as i64;
        let proxy = Proxy::new(config).await.unwrap();

        let now = now_epoch();
        proxy
            .cache
            .put(
                "rim",
                "aaaa",
                b"ancient",
                JSON_CONTENT_TYPE,
                now - max_stale - 1000,
                now - max_stale - 100,
                Some(EntrySource::RimId("OLD".into())),
            )
            .await
            .unwrap();
        proxy
            .cache
            .put(
                "ocsp",
                "bbbb",
                b"expired",
                OCSP_CONTENT_TYPE,
                now - 1000,
                now - 10,
                None,
            )
            .await
            .unwrap();

        proxy.refresh_once().await;
        assert!(proxy.cache.list("rim").await.unwrap().is_empty());
        assert!(proxy.cache.list("ocsp").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn fill_locks_are_released() {
        let now = now_epoch();
        let response = ocsp_response(now);
        let (upstream_url, _requests, upstream) =
            mock_upstream(response.clone(), OCSP_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(test_config(
            cache_dir.path().to_path_buf(),
            upstream_url.clone(),
            upstream_url,
        ))
        .await
        .unwrap();

        proxy.handle_ocsp(ocsp_request(1)).await;
        proxy.handle_rim("NV_GPU_DRIVER_GH100_580.1").await;
        assert!(proxy.fills.is_empty());
        upstream.abort();
    }

    #[test]
    fn half_life_refresh_decision() {
        // 100-second lifetime: refresh from age 50 onwards.
        assert!(!should_refresh(1000, 1100, 1049));
        assert!(should_refresh(1000, 1100, 1050));
        // Expired entries still satisfy the predicate; get() decides whether
        // they are dropped or (stale RIM) refreshed.
        assert!(should_refresh(1000, 1100, 2000));
        // Degenerate lifetimes never refresh.
        assert!(!should_refresh(1000, 1000, 2000));
        assert!(!should_refresh(1000, 900, 2000));
    }
}
