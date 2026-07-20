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
use bytes::Bytes;
use cache::{CacheEntry, CacheStore};
use dashmap::DashMap;
use http::{
    header::{ACCEPT, CACHE_CONTROL, CONTENT_TYPE},
    HeaderValue, Method, Request, Response, StatusCode,
};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::TokioIo;
use reqwest::Client;
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::Mutex};
use tracing::{info, warn};
use url::Url;

const MAX_OCSP_REQUEST_BYTES: usize = 64 * 1024;
const MAX_OCSP_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_RIM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const OCSP_CONTENT_TYPE: &str = "application/ocsp-response";
const JSON_CONTENT_TYPE: &str = "application/json";

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
    pub rim_ttl: Duration,
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
            ("RIM TTL", self.rim_ttl),
        ] {
            if value.is_zero() {
                bail!("{name} must be greater than zero");
            }
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

    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("failed to accept connection")?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            if let Err(error) = http1::Builder::new()
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
                "dstack-gpu-attest-proxy/",
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

    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        match (request.method(), request.uri().path()) {
            (&Method::GET, "/healthz") => text_response(StatusCode::OK, "ok\n"),
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
            (&Method::GET, "/ocsp") | (&Method::POST, "/healthz") => {
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
        if let Some(entry) = self.cache_get("ocsp", &key).await {
            return cached_response(entry, "HIT");
        }

        let fill = self.fill_lock("ocsp", &key);
        let _fill = fill.lock().await;
        if let Some(entry) = self.cache_get("ocsp", &key).await {
            return cached_response(entry, "HIT");
        }

        let upstream = match self.fetch_ocsp(body).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, "OCSP upstream request failed");
                return text_response(StatusCode::BAD_GATEWAY, "OCSP upstream unavailable\n");
            }
        };
        if upstream.status == StatusCode::OK {
            let now = now_epoch();
            match ocsp::response_cache_expiry(
                &upstream.body,
                now,
                self.config.ocsp_max_ttl.as_secs(),
                self.config.ocsp_default_ttl.as_secs(),
            ) {
                Ok(expires_at) => {
                    if let Err(error) = self
                        .cache
                        .put(
                            "ocsp",
                            &key,
                            &upstream.body,
                            &upstream.content_type,
                            now,
                            expires_at,
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
        upstream_response(upstream, "MISS")
    }

    async fn handle_rim(&self, rim_id: &str) -> Response<Full<Bytes>> {
        let key = hex::encode(Sha256::digest(rim_id.as_bytes()));
        if let Some(entry) = self.cache_get("rim", &key).await {
            return cached_response(entry, "HIT");
        }

        let fill = self.fill_lock("rim", &key);
        let _fill = fill.lock().await;
        if let Some(entry) = self.cache_get("rim", &key).await {
            return cached_response(entry, "HIT");
        }

        let upstream = match self.fetch_rim(rim_id).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, %rim_id, "RIM upstream request failed");
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
                    &key,
                    &upstream.body,
                    &upstream.content_type,
                    now,
                    expires_at,
                )
                .await
            {
                warn!(%error, "failed to persist RIM cache entry");
            }
        }
        upstream_response(upstream, "MISS")
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

    async fn cache_get(&self, namespace: &str, key: &str) -> Option<CacheEntry> {
        match self.cache.get(namespace, key, now_epoch()).await {
            Ok(entry) => entry,
            Err(error) => {
                warn!(%error, %namespace, "failed to read cache entry");
                None
            }
        }
    }

    fn fill_lock(&self, namespace: &str, key: &str) -> Arc<Mutex<()>> {
        self.fills
            .entry(format!("{namespace}:{key}"))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
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
            der(0xa0, &der(0x18, format(now + 3600).as_bytes())),
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

    #[tokio::test]
    async fn ocsp_cache_reuses_response_across_nonces_and_restarts() {
        let now = now_epoch();
        let response = ocsp_response(now);
        let (upstream_url, requests, upstream) =
            mock_upstream(response.clone(), OCSP_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let config = ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cache_dir: cache_dir.path().to_path_buf(),
            ocsp_url: upstream_url.clone(),
            rim_url: Url::parse("https://rim.attestation.nvidia.com").unwrap(),
            service_key: None,
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(1),
            ocsp_max_ttl: Duration::from_secs(86_400),
            ocsp_default_ttl: Duration::from_secs(3600),
            rim_ttl: Duration::from_secs(86_400),
            max_cache_entries_per_kind: 10,
        };

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
    async fn rim_cache_uses_versioned_id() {
        let response = Bytes::from_static(br#"{"id":"NV_GPU_DRIVER_GH100_580.1","rim":"test"}"#);
        let (upstream_url, requests, upstream) =
            mock_upstream(response.clone(), JSON_CONTENT_TYPE).await;
        let cache_dir = tempfile::tempdir().unwrap();
        let proxy = Proxy::new(ProxyConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            cache_dir: cache_dir.path().to_path_buf(),
            ocsp_url: upstream_url.clone(),
            rim_url: upstream_url,
            service_key: None,
            request_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(1),
            ocsp_max_ttl: Duration::from_secs(86_400),
            ocsp_default_ttl: Duration::from_secs(3600),
            rim_ttl: Duration::from_secs(86_400),
            max_cache_entries_per_kind: 10,
        })
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
}
