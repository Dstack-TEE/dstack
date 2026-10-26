// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use dstack_nvidia_attest_proxy::ProxyConfig;
use tracing_subscriber::EnvFilter;
use url::Url;

#[derive(Debug, Parser)]
#[command(about = "Persistent NVIDIA OCSP and RIM cache for dstack GPU attestation")]
struct Args {
    /// Address on which the HTTP proxy listens.
    #[arg(
        long,
        env = "NVIDIA_ATTEST_PROXY_LISTEN",
        default_value = "0.0.0.0:8090"
    )]
    listen: SocketAddr,

    /// Directory for persistent OCSP and RIM cache entries.
    #[arg(
        long,
        env = "NVIDIA_ATTEST_PROXY_CACHE_DIR",
        default_value = "/var/cache/dstack/nvidia-attest-proxy"
    )]
    cache_dir: PathBuf,

    /// NVIDIA OCSP responder URL.
    #[arg(
        long,
        env = "NVIDIA_ATTEST_PROXY_OCSP_URL",
        default_value = "https://ocsp.ndis.nvidia.com"
    )]
    ocsp_url: Url,

    /// NVIDIA RIM service base URL.
    #[arg(
        long,
        env = "NVIDIA_ATTEST_PROXY_RIM_URL",
        default_value = "https://rim.attestation.nvidia.com"
    )]
    rim_url: Url,

    /// Optional NVIDIA attestation service bearer token.
    #[arg(long, env = "NV_ATTESTATION_SERVICE_KEY", hide_env_values = true)]
    service_key: Option<String>,

    #[arg(long, env = "NVIDIA_ATTEST_PROXY_REQUEST_TIMEOUT", default_value = "30s", value_parser = parse_duration)]
    request_timeout: Duration,

    #[arg(long, env = "NVIDIA_ATTEST_PROXY_CONNECT_TIMEOUT", default_value = "10s", value_parser = parse_duration)]
    connect_timeout: Duration,

    /// Maximum time an OCSP response may remain cached. Signed nextUpdate can shorten it.
    #[arg(long, env = "NVIDIA_ATTEST_PROXY_OCSP_MAX_TTL", default_value = "24h", value_parser = parse_duration)]
    ocsp_max_ttl: Duration,

    /// Cache lifetime for OCSP responses that omit nextUpdate.
    #[arg(long, env = "NVIDIA_ATTEST_PROXY_OCSP_DEFAULT_TTL", default_value = "1h", value_parser = parse_duration)]
    ocsp_default_ttl: Duration,

    /// Refresh an OCSP response when less than this much validity remains.
    #[arg(long, env = "GPU_ATTEST_PROXY_OCSP_REFRESH_BEFORE", default_value = "5m", value_parser = parse_duration)]
    ocsp_refresh_before: Duration,

    /// Cache lifetime for version-addressed RIM documents.
    #[arg(long, env = "NVIDIA_ATTEST_PROXY_RIM_TTL", default_value = "30d", value_parser = parse_duration)]
    rim_ttl: Duration,

    /// How long an expired RIM document may still be served when the upstream
    /// cannot provide a fresh copy. RIM documents are signed and
    /// version-addressed, so this trades availability, not security. 0
    /// disables stale serving.
    #[arg(long, env = "NVIDIA_ATTEST_PROXY_RIM_MAX_STALE", default_value = "7d", value_parser = parse_duration)]
    rim_max_stale: Duration,

    /// Interval between background refresh sweeps renewing cache entries past
    /// half their lifetime. 0 disables background refresh.
    #[arg(long, env = "NVIDIA_ATTEST_PROXY_REFRESH_INTERVAL", default_value = "10m", value_parser = parse_duration)]
    refresh_interval: Duration,

    /// Maximum persistent entries in each of the OCSP and RIM caches.
    #[arg(
        long,
        env = "NVIDIA_ATTEST_PROXY_MAX_CACHE_ENTRIES_PER_KIND",
        default_value_t = 10_000
    )]
    max_cache_entries_per_kind: usize,
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    humantime::parse_duration(value).map_err(|error| error.to_string())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let args = Args::parse();
    dstack_nvidia_attest_proxy::run(ProxyConfig {
        listen_addr: args.listen,
        cache_dir: args.cache_dir,
        ocsp_url: args.ocsp_url,
        rim_url: args.rim_url,
        service_key: args.service_key,
        request_timeout: args.request_timeout,
        connect_timeout: args.connect_timeout,
        ocsp_max_ttl: args.ocsp_max_ttl,
        ocsp_default_ttl: args.ocsp_default_ttl,
        ocsp_refresh_before: args.ocsp_refresh_before,
        rim_ttl: args.rim_ttl,
        rim_max_stale: args.rim_max_stale,
        refresh_interval: args.refresh_interval,
        max_cache_entries_per_kind: args.max_cache_entries_per_kind,
    })
    .await
    .context("GPU attestation proxy failed")
}
