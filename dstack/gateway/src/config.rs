// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use cmd_lib::run_cmd as cmd;
use dstack_attest::attestation::AttestationVerifierConfig;
use ipnet::Ipv4Net;
use load_config::load_config;
use rocket::figment::Figment;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct WgConfig {
    pub public_key: String,
    pub private_key: String,
    pub listen_port: u16,
    pub ip: Ipv4Net,
    pub reserved_net: Vec<Ipv4Net>,
    pub client_ip_range: Ipv4Net,
    pub interface: String,
    pub config_path: String,
    pub endpoint: String,
}

impl WgConfig {
    fn validate(&self) -> Result<()> {
        validate(self.ip, &self.reserved_net, self.client_ip_range)
    }
}

fn validate(ip: Ipv4Net, reserved_net: &[Ipv4Net], client_ip_range: Ipv4Net) -> Result<()> {
    // The reserved net must be in the network
    for net in reserved_net {
        if !ip.contains(net) {
            bail!("Reserved net is not in the network");
        }
    }

    // The ip must be in one of the reserved net
    if !reserved_net.iter().any(|net| net.contains(&ip.addr())) {
        bail!("Wg peer IP is not in the reserved net");
    }

    // The client ip range must be in the network
    if !ip.trunc().contains(&client_ip_range) {
        bail!("Client IP range is not in the network");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub enum CryptoProvider {
    #[serde(rename = "aws-lc-rs")]
    AwsLcRs,
    #[serde(rename = "ring")]
    Ring,
}

#[derive(Debug, Clone, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

/// Deserialize a port range from either a single integer (443) or a string range ("443-543").
fn deserialize_port_range<'de, D>(deserializer: D) -> std::result::Result<Vec<u16>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum PortSpec {
        Single(u16),
        Range(String),
    }

    match PortSpec::deserialize(deserializer)? {
        PortSpec::Single(p) => Ok(vec![p]),
        PortSpec::Range(s) => {
            if let Some((start, end)) = s.split_once('-') {
                let start: u16 = start.trim().parse().map_err(de::Error::custom)?;
                let end: u16 = end.trim().parse().map_err(de::Error::custom)?;
                if start > end {
                    return Err(de::Error::custom(format!(
                        "invalid port range: {start} > {end}"
                    )));
                }
                Ok((start..=end).collect())
            } else {
                let p: u16 = s.trim().parse().map_err(de::Error::custom)?;
                Ok(vec![p])
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub tls_crypto_provider: CryptoProvider,
    pub tls_versions: Vec<TlsVersion>,
    pub listen_addr: Ipv4Addr,
    #[serde(deserialize_with = "deserialize_port_range")]
    pub listen_port: Vec<u16>,
    pub timeouts: Timeouts,
    pub buffer_size: usize,
    pub connect_top_n: usize,
    pub localhost_enabled: bool,
    pub workers: usize,
    /// Run one single-threaded runtime per worker, each with its own
    /// `SO_REUSEPORT` listener, instead of one accept thread feeding a shared
    /// work-stealing runtime.
    ///
    /// A connection is then accepted and served entirely on one thread. The
    /// default model costs ~0.6 context switches per request (accept-thread
    /// handoff plus work-stealing migrations); HAProxy's thread-per-core design
    /// measures ~0. Linux-only (needs SO_REUSEPORT).
    #[serde(default)]
    pub thread_per_core: bool,
    /// Hand a freshly accepted connection to a less loaded core when the
    /// accepting one is running ahead.
    ///
    /// `SO_REUSEPORT` picks a listener by hashing the connection's 4-tuple and
    /// thread-per-core cannot move a connection afterwards, so a core can sit
    /// starved: measured at 16 connections over 4 cores, utilisation came out
    /// `[99, 42, 101, 101]`. Rebalancing costs one channel send per *rebalanced
    /// connection*, never per request. Requires `thread_per_core`.
    ///
    /// The trade, measured over 6 restarts per arm on a 4-core gateway:
    ///
    /// | connections | off | on |
    /// |---|---|---|
    /// | 16 (hash skews) | 236 110 rps, worst core 72% | 251 840 rps, worst core 85% |
    /// | 50 (hash even) | 291 932 rps | 287 440 rps |
    ///
    /// So it trades ~1.5% at high connection counts, where the hash is already
    /// even and the balancer only costs its bookkeeping, for ~6.7% where the
    /// hash skews -- and it lifts the worst case far more than the average, from
    /// a core at 47% to none below 76%.
    #[serde(default)]
    pub connection_rebalance: bool,
    #[serde(default)]
    pub base_domain: Option<String>,
    #[serde(default)]
    pub cert_chain: Option<PathBuf>,
    #[serde(default)]
    pub cert_key: Option<PathBuf>,
    pub app_address_ns_prefix: String,
    pub app_address_ns_compat: bool,
    /// Maximum concurrent connections per app. 0 means unlimited.
    pub max_connections_per_app: u64,
    /// Port the dstack guest-agent listens on inside each CVM. Used by the
    /// gateway to fetch app metadata (e.g. port_policy for legacy CVMs).
    pub agent_port: u16,
    /// Whether to read PROXY protocol headers from inbound connections
    /// (e.g. when behind a PP-aware load balancer like Cloudflare).
    #[serde(default)]
    pub inbound_pp_enabled: bool,
    /// Use `splice(2)` zero-copy relaying for the TLS-passthrough path. Both
    /// sides are raw TCP there, so payload never needs to enter userspace.
    /// Linux-only; ignored for the TLS-terminate path.
    ///
    /// Tradeoff (measured on a 4-core gateway): bulk passthrough throughput
    /// +~12% with a lower tail latency under load, but small-request latency
    /// regresses (each tiny message pays an extra pipe hop). Enable it for
    /// passthrough traffic dominated by large transfers; leave it off (default)
    /// for request/response passthrough workloads.
    #[serde(default)]
    pub tcp_splice_enabled: bool,
    /// Bytes a passthrough connection must transfer before splice takes over.
    ///
    /// splice costs ~17 syscalls per connection to move a small response (fill
    /// pipe, drain pipe, readiness retries) where a read/write pair needs two;
    /// its benefit is per byte but its cost is per connection. With a non-zero
    /// threshold short request/response connections never touch a pipe while
    /// bulk transfers still get zero-copy. Requires `tcp_splice_enabled`.
    /// 0 keeps the previous behaviour (splice from the first byte).
    #[serde(default)]
    pub tcp_splice_after_bytes: u64,
    /// Offload TLS record encryption to the kernel (kTLS) on the
    /// TLS-terminate path. The handshake still runs in rustls; only the
    /// symmetric crypto moves into the kernel afterwards. Linux-only.
    ///
    /// Security note: enabling this hands the negotiated session keys to the
    /// kernel via `dangerous_extract_secrets`, so the keys live outside
    /// rustls' control. Inside a CVM the kernel is part of the measured TCB,
    /// but on a non-TEE host this widens key exposure. Off by default.
    #[serde(default)]
    pub ktls_enabled: bool,
    /// Bytes a connection must transfer before it is handed over to kTLS.
    ///
    /// kTLS costs ~30% of connection setup rate but wins ~25% on bulk
    /// throughput, so paying the setup cost up front is wrong for short
    /// request/response connections. With a non-zero threshold the connection
    /// starts in userspace rustls and is switched to kTLS + splice only once it
    /// has proven to be a bulk transfer. Requires `ktls_enabled`.
    /// 0 disables the adaptive path (offload immediately after the handshake).
    #[serde(default)]
    pub ktls_offload_after_bytes: u64,
    /// Background lazy-fetch behaviour for `port_policy` (legacy CVMs).
    pub port_policy_fetch: PortPolicyFetchConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortPolicyFetchConfig {
    /// Timeout for a single `Info()` RPC attempt.
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
    /// Maximum number of attempts after the initial try (0 = no retry).
    /// Retries cover the window where a freshly-registered CVM hasn't
    /// finished its WireGuard handshake yet.
    pub max_retries: u32,
    /// Delay before the first retry; doubles on each subsequent retry,
    /// capped at `backoff_max`.
    #[serde(with = "serde_duration")]
    pub backoff_initial: Duration,
    #[serde(with = "serde_duration")]
    pub backoff_max: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Timeouts {
    #[serde(with = "serde_duration")]
    pub connect: Duration,
    #[serde(with = "serde_duration")]
    pub handshake: Duration,
    #[serde(with = "serde_duration")]
    pub total: Duration,

    #[serde(with = "serde_duration")]
    pub cache_top_n: Duration,

    /// Timeout for DNS TXT record resolution (app address lookup).
    #[serde(with = "serde_duration")]
    pub dns_resolve: Duration,

    pub data_timeout_enabled: bool,
    #[serde(with = "serde_duration")]
    pub idle: Duration,
    #[serde(with = "serde_duration")]
    pub write: Duration,
    #[serde(with = "serde_duration")]
    pub shutdown: Duration,
    /// Timeout for reading the proxy protocol header from inbound connections.
    #[serde(with = "serde_duration")]
    pub pp_header: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecycleConfig {
    pub enabled: bool,
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
    #[serde(with = "serde_duration")]
    pub node_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
    pub my_url: String,
    /// The URL of the bootnode used to fetch initial peer list when joining the network
    pub bootnode: String,
    /// WaveKV node ID for this gateway (must be unique across cluster)
    pub node_id: u32,
    /// Data directory for WaveKV persistence
    pub data_dir: String,
    /// Interval for periodic WAL persistence (default: 10s)
    #[serde(with = "serde_duration")]
    pub persist_interval: Duration,
    /// Enable periodic sync of instance connections to KV store
    pub sync_connections_enabled: bool,
    /// Interval for syncing instance connections to KV store
    #[serde(with = "serde_duration")]
    pub sync_connections_interval: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub wg: WgConfig,
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub attestation: AttestationVerifierConfig,
    pub recycle: RecycleConfig,
    pub set_ulimit: bool,
    pub rpc_domain: String,
    pub kms_url: String,
    pub admin: AdminConfig,
    /// Debug server configuration (separate port for debug RPCs)
    pub debug: DebugConfig,
    pub sync: SyncConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DebugConfig {
    /// Enable debug server
    #[serde(default)]
    pub insecure_enable_debug_rpc: bool,
    #[serde(default)]
    pub insecure_skip_attestation: bool,
    /// Path to pre-generated debug key data file (JSON format containing key, quote, event_log, and vm_config)
    #[serde(default)]
    pub key_file: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub url: String,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
}

impl Config {
    /// Get or generate a unique node UUID.
    /// The UUID is stored in `{data_dir}/node_uuid` and persisted across restarts.
    pub fn uuid(&self) -> Vec<u8> {
        use std::fs;
        use std::path::Path;

        let uuid_path = Path::new(&self.sync.data_dir).join("node_uuid");

        // Try to read existing UUID
        if let Ok(content) = fs::read_to_string(&uuid_path) {
            if let Ok(uuid) = uuid::Uuid::parse_str(content.trim()) {
                return uuid.as_bytes().to_vec();
            }
        }

        // Generate new UUID
        let uuid = uuid::Uuid::new_v4();

        // Ensure directory exists
        if let Some(parent) = uuid_path.parent() {
            let _ = fs::create_dir_all(parent);
        }

        // Save UUID to file
        if let Err(err) = fs::write(&uuid_path, uuid.to_string()) {
            tracing::warn!(
                "failed to save node UUID to {}: {}",
                uuid_path.display(),
                err
            );
        } else {
            tracing::info!("generated new node UUID: {}", uuid);
        }

        uuid.as_bytes().to_vec()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub enabled: bool,
    /// Shared secret required to call any admin endpoint (RPC + dashboard).
    /// Can also be supplied via `DSTACK_GATEWAY_ADMIN_TOKEN` / `ADMIN_API_TOKEN`
    /// env vars. Required unless `insecure_no_auth = true`.
    ///
    /// Accepts the legacy `admin_token` key for backward compatibility.
    #[serde(default, alias = "admin_token")]
    pub auth_token: String,
    /// Optional Apache htpasswd file. Enables standard HTTP Basic auth while
    /// preserving token authentication for existing clients.
    #[serde(default)]
    pub htpasswd_file: PathBuf,
    /// Disable authentication entirely. Development/testing only; never enable
    /// on an admin interface that is reachable from the network.
    #[serde(default)]
    pub insecure_no_auth: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub key: String,
    pub certs: String,
    pub mutual: MutualConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MutualConfig {
    pub ca_certs: String,
}

pub const DEFAULT_CONFIG: &str = include_str!("../gateway.toml");
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("gateway", DEFAULT_CONFIG, config_file, false)
}

pub fn setup_wireguard(config: &WgConfig) -> Result<()> {
    config.validate().context("Invalid wireguard config")?;

    info!("Setting up wireguard interface");

    let ifname = &config.interface;

    // Check if interface exists by trying to run ip link show
    if cmd!(ip link show $ifname > /dev/null).is_ok() {
        info!("WireGuard interface {ifname} already exists");
        return Ok(());
    }

    let addr = format!("{}", config.ip);
    // Interface doesn't exist, create and configure it
    cmd! {
        ip link add $ifname type wireguard;
        ip address add $addr dev $ifname;
        ip link set $ifname up;
    }?;

    info!("Created and configured WireGuard interface {ifname}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::providers::{Format, Toml};
    use std::str::FromStr;

    #[test]
    fn admin_auth_token_reads_new_and_legacy_keys() {
        // new key
        let cfg: AdminConfig =
            Figment::from(Toml::string("enabled = true\nauth_token = \"new\"\n"))
                .extract()
                .unwrap();
        assert_eq!(cfg.auth_token, "new");
        // legacy `admin_token` key still deserializes via the serde alias
        let cfg: AdminConfig =
            Figment::from(Toml::string("enabled = true\nadmin_token = \"legacy\"\n"))
                .extract()
                .unwrap();
        assert_eq!(cfg.auth_token, "legacy");
    }

    #[test]
    fn test_validate() {
        // Valid configuration
        let ip = Ipv4Net::from_str("10.1.2.3/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.2.0/30").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.1.2.128/25").unwrap(),
        );
        assert!(result.is_ok());

        // Reserved net does not contain network
        let ip = Ipv4Net::from_str("10.2.0.1/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.0.0/16").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.2.0.128/25").unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Reserved net is not in the network"
        );

        // IP not in reserved net
        let ip = Ipv4Net::from_str("10.1.2.16/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.2.0/30").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.1.2.128/25").unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Wg peer IP is not in the reserved net"
        );

        // Client IP range not in network
        let ip = Ipv4Net::from_str("10.1.2.3/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.2.0/30").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.1.3.128/25").unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Client IP range is not in the network"
        );
    }
}
