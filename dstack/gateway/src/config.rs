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
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};
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

    /// Whether this gateway may allocate `ip` to a CVM registering with it.
    ///
    /// Narrower than [`Self::is_routable_client_ip`]: `client_ip_range` is this
    /// node's *share* of the cluster's address space, and handing out an address
    /// from outside it would collide with whichever node owns that share.
    pub fn is_valid_client_ip(&self, ip: Ipv4Addr) -> bool {
        self.client_ip_range.contains(&ip) && self.is_routable_client_ip(ip)
    }

    /// Whether `ip` may appear as a WireGuard peer address on this gateway.
    ///
    /// Deliberately says nothing about *which pool* the address came from. A
    /// CVM registers with one gateway but is handed every gateway as a
    /// WireGuard server, so each node carries peers for the CVMs registered on
    /// the other nodes — and each node allocates from its own
    /// `client_ip_range`. Nothing in this node's config describes the other
    /// nodes' pools, and the deployments do not even agree on a shape that
    /// could be inferred: `dstack-app/deploy-to-vmm.sh` puts every pool inside
    /// one /16 that each interface covers, while `test-run/cluster.sh` and the
    /// e2e configs give each node a /24 that no other node's interface covers.
    /// Judging a replicated address by local topology refuses legitimate peers
    /// under the second shape, so this is limited to what a node can assert on
    /// its own: an ordinary unicast address that is not one of *this* gateway's.
    ///
    /// What keeps the peer list coherent is not this check but the uniqueness
    /// pass in `kv::import` — no two instances may claim the same address —
    /// which holds cluster-wide because it runs over the whole KV contents.
    pub fn is_routable_client_ip(&self, ip: Ipv4Addr) -> bool {
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
            return false;
        }
        // This gateway's own addresses: handing them to a peer would point the
        // interface's traffic into a tunnel.
        if self.ip.addr() == ip || self.ip.broadcast() == ip {
            return false;
        }
        if self.reserved_net.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        true
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

fn default_true() -> bool {
    true
}

fn default_handshake_stale() -> Duration {
    Duration::from_secs(30 * 60)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub tls_crypto_provider: CryptoProvider,
    pub tls_versions: Vec<TlsVersion>,
    pub listen_addr: Ipv4Addr,
    #[serde(deserialize_with = "deserialize_port_range")]
    pub listen_port: Vec<u16>,
    pub timeouts: Timeouts,
    /// Relay buffer size, per direction, for connections that copy through
    /// userspace -- TLS terminate, and passthrough before the splice gate.
    ///
    /// Costs `2 * buffer_size` of address space per such connection, of which
    /// only the pages actually touched become resident: measured at 2 000
    /// concurrent streaming connections, the userspace relay path sat at ~52 KB
    /// RSS per connection. Budget for it before raising this on a gateway that
    /// fronts many idle-ish connections; the same measurement with kTLS, where
    /// the payload is spliced and never enters the process, was ~12 KB.
    ///
    /// 64 KiB is the bulk-throughput sweet spot: it is large enough to keep a
    /// 1 MiB pipe fed without the syscall rate 8 KiB imposed.
    pub buffer_size: usize,
    pub connect_top_n: usize,
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
    /// On by default. It used to be opt-in, because handing a connection over
    /// cost 2-3% wherever the hash was already even -- that turned out to be a
    /// bug (the migrated socket kept its registration on the accepting core's
    /// reactor), and with it fixed the trade is one-sided. Measured on a 4-core
    /// gateway, 3-5 runs per arm after warmup:
    ///
    /// | workload | off | on | |
    /// |---|---|---|---|
    /// | passthrough small-request, 8 conns | 113 350 | 143 341 | **+26.5%** |
    /// | passthrough small-request, 16 conns | 231 043 | 258 787 | **+12.0%** |
    /// | passthrough small-request, 50 conns | 294 937 | 295 311 | +0.1% |
    /// | TLS terminate small-request, 50 conns | 244 304 | 246 228 | +0.8% |
    /// | TLS terminate, connections/s | 41 024 | 43 019 | +4.9% |
    /// | passthrough, connections/s | 17 431 | 17 319 | -0.6% |
    /// | passthrough, bulk throughput | 12.10 GB/s | 12.16 GB/s | +0.5% |
    ///
    /// The gain is largest where the hash has fewest connections to spread and
    /// the worst-loaded core would otherwise starve: at 16 connections the
    /// quietest core goes from 63% to 97% busy.
    #[serde(default = "default_true")]
    pub connection_rebalance: bool,
    #[serde(default)]
    pub base_domain: Option<String>,
    #[serde(default)]
    pub cert_chain: Option<PathBuf>,
    #[serde(default)]
    pub cert_key: Option<PathBuf>,
    pub app_address_ns_prefix: String,
    pub app_address_ns_compat: bool,
    /// Dedicated DNS servers for app-address TXT lookups.
    /// The system resolver is used when this list is empty.
    #[serde(default)]
    pub app_address_dns_servers: Vec<SocketAddr>,
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
    /// Absent disables splice entirely; see [`EngageAfter`] for what a present
    /// section means.
    ///
    /// Tradeoff (measured on a 4-core gateway): bulk passthrough throughput
    /// +~12% with a lower tail latency under load, but small-request latency
    /// regresses (each tiny message pays an extra pipe hop). splice costs ~17
    /// syscalls per connection to move a small response (fill pipe, drain pipe,
    /// readiness retries) where a read/write pair needs two: its benefit is per
    /// byte, its cost is per connection, which is what the gates amortise.
    #[serde(default)]
    pub tcp_splice: Option<SpliceConfig>,
    /// Offload TLS record encryption to the kernel (kTLS) on the
    /// TLS-terminate path. The handshake still runs in rustls; only the
    /// symmetric crypto moves into the kernel afterwards. Linux-only.
    ///
    /// Absent disables kTLS entirely; see [`EngageAfter`] for what a present
    /// section means. Gated offload additionally requires `tcp_splice`, since
    /// the point of handing the socket to the kernel is to then splice it.
    ///
    /// A kernel built without `CONFIG_TLS` cannot honour this, so startup
    /// probes for the TLS ULP and clears this section with a warning if it is
    /// missing, rather than letting every connection discover it at the gate.
    ///
    /// kTLS costs ~30% of connection setup rate but wins ~25% on bulk
    /// throughput, so paying the setup cost up front is wrong for short
    /// request/response connections.
    ///
    /// On token-streaming traffic the throughput win does not materialise, but
    /// a memory win does. Measured on the terminate path, 10k connections with
    /// 2k streaming a 64 B record every 25 ms, 2 runs per arm:
    ///
    /// | | userspace rustls | kTLS |
    /// |---|---|---|
    /// | latency p50 | 0.174 / 0.181 ms | 0.180 / 0.174 ms |
    /// | latency p99 | 0.602 / 0.526 ms | 0.859 / 0.537 ms |
    /// | **RSS** | **349 MB** | **206 MB** |
    ///
    /// Latency is unchanged, as expected: at 64 B per record the per-record
    /// overhead dominates and there is almost no symmetric crypto to move into
    /// the kernel. The 41% RSS drop is the real effect and was not predicted --
    /// with kTLS the payload is spliced without ever entering this process, so
    /// the per-connection userspace relay buffers disappear (~14 KB/connection
    /// here). Weigh that against handing session keys to the kernel.
    ///
    /// Security note: enabling this hands the negotiated session keys to the
    /// kernel via `dangerous_extract_secrets`, so the keys live outside
    /// rustls' control. Inside a CVM the kernel is part of the measured TCB,
    /// but on a non-TEE host this widens key exposure. Off by default.
    #[serde(default)]
    pub ktls: Option<EngageAfter>,
    /// Background lazy-fetch behaviour for `port_policy` (legacy CVMs).
    pub port_policy_fetch: PortPolicyFetchConfig,
    pub health_check: HealthCheckConfig,
}

impl ProxyConfig {
    /// The idle window every relay enforces, or `None` when data timeouts are
    /// off. Computed in one place so the buffered bridge and the gated fast
    /// paths cannot end up enforcing different things.
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.timeouts
            .data_timeout_enabled
            .then_some(self.timeouts.idle)
    }
}

/// Configuration for `splice(2)` relaying on the TLS-passthrough path.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SpliceConfig {
    /// When splice should take over from the buffered relay.
    #[serde(flatten)]
    pub engage: EngageAfter,
    /// Return a splice pipe to the thread-local pool while waiting for the
    /// next chunk, instead of holding it for the connection's lifetime.
    ///
    /// A relay holds one pipe per direction, so a spliced connection pins four
    /// descriptors. Held for the connection's lifetime that is proportional to
    /// *connections*: 50k streaming connections need 300k descriptors. Released
    /// while idle it is proportional to *chunks actually in flight*, which for
    /// bursty traffic is far smaller -- LLM token streaming moves a ~64 B record
    /// every 25 ms and spends over 99% of the connection idle.
    ///
    /// The pipe is provably empty at the point it is released: the relay only
    /// waits for readability after the previous chunk has been fully drained
    /// into the destination, so nothing is left to corrupt the next borrower.
    ///
    /// The cost is a pool pop and push per idle-to-active transition, both
    /// `Vec` operations on a thread-local. Pipes are only created when the pool
    /// is empty, so the live pipe count converges on the peak number of
    /// concurrent in-flight chunks rather than churning `pipe2`/`close`.
    ///
    /// Measured on a 4-core gateway streaming a 64 B record every 25 ms per
    /// connection, 2 runs per arm at each scale:
    ///
    /// | | off | on |
    /// |---|---|---|
    /// | pipe fds, 2k connections | 8 000 | **8** |
    /// | pipe fds, 50k conns / 10k streams | 53 864 / 55 212 | **8** |
    /// | RSS, 50k connections | 1 203 MB | 1 202 / 1 204 MB |
    /// | latency p50, 50k | 20.9 / 20.3 ms | 21.6 / 21.7 ms |
    /// | latency p999, 50k | 111 / 113 ms | 68 / 79 ms |
    ///
    /// The descriptor result is the point, and it is flat in the connection
    /// count: 8 descriptors is four pipes, one per worker thread, for the whole
    /// gateway, at 2k connections and at 50k alike. That is the bound this knob
    /// exists to impose.
    ///
    /// Latency is close to a wash and should not be used to justify the knob. At
    /// 2k connections there was no consistent difference at all (the single
    /// fastest run of seven was an `off` run). At 50k, where the box is
    /// saturated, `on` costs ~1 ms on p50 and saves ~40 ms on p999; the p999
    /// gain is consistent across repeats but comes from a regime that is already
    /// over budget. RSS is unchanged either way.
    ///
    /// Mixing bulk transfers with token streams does not break the pooling, and
    /// this was the failure worth checking: a connection that is never idle
    /// never reaches the release point, so bulk traffic could in principle hold
    /// every pipe and force each token to allocate a fresh one. Measured with
    /// 10k streaming connections alongside 256 bulk connections saturating the
    /// passthrough path at 12.8 GB/s, 2 runs per arm:
    ///
    /// | | off | on |
    /// |---|---|---|
    /// | pipe fds | 9 024 (= 2000*4 + 256*4) | **8** |
    /// | bulk throughput | 12.8 GB/s | 12.8 GB/s |
    /// | stream latency p50 | 0.099 / 0.102 ms | 0.093 / 0.089 ms |
    /// | bulk latency p999 | 14.3 / 11.4 ms | 6.9 / 7.7 ms |
    ///
    /// The pool never degenerates because even a saturated bulk connection is
    /// idle for tens of microseconds between chunks (measured inter-record gap
    /// 62 us) and releases in that window. Throughput is identical and both
    /// traffic classes are slightly better off with `on`, so there is no bulk
    /// regression to trade against the descriptor saving.
    #[serde(default)]
    pub release_idle_pipes: bool,
}

/// When an adaptive optimisation should engage on a connection.
///
/// Both gates are optional and independent, and the optimisation engages as
/// soon as *either* fires. They catch different traffic and neither subsumes
/// the other:
///
/// - `after_bytes` catches high-rate connections almost immediately -- a bulk
///   transfer trips a 64 KiB gate within milliseconds -- but is blind to
///   long-lived low-rate streams. LLM token streaming at 40 tok/s of ~64 B
///   records needs ~25 s of wall time to move 64 KiB, so a byte gate leaves the
///   whole early phase of every stream on the copy path, and never promotes
///   short conversations at all.
///   Measured: with a 64 KiB byte gate alone, connections streaming a 64 B
///   record every 25 ms promoted 25 s after they started streaming, matching
///   `65536 / (64 B * 40/s)`. Adding `after_duration = "5s"` moved that to 5 s,
///   a 5x earlier handover, with no change in added latency or RSS.
/// - `after_duration` catches exactly those long-lived low-rate streams, but is
///   blind to short high-rate ones, which finish before it fires.
///
/// With neither gate set there is nothing to wait for, so the optimisation
/// engages from the first byte. "Never engage" is expressed by omitting the
/// whole section rather than by a sentinel value here, so every state has
/// exactly one representation.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct EngageAfter {
    /// Bytes the connection must transfer first. Absent = this gate never
    /// fires.
    #[serde(default)]
    pub after_bytes: Option<u64>,
    /// Wall time the connection must stay alive first, measured from the point
    /// the relay starts (upstream already connected). Absent = this gate never
    /// fires.
    #[serde(default, with = "serde_duration::option")]
    pub after_duration: Option<Duration>,
}

impl EngageAfter {
    /// No gate configured, so there is nothing to wait for.
    pub fn is_immediate(&self) -> bool {
        self.after_bytes.is_none() && self.after_duration.is_none()
    }

    /// Whether either gate has been reached.
    ///
    /// `start` is only read when the duration gate is configured, so a
    /// bytes-only config pays no clock read per message.
    pub fn reached(&self, moved: u64, start: Instant) -> bool {
        self.after_bytes.is_some_and(|bytes| moved >= bytes)
            || self
                .after_duration
                .is_some_and(|limit| start.elapsed() >= limit)
    }
}

/// Rendered for the dashboard and the `Status` RPC, so it reads as the answer to
/// "when does this engage?" rather than as a struct dump.
impl std::fmt::Display for EngageAfter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.after_bytes, self.after_duration) {
            (None, None) => write!(f, "immediate"),
            (Some(bytes), None) => write!(f, "after {}", DisplayBytes(bytes)),
            (None, Some(after)) => write!(f, "after {after:?}"),
            (Some(bytes), Some(after)) => write!(f, "after {} or {after:?}", DisplayBytes(bytes)),
        }
    }
}

/// A byte threshold in the units the config file writes it in: binary units
/// when they divide evenly, raw bytes otherwise.
struct DisplayBytes(u64);

impl std::fmt::Display for DisplayBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const KIB: u64 = 1 << 10;
        const MIB: u64 = 1 << 20;
        match self.0 {
            bytes if bytes >= MIB && bytes % MIB == 0 => write!(f, "{} MiB", bytes / MIB),
            bytes if bytes >= KIB && bytes % KIB == 0 => write!(f, "{} KiB", bytes / KIB),
            bytes => write!(f, "{bytes} B"),
        }
    }
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

/// Application-level health polling of registered CVMs.
///
/// The gateway asks each guest agent whether the app is serving, rather than
/// having the CVM push the answer. A wedged agent then shows up as a failed
/// poll instead of as silence that has to be told apart from "nothing changed",
/// and only CVMs that asked to be gated (`RegisterCvmRequest.health_check`) are
/// polled at all.
#[derive(Debug, Clone, Deserialize)]
pub struct HealthCheckConfig {
    /// Poll instances at all. Turning this off leaves every instance eligible,
    /// which is how the gateway behaved before health polling existed.
    pub enabled: bool,
    /// Delay between polling rounds.
    ///
    /// There is little point going much below this: end-to-end detection is
    /// dominated by the app's own `healthcheck` settings, where Docker's
    /// defaults (30s interval, 3 retries) take up to 90s to mark a container
    /// unhealthy in the first place.
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    /// Timeout for a single `Worker.Health` RPC. A poll that times out counts
    /// as unhealthy -- an agent that cannot answer cannot vouch for the app.
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
    /// How many instances to poll at once, so a large fleet does not arrive as
    /// one burst of connections.
    pub concurrency: usize,
    /// Consecutive failures to *reach* an agent before a healthy instance is
    /// demoted.
    ///
    /// Only unreachability is counted. An agent that answers "unhealthy" is
    /// believed on the spot -- it can see the app and this gateway cannot.
    /// Without this, one dropped packet ejects an instance and recomputes the
    /// whole app's selection, and it costs a second invalidation coming back.
    pub failure_threshold: u32,
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
    /// Maximum WireGuard handshake age for an instance to be considered healthy.
    #[serde(default = "default_handshake_stale", with = "serde_duration")]
    pub handshake_stale: Duration,

    /// Timeout for DNS TXT record resolution (app address lookup).
    #[serde(with = "serde_duration")]
    pub dns_resolve: Duration,

    pub data_timeout_enabled: bool,
    #[serde(with = "serde_duration")]
    pub idle: Duration,
    /// No longer read. The per-operation write timer was replaced by the
    /// connection-level progress watchdog in `io_bridge`, which catches a
    /// stalled write through `idle` instead: a write that makes no progress
    /// stops bumping the direction's progress counter, and the watchdog fires.
    /// The key is still accepted so existing configs -- and the CVM app
    /// entrypoint's `TIMEOUT_WRITE` -- keep parsing.
    #[allow(dead_code)]
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
    /// How long a KV write may sit in the page cache before the write-ahead log
    /// is forced to disk. Zero forces every write before it returns.
    #[serde(with = "serde_duration")]
    pub wal_sync_interval: Duration,
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
    /// Let the app-address `localhost` resolve to 127.0.0.1, so a hostname can
    /// be routed to a service on the gateway host itself.
    ///
    /// This lives under `debug` and carries the `insecure_` prefix because the
    /// app address is not only read from the platform's own `<id>.<base_domain>`
    /// grammar: it also comes from the `_dstack-app-address` TXT record of an
    /// arbitrary custom domain. With this on, anyone who controls any DNS zone
    /// can point the gateway at its own loopback -- where the admin and debug
    /// listeners bind precisely because being unreachable is their access
    /// control -- and pick the port, since the `localhost` shortcut is not a
    /// registered instance and so bypasses `port_policy` entirely.
    #[serde(default)]
    pub insecure_localhost_backend: bool,
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

    fn engage_after(toml: &str) -> EngageAfter {
        Figment::from(Toml::string(toml))
            .extract()
            .expect("valid EngageAfter")
    }

    #[test]
    fn no_gate_engages_immediately() {
        let gate = engage_after("");
        assert!(gate.is_immediate());
        assert!(gate.after_bytes.is_none());
        assert!(gate.after_duration.is_none());
    }

    #[test]
    fn a_configured_gate_is_not_immediate() {
        assert!(!engage_after("after_bytes = 65536").is_immediate());
        assert!(!engage_after("after_duration = \"5s\"").is_immediate());
    }

    #[test]
    fn byte_gate_ignores_elapsed_time() {
        let gate = engage_after("after_bytes = 1024");
        let long_ago = Instant::now() - Duration::from_secs(3600);
        assert!(!gate.reached(1023, long_ago));
        assert!(gate.reached(1024, long_ago));
    }

    #[test]
    fn duration_gate_ignores_bytes() {
        let gate = engage_after("after_duration = \"5s\"");
        assert!(!gate.reached(u64::MAX, Instant::now()));
        assert!(gate.reached(0, Instant::now() - Duration::from_secs(5)));
    }

    #[test]
    fn gates_are_independent_and_either_fires() {
        // The case the byte gate alone cannot express: a low-rate stream that
        // stays well under `after_bytes` but outlives `after_duration`.
        let gate = engage_after("after_bytes = 65536\nafter_duration = \"5s\"");
        let just_started = Instant::now();
        assert!(!gate.reached(64, just_started));
        assert!(gate.reached(65536, just_started));
        assert!(gate.reached(64, Instant::now() - Duration::from_secs(5)));
    }

    #[test]
    fn splice_section_is_optional() {
        #[derive(Deserialize)]
        struct Holder {
            #[serde(default)]
            tcp_splice: Option<EngageAfter>,
        }
        let absent: Holder = Figment::from(Toml::string("")).extract().unwrap();
        assert!(
            absent.tcp_splice.is_none(),
            "absent section disables splice"
        );

        let present: Holder = Figment::from(Toml::string("[tcp_splice]\nafter_duration = \"5s\""))
            .extract()
            .unwrap();
        let gate = present.tcp_splice.expect("section present");
        assert_eq!(gate.after_duration, Some(Duration::from_secs(5)));
        assert!(gate.after_bytes.is_none());
    }
}
