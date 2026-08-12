// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV-based sync layer for dstack-gateway.
//!
//! This module provides synchronization between gateway nodes. The local ProxyState
//! remains the primary data store for fast reads, while WaveKV handles cross-node sync.
//!
//! Key schema:
//!
//! # Persistent WaveKV (needs persistence + sync)
//! - `inst/{instance_id}` → InstanceData
//! - `node/{node_id}` → NodeData
//! - `dns_cred/{cred_id}` → DnsCredential
//! - `dns_cred_default` → cred_id (default credential ID)
//! - `global/certbot_config` → GlobalCertbotConfig
//! - `cert/{domain}/config` → ZtDomainConfig
//! - `cert/{domain}/data` → CertData
//! - `global/acme_credentials` → CertCredentials (shared ACME account)
//! - `global/acme_attestation` → AcmeAttestation (TDX quote of ACME account URI)
//! - `cert/{domain}/lock` → CertRenewLock
//! - `cert/{domain}/attestation/latest` → CertAttestation
//! - `cert/{domain}/attestation/{timestamp}` → CertAttestation (history)
//!
//! # Ephemeral WaveKV (no persistence, sync only)
//! - `conn/{instance_id}/{node_id}` → u64 (connection count)
//! - `last_seen/inst/{instance_id}` → u64 (timestamp)
//! - `last_seen/node/{node_id}/{seen_by_node_id}` → u64 (timestamp)

mod https_client;
pub mod import;
mod sync_service;

pub use https_client::{AppIdValidator, HttpsClientConfig};
pub use sync_service::{fetch_peers_from_bootnode, WaveKvSyncService};
use tracing::{error, warn};

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::time::now_secs;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use wavekv::{node::NodeState, types::NodeId, Node};

/// Per-port flags applied by the gateway when proxying to a CVM port.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortFlags {
    /// Send a PROXY protocol header on outbound connections to this port.
    #[serde(default)]
    pub pp: bool,
}

/// Gateway-relevant per-port policy declared by the app in its compose file.
/// Reported atomically at CVM registration; `Option<PortPolicy>` distinguishes
/// "not reported" (legacy CVM) from "reported with no entries".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PortPolicy {
    /// Per-port flags (PROXY protocol opt-in, etc.).
    #[serde(default)]
    pub ports: BTreeMap<u16, PortFlags>,
    /// When true, only ports listed in `ports` are forwarded; connections to
    /// any other port are rejected at TCP-accept time.
    #[serde(default)]
    pub restrict_mode: bool,
}

/// Instance core data (persistent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstanceData {
    pub app_id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
    pub reg_time: u64,
    /// Port policy reported at registration. `None` means "not reported"
    /// (legacy CVM); the gateway will fall back to fetching app-compose via
    /// Info() on first connection and populate this lazily.
    #[serde(default)]
    pub port_policy: Option<PortPolicy>,
    /// Hex-encoded compose_hash that `port_policy` was learned against.
    /// When a re-registration presents a different compose_hash (app upgrade),
    /// the cache is invalidated and re-fetched lazily.
    #[serde(default)]
    pub port_policy_hash: String,
    /// Operator-set override applied via the Admin RPC. Takes precedence over
    /// the instance-reported `port_policy` when set, and survives app upgrades
    /// (compose_hash changes do not clear it). Cleared explicitly via
    /// ClearInstancePortPolicy.
    #[serde(default)]
    pub admin_port_policy: Option<PortPolicy>,
}

/// The `inst/` records currently in the KV store, split by readability.
///
/// A key that is absent or tombstoned does not appear here at all — that is the
/// signal that the instance was deleted. A key whose bytes no longer decode
/// lands in `undecodable`, which is deliberately *not* the same signal: the
/// record still exists, we just cannot read it, and dropping the instance from
/// the data plane on that basis would turn one unreadable record into an
/// outage.
#[derive(Debug, Default)]
pub struct LoadedInstances {
    /// Records that decoded successfully, keyed by instance ID.
    pub decoded: BTreeMap<String, InstanceData>,
    /// Instance IDs whose stored bytes are present but no longer decode.
    pub undecodable: BTreeSet<String>,
}

/// Gateway node status (stored separately for independent updates)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    #[default]
    Up,
    Down,
}

/// Gateway node data (persistent, rarely changes)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeData {
    pub uuid: Vec<u8>,
    pub url: String,
    pub wg_public_key: String,
    pub wg_endpoint: String,
    pub wg_ip: String,
}

/// Certificate credentials (ACME account)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertCredentials {
    pub acme_credentials: String,
}

/// ACME account attestation (TDX Quote of account URI)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcmeAttestation {
    /// ACME account URI
    pub account_uri: String,
    /// TDX Quote (JSON serialized)
    #[serde(default)]
    pub quote: String,
    /// Full attestation (JSON serialized)
    #[serde(default)]
    pub attestation: String,
    /// Node that generated this attestation
    #[serde(default)]
    pub generated_by: NodeId,
    /// Timestamp when this attestation was generated
    #[serde(default)]
    pub generated_at: u64,
}

/// Certificate data (cert + key)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertData {
    pub cert_pem: String,
    pub key_pem: String,
    pub not_after: u64,
    pub issued_by: NodeId,
    pub issued_at: u64,
}

/// Certificate renew lock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertRenewLock {
    pub started_at: u64,
    pub started_by: NodeId,
}

/// Certificate attestation (TDX Quote of certificate public key)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CertAttestation {
    /// Certificate public key (DER encoded)
    pub public_key: Vec<u8>,
    /// TDX Quote (JSON serialized)
    #[serde(default)]
    pub quote: String,
    /// Full attestation (JSON serialized)
    #[serde(default)]
    pub attestation: String,
    /// Node that generated this attestation
    #[serde(default)]
    pub generated_by: NodeId,
    /// Timestamp when this attestation was generated
    #[serde(default)]
    pub generated_at: u64,
}

/// DNS credential configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCredential {
    /// Unique identifier
    pub id: String,
    /// Display name
    pub name: String,
    /// DNS provider configuration
    pub provider: DnsProvider,
    /// Maximum DNS wait time
    #[serde(with = "serde_duration")]
    pub max_dns_wait: Duration,
    /// DNS TXT record TTL
    pub dns_txt_ttl: u32,
    /// Creation timestamp
    pub created_at: u64,
    /// Last update timestamp
    pub updated_at: u64,
}

/// DNS provider configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DnsProvider {
    Cloudflare {
        api_token: String,
        /// Cloudflare API URL (defaults to https://api.cloudflare.com/client/v4 if not set)
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_url: Option<String>,
    },
    // Future providers can be added here
}

/// ZT-Domain configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZtDomainConfig {
    /// Base domain name (e.g., "app.example.com")
    /// Certificate will be issued for "*.{domain}" automatically
    pub domain: String,
    /// DNS credential ID to use (None = use default)
    pub dns_cred_id: Option<String>,
    /// Port this domain serves on (e.g., 443)
    #[serde(default)]
    pub port: u16,
    /// Node binding (None = any node can serve this domain)
    /// If set, only this node will serve this domain
    #[serde(default)]
    pub node: Option<u32>,
    /// Priority for default base_domain selection (higher = preferred)
    /// The domain with highest priority is returned as the default base_domain in APIs
    #[serde(default)]
    pub priority: i32,
}

/// Global certbot configuration (stored in KV, synced across nodes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalCertbotConfig {
    /// Interval between renewal checks
    #[serde(with = "serde_duration")]
    pub renew_interval: Duration,
    /// Time before expiration to trigger renewal (e.g., 30 days)
    #[serde(with = "serde_duration")]
    pub renew_before_expiration: Duration,
    /// Timeout for certificate renewal operations
    #[serde(with = "serde_duration")]
    pub renew_timeout: Duration,
    /// ACME server URL (None means use default Let's Encrypt production)
    pub acme_url: String,
}

impl Default for GlobalCertbotConfig {
    fn default() -> Self {
        Self {
            renew_interval: Duration::from_secs(12 * 3600), // 12 hours
            renew_before_expiration: Duration::from_secs(30 * 86400), // 30 days
            renew_timeout: Duration::from_secs(300),        // 5 minutes
            acme_url: Default::default(),                   // default Let's Encrypt
        }
    }
}

// Key prefixes and builders
pub mod keys {
    use super::NodeId;

    pub const INST_PREFIX: &str = "inst/";
    pub const NODE_PREFIX: &str = "node/";
    pub const NODE_INFO_PREFIX: &str = "node/info/";
    pub const NODE_STATUS_PREFIX: &str = "node/status/";
    pub const CONN_PREFIX: &str = "conn/";
    pub const HANDSHAKE_PREFIX: &str = "handshake/";
    pub const LAST_SEEN_NODE_PREFIX: &str = "last_seen/node/";
    pub const PEER_ADDR_PREFIX: &str = "__peer_addr/";
    pub const CERT_PREFIX: &str = "cert/";
    pub const DNS_CRED_PREFIX: &str = "dns_cred/";
    pub const DNS_CRED_DEFAULT: &str = "dns_cred_default";
    /// Shared by the `GLOBAL_*` keys below; not itself a key.
    pub const GLOBAL_PREFIX: &str = "global/";
    pub const GLOBAL_CERTBOT_CONFIG: &str = "global/certbot_config";
    pub const GLOBAL_ACME_CREDENTIALS: &str = "global/acme_credentials";
    pub const GLOBAL_ACME_ATTESTATION: &str = "global/acme_attestation";
    pub const GLOBAL_ACME_ROTATION_LOCK: &str = "global/acme_rotation_lock";

    pub fn inst(instance_id: &str) -> String {
        format!("{INST_PREFIX}{instance_id}")
    }

    pub fn node_info(node_id: NodeId) -> String {
        format!("{NODE_INFO_PREFIX}{node_id}")
    }

    pub fn node_status(node_id: NodeId) -> String {
        format!("{NODE_STATUS_PREFIX}{node_id}")
    }

    pub fn conn(instance_id: &str, node_id: NodeId) -> String {
        format!("{CONN_PREFIX}{instance_id}/{node_id}")
    }

    /// Key for instance handshake timestamp observed by a specific node
    /// Format: handshake/{instance_id}/{observer_node_id}
    pub fn handshake(instance_id: &str, observer_node_id: NodeId) -> String {
        format!("{HANDSHAKE_PREFIX}{instance_id}/{observer_node_id}")
    }

    /// Prefix to iterate all handshake observations for an instance
    pub fn handshake_prefix(instance_id: &str) -> String {
        format!("{HANDSHAKE_PREFIX}{instance_id}/")
    }

    pub fn last_seen_node(node_id: NodeId, seen_by: NodeId) -> String {
        format!("{LAST_SEEN_NODE_PREFIX}{node_id}/{seen_by}")
    }

    pub fn last_seen_node_prefix(node_id: NodeId) -> String {
        format!("{LAST_SEEN_NODE_PREFIX}{node_id}/")
    }

    pub fn peer_addr(node_id: NodeId) -> String {
        format!("{PEER_ADDR_PREFIX}{node_id}")
    }

    // ==================== DNS Credential keys ====================

    /// Key for a DNS credential
    pub fn dns_cred(cred_id: &str) -> String {
        format!("{DNS_CRED_PREFIX}{cred_id}")
    }

    // ==================== Certificate keys (per domain) ====================

    /// Key for ZT-Domain configuration
    pub fn zt_domain_config(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/config")
    }

    /// Key for domain certificate data (cert + key)
    pub fn cert_data(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/data")
    }

    /// Key for domain certificate renew lock
    pub fn cert_lock(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/lock")
    }

    /// Key for latest attestation of a domain
    pub fn cert_attestation_latest(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/attestation/latest")
    }

    /// Key for historical attestation of a domain
    pub fn cert_attestation_history(domain: &str, timestamp: u64) -> String {
        format!("{CERT_PREFIX}{domain}/attestation/{timestamp}")
    }

    /// Prefix for all attestations of a domain (for iteration)
    pub fn cert_attestation_prefix(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/attestation/")
    }

    /// Parse domain from cert/{domain}/... key
    pub fn parse_cert_domain(key: &str) -> Option<&str> {
        let rest = key.strip_prefix(CERT_PREFIX)?;
        rest.split('/').next()
    }

    // ==================== Parse helpers ====================

    /// Parse instance_id from key
    pub fn parse_inst_key(key: &str) -> Option<&str> {
        key.strip_prefix(INST_PREFIX)
    }

    /// Parse node_id from node/info/{node_id} key
    pub fn parse_node_info_key(key: &str) -> Option<NodeId> {
        key.strip_prefix(NODE_INFO_PREFIX)?.parse().ok()
    }
}

/// Ceiling on a decompressed sync payload.
///
/// The wire is gzipped, and gzip expands by three orders of magnitude on
/// attacker-chosen input: the 16 MiB cap the sync route puts on a request body
/// is a cap on the *compressed* size, which bounds nothing useful on its own.
/// Every gateway in a cluster shares one app_id, so the RA-TLS check on the
/// route proves the sender is *some* gateway of this deployment — not that its
/// payload is well-formed.
///
/// The value is far above any legitimate payload: a sync response carries the
/// whole live state, which is bounded by the gateway's own key set (instances,
/// nodes, certificates) rather than by anything a peer controls.
pub const MAX_DECOMPRESSED_SYNC_BYTES: usize = 128 * 1024 * 1024;

/// Ceiling on a compressed sync body, mirroring the 16 MiB the route accepts on
/// a request. Without it a peer's *response* is read to completion before any
/// decompression bound applies, and the memory is already spent.
pub const MAX_COMPRESSED_SYNC_BYTES: usize = 16 * 1024 * 1024;

/// Decompress gzip, refusing anything that expands past `limit`.
///
/// Reads one byte past the limit so a payload landing exactly on it is still
/// accepted and a larger one is rejected rather than silently truncated —
/// `Read::take` alone would hand back a short buffer that then fails to decode,
/// reporting the wrong fault.
pub fn gunzip_bounded(data: &[u8], limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut out = Vec::new();
    flate2::read::GzDecoder::new(data)
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .context("failed to decompress payload")?;
    if out.len() > limit {
        anyhow::bail!("decompressed payload exceeds {limit} bytes");
    }
    Ok(out)
}

/// How far into the future a replicated observation may be timestamped before
/// this node ignores it.
///
/// `handshake/` and `last_seen/` records are wall-clock seconds written by
/// whichever node made the observation, and the gateway aggregates them with
/// `max`. Without a horizon, a single node with a fast clock — or one corrupt
/// record near `u64::MAX` — keeps a dead CVM "alive" on every node forever:
/// `recycle()` never fires and top-N routing keeps steering traffic at it.
/// 5 minutes is well above the drift between NTP-synced hosts and well below
/// the recycle timeout.
pub const MAX_CLOCK_DRIFT_SECS: u64 = 300;

/// Drop observations timestamped beyond [`MAX_CLOCK_DRIFT_SECS`] into the
/// future, logging once per call with the number dropped.
fn drop_future_observations<T>(
    observations: impl Iterator<Item = T>,
    timestamp: impl Fn(&T) -> u64,
    kind: &str,
) -> Vec<T> {
    let horizon = now_secs().saturating_add(MAX_CLOCK_DRIFT_SECS);
    let mut dropped = 0usize;
    let kept = observations
        .filter(|item| {
            let plausible = timestamp(item) <= horizon;
            dropped += usize::from(!plausible);
            plausible
        })
        .collect();
    if dropped > 0 {
        warn!("ignored {dropped} {kind} observation(s) dated more than {MAX_CLOCK_DRIFT_SECS}s ahead of local time");
    }
    kept
}

/// Encode a KV value as MessagePack.
///
/// Structs are encoded as maps keyed by field name rather than as positional
/// arrays. Field-name keys let a reader skip fields it does not know and fill
/// in `#[serde(default)]` fields it does not receive, so the value types below
/// can gain fields without breaking gateways running an older build. Decoding
/// accepts both forms, so values written by older releases stay readable.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::encode::to_vec_named(value).context("failed to encode value")
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::decode::from_slice(bytes).context("failed to decode value")
}

trait GetPutCodec {
    fn decode<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Option<T>;
    fn decode_strict<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Result<Option<T>>;
    fn put_encoded<T: serde::Serialize>(&mut self, key: String, value: &T) -> Result<()>;
    fn iter_decoded<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = (String, T)>;
    fn iter_decoded_values<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = T>;
    fn iter_decoded_strict<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = (String, Result<T>)>;
}

impl GetPutCodec for NodeState {
    fn decode<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.get(key)
            .and_then(|entry| match decode(entry.value.as_ref()?) {
                Ok(value) => Some(value),
                Err(e) => {
                    crate::metrics::record_decode_failure(key);
                    warn!("failed to decode value for key {key}: {e:?}");
                    None
                }
            })
    }

    /// Three-state read: `Ok(None)` for a key that is missing or tombstoned,
    /// `Ok(Some)` for a decodable value, `Err` for a stored value that no
    /// longer decodes.
    ///
    /// [`Self::decode`] folds corruption into `None`, which is right for
    /// per-instance records (skip the bad one, keep serving the rest) and
    /// wrong for global records, where "absent" means "apply the default" and
    /// a corrupt record would silently change cluster-wide behavior.
    fn decode_strict<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let Some(entry) = self.get(key) else {
            return Ok(None);
        };
        // A `None` value is a tombstone: the key was deliberately deleted.
        let Some(value) = entry.value.as_ref() else {
            return Ok(None);
        };
        decode(value)
            .map(Some)
            .with_context(|| format!("corrupt record at KV key {key}"))
    }

    fn put_encoded<T: serde::Serialize>(&mut self, key: String, value: &T) -> Result<()> {
        self.put(key.clone(), encode(value)?)
            .with_context(|| format!("failed to put key {key}"))?;
        Ok(())
    }

    fn iter_decoded<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = (String, T)> {
        self.iter_by_prefix(prefix).filter_map(|(key, entry)| {
            let value = match decode(entry.value.as_ref()?) {
                Ok(value) => value,
                Err(e) => {
                    crate::metrics::record_decode_failure(key);
                    warn!("failed to decode value for key {key}: {e:?}");
                    return None;
                }
            };
            Some((key.to_string(), value))
        })
    }

    fn iter_decoded_values<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = T> {
        self.iter_by_prefix(prefix).filter_map(|(key, entry)| {
            let value = match decode(entry.value.as_ref()?) {
                Ok(value) => value,
                Err(e) => {
                    crate::metrics::record_decode_failure(key);
                    warn!("failed to decode value for key {key}: {e:?}");
                    return None;
                }
            };
            Some(value)
        })
    }

    /// Like [`Self::iter_decoded`], but surfaces undecodable records instead of
    /// skipping them.
    ///
    /// Tombstoned keys are still skipped — a deleted record and an unreadable
    /// one call for opposite responses, and only this form lets the caller tell
    /// them apart.
    fn iter_decoded_strict<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = (String, Result<T>)> {
        self.iter_by_prefix(prefix).filter_map(|(key, entry)| {
            let value = entry.value.as_ref()?;
            Some((
                key.to_string(),
                decode(value).with_context(|| format!("corrupt record at KV key {key}")),
            ))
        })
    }
}

/// Sync store wrapping two WaveKV Nodes (persistent and ephemeral).
///
/// This is the sync layer - not the primary data store.
/// ProxyState remains in memory for fast reads.
#[derive(Clone)]
pub struct KvStore {
    /// Persistent WaveKV Node (with WAL)
    persistent: Node,
    /// Ephemeral WaveKV Node (in-memory only)
    ephemeral: Node,
    /// This gateway's node ID
    my_node_id: NodeId,
}

/// Whether opening the persistent store failed because the storage is
/// unavailable, rather than because the stored bytes are unreadable.
///
/// wavekv reports both through `anyhow`, so they have to be told apart by what
/// is in the error chain. Unreadable content arrives as a decode failure, a
/// checksum or header `bail!`, or a read that ran off the end of a truncated
/// file — the last of which is an `io::Error`, but only ever `UnexpectedEof` or
/// `InvalidData`. Every other `io::Error` is the storage layer talking: no
/// space left, permission denied, too many open files, the data volume not
/// mounted yet.
fn is_storage_failure(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| {
            !matches!(
                io.kind(),
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData
            )
        })
}

impl KvStore {
    /// Create a new sync store.
    ///
    /// If the on-disk WAL/snapshot cannot be *read*, the data directory is
    /// moved aside and the store starts empty rather than refusing to boot: the
    /// persistent state is replicated on every peer, a torn WAL tail is the
    /// normal artifact of a crash, and a gateway that cannot start serves no
    /// traffic at all. Nothing is deleted — the unreadable directory is kept
    /// under `<data_dir>.corrupt.<unix_ts>` for inspection.
    ///
    /// A failure of the *storage* is a different matter and fails the boot. A
    /// full disk, an exhausted fd table or a volume that has not finished
    /// mounting all say nothing about the contents, so moving the directory
    /// aside would discard intact state — and, because the condition persists
    /// across restarts, would do it again on every attempt, burying the real
    /// data under a pile of `.corrupt.*` directories. Failing here instead
    /// leaves the state alone and puts the actual cause in front of the
    /// operator, which for a single-node deployment holding the only copy of
    /// the ACME account and DNS credentials is the difference between a restart
    /// and a rebuild.
    pub fn new(
        my_node_id: NodeId,
        peer_ids: Vec<NodeId>,
        data_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        let persistent = match Node::new_with_persistence(my_node_id, peer_ids.clone(), data_dir) {
            Ok(node) => node,
            Err(err) if is_storage_failure(&err) => {
                return Err(err).with_context(|| {
                    format!(
                        "cannot open the WaveKV data dir {}; refusing to start rather than \
                         quarantine a directory whose contents are most likely intact",
                        data_dir.display()
                    )
                });
            }
            Err(err) => {
                // Keep the original open error in the context: if moving the
                // directory aside also fails, the reason the open failed is the
                // more useful half of the diagnosis and is otherwise lost.
                let quarantined = quarantine_data_dir(data_dir).with_context(|| {
                    format!(
                        "failed to open the WaveKV data dir ({err:#}) and failed to \
                         move it aside for recovery"
                    )
                })?;
                error!(
                    "WaveKV data dir {} is unreadable ({err:#}); moved it to {} and started empty — \
                     state will be re-fetched from peers",
                    data_dir.display(),
                    quarantined.display(),
                );
                Node::new_with_persistence(my_node_id, peer_ids.clone(), data_dir)
                    .context("failed to create persistent wavekv node on a fresh data dir")?
            }
        };

        // Get peers from persistent store (may have been restored from WAL)
        // and include them when creating ephemeral store
        let persistent_peers = persistent.read().status().peers;
        let mut all_peer_ids = peer_ids;
        for peer_status in persistent_peers {
            if !all_peer_ids.contains(&peer_status.id) {
                all_peer_ids.push(peer_status.id);
            }
        }

        let ephemeral = Node::new(my_node_id, all_peer_ids);

        Ok(Self {
            persistent,
            ephemeral,
            my_node_id,
        })
    }

    pub fn my_node_id(&self) -> NodeId {
        self.my_node_id
    }

    pub fn persistent(&self) -> &Node {
        &self.persistent
    }

    pub fn ephemeral(&self) -> &Node {
        &self.ephemeral
    }

    // ==================== Instance Sync ====================

    /// Sync instance data to other nodes
    pub fn sync_instance(&self, instance_id: &str, data: &InstanceData) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::inst(instance_id), data)
    }

    /// Sync instance deletion to other nodes
    pub fn sync_delete_instance(&self, instance_id: &str) -> Result<()> {
        self.persistent.write().delete(keys::inst(instance_id))?;
        self.ephemeral
            .write()
            .delete(keys::conn(instance_id, self.my_node_id))?;
        // Delete this node's handshake record
        self.ephemeral
            .write()
            .delete(keys::handshake(instance_id, self.my_node_id))?;
        Ok(())
    }

    /// Load all instances from the sync store.
    pub fn load_all_instances(&self) -> LoadedInstances {
        let mut loaded = LoadedInstances::default();
        for (key, result) in self
            .persistent
            .read()
            .iter_decoded_strict::<InstanceData>(keys::INST_PREFIX)
        {
            let Some(instance_id) = keys::parse_inst_key(&key) else {
                continue;
            };
            match result {
                Ok(data) => {
                    loaded.decoded.insert(instance_id.into(), data);
                }
                Err(err) => {
                    error!("{err:#}");
                    loaded.undecodable.insert(instance_id.into());
                }
            }
        }
        loaded
    }

    // ==================== Node Sync ====================

    /// Sync node data to other nodes
    pub fn sync_node(&self, node_id: NodeId, data: &NodeData) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::node_info(node_id), data)
    }

    /// Load all nodes from sync store
    pub fn load_all_nodes(&self) -> BTreeMap<NodeId, NodeData> {
        self.persistent
            .read()
            .iter_decoded(keys::NODE_INFO_PREFIX)
            .filter_map(|(key, data)| {
                let node_id = keys::parse_node_info_key(&key)?;
                Some((node_id, data))
            })
            .collect()
    }

    // ==================== Node Status Sync ====================

    /// Set node status (stored separately from NodeData)
    pub fn set_node_status(&self, node_id: NodeId, status: NodeStatus) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::node_status(node_id), &status)?;
        Ok(())
    }

    /// Get node status
    pub fn get_node_status(&self, node_id: NodeId) -> NodeStatus {
        self.persistent
            .read()
            .decode(&keys::node_status(node_id))
            .unwrap_or_default()
    }

    /// Load all node statuses
    pub fn load_all_node_statuses(&self) -> BTreeMap<NodeId, NodeStatus> {
        self.persistent
            .read()
            .iter_decoded(keys::NODE_STATUS_PREFIX)
            .filter_map(|(key, status)| {
                let node_id: NodeId = key.strip_prefix(keys::NODE_STATUS_PREFIX)?.parse().ok()?;
                Some((node_id, status))
            })
            .collect()
    }

    /// Whether a node counts as active. A node with no recorded status is up.
    ///
    /// The routing path and the metrics sampler both filter on this, and they
    /// have to agree: a gauge that counts a node the router has dropped is
    /// describing a routing table that does not exist.
    pub(crate) fn node_is_active(status: Option<&NodeStatus>) -> bool {
        !matches!(status, Some(NodeStatus::Down))
    }

    /// Count all and active nodes, without materialising `GatewayNodeInfo`.
    ///
    /// A scrape wants two numbers. Reaching them through `get_all_nodes()` and
    /// `get_active_nodes()` instead means loading the node table twice, cloning
    /// five strings per node, and taking the ephemeral lock once per node for a
    /// `last_seen` that the count never reads -- all of it under the proxy lock
    /// that the data path takes on every connection.
    pub fn count_nodes(&self) -> (u64, u64) {
        let statuses = self.load_all_node_statuses();
        let nodes = self.load_all_nodes();
        let active = nodes
            .keys()
            .filter(|id| Self::node_is_active(statuses.get(id)))
            .count() as u64;
        (nodes.len() as u64, active)
    }

    // ==================== Connection Count Sync ====================

    /// Sync connection count for an instance (from this node)
    pub fn sync_connections(&self, instance_id: &str, count: u64) -> Result<()> {
        self.ephemeral
            .write()
            .put_encoded(keys::conn(instance_id, self.my_node_id), &count)?;
        Ok(())
    }

    // ==================== Handshake Sync ====================

    /// Sync handshake timestamp for an instance (as observed by this node)
    pub fn sync_instance_handshake(&self, instance_id: &str, timestamp: u64) -> Result<()> {
        self.ephemeral
            .write()
            .put_encoded(keys::handshake(instance_id, self.my_node_id), &timestamp)?;
        Ok(())
    }

    /// Get all handshake observations for an instance (from all nodes).
    ///
    /// Observations dated into the future are dropped; see
    /// [`MAX_CLOCK_DRIFT_SECS`].
    pub fn get_instance_handshakes(&self, instance_id: &str) -> BTreeMap<NodeId, u64> {
        let observations = self
            .ephemeral
            .read()
            .iter_decoded(&keys::handshake_prefix(instance_id))
            .filter_map(|(key, ts)| {
                let suffix = key.strip_prefix(&keys::handshake_prefix(instance_id))?;
                let observer: NodeId = suffix.parse().ok()?;
                Some((observer, ts))
            })
            .collect::<Vec<_>>();
        drop_future_observations(observations.into_iter(), |(_, ts)| *ts, "handshake")
            .into_iter()
            .collect()
    }

    /// Get the latest handshake timestamp for an instance (max across all
    /// nodes), ignoring future-dated observations.
    pub fn get_instance_latest_handshake(&self, instance_id: &str) -> Option<u64> {
        let observations = self
            .ephemeral
            .read()
            .iter_decoded_values(&keys::handshake_prefix(instance_id))
            .collect::<Vec<u64>>();
        drop_future_observations(observations.into_iter(), |ts| *ts, "handshake")
            .into_iter()
            .max()
    }

    /// Sync node last_seen (as observed by this node)
    pub fn sync_node_last_seen(&self, node_id: NodeId, timestamp: u64) -> Result<()> {
        self.ephemeral
            .write()
            .put_encoded(keys::last_seen_node(node_id, self.my_node_id), &timestamp)?;
        Ok(())
    }

    /// Get all observations of a node's last_seen, ignoring future-dated ones.
    pub fn get_node_last_seen_by_all(&self, node_id: NodeId) -> BTreeMap<NodeId, u64> {
        let observations = self
            .ephemeral
            .read()
            .iter_decoded(&keys::last_seen_node_prefix(node_id))
            .filter_map(|(key, ts)| {
                let suffix = key.strip_prefix(&keys::last_seen_node_prefix(node_id))?;
                let seen_by: NodeId = suffix.parse().ok()?;
                Some((seen_by, ts))
            })
            .collect::<Vec<_>>();
        drop_future_observations(observations.into_iter(), |(_, ts)| *ts, "node last_seen")
            .into_iter()
            .collect()
    }

    /// Get the latest last_seen timestamp for a node (max across all
    /// observers), ignoring future-dated observations.
    pub fn get_node_latest_last_seen(&self, node_id: NodeId) -> Option<u64> {
        let observations = self
            .ephemeral
            .read()
            .iter_decoded_values(&keys::last_seen_node_prefix(node_id))
            .collect::<Vec<u64>>();
        drop_future_observations(observations.into_iter(), |ts| *ts, "node last_seen")
            .into_iter()
            .max()
    }

    // ==================== Watch for Remote Changes ====================

    /// Watch for remote instance changes (for updating local ProxyState)
    pub fn watch_instances(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::INST_PREFIX)
    }

    /// Watch for remote node changes
    pub fn watch_nodes(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::NODE_PREFIX)
    }

    // ==================== Persistence ====================

    pub fn persist_if_dirty(&self) -> Result<bool> {
        self.persistent.persist_if_dirty()
    }

    // ==================== Peer Management ====================

    pub fn add_peer(&self, peer_id: NodeId) -> Result<()> {
        self.persistent.write().add_peer(peer_id)?;
        self.ephemeral.write().add_peer(peer_id)?;
        Ok(())
    }

    // ==================== Peer Address (in DB) ====================

    /// Register a node's sync URL in DB and add to peer list for sync
    ///
    /// This stores the URL in KvStore (for address lookup) and also adds the node
    /// to the wavekv peer list (so SyncManager knows to sync with it).
    pub fn register_peer_url(&self, node_id: NodeId, url: &str) -> Result<()> {
        validate_peer_url(url)?;

        // Store URL in persistent KvStore
        self.persistent
            .write()
            .put_encoded(keys::peer_addr(node_id), &url)?;

        let _ = self.add_peer(node_id);
        Ok(())
    }

    /// Get a peer's sync URL from DB
    pub fn get_peer_url(&self, node_id: NodeId) -> Option<String> {
        self.persistent.read().decode(&keys::peer_addr(node_id))
    }

    /// Query the UUID for a given node ID from KvStore
    pub fn get_peer_uuid(&self, peer_id: NodeId) -> Option<Vec<u8>> {
        let node_data: NodeData = self.persistent.read().decode(&keys::node_info(peer_id))?;
        Some(node_data.uuid)
    }

    pub fn update_peer_last_seen(&self, peer_id: NodeId) {
        let ts = now_secs();
        let key = keys::last_seen_node(peer_id, self.my_node_id);
        if let Err(e) = self.ephemeral.write().put_encoded(key, &ts) {
            warn!("failed to update peer {peer_id} last_seen: {e}");
        }
    }

    /// Get all peer addresses from DB (for debugging/testing)
    pub fn get_all_peer_addrs(&self) -> BTreeMap<NodeId, String> {
        self.persistent
            .read()
            .iter_decoded(keys::PEER_ADDR_PREFIX)
            .filter_map(|(key, url)| {
                let node_id: NodeId = key.strip_prefix(keys::PEER_ADDR_PREFIX)?.parse().ok()?;
                Some((node_id, url))
            })
            .collect()
    }

    // ==================== DNS Credential Management ====================

    /// Get a DNS credential by ID.
    ///
    /// Fails closed on a corrupt record: silently reading it as "no such
    /// credential" would make the certbot fall back to the default credential
    /// and issue the domain's certificate through the wrong DNS account.
    pub fn get_dns_credential(&self, cred_id: &str) -> Result<Option<DnsCredential>> {
        self.persistent
            .read()
            .decode_strict(&keys::dns_cred(cred_id))
    }

    /// Save a DNS credential
    pub fn save_dns_credential(&self, cred: &DnsCredential) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::dns_cred(&cred.id), cred)?;
        Ok(())
    }

    /// Delete a DNS credential
    pub fn delete_dns_credential(&self, cred_id: &str) -> Result<()> {
        self.persistent.write().delete(keys::dns_cred(cred_id))?;
        Ok(())
    }

    /// List all DNS credentials
    pub fn list_dns_credentials(&self) -> Vec<DnsCredential> {
        self.persistent
            .read()
            .iter_decoded_values(keys::DNS_CRED_PREFIX)
            .collect()
    }

    /// Get the default DNS credential ID.
    ///
    /// Fails closed on a corrupt record for the same reason as
    /// [`Self::get_dns_credential`].
    pub fn get_default_dns_credential_id(&self) -> Result<Option<String>> {
        self.persistent.read().decode_strict(keys::DNS_CRED_DEFAULT)
    }

    /// Set the default DNS credential ID
    pub fn set_default_dns_credential_id(&self, cred_id: &str) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::DNS_CRED_DEFAULT.to_string(), &cred_id)?;
        Ok(())
    }

    /// Get the default DNS credential (resolves the ID to the actual credential)
    pub fn get_default_dns_credential(&self) -> Result<Option<DnsCredential>> {
        let Some(cred_id) = self.get_default_dns_credential_id()? else {
            return Ok(None);
        };
        self.get_dns_credential(&cred_id)
    }

    // ==================== Global Certbot Config ====================

    /// Get global certbot configuration (returns default if not set).
    ///
    /// Fails closed on a corrupt record: falling back to the defaults would
    /// silently switch `acme_url` back to Let's Encrypt production and reset
    /// every renewal interval on this node.
    pub fn get_certbot_config(&self) -> Result<GlobalCertbotConfig> {
        Ok(self
            .persistent
            .read()
            .decode_strict(keys::GLOBAL_CERTBOT_CONFIG)?
            .unwrap_or_default())
    }

    /// Set global certbot configuration
    pub fn set_certbot_config(&self, config: &GlobalCertbotConfig) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::GLOBAL_CERTBOT_CONFIG.to_string(), config)?;
        Ok(())
    }

    // ==================== ZT-Domain Config ====================

    /// Get ZT-Domain configuration
    pub fn get_zt_domain_config(&self, domain: &str) -> Option<ZtDomainConfig> {
        self.persistent
            .read()
            .decode(&keys::zt_domain_config(domain))
    }

    /// Save ZT-Domain configuration
    pub fn save_zt_domain_config(&self, config: &ZtDomainConfig) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::zt_domain_config(&config.domain), config)?;
        Ok(())
    }

    /// Delete ZT-Domain configuration
    pub fn delete_zt_domain_config(&self, domain: &str) -> Result<()> {
        self.persistent
            .write()
            .delete(keys::zt_domain_config(domain))?;
        Ok(())
    }

    /// List all ZT-Domain configurations.
    ///
    /// A record whose `domain` disagrees with the domain in its key is
    /// skipped: everything downstream (certificate issuance, DNS-01 challenge,
    /// `cert/{domain}/data`) is driven by the value, so honouring it would let
    /// one poisoned record request a certificate for an unrelated domain.
    pub fn list_zt_domain_configs(&self) -> Vec<ZtDomainConfig> {
        let state = self.persistent.read();
        state
            .iter_by_prefix(keys::CERT_PREFIX)
            .filter_map(|(key, entry)| {
                // Only decode config entries (not data/acme/lock/attestation)
                if !key.ends_with("/config") {
                    return None;
                }
                let value = entry.value.as_ref()?;
                let config: ZtDomainConfig = match decode(value) {
                    Ok(config) => config,
                    Err(e) => {
                        crate::metrics::record_decode_failure(key);
                        warn!("failed to decode cert config for key {key}: {e:?}");
                        return None;
                    }
                };
                let key_domain = keys::parse_cert_domain(key)?;
                if key_domain != config.domain {
                    warn!(
                        "skipping cert config at key {key}: record claims domain {}",
                        config.domain
                    );
                    return None;
                }
                Some(config)
            })
            .collect()
    }

    /// Watch for ZT-Domain config changes
    pub fn watch_zt_domain_configs(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::CERT_PREFIX)
    }

    /// Get the best ZT-Domain config for this node.
    ///
    /// Selection rules:
    /// 1. Only considers domains where node == None or node == my_node_id
    /// 2. Higher priority wins
    /// 3. If priority is equal, node == None wins (global domains preferred over node-specific)
    ///
    /// Returns (domain, port) of the best match, or None if no domains configured.
    pub fn get_best_zt_domain(&self) -> Option<(String, u16)> {
        let my_node_id = self.my_node_id;
        let configs = self.list_zt_domain_configs();

        configs
            .into_iter()
            .filter(|c| c.node.is_none() || c.node == Some(my_node_id))
            .max_by(|a, b| {
                // Compare by priority first (higher wins)
                match a.priority.cmp(&b.priority) {
                    std::cmp::Ordering::Equal => {
                        // If priority equal, None (global) wins over Some (node-specific)
                        // None < Some in Option ordering, so we reverse
                        b.node.cmp(&a.node)
                    }
                    other => other,
                }
            })
            .map(|c| (c.domain, c.port))
    }

    // ==================== Certificate Data ====================

    /// Get certificate data for a domain
    pub fn get_cert_data(&self, domain: &str) -> Option<CertData> {
        self.persistent.read().decode(&keys::cert_data(domain))
    }

    /// Save certificate data for a domain
    pub fn save_cert_data(&self, domain: &str, data: &CertData) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::cert_data(domain), data)?;
        Ok(())
    }

    /// Load all certificate data (for startup)
    pub fn load_all_cert_data(&self) -> BTreeMap<String, CertData> {
        let state = self.persistent.read();
        state
            .iter_by_prefix(keys::CERT_PREFIX)
            .filter_map(|(key, entry)| {
                // Only decode data entries (not config/acme/lock/attestation)
                if !key.ends_with("/data") {
                    return None;
                }
                let domain = keys::parse_cert_domain(key)?;
                let value = entry.value.as_ref()?;
                match decode(value) {
                    Ok(data) => Some((domain.to_string(), data)),
                    Err(e) => {
                        crate::metrics::record_decode_failure(key);
                        warn!("failed to decode cert data for key {key}: {e:?}");
                        None
                    }
                }
            })
            .collect()
    }

    // ==================== Global ACME Credentials ====================

    /// Get global ACME credentials (shared across all domains).
    ///
    /// Fails closed on a corrupt record: a missing or deleted key is
    /// `Ok(None)`, but a stored value that no longer decodes is an error.
    /// Treating corruption as absence would silently register a fresh ACME
    /// account that the existing account-bound CAA records refuse.
    pub fn get_acme_credentials(&self) -> Result<Option<CertCredentials>> {
        self.persistent
            .read()
            .decode_strict(keys::GLOBAL_ACME_CREDENTIALS)
            .context("corrupt ACME credentials record in KvStore")
    }

    /// Save global ACME credentials
    pub fn save_acme_credentials(&self, creds: &CertCredentials) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::GLOBAL_ACME_CREDENTIALS.to_string(), creds)?;
        Ok(())
    }

    /// Get global ACME attestation (TDX quote of account URI).
    ///
    /// Fails closed on a corrupt record: reporting "no attestation" for an
    /// account that does have one lets a verifier conclude the ACME account is
    /// unattested.
    pub fn get_acme_attestation(&self) -> Result<Option<AcmeAttestation>> {
        self.persistent
            .read()
            .decode_strict(keys::GLOBAL_ACME_ATTESTATION)
    }

    /// Save global ACME attestation
    pub fn save_acme_attestation(&self, attestation: &AcmeAttestation) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::GLOBAL_ACME_ATTESTATION.to_string(), attestation)?;
        Ok(())
    }

    // ==================== Certificate Renew Lock ====================

    /// Get certificate renew lock for a domain
    pub fn get_cert_lock(&self, domain: &str) -> Option<CertRenewLock> {
        self.persistent.read().decode(&keys::cert_lock(domain))
    }

    /// Try to acquire certificate renew lock
    /// Returns true if lock acquired, false if already locked by another node
    pub fn try_acquire_cert_lock(&self, domain: &str, lock_timeout_secs: u64) -> bool {
        let now = now_secs();

        if let Some(existing) = self.get_cert_lock(domain) {
            // Check if lock is still valid (not expired)
            if now < existing.started_at.saturating_add(lock_timeout_secs) {
                return false;
            }
        }

        // Acquire the lock
        let lock = CertRenewLock {
            started_at: now,
            started_by: self.my_node_id,
        };
        self.persistent
            .write()
            .put_encoded(keys::cert_lock(domain), &lock)
            .is_ok()
    }

    /// Release certificate renew lock
    pub fn release_cert_lock(&self, domain: &str) -> Result<()> {
        self.persistent.write().delete(keys::cert_lock(domain))?;
        Ok(())
    }

    /// Try to acquire the global ACME credential rotation lock.
    ///
    /// Returns the lock value that was written; pass it back to
    /// [`Self::release_rotation_lock`] so a rotation that outlived the timeout
    /// cannot delete the lock of the node that took over.
    ///
    /// Best-effort only: WaveKV is last-writer-wins without compare-and-swap,
    /// so two nodes can both acquire during a replication gap. This narrows the
    /// window for concurrent rotation from the full rotation duration to the
    /// replication latency; it is not mutual exclusion. A crashed holder is
    /// covered by the timeout.
    pub fn try_acquire_rotation_lock(&self, lock_timeout_secs: u64) -> Option<CertRenewLock> {
        let now = now_secs();

        if let Some(existing) = self.get_rotation_lock() {
            // Check if lock is still valid (not expired)
            if now < existing.started_at.saturating_add(lock_timeout_secs) {
                return None;
            }
        }

        let lock = CertRenewLock {
            started_at: now,
            started_by: self.my_node_id,
        };
        self.persistent
            .write()
            .put_encoded(keys::GLOBAL_ACME_ROTATION_LOCK.to_string(), &lock)
            .ok()?;
        Some(lock)
    }

    /// Get the global ACME credential rotation lock
    pub fn get_rotation_lock(&self) -> Option<CertRenewLock> {
        self.persistent
            .read()
            .decode(keys::GLOBAL_ACME_ROTATION_LOCK)
    }

    /// Release the global ACME credential rotation lock.
    ///
    /// Only deletes the lock when the currently visible value is the one that
    /// `acquired` wrote: a rotation that outlived the lock timeout must not
    /// delete the lock of the node that took over (which would let a third
    /// rotation start concurrently). Like acquisition, the check is
    /// best-effort under WaveKV's last-writer-wins replication.
    pub fn release_rotation_lock(&self, acquired: &CertRenewLock) -> Result<()> {
        if let Some(current) = self.get_rotation_lock() {
            if current.started_by != acquired.started_by
                || current.started_at != acquired.started_at
            {
                warn!(
                    "not releasing ACME rotation lock: node {} took it over after this rotation exceeded the lock timeout",
                    current.started_by
                );
                return Ok(());
            }
        }
        self.persistent
            .write()
            .delete(keys::GLOBAL_ACME_ROTATION_LOCK.to_string())?;
        Ok(())
    }

    // ==================== Certificate Attestation ====================

    /// Get the latest attestation for a domain
    pub fn get_cert_attestation_latest(&self, domain: &str) -> Option<CertAttestation> {
        self.persistent
            .read()
            .decode(&keys::cert_attestation_latest(domain))
    }

    /// Save attestation for a domain (saves both latest and history)
    pub fn save_cert_attestation(&self, domain: &str, attestation: &CertAttestation) -> Result<()> {
        let mut state = self.persistent.write();
        // Save to history
        state.put_encoded(
            keys::cert_attestation_history(domain, attestation.generated_at),
            attestation,
        )?;
        // Update latest
        state.put_encoded(keys::cert_attestation_latest(domain), attestation)?;
        Ok(())
    }

    /// List all attestation history for a domain (sorted by timestamp descending)
    pub fn list_cert_attestations(&self, domain: &str) -> Vec<CertAttestation> {
        let prefix = keys::cert_attestation_prefix(domain);
        let latest_key = keys::cert_attestation_latest(domain);
        let state = self.persistent.read();
        let mut attestations: Vec<CertAttestation> = state
            .iter_by_prefix(&prefix)
            .filter_map(|(key, entry)| {
                // Skip the "latest" entry
                if key == &latest_key {
                    return None;
                }
                let value = entry.value.as_ref()?;
                match decode(value) {
                    Ok(att) => Some(att),
                    Err(e) => {
                        crate::metrics::record_decode_failure(key);
                        warn!("failed to decode attestation for key {key}: {e:?}");
                        None
                    }
                }
            })
            .collect();
        // Sort by generated_at descending (newest first)
        attestations.sort_by(|a, b| b.generated_at.cmp(&a.generated_at));
        attestations
    }

    // ==================== Watch helpers ====================

    /// Watch for certificate data changes (any domain)
    pub fn watch_all_certs(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::CERT_PREFIX)
    }
}

/// Move an unreadable WaveKV data dir aside, returning the new path.
///
/// Renaming keeps the bytes for post-mortem analysis and guarantees the
/// gateway never starts on half-readable state.
fn quarantine_data_dir(data_dir: &Path) -> Result<std::path::PathBuf> {
    anyhow::ensure!(
        data_dir.exists(),
        "WaveKV data dir {} does not exist",
        data_dir.display()
    );
    let stamp = now_secs();
    for attempt in 0..u32::MAX {
        let suffix = if attempt == 0 {
            format!("corrupt.{stamp}")
        } else {
            format!("corrupt.{stamp}.{attempt}")
        };
        let mut target = data_dir.as_os_str().to_owned();
        target.push(".");
        target.push(&suffix);
        let target = std::path::PathBuf::from(target);
        if target.exists() {
            continue;
        }
        std::fs::rename(data_dir, &target)
            .with_context(|| format!("failed to rename {}", data_dir.display()))?;
        return Ok(target);
    }
    anyhow::bail!("no free quarantine path for {}", data_dir.display())
}

fn validate_peer_url(url: &str) -> Result<()> {
    let parsed = reqwest::Url::parse(url).context("invalid peer URL")?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "peer URL scheme must be http or https"
    );
    anyhow::ensure!(parsed.host_str().is_some(), "peer URL must include a host");
    anyhow::ensure!(
        parsed.username().is_empty() && parsed.password().is_none(),
        "peer URL must not contain credentials"
    );
    Ok(())
}

#[cfg(test)]
mod acme_credentials_tests {
    use super::*;

    fn test_kv(data_dir: &std::path::Path) -> KvStore {
        KvStore::new(1, vec![], data_dir).expect("failed to create kv store")
    }

    #[test]
    fn missing_and_deleted_credentials_are_absent_not_errors() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        assert!(kv
            .get_acme_credentials()
            .expect("missing key should not error")
            .is_none());

        kv.save_acme_credentials(&CertCredentials {
            acme_credentials: "{}".to_string(),
        })
        .expect("save should succeed");
        kv.persistent
            .write()
            .delete(keys::GLOBAL_ACME_CREDENTIALS.to_string())
            .expect("delete should succeed");
        assert!(kv
            .get_acme_credentials()
            .expect("tombstone should not error")
            .is_none());
    }

    #[test]
    fn corrupt_credentials_record_fails_closed() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        kv.persistent
            .write()
            .put(
                keys::GLOBAL_ACME_CREDENTIALS.to_string(),
                b"not-messagepack".to_vec(),
            )
            .expect("raw put should succeed");
        let err = kv
            .get_acme_credentials()
            .expect_err("corrupt record must not read as absent");
        assert!(
            err.to_string().contains("corrupt ACME credentials"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn lease_expiry_does_not_overflow() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        kv.persistent
            .write()
            .put_encoded(
                keys::GLOBAL_ACME_ROTATION_LOCK.to_string(),
                &CertRenewLock {
                    started_at: u64::MAX,
                    started_by: 2,
                },
            )
            .expect("lock write should succeed");

        assert!(
            kv.try_acquire_rotation_lock(600).is_none(),
            "a non-expired lock with a saturated expiry must remain held"
        );

        kv.persistent
            .write()
            .put_encoded(
                keys::cert_lock("overflow.example"),
                &CertRenewLock {
                    started_at: u64::MAX,
                    started_by: 2,
                },
            )
            .expect("certificate lock write should succeed");
        assert!(
            !kv.try_acquire_cert_lock("overflow.example", 600),
            "a non-expired certificate lock with a saturated expiry must remain held"
        );
    }
}

/// KV values replicate between gateways, so their MessagePack encoding is a wire
/// contract across a mixed-version cluster and across a node's own restart. Named
/// maps keep that contract on field names rather than field order, so a value type
/// can gain a field without breaking gateways still running an older build.
#[cfg(test)]
mod value_encoding_tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    /// A value type that has since gained a field. Stands in for an older gateway
    /// reading a record written by this build.
    #[derive(Debug, Serialize, Deserialize)]
    struct ReducedCertRenewLock {
        started_at: u64,
    }

    /// True when `bytes` opens with a MessagePack map header of any width. The header
    /// widens from fixmap to map16 at 16 entries, so matching on the fixmap range alone
    /// would start failing precisely when a value type grows past 15 fields — the case
    /// this encoding exists to support.
    fn starts_with_msgpack_map(bytes: &[u8]) -> bool {
        matches!(bytes.first().copied(), Some(0x80..=0x8f | 0xde | 0xdf))
    }

    /// The positional counterpart: fixarray, array16, or array32.
    fn starts_with_msgpack_array(bytes: &[u8]) -> bool {
        matches!(bytes.first().copied(), Some(0x90..=0x9f | 0xdc | 0xdd))
    }

    #[test]
    fn values_are_encoded_as_named_maps() {
        let encoded = encode(&CertRenewLock {
            started_at: 1_700_000_000,
            started_by: 7,
        })
        .expect("encode should succeed");

        assert!(
            starts_with_msgpack_map(&encoded),
            "values must encode as MessagePack maps, not positional arrays"
        );
    }

    /// New writer, old reader: a peer whose struct predates a field must skip it.
    #[test]
    fn named_values_decode_against_a_reduced_field_set() {
        let encoded = encode(&CertRenewLock {
            started_at: 1_700_000_000,
            started_by: 7,
        })
        .expect("encode should succeed");

        let reduced: ReducedCertRenewLock =
            decode(&encoded).expect("a reader without started_by must skip the field, not fail");
        assert_eq!(reduced.started_at, 1_700_000_000);
    }

    /// Old writer, new reader: records written before this change are positional
    /// arrays and must keep decoding after an upgrade.
    #[test]
    fn legacy_positional_records_are_still_readable() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = KvStore::new(1, vec![], dir.path()).expect("failed to create kv store");

        let legacy = rmp_serde::encode::to_vec(&CertRenewLock {
            started_at: 1_700_000_000,
            started_by: 7,
        })
        .expect("legacy encode should succeed");
        assert!(
            starts_with_msgpack_array(&legacy),
            "fixture must be a positional array to exercise the legacy path"
        );

        kv.persistent
            .write()
            .put(keys::cert_lock("legacy.example"), legacy)
            .expect("put should succeed");

        let decoded = kv
            .get_cert_lock("legacy.example")
            .expect("a record written by an older gateway must stay readable");
        assert_eq!(decoded.started_at, 1_700_000_000);
        assert_eq!(decoded.started_by, 7);
    }

    /// `DnsCredential` is the most demanding value type in the set: it nests an
    /// internally tagged enum and a field with a custom `serde(with)` codec, both of
    /// which behave differently across self-describing and positional encodings.
    #[test]
    fn nested_tagged_enums_and_custom_codecs_survive_both_encodings() {
        let credential = DnsCredential {
            id: "cred-1".to_string(),
            name: "primary".to_string(),
            provider: DnsProvider::Cloudflare {
                api_token: "token".to_string(),
                api_url: Some("https://api.cloudflare.com/client/v4".to_string()),
            },
            max_dns_wait: Duration::from_secs(90),
            dns_txt_ttl: 60,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_001,
        };

        for (label, encoded) in [
            ("named", encode(&credential).expect("named encode")),
            (
                "legacy positional",
                rmp_serde::encode::to_vec(&credential).expect("positional encode"),
            ),
        ] {
            let decoded: DnsCredential =
                decode(&encoded).unwrap_or_else(|err| panic!("{label} decode failed: {err}"));
            assert_eq!(decoded.id, credential.id, "{label}");
            assert_eq!(decoded.max_dns_wait, credential.max_dns_wait, "{label}");
            assert_eq!(decoded.dns_txt_ttl, credential.dns_txt_ttl, "{label}");
            let DnsProvider::Cloudflare { api_token, api_url } = decoded.provider;
            assert_eq!(api_token, "token", "{label}");
            assert_eq!(
                api_url.as_deref(),
                Some("https://api.cloudflare.com/client/v4"),
                "{label}"
            );
        }
    }
}

#[cfg(test)]
mod decompression_tests {
    use super::*;
    use std::io::Write;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(bytes).expect("write");
        encoder.finish().expect("finish")
    }

    /// A bomb rejected by size, not by decoding: gzip expands by three orders of
    /// magnitude on attacker-chosen input, so the cap on the compressed body
    /// bounds nothing on its own.
    #[test]
    fn an_expansion_past_the_limit_is_refused() {
        let bomb = gzip(&vec![0u8; 512 * 1024]);
        assert!(gunzip_bounded(&bomb, 4096).is_err());
        assert!(bomb.len() < 4096, "the fixture must be small compressed");
    }

    /// The limit is inclusive, so a payload landing exactly on it still decodes.
    /// Without this the bound could tighten by a byte and only the bomb test would
    /// still pass.
    #[test]
    fn a_payload_exactly_on_the_limit_still_decompresses() {
        let exact = gzip(&vec![7u8; 4096]);
        let out = gunzip_bounded(&exact, 4096).expect("must be accepted");
        assert_eq!(out.len(), 4096);
        assert!(gunzip_bounded(&gzip(&vec![7u8; 4097]), 4096).is_err());
    }
}

#[cfg(test)]
mod corruption_tests {
    use super::*;

    fn test_kv(data_dir: &std::path::Path) -> KvStore {
        KvStore::new(1, vec![], data_dir).expect("failed to create kv store")
    }

    fn put_raw(kv: &KvStore, key: &str, value: &[u8]) {
        kv.persistent
            .write()
            .put(key.to_string(), value.to_vec())
            .expect("raw put should succeed");
    }

    #[test]
    fn a_corrupt_certbot_config_does_not_read_as_the_default() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        // Absent means "use the defaults" — that part must keep working.
        let default = kv
            .get_certbot_config()
            .expect("missing key should not error");
        assert!(default.acme_url.is_empty());

        kv.set_certbot_config(&GlobalCertbotConfig {
            acme_url: "https://acme-staging.example/directory".to_string(),
            ..Default::default()
        })
        .expect("save should succeed");
        put_raw(&kv, keys::GLOBAL_CERTBOT_CONFIG, b"not-messagepack");
        // Reading the corrupt record as the default would silently move
        // issuance back to Let's Encrypt production.
        assert!(kv.get_certbot_config().is_err());
    }

    #[test]
    fn a_corrupt_certbot_config_can_still_be_replaced_by_an_operator() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        put_raw(&kv, keys::GLOBAL_CERTBOT_CONFIG, b"not-messagepack");

        // The key is a singleton with no delete RPC, so overwriting it is the
        // only repair path there is; the write must not inherit the read's
        // fail-closed behaviour. (Which fields an operator has to supply to be
        // allowed to overwrite is decided one layer up, in `admin_service`.)
        kv.set_certbot_config(&GlobalCertbotConfig {
            acme_url: "https://acme-staging.example/directory".to_string(),
            ..Default::default()
        })
        .expect("save should succeed");

        let repaired = kv.get_certbot_config().expect("record should be readable");
        assert_eq!(repaired.acme_url, "https://acme-staging.example/directory");
    }

    #[test]
    fn corrupt_global_records_fail_closed() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        put_raw(&kv, keys::GLOBAL_ACME_ATTESTATION, b"not-messagepack");
        put_raw(&kv, keys::DNS_CRED_DEFAULT, b"not-messagepack");
        assert!(kv.get_acme_attestation().is_err());
        assert!(kv.get_default_dns_credential_id().is_err());
        assert!(kv.get_default_dns_credential().is_err());
    }

    #[test]
    fn future_dated_observations_are_ignored() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        let now = now_secs();

        kv.ephemeral
            .write()
            .put_encoded(keys::handshake("cvm", 2), &(now.saturating_sub(30)))
            .unwrap();
        kv.ephemeral
            .write()
            .put_encoded(keys::handshake("cvm", 3), &u64::MAX)
            .unwrap();
        // A peer with a broken clock must not keep a dead CVM alive forever.
        let latest = kv
            .get_instance_latest_handshake("cvm")
            .expect("the plausible observation should survive");
        assert!(latest <= now, "kept a future-dated handshake: {latest}");
        assert_eq!(kv.get_instance_handshakes("cvm").len(), 1);

        kv.ephemeral
            .write()
            .put_encoded(keys::last_seen_node(7, 3), &u64::MAX)
            .unwrap();
        assert_eq!(kv.get_node_latest_last_seen(7), None);
        assert!(kv.get_node_last_seen_by_all(7).is_empty());

        // Drift within the allowance stays usable: nodes are not perfectly
        // synchronized and dropping every slightly-ahead record would make
        // instances look stale.
        kv.ephemeral
            .write()
            .put_encoded(keys::handshake("cvm", 4), &(now + MAX_CLOCK_DRIFT_SECS / 2))
            .unwrap();
        assert_eq!(kv.get_instance_handshakes("cvm").len(), 2);
    }

    #[test]
    fn a_storage_failure_fails_the_boot_instead_of_quarantining_intact_state() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        // Stand in for the storage being unusable — a full disk, an exhausted
        // fd table, a volume that has not finished mounting. None of these say
        // anything about the contents, and the condition survives a restart, so
        // quarantining here would discard intact state once per boot attempt.
        let data_dir = dir.path().join("kv");
        std::fs::write(&data_dir, b"not a directory").expect("failed to create blocker");

        let Err(err) = KvStore::new(1, vec![], &data_dir) else {
            panic!("startup must fail when the storage is unusable");
        };
        assert!(
            format!("{err:#}").contains("refusing to start"),
            "wrong failure: {err:#}"
        );
        let quarantined = std::fs::read_dir(dir.path())
            .expect("failed to read temp dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
            .count();
        assert_eq!(quarantined, 0, "quarantined a directory it could not read");
    }

    #[test]
    fn an_unreadable_data_dir_is_quarantined_instead_of_blocking_startup() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let data_dir = dir.path().join("kv");
        {
            let kv = test_kv(&data_dir);
            kv.sync_instance(
                "cvm",
                &InstanceData {
                    app_id: "app".to_string(),
                    ip: "10.0.0.20".parse().unwrap(),
                    public_key: "key".to_string(),
                    reg_time: 1,
                    port_policy: None,
                    port_policy_hash: String::new(),
                    admin_port_policy: None,
                },
            )
            .expect("sync should succeed");
            kv.persist_if_dirty().expect("persist should succeed");
        }
        // A torn WAL tail is the normal artifact of a crash and every record is
        // replicated, so it must not keep the gateway from booting.
        std::fs::write(data_dir.join("node_1.wal"), b"garbage").expect("failed to corrupt wal");

        let kv = KvStore::new(1, vec![], &data_dir).expect("startup must survive a corrupt wal");
        let loaded = kv.load_all_instances();
        assert!(loaded.decoded.is_empty());
        assert!(loaded.undecodable.is_empty());
        let quarantined: Vec<_> = std::fs::read_dir(dir.path())
            .expect("failed to read temp dir")
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name().to_string_lossy().contains(".corrupt."))
            .collect();
        assert_eq!(
            quarantined.len(),
            1,
            "the unreadable data dir must be kept for inspection"
        );
    }

    #[test]
    fn a_cert_config_that_disagrees_with_its_key_is_skipped() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());
        kv.save_zt_domain_config(&ZtDomainConfig {
            domain: "good.example".to_string(),
            dns_cred_id: None,
            port: 443,
            node: None,
            priority: 0,
        })
        .expect("save should succeed");
        // Same record filed under another domain's key: honouring the value
        // would request a certificate for a domain nobody configured.
        kv.persistent
            .write()
            .put_encoded(
                keys::zt_domain_config("victim.example"),
                &ZtDomainConfig {
                    domain: "attacker.example".to_string(),
                    dns_cred_id: None,
                    port: 443,
                    node: None,
                    priority: 100,
                },
            )
            .expect("raw put should succeed");

        let domains: Vec<String> = kv
            .list_zt_domain_configs()
            .into_iter()
            .map(|c| c.domain)
            .collect();
        assert_eq!(domains, vec!["good.example".to_string()]);
    }
}

#[cfg(test)]
mod peer_url_tests {
    use super::validate_peer_url;

    #[test]
    fn accepts_http_sync_urls() {
        assert!(validate_peer_url("https://gateway.example:8011/sync").is_ok());
        assert!(validate_peer_url("http://127.0.0.1:8011").is_ok());
    }

    #[test]
    fn rejects_malformed_or_unsafe_sync_urls() {
        for url in [
            "not-a-sync-url",
            "ftp://gateway.example/sync",
            "https://user:secret@gateway.example/sync",
        ] {
            assert!(validate_peer_url(url).is_err(), "accepted {url}");
        }
    }
}

/// The key namespace is the on-disk contract between releases.
///
/// Every builder and parser here survived mutation: `handshake_prefix` could return
/// `""`, `parse_inst_key` could return `Some("xyzzy")`, and nothing noticed. That is not
/// a cosmetic gap — these strings are what a gateway uses to find its own state after an
/// upgrade. Changing one silently orphans every existing record: the data is still
/// replicated, still in the digest, and no longer reachable by any reader.
#[cfg(test)]
mod key_schema_tests {
    use super::keys;

    /// A prefix must actually be a prefix of the keys it is used to iterate, or a range
    /// scan silently returns nothing and the caller reads an empty collection as "none".
    #[test]
    fn every_iteration_prefix_matches_the_keys_it_must_find() {
        assert!(keys::handshake("inst-a", 7).starts_with(&keys::handshake_prefix("inst-a")));
        assert!(keys::last_seen_node(3, 7).starts_with(&keys::last_seen_node_prefix(3)));
        assert!(keys::cert_attestation_latest("a.example")
            .starts_with(&keys::cert_attestation_prefix("a.example")));
        assert!(keys::cert_attestation_history("a.example", 1234)
            .starts_with(&keys::cert_attestation_prefix("a.example")));
    }

    /// A prefix must not be so short that it also matches a neighbour's keys, which
    /// would make an iteration return another instance's or node's records.
    #[test]
    fn an_iteration_prefix_does_not_capture_a_neighbour() {
        assert!(!keys::handshake("inst-b", 7).starts_with(&keys::handshake_prefix("inst-a")));
        assert!(!keys::last_seen_node(4, 7).starts_with(&keys::last_seen_node_prefix(3)));
        assert!(!keys::cert_attestation_latest("b.example")
            .starts_with(&keys::cert_attestation_prefix("a.example")));
        // `inst-a` must not swallow `inst-ab`.
        assert!(!keys::handshake("inst-ab", 7).starts_with(&keys::handshake_prefix("inst-a")));
    }

    /// Builders and parsers must agree, or a record written by one release is invisible
    /// to the next.
    #[test]
    fn every_key_parses_back_to_what_built_it() {
        assert_eq!(keys::parse_inst_key(&keys::inst("inst-a")), Some("inst-a"));
        assert_eq!(keys::parse_node_info_key(&keys::node_info(42)), Some(42));
        assert_eq!(
            keys::parse_cert_domain(&keys::cert_attestation_latest("a.example")),
            Some("a.example")
        );
        assert_eq!(
            keys::parse_cert_domain(&keys::cert_lock("a.example")),
            Some("a.example")
        );
    }

    /// A parser must reject a key from another namespace rather than returning a value
    /// derived from it, which would cross-wire two record types.
    #[test]
    fn a_parser_refuses_a_key_from_another_namespace() {
        assert_eq!(keys::parse_inst_key(&keys::node_info(1)), None);
        assert_eq!(keys::parse_cert_domain(&keys::inst("inst-a")), None);
        assert_eq!(keys::parse_node_info_key(&keys::node_status(1)), None);
        assert_eq!(keys::parse_node_info_key(&keys::inst("inst-a")), None);
        // `node/info/` and `node/status/` share a stem; neither may claim the other.
        assert_eq!(keys::parse_node_info_key("node/info/not-a-number"), None);
    }
}
