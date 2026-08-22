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
//!
//! The key list above is documentation, not an enforced allowlist, and deliberately so.
//! A gateway terminates TLS, so a peer with code execution already holds the mesh
//! WireGuard keys, the base-domain certificate and every proxied request in plaintext;
//! restricting which keys it may replicate protects nothing that is still standing. It
//! also would not bound the store, since key shape says nothing about volume -- that is
//! what wavekv `Limits` (entry size, clock drift, capacity) is for. What such a check
//! does reach is our own rolling upgrades: a refused entry parks ack adoption for the
//! whole node pair, so a node writing a key its peer does not know silently stops the
//! two from converging. Bound what a peer can consume; do not police what it means.

mod compat;
mod https_client;
pub mod import;
mod sync_service;

#[cfg(test)]
pub(crate) use https_client::HttpsClient;
pub use https_client::{AppIdValidator, HttpsClientConfig};
pub use sync_service::{fetch_peers_from_bootnode, PersistentWriteNotifier, WaveKvSyncService};
use tracing::{error, warn};

use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv4Addr,
    path::Path,
    time::Duration,
};

use anyhow::{Context, Result};

use crate::models::InstanceInfo;
use crate::time::{encode_ts, now_secs};
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
}

/// The operator's traffic gate for one instance, under `admin/<id>/ready`.
///
/// A struct rather than a bare `bool` so the record can gain a field the way
/// every other value here can -- who set it, when, why.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceGate {
    /// false takes the instance out of its app's load-balancing rotation.
    pub ready: bool,
}

/// The operator's port-policy override for one instance, under
/// `admin/<id>/port_policy`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdminPortPolicy {
    /// `None` is an operator having cleared the override, which is not the same
    /// as never having set one. Absent lets the copy an older build left in the
    /// instance record apply; cleared does not, or clearing an override would
    /// be undone by that copy.
    #[serde(default)]
    pub policy: Option<PortPolicy>,
}

/// What an operator has decided about one instance.
///
/// A read-side view assembled from the two keys above, not a stored record.
/// Both live outside [`InstanceData`] because the writer is different, and that
/// is what decides which key a fact lives in. `inst/` states what the CVM
/// reports about itself, and is rewritten in full by whichever node the CVM
/// registers against, from that node's own memory -- so anything in it the CVM
/// does not report is dropped the moment a node that has not yet synced
/// re-registers the instance. `gateway_checker` re-registers every 180s, so
/// that window is hit routinely.
///
/// For a CVM-reported fact that is harmless: the CVM restates it. For the
/// cached `port_policy` it is harmless too: it is re-fetched. For an operator's
/// decision it is not, and the two fail in the direction that matters --
/// a lost gate silently returns a quarantined instance to rotation, and a lost
/// port-policy override silently widens the ports the app will serve. Only the
/// operator writes those keys, so a re-registration cannot touch them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminOverrides {
    pub port_policy: Option<PortPolicy>,
    pub ready: Option<bool>,
}

impl AdminOverrides {
    /// Whether an operator has actually set anything.
    pub fn is_empty(&self) -> bool {
        self.port_policy.is_none() && self.ready.is_none()
    }
}

/// The same two overrides as they were once stored: inside the instance record.
///
/// `InstanceData` no longer declares them, which is deliberate on both sides of
/// an upgrade. Reading, this type recovers them for the move to their own keys.
/// Writing, an undeclared field is one [`compat::carry_unknown_fields`]
/// preserves verbatim, so a node still on the previous build keeps finding its
/// copy where it left it for as long as the upgrade takes.
#[derive(Debug, Clone, Deserialize)]
struct LegacyInstanceOverrides {
    #[serde(default)]
    admin_port_policy: Option<PortPolicy>,
    #[serde(default)]
    ready: Option<bool>,
}

impl From<LegacyInstanceOverrides> for AdminOverrides {
    fn from(legacy: LegacyInstanceOverrides) -> Self {
        Self {
            port_policy: legacy.admin_port_policy,
            ready: legacy.ready,
        }
    }
}

/// The record this node would publish for `info`.
///
/// Every writer rewrites the whole record, so every writer has to name every
/// field -- and each hand-written copy is one more place a field added later
/// can be forgotten. `admin_port_policy` was dropped that way once already.
/// Going through one conversion makes the compiler the thing that remembers.
///
/// What an operator set is deliberately absent: it lives under `admin/`,
/// written only from the Admin RPCs, so this rewrite -- which any node performs
/// on any registration -- cannot reach it.
impl From<&InstanceInfo> for InstanceData {
    fn from(info: &InstanceInfo) -> Self {
        Self {
            app_id: info.app_id.clone(),
            ip: info.ip,
            public_key: info.public_key.clone(),
            reg_time: encode_ts(info.reg_time),
            port_policy: info.port_policy.clone(),
            port_policy_hash: info.port_policy_hash.clone(),
        }
    }
}

/// The `admin/` records currently in the KV store, split by readability.
#[derive(Debug, Default)]
pub struct LoadedOverrides {
    /// What each instance's readable override records say, keyed by instance
    /// ID. An instance appears once both keys are accounted for; a field is
    /// `None` when its key is absent, which is what lets the legacy copy in the
    /// instance record still apply.
    pub decoded: BTreeMap<String, AdminOverrides>,
    /// Which of an instance's override keys exist, readable or not.
    ///
    /// Separate from `decoded` because absent and cleared are different
    /// answers: a cleared port-policy override is a present record holding
    /// `None`, and only this tells it from a key that was never written.
    pub present: BTreeMap<String, BTreeSet<String>>,
    /// Instance IDs whose override record is present but no longer decodes,
    /// mapped to the decode error.
    ///
    /// Read as "unknown", not as "nothing is overridden". The gate is an
    /// operator saying an instance must not be given work, so an unreadable
    /// answer keeps it out of app-id rotation until the record is readable
    /// again -- re-issuing either override rewrites it. Instance-id routing is
    /// never gated, so the instance stays reachable for investigation either
    /// way, which is the property the gate itself is built on.
    pub unreadable: BTreeMap<String, String>,
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
    /// Instance IDs whose stored bytes are present but no longer decode,
    /// mapped to the decode error. Loading does not log these: the reload
    /// path reports them on transitions, and read-only listings must stay
    /// quiet no matter how often an operator runs them.
    pub undecodable: BTreeMap<String, String>,
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
    pub const ADMIN_PREFIX: &str = "admin/";
    /// Suffix of the traffic-gate key. See [`admin_ready`].
    pub const ADMIN_READY: &str = "ready";
    /// Suffix of the port-policy override key. See [`admin_port_policy`].
    pub const ADMIN_PORT_POLICY: &str = "port_policy";
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

    /// Key for an instance's operator-set traffic gate.
    ///
    /// One key per override rather than one record holding both: WaveKV
    /// resolves a conflict by taking a whole value, so two overrides sharing a
    /// key means setting one on this node discards a peer's unsynced change to
    /// the other. They are independent decisions and are set by independent
    /// calls, so they get independent keys.
    pub fn admin_ready(instance_id: &str) -> String {
        format!("{ADMIN_PREFIX}{instance_id}/{ADMIN_READY}")
    }

    /// Key for an instance's operator-set port-policy override.
    /// See [`admin_ready`] for why this is not a field of the same record.
    pub fn admin_port_policy(instance_id: &str) -> String {
        format!("{ADMIN_PREFIX}{instance_id}/{ADMIN_PORT_POLICY}")
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

    /// Parse (instance_id, override name) from an admin/{instance_id}/{name} key.
    ///
    /// Split from the right, so an instance id is not required to be free of
    /// `/` for the override name to come out right.
    pub fn parse_admin_key(key: &str) -> Option<(&str, &str)> {
        let rest = key.strip_prefix(ADMIN_PREFIX)?;
        let (instance_id, name) = rest.rsplit_once('/')?;
        (!instance_id.is_empty() && !name.is_empty()).then_some((instance_id, name))
    }

    /// Parse node_id from node/info/{node_id} key
    pub fn parse_node_info_key(key: &str) -> Option<NodeId> {
        key.strip_prefix(NODE_INFO_PREFIX)?.parse().ok()
    }
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

/// Ceiling on a decompressed sync payload.
///
/// The wire is gzipped, and gzip expands by three orders of magnitude on
/// attacker-chosen input: the 16 MiB cap on a request body is a cap on the *compressed*
/// size, which bounds nothing useful on its own. Every gateway in the cluster shares one
/// app_id, so mTLS proves only that a peer is *some* gateway of this deployment, and a
/// peer running a buggy build can send a body that decompresses to more memory than the
/// node has.
///
/// The value is far above any legitimate payload. A v2 delta is capped by
/// `max_delta_bytes` (4 MiB by default).
pub const MAX_DECOMPRESSED_SYNC_BYTES: usize = 128 * 1024 * 1024;

/// Ceiling on a compressed sync response, mirroring the 16 MiB the routes accept on a
/// request. Without it a peer's response body is read to completion before any decoding
/// bound applies.
pub const MAX_COMPRESSED_SYNC_BYTES: usize = 16 * 1024 * 1024;

/// Decompress gzip, refusing anything that expands past `limit`.
///
/// Reads one byte past the limit so a payload landing exactly on it is still accepted
/// and a larger one is rejected rather than silently truncated — `Read::take` alone
/// would hand back a short buffer that then fails to decode, reporting the wrong fault.
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

/// Encode a KV value as MessagePack.
///
/// Structs are encoded as maps keyed by field name rather than as positional
/// arrays. Field-name keys let a reader skip fields it does not know and fill
/// in `#[serde(default)]` fields it does not receive, so the value types below
/// can gain fields without breaking gateways running an older build. Decoding
/// accepts both forms, so values written by older releases stay readable.
///
/// Skipping on read is only half of a rolling upgrade: this encoding contains
/// exactly the fields the writing binary declares, so an older node rewriting a
/// record would drop the rest. [`compat`] puts them back on the way out.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::encode::to_vec_named(value).context("failed to encode value")
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::decode::from_slice(bytes).context("failed to decode value")
}

trait GetPutCodec {
    fn decode<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Option<T>;
    fn decode_strict<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Result<Option<T>>;
    fn put_encoded<T: serde::Serialize + serde::de::DeserializeOwned>(
        &mut self,
        key: String,
        value: &T,
        update: bool,
    ) -> Result<()>;
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

    /// Write a value.
    ///
    /// `update` is true when the write modifies a record that outlives it, and
    /// false when it states a complete new fact. An update keeps the fields the
    /// stored record holds and this binary does not declare; a replacement does
    /// not, because they describe the fact being replaced. See [`compat`] for
    /// why that is the caller's call, and why keeping a field is not the same
    /// as keeping every field the encoding happens to be missing.
    fn put_encoded<T: serde::Serialize + serde::de::DeserializeOwned>(
        &mut self,
        key: String,
        value: &T,
        update: bool,
    ) -> Result<()> {
        let encoded = encode(value)?;
        let declared = update.then(compat::declared_fields::<T>).flatten();
        let bytes = match declared {
            Some(declared) => match self.get(&key).and_then(|entry| entry.value) {
                Some(stored) => compat::carry_unknown_fields::<T>(&key, declared, &stored, encoded),
                None => encoded,
            },
            None => encoded,
        };
        self.put(key.clone(), bytes)
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

/// Which of an instance's records a write is touching.
///
/// Named at every call site because the delete path issues all of them and
/// reports them individually: an operator can do something about an `inst/`
/// tombstone that did not land and nothing about an ephemeral observation that
/// did not, so "a delete failed" is not a useful thing to be told.
///
/// It is also what [`KvStore::fail_writes_for_test`] aims at, which is why the
/// write paths take one instead of a `u8` that means nothing outside a test
/// build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InstanceRecord {
    /// The persistent `inst/` record, and its tombstone.
    Instance,
    /// The persistent `admin/<id>/ready` record, and its tombstone.
    Gate,
    /// The persistent `admin/<id>/port_policy` record, and its tombstone.
    PortPolicyOverride,
    /// The ephemeral `conn/` key this node owns.
    Connections,
    /// The ephemeral `handshake/` key this node owns.
    Handshake,
}

impl InstanceRecord {
    /// What an error message calls it.
    fn name(self) -> &'static str {
        match self {
            Self::Instance => "instance",
            Self::Gate => "traffic gate",
            Self::PortPolicyOverride => "port-policy override",
            Self::Connections => "connection count",
            Self::Handshake => "handshake observation",
        }
    }

    #[cfg(test)]
    fn bit(self) -> u8 {
        match self {
            Self::Instance => 0b00001,
            Self::Gate => 0b00010,
            Self::PortPolicyOverride => 0b00100,
            Self::Connections => 0b01000,
            Self::Handshake => 0b10000,
        }
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
    /// Which instance writes to fail, so the paths that report a failure can
    /// be tested at all.
    ///
    /// The real failures here are WAL I/O -- no space, permission denied, the
    /// data volume unmounted -- and none of them can be provoked from a test
    /// without a filesystem to sabotage. Faking the outcome is the only way to
    /// cover the code that reports them, which is the whole reason
    /// `persist_instance_record` returns a `Result` and the whole reason
    /// `sync_delete_instance` does not short-circuit.
    ///
    /// A bitmask of [`FailWrite`].
    #[cfg(test)]
    injected_failures: std::sync::Arc<std::sync::atomic::AtomicU8>,
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
    ///
    /// `wal_sync_interval` is how long a write may sit in the page cache before
    /// the log is forced to disk; `None` forces every write before it returns.
    /// It applies only to the persistent store — the ephemeral one keeps no log
    /// and never touches the disk.
    pub fn new(
        my_node_id: NodeId,
        peer_ids: Vec<NodeId>,
        data_dir: impl AsRef<Path>,
        wal_sync_interval: Option<Duration>,
    ) -> Result<Self> {
        let data_dir = data_dir.as_ref();
        let node_config = wavekv::NodeConfig {
            wal_sync_interval,
            ..Default::default()
        };
        let persistent = match Node::with_persistence_and_config(
            my_node_id,
            peer_ids.clone(),
            data_dir,
            node_config.clone(),
        ) {
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
                Node::with_persistence_and_config(
                    my_node_id,
                    peer_ids.clone(),
                    data_dir,
                    node_config,
                )
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
            #[cfg(test)]
            injected_failures: Default::default(),
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
        self.injected_failure(InstanceRecord::Instance)?;
        self.persistent
            .write()
            .put_encoded(keys::inst(instance_id), data, true)
    }

    // ==================== Operator Override Sync ====================

    /// Load every instance's operator-set overrides.
    ///
    /// A record that no longer decodes is reported rather than skipped. Skipping
    /// it would read as "no operator has decided anything", which is the one
    /// answer that must not be guessed: it returns a quarantined instance to
    /// rotation and drops a port-policy override back to whatever the instance
    /// says about itself. See [`LoadedOverrides::unreadable`].
    pub fn load_all_instance_overrides(&self) -> LoadedOverrides {
        let mut loaded = LoadedOverrides::default();
        let store = self.persistent.read();
        for (key, entry) in store.iter_by_prefix(keys::ADMIN_PREFIX) {
            // A tombstone is a key that was deleted, which is the same as one
            // that was never written.
            let Some(bytes) = entry.value.as_ref() else {
                continue;
            };
            let Some((instance_id, name)) = keys::parse_admin_key(key) else {
                continue;
            };
            loaded
                .present
                .entry(instance_id.to_string())
                .or_default()
                .insert(name.to_string());
            let overrides = loaded.decoded.entry(instance_id.to_string()).or_default();
            let decoded = match name {
                keys::ADMIN_READY => {
                    decode::<InstanceGate>(bytes).map(|gate| overrides.ready = Some(gate.ready))
                }
                keys::ADMIN_PORT_POLICY => decode::<AdminPortPolicy>(bytes)
                    .map(|stored| overrides.port_policy = stored.policy),
                // A key this build does not know. A newer peer may have added
                // one; leaving it alone is what lets it.
                _ => continue,
            };
            if let Err(err) = decoded {
                loaded
                    .unreadable
                    .insert(instance_id.to_string(), format!("{key}: {err:#}"));
            }
        }
        loaded
    }

    /// The overrides an instance record still carries from before they had keys
    /// of their own, for instances that have not been moved across yet.
    ///
    /// Read from the same `inst/` bytes as [`InstanceData`], through a type
    /// that declares only the retired fields.
    pub fn legacy_instance_overrides(&self) -> BTreeMap<String, AdminOverrides> {
        self.persistent
            .read()
            .iter_decoded::<LegacyInstanceOverrides>(keys::INST_PREFIX)
            .filter_map(|(key, legacy)| {
                let overrides = AdminOverrides::from(legacy);
                if overrides.is_empty() {
                    return None;
                }
                Some((keys::parse_inst_key(&key)?.to_string(), overrides))
            })
            .collect()
    }

    /// Move any overrides still living in an instance record to their own keys.
    ///
    /// Runs on every reload rather than once at startup, because the source is
    /// not only this node's own data directory: a node still on the previous
    /// build writes overrides into `inst/`, and this is how they reach the new
    /// keys during a rolling upgrade instead of being lost at that instance's
    /// next re-registration.
    ///
    /// Per override, not per instance -- which is the point of them having a
    /// key each. Only where the key does not exist at all: once it does it is
    /// the answer, including when it says "no override", which is what clearing
    /// one leaves behind. Without that rule, clearing an override here would be
    /// undone by the stale copy an old node left in the instance record.
    ///
    /// Returns the keys written. Failures are logged and skipped: the next
    /// reload tries again, and the read-side fallback keeps the override in
    /// force in the meantime.
    pub fn migrate_legacy_instance_overrides(&self) -> Vec<String> {
        let legacy = self.legacy_instance_overrides();
        if legacy.is_empty() {
            return Vec::new();
        }
        let existing = self.load_all_instance_overrides();
        let mut moved = Vec::new();
        for (instance_id, overrides) in legacy {
            let present = existing.present.get(&instance_id);
            let has = |name: &str| present.is_some_and(|names| names.contains(name));
            if let Some(ready) = overrides.ready {
                if !has(keys::ADMIN_READY) {
                    self.record_migration(
                        &mut moved,
                        InstanceRecord::Gate,
                        keys::admin_ready(&instance_id),
                        &InstanceGate { ready },
                    );
                }
            }
            if overrides.port_policy.is_some() && !has(keys::ADMIN_PORT_POLICY) {
                self.record_migration(
                    &mut moved,
                    InstanceRecord::PortPolicyOverride,
                    keys::admin_port_policy(&instance_id),
                    &AdminPortPolicy {
                        policy: overrides.port_policy,
                    },
                );
            }
        }
        moved
    }

    fn record_migration<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        moved: &mut Vec<String>,
        record: InstanceRecord,
        key: String,
        value: &T,
    ) {
        match self.put_admin_override(record, key.clone(), value) {
            Ok(()) => moved.push(key),
            Err(err) => warn!("failed to move operator override to {key}: {err:?}"),
        }
    }

    /// Publish an instance's operator-set traffic gate.
    pub fn sync_instance_gate(&self, instance_id: &str, gate: &InstanceGate) -> Result<()> {
        self.put_admin_override(InstanceRecord::Gate, keys::admin_ready(instance_id), gate)
    }

    /// Publish an instance's operator-set port-policy override.
    ///
    /// A cleared override is written, not deleted: an absent key is what lets
    /// the copy an older build left in the instance record apply, so deleting
    /// would put the override straight back.
    pub fn sync_instance_port_policy_override(
        &self,
        instance_id: &str,
        data: &AdminPortPolicy,
    ) -> Result<()> {
        self.put_admin_override(
            InstanceRecord::PortPolicyOverride,
            keys::admin_port_policy(instance_id),
            data,
        )
    }

    /// Written as a replacement rather than an update: each record states one
    /// complete fact, so carrying a field a peer wrote would leave half of one
    /// operator's decision beside half of another's.
    fn put_admin_override<T: Serialize + serde::de::DeserializeOwned>(
        &self,
        record: InstanceRecord,
        key: String,
        value: &T,
    ) -> Result<()> {
        self.injected_failure(record)
            .and_then(|()| self.persistent.write().put_encoded(key, value, false))
            .with_context(|| format!("failed to write the {} record", record.name()))
    }

    /// Fail every write touching one of `records` until called again. See
    /// [`KvStore::injected_failures`].
    #[cfg(test)]
    pub(crate) fn fail_writes_for_test(&self, records: &[InstanceRecord]) {
        let mask = records.iter().fold(0u8, |mask, record| mask | record.bit());
        self.injected_failures
            .store(mask, std::sync::atomic::Ordering::Relaxed);
    }

    /// Deliberately terse: what an operator reads is the context the write path
    /// adds, so a test that asserts on the message is asserting on the real one.
    #[cfg(test)]
    fn injected_failure(&self, record: InstanceRecord) -> Result<()> {
        let mask = self
            .injected_failures
            .load(std::sync::atomic::Ordering::Relaxed);
        anyhow::ensure!(mask & record.bit() == 0, "injected store failure");
        Ok(())
    }

    /// Nothing to inject outside a test build, so the write paths read the same
    /// in both instead of carrying a `cfg` in their bodies.
    #[cfg(not(test))]
    #[inline(always)]
    fn injected_failure(&self, _record: InstanceRecord) -> Result<()> {
        Ok(())
    }

    /// Sync instance deletion to other nodes
    ///
    /// Returns whether a live record (including an undecodable one) existed
    /// before the tombstone was written.
    pub fn sync_delete_instance(&self, instance_id: &str) -> Result<bool> {
        // Every delete is attempted even if an earlier one fails. Short-circuiting
        // on `?` would leave the later keys behind while the `inst/` tombstone is
        // already published, and nothing garbage-collects orphans. They are then
        // reported in the order they were issued, so a failure to tombstone
        // `inst/` -- the only one of the three that is persistent, and the one an
        // operator needs to know about -- is not masked by an ephemeral key that
        // also happened to fail.
        let previous = self.delete_persistent(keys::inst(instance_id), InstanceRecord::Instance);
        // The overrides outlive the instance record unless they are tombstoned
        // too, and instance ids are recycled -- an id reused after a delete
        // would inherit the gate and port policy an operator set for whatever
        // ran under it before.
        let gate = self.delete_persistent(keys::admin_ready(instance_id), InstanceRecord::Gate);
        let override_policy = self.delete_persistent(
            keys::admin_port_policy(instance_id),
            InstanceRecord::PortPolicyOverride,
        );
        let observations = self.sync_forget_local_observations(instance_id);

        let previous = previous?;
        gate?;
        override_policy?;
        observations?;
        Ok(previous.is_some_and(|entry| !entry.is_deleted()))
    }

    /// Withdraw this node's observations of an instance.
    ///
    /// `conn/` and `handshake/` are keyed by observer, so a delete can only
    /// withdraw the deleting node's own -- they are the only ones it owns.
    /// Every other node has to withdraw its own when it learns of the deletion,
    /// or its observation outlives the CVM it describes: nothing sweeps those
    /// prefixes, and a node's recycle loop cannot see an instance it has
    /// already dropped from memory. They are ephemeral, so a restart collects
    /// them, but a gateway's uptime is measured in months.
    pub fn sync_forget_local_observations(&self, instance_id: &str) -> Result<()> {
        let conn = self.delete_ephemeral(
            keys::conn(instance_id, self.my_node_id),
            InstanceRecord::Connections,
        );
        let handshake = self.delete_ephemeral(
            keys::handshake(instance_id, self.my_node_id),
            InstanceRecord::Handshake,
        );
        conn?;
        handshake?;
        Ok(())
    }

    fn delete_persistent(
        &self,
        key: String,
        record: InstanceRecord,
    ) -> Result<Option<wavekv::types::Entry>> {
        self.injected_failure(record)
            .and_then(|()| self.persistent.write().delete(key))
            .with_context(|| format!("failed to delete the {} record", record.name()))
    }

    fn delete_ephemeral(
        &self,
        key: String,
        record: InstanceRecord,
    ) -> Result<Option<wavekv::types::Entry>> {
        self.injected_failure(record)
            .and_then(|()| self.ephemeral.write().delete(key))
            .with_context(|| format!("failed to delete the {} record", record.name()))
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
                    loaded
                        .undecodable
                        .insert(instance_id.into(), format!("{err:#}"));
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
            .put_encoded(keys::node_info(node_id), data, true)
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

    /// Remove a gateway node from replicated state.
    ///
    /// Writes tombstones for the node's info, status, and sync address, and
    /// drops this node's own last_seen observation of it. The `__peer_addr`
    /// tombstone doubles as the cluster-wide removal signal: every gateway
    /// prunes its sync peer set when it observes the deletion (see
    /// [`Self::prune_removed_peers`]).
    ///
    /// Returns whether any of the node's persistent records was live before
    /// the tombstones were written, so a node known only by its sync address
    /// (registered via `SetNodeUrl` but never booted) still reports as
    /// existing.
    pub fn sync_remove_node(&self, node_id: NodeId) -> Result<bool> {
        let previous = {
            let mut persistent = self.persistent.write();
            [
                persistent.delete(keys::node_info(node_id))?,
                persistent.delete(keys::node_status(node_id))?,
                persistent.delete(keys::peer_addr(node_id))?,
            ]
        };
        self.ephemeral
            .write()
            .delete(keys::last_seen_node(node_id, self.my_node_id))?;
        Ok(previous
            .into_iter()
            .any(|entry| entry.is_some_and(|entry| !entry.is_deleted())))
    }

    // ==================== Node Status Sync ====================

    /// Set node status (stored separately from NodeData)
    pub fn set_node_status(&self, node_id: NodeId, status: NodeStatus) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::node_status(node_id), &status, false)?;
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
        self.ephemeral.write().put_encoded(
            keys::conn(instance_id, self.my_node_id),
            &count,
            false,
        )?;
        Ok(())
    }

    // ==================== Handshake Sync ====================

    /// Sync handshake timestamp for an instance (as observed by this node)
    pub fn sync_instance_handshake(&self, instance_id: &str, timestamp: u64) -> Result<()> {
        self.ephemeral.write().put_encoded(
            keys::handshake(instance_id, self.my_node_id),
            &timestamp,
            false,
        )?;
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
        self.ephemeral.write().put_encoded(
            keys::last_seen_node(node_id, self.my_node_id),
            &timestamp,
            false,
        )?;
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

    /// Watch for changes to any instance's operator-set overrides.
    ///
    /// A separate watcher because they are a separate key: a peer opening or
    /// closing a traffic gate touches `admin/` and nothing else, so the
    /// instance watcher never fires and the gate would sit in the store
    /// unapplied on every node but the one that took the RPC.
    pub fn watch_instance_overrides(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::ADMIN_PREFIX)
    }

    /// Watch for remote node changes
    pub fn watch_nodes(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::NODE_PREFIX)
    }

    /// Watch for changes to replicated peer sync addresses
    pub fn watch_peer_addrs(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::PEER_ADDR_PREFIX)
    }

    // ==================== Persistence ====================

    pub fn persist_if_dirty(&self) -> Result<bool> {
        self.persistent.persist_if_dirty()
    }

    /// Force the write-ahead log to disk if the configured window has elapsed.
    ///
    /// Returns whether an fsync happened. A no-op when no window is configured
    /// — every write was already forced — or when nothing has been written
    /// since the last one, so an idle gateway costs a lock acquisition.
    pub fn sync_wal_if_due(&self) -> Result<bool> {
        self.persistent.sync_wal_if_due()
    }

    // ==================== Peer Management ====================

    pub fn add_peer(&self, peer_id: NodeId) -> Result<()> {
        self.persistent.write().add_peer(peer_id)?;
        self.ephemeral.write().add_peer(peer_id)?;
        Ok(())
    }

    /// Drop a node from the sync peer set of both stores.
    ///
    /// Returns whether the persistent store still had it as a peer.
    pub fn remove_peer(&self, peer_id: NodeId) -> Result<bool> {
        let removed = self.persistent.write().remove_peer(peer_id)?;
        self.ephemeral.write().remove_peer(peer_id)?;
        Ok(removed)
    }

    /// Drop peers whose sync address has been explicitly deleted.
    ///
    /// A tombstoned `__peer_addr/{id}` record is the replicated signal that
    /// an operator removed the node (see [`Self::sync_remove_node`]). An
    /// address that was never written does not count: bootstrap can add a
    /// peer before its address record has synced in, and such a peer must
    /// not be dropped for being early.
    pub fn prune_removed_peers(&self) {
        let peer_ids: Vec<NodeId> = self
            .persistent
            .read()
            .status()
            .peers
            .iter()
            .map(|peer| peer.id)
            .collect();
        for peer_id in peer_ids {
            // `get` filters tombstones out, so the deletion signal is only
            // visible through the tombstone-inclusive accessor.
            let tombstoned = self
                .persistent
                .read()
                .get_including_tombstones(&keys::peer_addr(peer_id))
                .is_some_and(|entry| entry.is_deleted());
            if !tombstoned {
                continue;
            }
            warn!("dropping removed node {peer_id} from the sync peer set");
            if let Err(err) = self.remove_peer(peer_id) {
                warn!("failed to remove peer {peer_id}: {err:#}");
            }
        }
    }

    // ==================== Peer Address (in DB) ====================

    /// Register a node's sync URL in DB and add to peer list for sync
    ///
    /// This stores the URL in KvStore (for address lookup) and also adds the node
    /// to the wavekv peer list (so SyncManager knows to sync with it).
    pub fn register_peer_url(&self, node_id: NodeId, url: &str) -> Result<()> {
        validate_peer_url(url)?;

        // Store URL in persistent KvStore. Owned, because the value has to be a
        // type a reader can name: `&str` borrows from the buffer it decodes.
        self.persistent
            .write()
            .put_encoded(keys::peer_addr(node_id), &url.to_string(), false)?;

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
        if let Err(e) = self.ephemeral.write().put_encoded(key, &ts, false) {
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
            .put_encoded(keys::dns_cred(&cred.id), cred, true)?;
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
        self.persistent.write().put_encoded(
            keys::DNS_CRED_DEFAULT.to_string(),
            &cred_id.to_string(),
            false,
        )?;
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
        self.persistent.write().put_encoded(
            keys::GLOBAL_CERTBOT_CONFIG.to_string(),
            config,
            true,
        )?;
        Ok(())
    }

    // ==================== ZT-Domain Config ====================

    /// Get ZT-Domain configuration
    pub fn get_zt_domain_config(&self, domain: &str) -> Option<ZtDomainConfig> {
        self.persistent
            .read()
            .decode(&keys::zt_domain_config(domain))
    }

    /// Whether any record — readable or not — exists for the domain's config.
    ///
    /// [`Self::get_zt_domain_config`] cannot distinguish a missing record
    /// from a corrupt one; deletion must, or a corrupt record could never be
    /// removed.
    pub fn zt_domain_config_exists(&self, domain: &str) -> bool {
        // `get` already excludes tombstones, so Some means a live record.
        self.persistent
            .read()
            .get(&keys::zt_domain_config(domain))
            .is_some()
    }

    /// Save ZT-Domain configuration
    pub fn save_zt_domain_config(&self, config: &ZtDomainConfig) -> Result<()> {
        self.persistent.write().put_encoded(
            keys::zt_domain_config(&config.domain),
            config,
            true,
        )?;
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
            .put_encoded(keys::cert_data(domain), data, false)?;
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
        self.persistent.write().put_encoded(
            keys::GLOBAL_ACME_CREDENTIALS.to_string(),
            creds,
            false,
        )?;
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
        self.persistent.write().put_encoded(
            keys::GLOBAL_ACME_ATTESTATION.to_string(),
            attestation,
            false,
        )?;
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
            .put_encoded(keys::cert_lock(domain), &lock, false)
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
            .put_encoded(keys::GLOBAL_ACME_ROTATION_LOCK.to_string(), &lock, false)
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
            false,
        )?;
        // Update latest
        state.put_encoded(keys::cert_attestation_latest(domain), attestation, false)?;
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
        KvStore::new(1, vec![], data_dir, None).expect("failed to create kv store")
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
                false,
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
                false,
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
        let kv = KvStore::new(1, vec![], dir.path(), None).expect("failed to create kv store");

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

    /// The configured window has to reach the store, not just the config file.
    ///
    /// An fsync per write runs under the store lock, so it bounds how fast this
    /// gateway accepts registrations; the window is what buys that back, and it
    /// buys nothing if the interval stops at `SyncConfig`.
    ///
    /// The window here is long enough that no scheduling delay can end it
    /// mid-test: the property is "not yet due", and a stalled runner must not be
    /// able to turn that into a failure.
    #[test]
    fn a_configured_window_holds_writes_out_of_the_disk() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = KvStore::new(1, vec![], dir.path(), Some(Duration::from_secs(3_600)))
            .expect("kv store");

        kv.set_node_status(1, NodeStatus::Up).expect("write");

        assert_eq!(
            kv.persistent().read().wal_sync_count(),
            0,
            "a write inside the window must not reach the disk"
        );
        assert!(
            !kv.sync_wal_if_due().expect("sync check"),
            "nothing is due before the window elapses"
        );
    }

    /// And the window has to end. The only timing this depends on is sleeping
    /// for longer than the window, which is safe in the direction that matters.
    #[test]
    fn an_elapsed_window_forces_the_log() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let window = Duration::from_millis(20);
        let kv = KvStore::new(1, vec![], dir.path(), Some(window)).expect("kv store");

        kv.set_node_status(1, NodeStatus::Up).expect("write");
        std::thread::sleep(window * 5);

        assert!(kv.sync_wal_if_due().expect("sync"), "the window elapsed");
        assert_eq!(kv.persistent().read().wal_sync_count(), 1);
        assert!(
            !kv.sync_wal_if_due().expect("sync check"),
            "a second call with nothing written must not force the disk again"
        );
    }

    /// Without a window every write is on the disk before it returns, which is
    /// what every release before this one did and what a single-node gateway
    /// holding the only copy of its ACME account still wants.
    #[test]
    fn without_a_window_every_write_reaches_the_disk_before_it_returns() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = KvStore::new(1, vec![], dir.path(), None).expect("kv store");

        kv.set_node_status(1, NodeStatus::Up).expect("write");
        kv.set_node_status(2, NodeStatus::Down).expect("write");

        assert_eq!(kv.persistent().read().wal_sync_count(), 2);
        assert!(
            !kv.sync_wal_if_due().expect("sync check"),
            "with no window there is never anything owing"
        );
    }

    /// An instance record as some later release will declare it.
    #[derive(Debug, Serialize, Deserialize)]
    struct FutureInstanceData {
        app_id: String,
        ip: Ipv4Addr,
        public_key: String,
        reg_time: u64,
        /// The field this build has never heard of.
        health_probe_path: String,
    }

    /// The write-path half of the mixed-version contract. Skipping an unknown
    /// field on read is not enough: this build re-encodes the record from the
    /// fields it declares, so without the merge a single re-registration by an
    /// older node erases a newer node's field for the entire cluster.
    #[test]
    fn a_record_keeps_the_fields_its_writer_does_not_know() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = KvStore::new(1, vec![], dir.path(), None).expect("failed to create kv store");

        let written_by_a_newer_node = encode(&FutureInstanceData {
            app_id: "app".to_string(),
            ip: Ipv4Addr::new(10, 0, 0, 1),
            public_key: "pubkey".to_string(),
            reg_time: 1_700_000_000,
            health_probe_path: "/healthz".to_string(),
        })
        .expect("encode should succeed");
        kv.persistent
            .write()
            .put(keys::inst("app"), written_by_a_newer_node)
            .expect("put should succeed");

        // This build re-registers the instance, knowing nothing of the new field.
        kv.sync_instance(
            "app",
            &InstanceData {
                app_id: "app".to_string(),
                ip: Ipv4Addr::new(10, 0, 0, 2),
                public_key: "pubkey".to_string(),
                reg_time: 1_700_000_100,
                port_policy: None,
                port_policy_hash: String::new(),
            },
        )
        .expect("sync should succeed");

        let stored = kv
            .persistent
            .read()
            .get(&keys::inst("app"))
            .and_then(|entry| entry.value)
            .expect("record should exist");
        let seen_by_a_newer_node: FutureInstanceData =
            decode(&stored).expect("the newer node must still read its own field");
        assert_eq!(
            seen_by_a_newer_node.health_probe_path, "/healthz",
            "the unknown field must survive a write by a build that cannot see it"
        );
        assert_eq!(
            seen_by_a_newer_node.ip,
            Ipv4Addr::new(10, 0, 0, 2),
            "the writer's own fields must still take effect"
        );
        let seen_by_this_build: InstanceData =
            decode(&stored).expect("this build must still read the record");
        assert_eq!(seen_by_this_build.reg_time, 1_700_000_100);
    }

    /// A certificate is a complete new fact on every write, so nothing may be
    /// carried across one. Attributing a previous certificate's field to the one
    /// just issued is worse than dropping the field: absent is a case the newer
    /// reader already handles, stale is not.
    #[test]
    fn a_snapshot_does_not_inherit_the_previous_writes_fields() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = KvStore::new(1, vec![], dir.path(), None).expect("failed to create kv store");

        #[derive(Debug, Serialize, Deserialize)]
        struct FutureCertData {
            cert_pem: String,
            key_pem: String,
            not_after: u64,
            issued_by: NodeId,
            issued_at: u64,
            chain_pem: String,
        }

        kv.persistent
            .write()
            .put(
                keys::cert_data("a.example"),
                encode(&FutureCertData {
                    cert_pem: "old-cert".to_string(),
                    key_pem: "old-key".to_string(),
                    not_after: 1_700_000_000,
                    issued_by: 2,
                    issued_at: 1_600_000_000,
                    chain_pem: "old-chain".to_string(),
                })
                .expect("encode should succeed"),
            )
            .expect("put should succeed");

        kv.save_cert_data(
            "a.example",
            &CertData {
                cert_pem: "new-cert".to_string(),
                key_pem: "new-key".to_string(),
                not_after: 1_800_000_000,
                issued_by: 1,
                issued_at: 1_700_000_100,
            },
        )
        .expect("save should succeed");

        let stored = kv
            .persistent
            .read()
            .get(&keys::cert_data("a.example"))
            .and_then(|entry| entry.value)
            .expect("record should exist");
        assert!(
            decode::<FutureCertData>(&stored).is_err(),
            "the previous certificate's chain must not be attached to the new one"
        );
    }
}

/// Gateway-layer tests for the WaveKV sync wire and admission policy.
#[cfg(test)]
mod sync_wire_tests {
    use super::*;
    use wavekv::sync::SyncEnvelope;

    fn store(dir: &std::path::Path, id: NodeId, peers: Vec<NodeId>) -> KvStore {
        KvStore::new(id, peers, dir, None).expect("failed to create kv store")
    }

    #[test]
    fn a_sync_envelope_survives_the_transport_framing() {
        use flate2::{read::GzDecoder, write::GzEncoder, Compression};
        use std::io::{Read, Write};

        let dir = tempfile::tempdir().expect("tempdir");
        let kv = store(dir.path(), 1, vec![2]);
        kv.persistent()
            .write()
            .put(keys::peer_addr(1), b"https://a.example".to_vec())
            .expect("put");

        // Requests deliberately carry no digest: sending it would let any responder
        // echo it back and forge agreement forever. So frame a *response*, which is
        // the direction the digest actually travels.
        assert!(kv
            .persistent()
            .read()
            .prepare_sync(2, Vec::new())
            .digest
            .is_none());
        let env = kv
            .persistent()
            .write()
            .handle_envelope(SyncEnvelope::new(2, Vec::new()), Vec::new())
            .expect("respond");
        assert!(!env.entries.is_empty());

        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(&env.encode().expect("encode")).unwrap();
        let wire = encoder.finish().unwrap();

        let mut plain = Vec::new();
        GzDecoder::new(&wire[..]).read_to_end(&mut plain).unwrap();
        let decoded = SyncEnvelope::decode(&plain).expect("decode");

        assert_eq!(decoded.sender_id, 1);
        assert_eq!(decoded.entries.len(), env.entries.len());
        assert!(
            decoded.digest.is_some(),
            "the digest drives divergence detection"
        );
    }
}

/// A production WaveKV 1.0 gateway is upgraded in place while stopped. There is no
/// mixed-version cluster protocol to preserve, but its persistent snapshot and WAL are
/// an on-disk compatibility contract.
#[cfg(test)]
mod wavekv_v1_migration_tests {
    use super::*;

    #[test]
    fn an_upgraded_gateway_opens_and_preserves_a_v1_data_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key = keys::peer_addr(7);
        let value = b"https://gateway-7.example:8011".to_vec();
        let wal_key = keys::peer_addr(8);
        let wal_value = b"https://gateway-8.example:8011".to_vec();

        {
            let v1 = wavekv_v1::Node::new_with_persistence(1, Vec::new(), dir.path())
                .expect("create v1 store");
            v1.write()
                .put(key.clone(), value.clone())
                .expect("write v1 data");
            v1.persist_if_dirty().expect("persist v1 snapshot");
            v1.write()
                .put(wal_key.clone(), wal_value.clone())
                .expect("write trailing v1 WAL entry");
        }

        let upgraded =
            KvStore::new(1, Vec::new(), dir.path(), None).expect("open v1 data after upgrade");
        assert_eq!(
            upgraded
                .persistent()
                .read()
                .get(&key)
                .and_then(|entry| entry.value),
            Some(value.clone()),
            "the stopped single-node upgrade must preserve the replicated state"
        );
        assert_eq!(
            upgraded
                .persistent()
                .read()
                .get(&wal_key)
                .and_then(|entry| entry.value),
            Some(wal_value.clone()),
            "the upgrade must replay v1 WAL entries written after the snapshot"
        );

        let new_key = keys::peer_addr(9);
        let new_value = b"https://gateway-9.example:8011".to_vec();
        upgraded
            .persistent()
            .write()
            .put(new_key.clone(), new_value.clone())
            .expect("write data after upgrade");
        upgraded.persist_if_dirty().expect("persist upgraded data");
        drop(upgraded);

        let restarted =
            KvStore::new(1, Vec::new(), dir.path(), None).expect("restart upgraded store");
        for (key, expected) in [(key, value), (wal_key, wal_value), (new_key, new_value)] {
            assert_eq!(
                restarted
                    .persistent()
                    .read()
                    .get(&key)
                    .and_then(|entry| entry.value),
                Some(expected),
                "all migrated and post-upgrade data must survive an upgraded restart: {key}"
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
        KvStore::new(1, vec![], data_dir, None).expect("failed to create kv store")
    }

    fn put_raw(kv: &KvStore, key: &str, value: &[u8]) {
        kv.persistent
            .write()
            .put(key.to_string(), value.to_vec())
            .expect("raw put should succeed");
    }

    fn seed_instance(kv: &KvStore, id: &str) {
        kv.sync_instance(
            id,
            &InstanceData {
                app_id: "app".to_string(),
                ip: "10.0.0.20".parse().unwrap(),
                public_key: "key".to_string(),
                reg_time: 1,
                port_policy: None,
                port_policy_hash: String::new(),
            },
        )
        .expect("seed");
        kv.sync_connections(id, 0).expect("seed conn");
        kv.sync_instance_handshake(id, 1).expect("seed handshake");
    }

    /// Short-circuiting on `?` would publish the `inst/` tombstone and then
    /// leave the ephemeral keys behind, and nothing garbage-collects orphans.
    #[test]
    fn a_failed_delete_does_not_abandon_the_remaining_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_instance(&kv, "cvm");

        kv.fail_writes_for_test(&[InstanceRecord::Connections]);
        kv.sync_delete_instance("cvm")
            .expect_err("the conn delete was made to fail");
        kv.fail_writes_for_test(&[]);

        assert!(
            kv.persistent
                .read()
                .get(&keys::inst("cvm"))
                .is_none_or(|entry| entry.is_deleted()),
            "the inst/ tombstone should still have been written"
        );
        assert!(
            kv.ephemeral
                .read()
                .get(&keys::handshake("cvm", kv.my_node_id))
                .is_none_or(|entry| entry.is_deleted()),
            "the handshake delete must be attempted even after conn/ failed"
        );
    }

    /// `inst/` is the only persistent one of the pair an operator can do
    /// anything about, so its failure must not be masked by an ephemeral key
    /// that also happened to fail -- and the message has to say which record it
    /// was, or the ordering buys nothing.
    #[test]
    fn the_persistent_failure_is_the_one_reported() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_instance(&kv, "cvm");

        kv.fail_writes_for_test(&[
            InstanceRecord::Instance,
            InstanceRecord::Connections,
            InstanceRecord::Handshake,
        ]);
        let err = kv
            .sync_delete_instance("cvm")
            .expect_err("all three were made to fail");
        kv.fail_writes_for_test(&[]);

        let message = format!("{err:#}");
        assert!(
            message.contains(InstanceRecord::Instance.name()),
            "expected the instance record to be named, got: {message}"
        );
        assert!(
            !message.contains(InstanceRecord::Handshake.name()),
            "the ephemeral failure must not mask it, got: {message}"
        );
    }

    #[test]
    fn a_clean_delete_still_reports_that_the_record_existed() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_instance(&kv, "cvm");
        assert!(kv.sync_delete_instance("cvm").expect("delete"));
        assert!(
            !kv.sync_delete_instance("cvm").expect("second delete"),
            "a tombstone is not a live record"
        );
    }

    /// Write an instance record the way the build before the overrides moved
    /// out of it did: with both operator fields inside.
    fn seed_legacy_record(
        kv: &KvStore,
        id: &str,
        port_policy: Option<PortPolicy>,
        ready: Option<bool>,
    ) {
        #[derive(serde::Serialize)]
        struct LegacyRecord {
            app_id: String,
            ip: std::net::Ipv4Addr,
            public_key: String,
            reg_time: u64,
            port_policy: Option<PortPolicy>,
            port_policy_hash: String,
            admin_port_policy: Option<PortPolicy>,
            ready: Option<bool>,
        }
        let encoded = encode(&LegacyRecord {
            app_id: "app".to_string(),
            ip: "10.0.0.20".parse().unwrap(),
            public_key: format!("key-{id}"),
            reg_time: 1,
            port_policy: None,
            port_policy_hash: String::new(),
            admin_port_policy: port_policy,
            ready,
        })
        .expect("encode");
        put_raw(kv, &keys::inst(id), &encoded);
    }

    fn restrictive() -> PortPolicy {
        PortPolicy {
            ports: BTreeMap::from([(8443, PortFlags { pp: false })]),
            restrict_mode: true,
        }
    }

    /// A gateway upgrading from a build that kept the overrides inside the
    /// instance record has them only there, and nothing rewrites that record on
    /// the operator's behalf. Losing the port-policy override silently widens
    /// the ports the app serves, so the move has to happen on load.
    #[test]
    fn overrides_left_in_an_instance_record_are_moved_to_their_own_keys() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_legacy_record(&kv, "legacy", Some(restrictive()), Some(false));

        // Until the move, the read-side fallback is what keeps them in force.
        assert_eq!(
            kv.legacy_instance_overrides()["legacy"],
            AdminOverrides {
                port_policy: Some(restrictive()),
                ready: Some(false),
            }
        );
        assert_eq!(
            kv.migrate_legacy_instance_overrides(),
            vec![
                keys::admin_ready("legacy"),
                keys::admin_port_policy("legacy")
            ]
        );
        assert_eq!(
            kv.load_all_instance_overrides().decoded["legacy"],
            AdminOverrides {
                port_policy: Some(restrictive()),
                ready: Some(false),
            }
        );
        assert!(
            kv.migrate_legacy_instance_overrides().is_empty(),
            "the move is not repeated once the keys exist"
        );
    }

    /// One key per override, so a legacy record holding only one of them moves
    /// only that one -- and the other stays open to being set later.
    #[test]
    fn each_override_is_moved_on_its_own() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_legacy_record(&kv, "legacy", None, Some(false));
        assert_eq!(
            kv.migrate_legacy_instance_overrides(),
            vec![keys::admin_ready("legacy")]
        );
        let loaded = kv.load_all_instance_overrides();
        assert_eq!(loaded.decoded["legacy"].ready, Some(false));
        assert!(!loaded.present["legacy"].contains(keys::ADMIN_PORT_POLICY));
    }

    /// Two overrides in one record meant setting one on this node discarded a
    /// peer's unsynced change to the other, because WaveKV resolves a conflict
    /// by taking a whole value. Separate keys are what make them independent.
    #[test]
    fn setting_one_override_leaves_the_other_alone() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        // What a peer set, arriving through sync.
        kv.sync_instance_port_policy_override(
            "cvm",
            &AdminPortPolicy {
                policy: Some(restrictive()),
            },
        )
        .expect("peer override");
        // What this node sets, from a snapshot that never saw it.
        kv.sync_instance_gate("cvm", &InstanceGate { ready: false })
            .expect("gate");

        assert_eq!(
            kv.load_all_instance_overrides().decoded["cvm"],
            AdminOverrides {
                port_policy: Some(restrictive()),
                ready: Some(false),
            }
        );
    }

    /// The instance record keeps its copy through the upgrade -- this build no
    /// longer declares those fields, so `carry_unknown_fields` preserves them
    /// and a node still on the previous build finds them where it left them.
    /// That is also why an empty override record has to stop the move: without
    /// it, clearing an override here would be undone by the stale copy.
    #[test]
    fn a_cleared_override_is_not_resurrected_from_the_instance_record() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_legacy_record(&kv, "legacy", Some(restrictive()), None);
        assert_eq!(
            kv.migrate_legacy_instance_overrides(),
            vec![keys::admin_port_policy("legacy")]
        );

        // The operator clears it. Cleared is written, not deleted.
        kv.sync_instance_port_policy_override("legacy", &AdminPortPolicy::default())
            .expect("clear");
        assert!(kv.load_all_instance_overrides().decoded["legacy"].is_empty());

        assert!(
            kv.migrate_legacy_instance_overrides().is_empty(),
            "an override record that says nothing is still an answer"
        );
        assert!(
            kv.load_all_instance_overrides().decoded["legacy"].is_empty(),
            "the copy in the instance record must not come back"
        );
    }

    /// Instance ids are recycled. An id reused after a delete would inherit the
    /// gate and port policy an operator set for whatever ran under it before.
    #[test]
    fn deleting_an_instance_tombstones_its_overrides() {
        let dir = tempfile::tempdir().expect("temp dir");
        let kv = test_kv(dir.path());
        seed_instance(&kv, "cvm");
        kv.sync_instance_gate("cvm", &InstanceGate { ready: false })
            .expect("seed gate");
        kv.sync_instance_port_policy_override(
            "cvm",
            &AdminPortPolicy {
                policy: Some(restrictive()),
            },
        )
        .expect("seed override");

        kv.sync_delete_instance("cvm").expect("delete");
        assert!(
            !kv.load_all_instance_overrides().decoded.contains_key("cvm"),
            "the override record must not outlive the instance"
        );
    }

    /// A build that adds a field must not make the record unreadable to one
    /// that does not know it: msgpack named maps let the older reader skip what
    /// it does not recognise. If this ever fails, widening `InstanceData` has
    /// stopped being a no-op for older nodes.
    ///
    /// `admin_port_policy` and `ready` stand in for the retired case as well as
    /// the future one: this build no longer declares them, so they arrive here
    /// the same way a field from a newer peer would.
    #[test]
    fn an_instance_record_with_an_unknown_field_still_decodes() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv = test_kv(dir.path());

        #[derive(serde::Serialize)]
        struct FutureRecord<'a> {
            app_id: &'a str,
            ip: std::net::Ipv4Addr,
            public_key: &'a str,
            reg_time: u64,
            port_policy: Option<PortPolicy>,
            port_policy_hash: &'a str,
            admin_port_policy: Option<PortPolicy>,
            ready: Option<bool>,
            reason: &'a str,
        }
        let widened = encode(&FutureRecord {
            app_id: "app",
            ip: "10.0.0.5".parse().unwrap(),
            public_key: "k",
            reg_time: 1,
            port_policy: None,
            port_policy_hash: "",
            admin_port_policy: None,
            ready: Some(false),
            reason: "under investigation",
        })
        .expect("encode should succeed");
        put_raw(&kv, &keys::inst("future"), &widened);

        let loaded = kv.load_all_instances();
        assert!(loaded.undecodable.is_empty(), "{:?}", loaded.undecodable);
        assert_eq!(loaded.decoded["future"].public_key, "k");
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
            .put_encoded(keys::handshake("cvm", 2), &(now.saturating_sub(30)), false)
            .unwrap();
        kv.ephemeral
            .write()
            .put_encoded(keys::handshake("cvm", 3), &u64::MAX, false)
            .unwrap();
        // A peer with a broken clock must not keep a dead CVM alive forever.
        let latest = kv
            .get_instance_latest_handshake("cvm")
            .expect("the plausible observation should survive");
        assert!(latest <= now, "kept a future-dated handshake: {latest}");
        assert_eq!(kv.get_instance_handshakes("cvm").len(), 1);

        kv.ephemeral
            .write()
            .put_encoded(keys::last_seen_node(7, 3), &u64::MAX, false)
            .unwrap();
        assert_eq!(kv.get_node_latest_last_seen(7), None);
        assert!(kv.get_node_last_seen_by_all(7).is_empty());

        // Drift within the allowance stays usable: nodes are not perfectly
        // synchronized and dropping every slightly-ahead record would make
        // instances look stale.
        kv.ephemeral
            .write()
            .put_encoded(
                keys::handshake("cvm", 4),
                &(now + MAX_CLOCK_DRIFT_SECS / 2),
                false,
            )
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

        let Err(err) = KvStore::new(1, vec![], &data_dir, None) else {
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
                },
            )
            .expect("sync should succeed");
            kv.persist_if_dirty().expect("persist should succeed");
        }
        // A torn WAL tail is the normal artifact of a crash and every record is
        // replicated, so it must not keep the gateway from booting.
        std::fs::write(data_dir.join("node_1.wal"), b"garbage").expect("failed to corrupt wal");

        let kv =
            KvStore::new(1, vec![], &data_dir, None).expect("startup must survive a corrupt wal");
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
                true,
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
        assert_eq!(
            keys::parse_admin_key(&keys::admin_ready("inst-a")),
            Some(("inst-a", keys::ADMIN_READY))
        );
        assert_eq!(
            keys::parse_admin_key(&keys::admin_port_policy("inst-a")),
            Some(("inst-a", keys::ADMIN_PORT_POLICY))
        );
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
        // The overrides and the instance record are keyed by the same id and
        // iterated by prefix. Either namespace claiming the other would make an
        // operator's decision arrive as an instance record, or the reverse.
        assert_eq!(keys::parse_admin_key(&keys::inst("inst-a")), None);
        assert_eq!(keys::parse_inst_key(&keys::admin_ready("inst-a")), None);
        assert!(!keys::admin_ready("inst-a").starts_with(keys::INST_PREFIX));
        assert!(!keys::inst("inst-a").starts_with(keys::ADMIN_PREFIX));
        // `inst-a` must not swallow `inst-ab`: the id is not the last segment,
        // so the parse has to split from the right to stay unambiguous.
        assert_eq!(
            keys::parse_admin_key(&keys::admin_ready("inst-ab")),
            Some(("inst-ab", keys::ADMIN_READY))
        );
        assert_eq!(keys::parse_node_info_key(&keys::node_status(1)), None);
        assert_eq!(keys::parse_node_info_key(&keys::inst("inst-a")), None);
        // `node/info/` and `node/status/` share a stem; neither may claim the other.
        assert_eq!(keys::parse_node_info_key("node/info/not-a-number"), None);
    }
}
