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
//! - `cert/{domain}/acme` → AcmeCredentials (ACME account for this domain)
//! - `cert/{domain}/lock` → CertRenewLock
//! - `cert/{domain}/attestation/latest` → CertAttestation
//! - `cert/{domain}/attestation/{timestamp}` → CertAttestation (history)
//!
//! # Ephemeral WaveKV (no persistence, sync only)
//! - `conn/{instance_id}/{node_id}` → u64 (connection count)
//! - `last_seen/inst/{instance_id}` → u64 (timestamp)
//! - `last_seen/node/{node_id}/{seen_by_node_id}` → u64 (timestamp)

mod https_client;
mod sync_service;

pub use https_client::{AppIdValidator, HttpsClientConfig};
pub use sync_service::{fetch_peers_from_bootnode, WaveKvSyncService};
use tracing::warn;

use std::{collections::BTreeMap, net::Ipv4Addr, path::Path, time::Duration};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use wavekv::{node::NodeState, types::NodeId, Node};

/// Instance core data (persistent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstanceData {
    pub app_id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
    pub reg_time: u64,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertAttestation {
    /// Certificate public key (DER encoded)
    pub public_key: Vec<u8>,
    /// TDX Quote (JSON serialized)
    pub quote: String,
    /// Node that generated this attestation
    pub generated_by: NodeId,
    /// Timestamp when this attestation was generated
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
    /// Domain name (e.g., "*.app.example.com")
    pub domain: String,
    /// DNS credential ID to use (None = use default)
    pub dns_cred_id: Option<String>,
    /// Creation timestamp
    pub created_at: u64,
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
    pub const GLOBAL_CERTBOT_CONFIG: &str = "global/certbot_config";

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

    /// Parse cred_id from dns_cred/{cred_id} key
    pub fn parse_dns_cred_key(key: &str) -> Option<&str> {
        key.strip_prefix(DNS_CRED_PREFIX)
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

    /// Key for domain ACME credentials
    pub fn cert_acme(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/acme")
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

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::encode::to_vec(value).context("failed to encode value")
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    rmp_serde::decode::from_slice(bytes).context("failed to decode value")
}

trait GetPutCodec {
    fn decode<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Option<T>;
    fn put_encoded<T: serde::Serialize>(&mut self, key: String, value: &T) -> Result<()>;
    fn iter_decoded<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = (String, T)>;
    fn iter_decoded_values<T: for<'de> serde::Deserialize<'de>>(
        &self,
        prefix: &str,
    ) -> impl Iterator<Item = T>;
}

impl GetPutCodec for NodeState {
    fn decode<T: for<'de> serde::Deserialize<'de>>(&self, key: &str) -> Option<T> {
        self.get(key)
            .and_then(|entry| match decode(entry.value.as_ref()?) {
                Ok(value) => Some(value),
                Err(e) => {
                    warn!("failed to decode value for key {key}: {e:?}");
                    None
                }
            })
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
                    warn!("failed to decode value for key {key}: {e:?}");
                    return None;
                }
            };
            Some(value)
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

impl KvStore {
    /// Create a new sync store
    pub fn new(
        my_node_id: NodeId,
        peer_ids: Vec<NodeId>,
        data_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        let persistent =
            Node::new_with_persistence(my_node_id, peer_ids.clone(), data_dir.as_ref())
                .context("failed to create persistent wavekv node")?;

        let ephemeral = Node::new(my_node_id, peer_ids);

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

    /// Load all instances from sync store (for initial sync on startup)
    pub fn load_all_instances(&self) -> BTreeMap<String, InstanceData> {
        self.persistent
            .read()
            .iter_decoded(keys::INST_PREFIX)
            .filter_map(|(key, data)| {
                let instance_id = keys::parse_inst_key(&key)?;
                Some((instance_id.into(), data))
            })
            .collect()
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

    /// Get all handshake observations for an instance (from all nodes)
    pub fn get_instance_handshakes(&self, instance_id: &str) -> BTreeMap<NodeId, u64> {
        self.ephemeral
            .read()
            .iter_decoded(&keys::handshake_prefix(instance_id))
            .filter_map(|(key, ts)| {
                let suffix = key.strip_prefix(&keys::handshake_prefix(instance_id))?;
                let observer: NodeId = suffix.parse().ok()?;
                Some((observer, ts))
            })
            .collect()
    }

    /// Get the latest handshake timestamp for an instance (max across all nodes)
    pub fn get_instance_latest_handshake(&self, instance_id: &str) -> Option<u64> {
        self.ephemeral
            .read()
            .iter_decoded_values(&keys::handshake_prefix(instance_id))
            .max()
    }

    /// Sync node last_seen (as observed by this node)
    pub fn sync_node_last_seen(&self, node_id: NodeId, timestamp: u64) -> Result<()> {
        self.ephemeral
            .write()
            .put_encoded(keys::last_seen_node(node_id, self.my_node_id), &timestamp)?;
        Ok(())
    }

    /// Get all observations of a node's last_seen
    pub fn get_node_last_seen_by_all(&self, node_id: NodeId) -> BTreeMap<NodeId, u64> {
        self.ephemeral
            .read()
            .iter_decoded(&keys::last_seen_node_prefix(node_id))
            .filter_map(|(key, ts)| {
                let suffix = key.strip_prefix(&keys::last_seen_node_prefix(node_id))?;
                let seen_by: NodeId = suffix.parse().ok()?;
                Some((seen_by, ts))
            })
            .collect()
    }

    /// Get the latest last_seen timestamp for a node (max across all observers)
    pub fn get_node_latest_last_seen(&self, node_id: NodeId) -> Option<u64> {
        self.ephemeral
            .read()
            .iter_decoded_values(&keys::last_seen_node_prefix(node_id))
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
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
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

    /// Get a DNS credential by ID
    pub fn get_dns_credential(&self, cred_id: &str) -> Option<DnsCredential> {
        self.persistent.read().decode(&keys::dns_cred(cred_id))
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

    /// Get the default DNS credential ID
    pub fn get_default_dns_credential_id(&self) -> Option<String> {
        self.persistent.read().decode(keys::DNS_CRED_DEFAULT)
    }

    /// Set the default DNS credential ID
    pub fn set_default_dns_credential_id(&self, cred_id: &str) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::DNS_CRED_DEFAULT.to_string(), &cred_id)?;
        Ok(())
    }

    /// Get the default DNS credential (resolves the ID to the actual credential)
    pub fn get_default_dns_credential(&self) -> Option<DnsCredential> {
        let cred_id = self.get_default_dns_credential_id()?;
        self.get_dns_credential(&cred_id)
    }

    /// Watch for DNS credential changes
    pub fn watch_dns_credentials(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::DNS_CRED_PREFIX)
    }

    // ==================== Global Certbot Config ====================

    /// Get global certbot configuration (returns default if not set)
    pub fn get_certbot_config(&self) -> GlobalCertbotConfig {
        self.persistent
            .read()
            .decode(keys::GLOBAL_CERTBOT_CONFIG)
            .unwrap_or_default()
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

    /// List all ZT-Domain configurations
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
                match decode(value) {
                    Ok(config) => Some(config),
                    Err(e) => {
                        warn!("failed to decode cert config for key {key}: {e:?}");
                        None
                    }
                }
            })
            .collect()
    }

    /// Watch for ZT-Domain config changes
    pub fn watch_zt_domain_configs(&self) -> watch::Receiver<()> {
        self.persistent.watch_prefix(keys::CERT_PREFIX)
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

    /// Delete certificate data for a domain
    pub fn delete_cert_data(&self, domain: &str) -> Result<()> {
        self.persistent.write().delete(keys::cert_data(domain))?;
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
                        warn!("failed to decode cert data for key {key}: {e:?}");
                        None
                    }
                }
            })
            .collect()
    }

    // ==================== ACME Credentials ====================

    /// Get ACME credentials for a domain
    pub fn get_cert_acme(&self, domain: &str) -> Option<CertCredentials> {
        self.persistent.read().decode(&keys::cert_acme(domain))
    }

    /// Save ACME credentials for a domain
    pub fn save_cert_acme(&self, domain: &str, creds: &CertCredentials) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::cert_acme(domain), creds)?;
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(existing) = self.get_cert_lock(domain) {
            // Check if lock is still valid (not expired)
            if now < existing.started_at + lock_timeout_secs {
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

    /// Watch for certificate data changes (specific domain)
    pub fn watch_cert(&self, domain: &str) -> watch::Receiver<()> {
        self.persistent.watch_prefix(&keys::cert_data(domain))
    }
}
