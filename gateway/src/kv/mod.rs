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

use std::{collections::BTreeMap, net::Ipv4Addr, path::Path};

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

    // Certificate keys (per domain)
    pub fn cert_credentials(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/credentials")
    }

    pub fn cert_data(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/data")
    }

    pub fn cert_renew_lock(domain: &str) -> String {
        format!("{CERT_PREFIX}{domain}/renew_lock")
    }

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
        self.persistent.read().decode(&keys::node_info(peer_id))
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

    // ==================== Certificate Sync ====================

    /// Get certificate credentials for a domain
    pub fn get_cert_credentials(&self, domain: &str) -> Option<CertCredentials> {
        self.persistent
            .read()
            .decode(&keys::cert_credentials(domain))
    }

    /// Save certificate credentials for a domain
    pub fn save_cert_credentials(&self, domain: &str, creds: &CertCredentials) -> Result<()> {
        self.persistent
            .write()
            .put_encoded(keys::cert_credentials(domain), creds)?;
        Ok(())
    }

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

    /// Get certificate renew lock for a domain
    pub fn get_cert_renew_lock(&self, domain: &str) -> Option<CertRenewLock> {
        self.persistent
            .read()
            .decode(&keys::cert_renew_lock(domain))
    }

    /// Try to acquire certificate renew lock
    /// Returns true if lock acquired, false if already locked by another node
    pub fn try_acquire_cert_renew_lock(&self, domain: &str, lock_timeout_secs: u64) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(existing) = self.get_cert_renew_lock(domain) {
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
            .put_encoded(keys::cert_renew_lock(domain), &lock)
            .is_ok()
    }

    /// Release certificate renew lock
    pub fn release_cert_renew_lock(&self, domain: &str) -> Result<()> {
        self.persistent
            .write()
            .delete(keys::cert_renew_lock(domain))?;
        Ok(())
    }

    /// Watch for certificate data changes
    pub fn watch_cert(&self, domain: &str) -> watch::Receiver<()> {
        self.persistent.watch_prefix(&keys::cert_data(domain))
    }
}
