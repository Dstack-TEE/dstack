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
pub use sync_service::WaveKvSyncService;

use std::{collections::BTreeMap, net::Ipv4Addr, path::Path};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use wavekv::{types::NodeId, Node};

/// Instance core data (persistent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InstanceData {
    pub app_id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
    pub reg_time: u64,
}

/// Gateway node data (persistent)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NodeData {
    pub id: Vec<u8>,
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
    pub const CONN_PREFIX: &str = "conn/";
    pub const LAST_SEEN_INST_PREFIX: &str = "last_seen/inst/";
    pub const LAST_SEEN_NODE_PREFIX: &str = "last_seen/node/";
    pub const PEER_ADDR_PREFIX: &str = "__peer_addr/";
    pub const CERT_PREFIX: &str = "cert/";

    pub fn inst(instance_id: &str) -> String {
        format!("{INST_PREFIX}{instance_id}")
    }

    pub fn node(node_id: NodeId) -> String {
        format!("{NODE_PREFIX}{node_id}")
    }

    pub fn conn(instance_id: &str, node_id: NodeId) -> String {
        format!("{CONN_PREFIX}{instance_id}/{node_id}")
    }

    pub fn conn_prefix(instance_id: &str) -> String {
        format!("{CONN_PREFIX}{instance_id}/")
    }

    pub fn last_seen_inst(instance_id: &str) -> String {
        format!("{LAST_SEEN_INST_PREFIX}{instance_id}")
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

    /// Parse node_id from key
    pub fn parse_node_key(key: &str) -> Option<NodeId> {
        key.strip_prefix(NODE_PREFIX)?.parse().ok()
    }
}

pub fn encode<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap_or_default()
}

pub fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Option<T> {
    bincode::serde::decode_from_slice(bytes, bincode::config::standard())
        .ok()
        .map(|(v, _)| v)
}

/// Sync store wrapping two WaveKV Nodes (persistent and ephemeral).
///
/// This is the sync layer - not the primary data store.
/// ProxyState remains in memory for fast reads.
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
        self.persistent()
            .write()
            .put(keys::inst(instance_id), encode(data))?;
        Ok(())
    }

    /// Sync instance deletion to other nodes
    pub fn sync_delete_instance(&self, instance_id: &str) -> Result<()> {
        self.persistent().write().delete(keys::inst(instance_id))?;
        self.ephemeral()
            .write()
            .delete(keys::last_seen_inst(instance_id))?;
        self.ephemeral()
            .write()
            .delete(keys::conn(instance_id, self.my_node_id))?;
        Ok(())
    }

    /// Load all instances from sync store (for initial sync on startup)
    pub fn load_all_instances(&self) -> BTreeMap<String, InstanceData> {
        self.persistent()
            .read()
            .iter_by_prefix(keys::INST_PREFIX)
            .filter_map(|(key, entry)| {
                let instance_id = keys::parse_inst_key(key)?;
                let data: InstanceData = decode(entry.value.as_ref()?)?;
                Some((instance_id.to_string(), data))
            })
            .collect()
    }

    // ==================== Node Sync ====================

    /// Sync node data to other nodes
    pub fn sync_node(&self, node_id: NodeId, data: &NodeData) -> Result<()> {
        self.persistent()
            .write()
            .put(keys::node(node_id), encode(data))?;
        Ok(())
    }

    /// Sync node deletion
    pub fn sync_delete_node(&self, node_id: NodeId) -> Result<()> {
        self.persistent().write().delete(keys::node(node_id))?;
        Ok(())
    }

    /// Load all nodes from sync store
    pub fn load_all_nodes(&self) -> BTreeMap<NodeId, NodeData> {
        self.persistent()
            .read()
            .iter_by_prefix(keys::NODE_PREFIX)
            .filter_map(|(key, entry)| {
                let node_id = keys::parse_node_key(key)?;
                let data: NodeData = decode(entry.value.as_ref()?)?;
                Some((node_id, data))
            })
            .collect()
    }

    // ==================== Connection Count Sync ====================

    /// Sync connection count for an instance (from this node)
    pub fn sync_connections(&self, instance_id: &str, count: u64) -> Result<()> {
        self.ephemeral()
            .write()
            .put(keys::conn(instance_id, self.my_node_id), encode(&count))?;
        Ok(())
    }

    /// Get total connections for an instance (sum from all nodes)
    pub fn get_total_connections(&self, instance_id: &str) -> u64 {
        self.ephemeral()
            .read()
            .iter_by_prefix(&keys::conn_prefix(instance_id))
            .filter_map(|(_, entry)| decode::<u64>(entry.value.as_ref()?))
            .sum()
    }

    // ==================== Last Seen Sync ====================

    /// Sync instance last_seen
    pub fn sync_instance_last_seen(&self, instance_id: &str, timestamp: u64) -> Result<()> {
        self.ephemeral()
            .write()
            .put(keys::last_seen_inst(instance_id), encode(&timestamp))?;
        Ok(())
    }

    /// Get instance last_seen
    pub fn get_instance_last_seen(&self, instance_id: &str) -> Option<u64> {
        self.ephemeral()
            .read()
            .get(&keys::last_seen_inst(instance_id))
            .and_then(|entry| decode(entry.value.as_ref()?))
    }

    /// Load all instances' last_seen
    pub fn load_all_instances_last_seen(&self) -> BTreeMap<String, u64> {
        self.ephemeral()
            .read()
            .iter_by_prefix(keys::LAST_SEEN_INST_PREFIX)
            .filter_map(|(key, entry)| {
                let instance_id = key.strip_prefix(keys::LAST_SEEN_INST_PREFIX)?;
                let ts: u64 = decode(entry.value.as_ref()?)?;
                Some((instance_id.to_string(), ts))
            })
            .collect()
    }

    /// Sync node last_seen (as observed by this node)
    pub fn sync_node_last_seen(&self, node_id: NodeId, timestamp: u64) -> Result<()> {
        self.ephemeral().write().put(
            keys::last_seen_node(node_id, self.my_node_id),
            encode(&timestamp),
        )?;
        Ok(())
    }

    /// Get all observations of a node's last_seen
    pub fn get_node_last_seen_by_all(&self, node_id: NodeId) -> BTreeMap<NodeId, u64> {
        self.ephemeral()
            .read()
            .iter_by_prefix(&keys::last_seen_node_prefix(node_id))
            .filter_map(|(key, entry)| {
                let suffix = key.strip_prefix(&keys::last_seen_node_prefix(node_id))?;
                let seen_by: NodeId = suffix.parse().ok()?;
                let ts: u64 = decode(entry.value.as_ref()?)?;
                Some((seen_by, ts))
            })
            .collect()
    }

    // ==================== Watch for Remote Changes ====================

    /// Watch for remote instance changes (for updating local ProxyState)
    pub fn watch_instances(&self) -> watch::Receiver<()> {
        self.persistent().watch_prefix(keys::INST_PREFIX)
    }

    /// Watch for remote node changes
    pub fn watch_nodes(&self) -> watch::Receiver<()> {
        self.persistent().watch_prefix(keys::NODE_PREFIX)
    }

    // ==================== Persistence ====================

    pub fn persist_if_dirty(&self) -> Result<bool> {
        self.persistent().persist_if_dirty()
    }

    pub fn persist(&self) -> Result<()> {
        self.persistent().persist()
    }

    // ==================== Peer Management ====================

    pub fn add_peer(&self, peer_id: NodeId) -> Result<()> {
        self.persistent().write().add_peer(peer_id)?;
        self.ephemeral().write().add_peer(peer_id)?;
        Ok(())
    }

    pub fn remove_peer(&self, peer_id: NodeId) -> Result<()> {
        self.persistent().write().remove_peer(peer_id)?;
        self.ephemeral().write().remove_peer(peer_id)?;
        Ok(())
    }

    // ==================== Peer Address (in DB) ====================

    /// Register a node's sync URL in DB (will be synced to all nodes)
    pub fn register_peer_url(&self, node_id: NodeId, url: &str) -> Result<()> {
        self.persistent()
            .write()
            .put(keys::peer_addr(node_id), url.as_bytes().to_vec())?;
        Ok(())
    }

    /// Get a peer's sync URL from DB
    pub fn get_peer_url(&self, node_id: NodeId) -> Option<String> {
        self.persistent()
            .read()
            .get(&keys::peer_addr(node_id))
            .and_then(|entry| entry.value.clone())
            .and_then(|bytes| String::from_utf8(bytes).ok())
    }

    /// Get all peer addresses from DB (for debugging/testing)
    pub fn get_all_peer_addrs(&self) -> BTreeMap<NodeId, String> {
        self.persistent()
            .read()
            .iter_by_prefix(keys::PEER_ADDR_PREFIX)
            .filter_map(|(key, entry)| {
                let node_id: NodeId = key.strip_prefix(keys::PEER_ADDR_PREFIX)?.parse().ok()?;
                let url = String::from_utf8(entry.value.clone()?).ok()?;
                Some((node_id, url))
            })
            .collect()
    }

    // ==================== Certificate Sync ====================

    /// Get certificate credentials for a domain
    pub fn get_cert_credentials(&self, domain: &str) -> Option<CertCredentials> {
        self.persistent()
            .read()
            .get(&keys::cert_credentials(domain))
            .and_then(|entry| decode(entry.value.as_ref()?))
    }

    /// Save certificate credentials for a domain
    pub fn save_cert_credentials(&self, domain: &str, creds: &CertCredentials) -> Result<()> {
        self.persistent()
            .write()
            .put(keys::cert_credentials(domain), encode(creds))?;
        Ok(())
    }

    /// Get certificate data for a domain
    pub fn get_cert_data(&self, domain: &str) -> Option<CertData> {
        self.persistent()
            .read()
            .get(&keys::cert_data(domain))
            .and_then(|entry| decode(entry.value.as_ref()?))
    }

    /// Save certificate data for a domain
    pub fn save_cert_data(&self, domain: &str, data: &CertData) -> Result<()> {
        self.persistent()
            .write()
            .put(keys::cert_data(domain), encode(data))?;
        Ok(())
    }

    /// Get certificate renew lock for a domain
    pub fn get_cert_renew_lock(&self, domain: &str) -> Option<CertRenewLock> {
        self.persistent()
            .read()
            .get(&keys::cert_renew_lock(domain))
            .and_then(|entry| decode(entry.value.as_ref()?))
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
        self.persistent()
            .write()
            .put(keys::cert_renew_lock(domain), encode(&lock))
            .is_ok()
    }

    /// Release certificate renew lock
    pub fn release_cert_renew_lock(&self, domain: &str) -> Result<()> {
        self.persistent()
            .write()
            .delete(keys::cert_renew_lock(domain))?;
        Ok(())
    }

    /// Watch for certificate data changes
    pub fn watch_cert(&self, domain: &str) -> watch::Receiver<()> {
        self.persistent().watch_prefix(&keys::cert_data(domain))
    }
}
