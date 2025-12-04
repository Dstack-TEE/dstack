// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV sync service - implements network transport for wavekv synchronization.
//!
//! Peer URLs are stored in the persistent KV store under `__peer_addr/{node_id}` keys.
//! This allows peer addresses to be automatically synced across nodes.

use std::sync::Arc;

use anyhow::{Context, Result};
use dstack_gateway_rpc::GetPeersResponse;
use tracing::{info, warn};
use wavekv::{
    sync::{ExchangeInterface, SyncConfig as KvSyncConfig, SyncManager, SyncMessage, SyncResponse},
    types::NodeId,
    Node,
};

use crate::{config::SyncConfig as GwSyncConfig, kv::GetPutCodec};

use super::https_client::{HttpsClient, HttpsClientConfig};
use super::{keys, KvStore};

/// HTTP-based network transport for WaveKV sync.
/// Holds a reference to the persistent node for reading peer URLs.
#[derive(Clone)]
pub struct HttpSyncNetwork {
    client: HttpsClient,
    /// Reference to persistent node for reading peer URLs
    persistent_node: Node,
    /// Reference to ephemeral node for updating peer last_seen
    ephemeral_node: Node,
    /// This node's ID (for recording who observed the peer)
    my_node_id: NodeId,
    /// This node's UUID (for node ID reuse detection)
    my_uuid: Vec<u8>,
    /// URL path suffix for this store (e.g., "persistent" or "ephemeral")
    store_path: &'static str,
}

impl HttpSyncNetwork {
    pub fn new(
        persistent_node: Node,
        ephemeral_node: Node,
        my_node_id: NodeId,
        my_uuid: Vec<u8>,
        store_path: &'static str,
        tls_config: &HttpsClientConfig,
    ) -> Result<Self> {
        let client = HttpsClient::new(tls_config)?;

        Ok(Self {
            client,
            persistent_node,
            ephemeral_node,
            my_node_id,
            my_uuid,
            store_path,
        })
    }

    /// Query the UUID for a given node ID from KvStore
    fn get_peer_uuid(&self, peer_id: NodeId) -> Option<Vec<u8>> {
        let entry = self.persistent_node.read().get(&keys::node_info(peer_id))?;
        let bytes = entry.value?;
        let node_data: super::NodeData = super::decode(&bytes).ok()?;
        Some(node_data.uuid)
    }

    /// Get peer URL from persistent node
    fn get_peer_url(&self, peer_id: NodeId) -> Option<String> {
        self.persistent_node
            .read()
            .decode(&keys::peer_addr(peer_id))
    }

    /// Update peer last_seen timestamp in ephemeral store
    fn update_peer_last_seen(&self, peer_id: NodeId) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let key = keys::last_seen_node(peer_id, self.my_node_id);
        if let Err(e) = self.ephemeral_node.write().put_encoded(key, &ts) {
            warn!("failed to update peer {peer_id} last_seen: {e}");
        }
    }
}

impl ExchangeInterface for HttpSyncNetwork {
    fn uuid(&self) -> Vec<u8> {
        self.my_uuid.clone()
    }

    fn query_uuid(&self, node_id: NodeId) -> Option<Vec<u8>> {
        self.get_peer_uuid(node_id)
    }

    async fn sync_to(&self, _node: &Node, peer: NodeId, msg: SyncMessage) -> Result<SyncResponse> {
        let url = self
            .get_peer_url(peer)
            .ok_or_else(|| anyhow::anyhow!("peer {} address not found in DB", peer))?;

        let sync_url = format!(
            "{}/wavekv/sync/{}",
            url.trim_end_matches('/'),
            self.store_path
        );

        // Send request with msgpack + gzip encoding
        // app_id verification happens during TLS handshake via AppIdVerifier
        let sync_response: SyncResponse = self
            .client
            .post_compressed_msg(&sync_url, &msg)
            .await
            .with_context(|| format!("failed to sync to peer {peer} at {sync_url}"))?;

        // Update peer last_seen on successful sync
        self.update_peer_last_seen(peer);

        Ok(sync_response)
    }
}

/// WaveKV sync service that manages synchronization for both persistent and ephemeral stores
pub struct WaveKvSyncService {
    pub persistent_manager: Arc<SyncManager<HttpSyncNetwork>>,
    pub ephemeral_manager: Arc<SyncManager<HttpSyncNetwork>>,
}

impl WaveKvSyncService {
    /// Create a new WaveKV sync service
    ///
    /// # Arguments
    /// * `kv_store` - The sync store containing persistent and ephemeral nodes
    /// * `my_uuid` - This node's UUID for node ID reuse detection
    /// * `sync_interval` - Interval between sync attempts
    /// * `tls_config` - TLS configuration for mTLS peer authentication
    pub fn new(
        kv_store: &KvStore,
        my_uuid: Vec<u8>,
        sync_config: &GwSyncConfig,
        tls_config: HttpsClientConfig,
    ) -> Result<Self> {
        let persistent_node = kv_store.persistent().clone();
        let ephemeral_node = kv_store.ephemeral().clone();
        let my_node_id = kv_store.my_node_id();

        let sync_config = KvSyncConfig {
            interval: sync_config.interval,
            timeout: sync_config.timeout,
        };

        // Both networks use the same persistent node for URL lookup, but different paths
        let persistent_network = HttpSyncNetwork::new(
            persistent_node.clone(),
            ephemeral_node.clone(),
            my_node_id,
            my_uuid.clone(),
            "persistent",
            &tls_config,
        )?;
        let ephemeral_network = HttpSyncNetwork::new(
            persistent_node,
            ephemeral_node,
            my_node_id,
            my_uuid,
            "ephemeral",
            &tls_config,
        )?;

        let persistent_manager = Arc::new(SyncManager::with_config(
            kv_store.persistent().clone(),
            persistent_network,
            sync_config.clone(),
        ));
        let ephemeral_manager = Arc::new(SyncManager::with_config(
            kv_store.ephemeral().clone(),
            ephemeral_network,
            sync_config,
        ));

        Ok(Self {
            persistent_manager,
            ephemeral_manager,
        })
    }

    /// Bootstrap from peers
    pub async fn bootstrap(&self) -> Result<()> {
        info!("bootstrapping persistent store...");
        if let Err(e) = self.persistent_manager.bootstrap().await {
            warn!("failed to bootstrap persistent store: {e}");
        }

        info!("bootstrapping ephemeral store...");
        if let Err(e) = self.ephemeral_manager.bootstrap().await {
            warn!("failed to bootstrap ephemeral store: {e}");
        }

        Ok(())
    }

    /// Start background sync tasks
    pub async fn start_sync_tasks(&self) {
        let persistent = self.persistent_manager.clone();
        let ephemeral = self.ephemeral_manager.clone();

        tokio::join!(persistent.start_sync_tasks(), ephemeral.start_sync_tasks(),);

        info!("WaveKV sync tasks started");
    }

    /// Handle incoming sync request for persistent store
    pub fn handle_persistent_sync(&self, msg: SyncMessage) -> Result<SyncResponse> {
        self.persistent_manager.handle_sync(msg)
    }

    /// Handle incoming sync request for ephemeral store
    pub fn handle_ephemeral_sync(&self, msg: SyncMessage) -> Result<SyncResponse> {
        self.ephemeral_manager.handle_sync(msg)
    }
}

/// Fetch peer list from bootnode and register them in KvStore.
///
/// This is called during startup to bootstrap the peer list from a known bootnode.
/// Uses Gateway.GetPeers RPC which requires mTLS gateway authentication.
pub async fn fetch_peers_from_bootnode(
    bootnode_url: &str,
    kv_store: &KvStore,
    my_node_id: NodeId,
    tls_config: &HttpsClientConfig,
) -> Result<()> {
    if bootnode_url.is_empty() {
        info!("no bootnode configured, skipping peer fetch");
        return Ok(());
    }

    info!("fetching peers from bootnode: {}", bootnode_url);

    // Create HTTPS client for bootnode communication (with mTLS)
    let client = HttpsClient::new(tls_config).context("failed to create HTTPS client")?;

    // Call Gateway.GetPeers RPC on bootnode (requires mTLS gateway auth)
    let peers_url = format!("{}/prpc/GetPeers", bootnode_url.trim_end_matches('/'));

    let response: GetPeersResponse = client
        .post_json(&peers_url, &())
        .await
        .with_context(|| format!("failed to fetch peers from bootnode {bootnode_url}"))?;

    info!(
        "bootnode returned {} peers (bootnode_id={})",
        response.peers.len(),
        response.my_id
    );

    // Register each peer
    for peer in &response.peers {
        if peer.id == my_node_id {
            continue; // Skip self
        }

        // Add peer to WaveKV
        if let Err(e) = kv_store.add_peer(peer.id) {
            warn!("failed to add peer {}: {}", peer.id, e);
            continue;
        }

        // Register peer URL
        if !peer.url.is_empty() {
            if let Err(e) = kv_store.register_peer_url(peer.id, &peer.url) {
                warn!("failed to register peer URL for node {}: {}", peer.id, e);
            } else {
                info!(
                    "registered peer from bootnode: node {} -> {}",
                    peer.id, peer.url
                );
            }
        }
    }

    Ok(())
}
