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
use tracing::{error, info, warn};
use wavekv::{
    sync::{
        ExchangeInterface, PeerLinkStatus, SyncConfig as KvSyncConfig, SyncEnvelope, SyncManager,
        SyncMessage, SyncResponse,
    },
    types::NodeId,
    Node,
};

use crate::config::SyncConfig as GwSyncConfig;

use super::https_client::{HttpStatusError, HttpsClient, HttpsClientConfig};
use super::KvStore;

/// HTTP-based network transport for WaveKV sync.
/// Holds a reference to the persistent node for reading peer URLs.
#[derive(Clone)]
pub struct HttpSyncNetwork {
    client: HttpsClient,
    /// Reference to persistent node for reading peer URLs
    kv_store: KvStore,
    /// This node's UUID (for node ID reuse detection)
    my_uuid: Vec<u8>,
    /// URL path suffix for this store (e.g., "persistent" or "ephemeral")
    store_path: &'static str,
}

impl HttpSyncNetwork {
    /// Whether a peer rejected a send with HTTP 403.
    fn was_rejected(err: &anyhow::Error) -> bool {
        err.chain()
            .filter_map(|cause| cause.downcast_ref::<HttpStatusError>())
            .any(|status| status.0 == 403)
    }

    /// Count a 403 for this node's own monitoring. Sync endpoints use 403 for
    /// both removal lockouts and app-identity mismatches, so the metric and log
    /// deliberately report a rejection without claiming which condition caused it.
    fn note_if_rejected(err: &anyhow::Error, peer: NodeId) {
        if !Self::was_rejected(err) {
            return;
        }
        crate::metrics::record_sync_rejected();
        error!(
            "peer {peer} rejected this node's sync envelope (HTTP 403); \
             this can indicate a removal lockout or an app-identity mismatch"
        );
    }
    /// `my_uuid` is passed in rather than read back out of the store.
    ///
    /// Our own uuid is local configuration, not replicated state, and sourcing
    /// it from the store forced this node's `node/info` record to be written
    /// before the service could be built — which is to say before `bootstrap`
    /// had rebuilt the sequence counter. After a data-directory loss that made
    /// the record spend a sequence number the peers already consider seen, so
    /// the one record they check us against was the one guaranteed to be
    /// dropped.
    pub fn new(
        kv_store: KvStore,
        store_path: &'static str,
        tls_config: &HttpsClientConfig,
        my_uuid: Vec<u8>,
    ) -> Result<Self> {
        let client = HttpsClient::new(tls_config)?;
        Ok(Self {
            client,
            kv_store,
            my_uuid,
            store_path,
        })
    }

    /// Get peer URL from persistent node
    fn get_peer_url(&self, peer_id: NodeId) -> Option<String> {
        self.kv_store.get_peer_url(peer_id)
    }
}

impl ExchangeInterface for HttpSyncNetwork {
    fn uuid(&self) -> Vec<u8> {
        self.my_uuid.clone()
    }

    fn query_uuid(&self, node_id: NodeId) -> Option<Vec<u8>> {
        self.kv_store.get_peer_uuid(node_id)
    }

    async fn sync_to(
        &self,
        _node: &Node,
        _peer: NodeId,
        _msg: SyncMessage,
    ) -> Result<SyncResponse> {
        anyhow::bail!("wavekv v1 peer synchronization is not supported")
    }

    /// Native WaveKV exchange.
    ///
    /// All deployed clusters use this wire protocol. WaveKV 1.0 data directories are
    /// migrated in place during a stopped single-node upgrade; no mixed-version network
    /// protocol is exposed by the gateway.
    async fn sync_v2_to(
        &self,
        _node: &Node,
        peer: NodeId,
        env: SyncEnvelope,
    ) -> Result<Option<SyncEnvelope>> {
        let sync_url = self.route_for(peer, "sync")?;

        let body = self
            .client
            .post_bytes_response(&sync_url, env.encode()?)
            .await
            .with_context(|| format!("failed to sync to peer {peer} at {sync_url}"))
            .inspect_err(|err| Self::note_if_rejected(err, peer))?;

        self.kv_store.update_peer_last_seen(peer);
        Ok(Some(SyncEnvelope::decode(&body)?))
    }

    /// Opportunistic push. Best-effort by design: the periodic round remains the
    /// anti-entropy backstop and the only ack authority.
    async fn push_to(&self, _node: &Node, peer: NodeId, env: SyncEnvelope) -> Result<()> {
        let push_url = self.route_for(peer, "push")?;
        self.client
            .post_bytes_no_response(&push_url, env.encode()?)
            .await
            .with_context(|| format!("failed to push to peer {peer} at {push_url}"))
            .inspect_err(|err| Self::note_if_rejected(err, peer))?;
        Ok(())
    }
}

impl HttpSyncNetwork {
    fn route_for(&self, peer: NodeId, verb: &str) -> Result<String> {
        let url = self
            .get_peer_url(peer)
            .ok_or_else(|| anyhow::anyhow!("peer {peer} address not found in DB"))?;
        Ok(format!(
            "{}/wavekv/{verb}/{}",
            url.trim_end_matches('/'),
            self.store_path
        ))
    }
}

/// WaveKV sync service that manages synchronization for both persistent and ephemeral stores
pub struct WaveKvSyncService {
    pub persistent_manager: Arc<SyncManager<HttpSyncNetwork>>,
    pub ephemeral_manager: Arc<SyncManager<HttpSyncNetwork>>,
}

/// Wake the opportunistic push path after a latency-sensitive persistent write.
pub trait PersistentWriteNotifier: Send + Sync {
    fn notify_persistent_write(&self);
}

impl PersistentWriteNotifier for WaveKvSyncService {
    fn notify_persistent_write(&self) {
        self.persistent_manager.notify_local_write();
    }
}

impl WaveKvSyncService {
    /// Create a new WaveKV sync service
    ///
    /// # Arguments
    /// * `kv_store` - The sync store containing persistent and ephemeral nodes
    /// * `sync_config` - Sync configuration
    /// * `tls_config` - TLS configuration for mTLS peer authentication
    /// * `my_uuid` - This node's uuid, from local configuration
    pub fn new(
        kv_store: &KvStore,
        sync_config: &GwSyncConfig,
        tls_config: HttpsClientConfig,
        my_uuid: Vec<u8>,
    ) -> Result<Self> {
        let sync_config = KvSyncConfig {
            interval: sync_config.interval,
            timeout: sync_config.timeout,
            ..Default::default()
        };

        // Both networks use the same persistent node for URL lookup, but different paths
        let persistent_network =
            HttpSyncNetwork::new(kv_store.clone(), "persistent", &tls_config, my_uuid.clone())?;
        let ephemeral_network =
            HttpSyncNetwork::new(kv_store.clone(), "ephemeral", &tls_config, my_uuid)?;

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

    fn manager_for(&self, store: &str) -> Option<&Arc<SyncManager<HttpSyncNetwork>>> {
        match store {
            "persistent" => Some(&self.persistent_manager),
            "ephemeral" => Some(&self.ephemeral_manager),
            _ => None,
        }
    }

    /// Handle an inbound sync envelope.
    pub fn handle_envelope(&self, store: &str, env: SyncEnvelope) -> Option<Result<SyncEnvelope>> {
        Some(self.manager_for(store)?.handle_envelope(env))
    }

    /// Handle an inbound opportunistic push (merges data only; never moves acks).
    pub fn handle_push(&self, store: &str, env: SyncEnvelope) -> Option<Result<()>> {
        Some(self.manager_for(store)?.handle_push(env))
    }

    /// Per-peer digest and failure telemetry for both stores.
    pub fn link_status(&self) -> Vec<(&'static str, Vec<PeerLinkStatus>)> {
        vec![
            ("persistent", self.persistent_manager.link_status()),
            ("ephemeral", self.ephemeral_manager.link_status()),
        ]
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

#[cfg(test)]
mod removal_refusal_tests {
    use super::*;

    fn wrapped(status: u16) -> anyhow::Error {
        anyhow::Error::new(HttpStatusError(status)).context(
            "failed to sync to peer 2 at https://gw2.example.com:9202/wavekv/sync/persistent",
        )
    }

    /// Only HTTP 403 is a rejection; transport errors and other HTTP failures
    /// must not increment the rejection counter.
    #[test]
    fn only_a_403_reads_as_rejected() {
        assert!(HttpSyncNetwork::was_rejected(&wrapped(403)));
        for status in [400u16, 401, 404, 500, 503] {
            assert!(
                !HttpSyncNetwork::was_rejected(&wrapped(status)),
                "status {status} must not read as a rejection"
            );
        }
        assert!(!HttpSyncNetwork::was_rejected(&anyhow::anyhow!(
            "connection refused"
        )));
    }

    /// The rejection must reach the node's own monitoring.
    #[test]
    fn a_refusal_is_counted_for_the_victims_own_monitoring() {
        // Process-wide static: assert on the delta, never the absolute value.
        let before = crate::metrics::sync_rejected_count();
        HttpSyncNetwork::note_if_rejected(&wrapped(500), 2);
        assert_eq!(
            crate::metrics::sync_rejected_count(),
            before,
            "an ordinary failure must not count as a rejection"
        );
        HttpSyncNetwork::note_if_rejected(&wrapped(403), 2);
        assert!(crate::metrics::sync_rejected_count() > before);
    }
}
