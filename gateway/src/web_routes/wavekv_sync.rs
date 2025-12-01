// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WaveKV sync HTTP endpoints

use crate::main_service::Proxy;
use ra_tls::traits::CertExt;
use rocket::{
    get,
    http::Status,
    mtls::{oid::Oid, Certificate},
    post,
    serde::json::Json,
    State,
};
use serde::Serialize;
use tracing::warn;
use wavekv::{
    node::{NodeStatus, PeerStatus},
    sync::{SyncMessage, SyncResponse},
    types::NodeId,
};

/// Wrapper to implement CertExt for Rocket's Certificate
struct RocketCert<'a>(&'a Certificate<'a>);

impl CertExt for RocketCert<'_> {
    fn get_extension_der(&self, oid: &[u64]) -> anyhow::Result<Option<Vec<u8>>> {
        let oid = Oid::from(oid).map_err(|_| anyhow::anyhow!("failed to create OID from slice"))?;
        let Some(ext) = self.0.extensions().iter().find(|ext| ext.oid == oid) else {
            return Ok(None);
        };
        Ok(Some(ext.value.to_vec()))
    }
}

/// Verify that the request is from a gateway with the same app_id (mTLS verification)
fn verify_gateway_peer(state: &Proxy, cert: Option<Certificate<'_>>) -> Result<(), Status> {
    // Skip verification if not running in dstack (test mode)
    if state.config.debug.insecure_skip_attestation {
        return Ok(());
    }

    let Some(cert) = cert else {
        warn!("WaveKV sync: client certificate required but not provided");
        return Err(Status::Unauthorized);
    };

    let remote_app_id = RocketCert(&cert).get_app_id().map_err(|e| {
        warn!("WaveKV sync: failed to extract app_id from certificate: {e}");
        Status::Unauthorized
    })?;

    let Some(remote_app_id) = remote_app_id else {
        warn!("WaveKV sync: certificate does not contain app_id");
        return Err(Status::Unauthorized);
    };

    if state.my_app_id() != Some(remote_app_id.as_slice()) {
        warn!(
            "WaveKV sync: app_id mismatch, expected {:?}, got {:?}",
            state.my_app_id(),
            remote_app_id
        );
        return Err(Status::Forbidden);
    }

    Ok(())
}

/// Handle persistent store sync request
#[post("/wavekv/sync/persistent", data = "<msg>")]
pub async fn sync_persistent(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    msg: Json<SyncMessage>,
) -> Result<Json<SyncResponse>, Status> {
    verify_gateway_peer(state, cert)?;

    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    wavekv_sync
        .handle_persistent_sync(msg.into_inner())
        .map(Json)
        .map_err(|e| {
            tracing::error!("Persistent sync failed: {e}");
            Status::InternalServerError
        })
}

/// Handle ephemeral store sync request
#[post("/wavekv/sync/ephemeral", data = "<msg>")]
pub async fn sync_ephemeral(
    state: &State<Proxy>,
    cert: Option<Certificate<'_>>,
    msg: Json<SyncMessage>,
) -> Result<Json<SyncResponse>, Status> {
    verify_gateway_peer(state, cert)?;

    let Some(ref wavekv_sync) = state.wavekv_sync else {
        return Err(Status::ServiceUnavailable);
    };

    wavekv_sync
        .handle_ephemeral_sync(msg.into_inner())
        .map(Json)
        .map_err(|e| {
            tracing::error!("Ephemeral sync failed: {e}");
            Status::InternalServerError
        })
}

/// WaveKV sync status for a single store
#[derive(Debug, Clone, Serialize)]
pub struct StoreStatus {
    pub name: &'static str,
    pub node_id: NodeId,
    pub n_keys: usize,
    pub next_seq: u64,
    pub dirty: bool,
    pub wal_enabled: bool,
    pub peers: Vec<PeerSyncStatus>,
}

/// Peer sync status with last_seen info
#[derive(Debug, Clone, Serialize)]
pub struct PeerSyncStatus {
    pub id: NodeId,
    /// Our local ack for this peer's logs
    pub local_ack: u64,
    /// Peer's ack for our logs
    pub peer_ack: u64,
    /// Number of logs buffered from this peer
    pub buffered_logs: usize,
    /// Last seen timestamps (reported by each observing node)
    pub last_seen: Vec<(NodeId, u64)>,
}

impl PeerSyncStatus {
    fn from_peer_status(status: PeerStatus, last_seen: Vec<(NodeId, u64)>) -> Self {
        Self {
            id: status.id,
            local_ack: status.ack,
            peer_ack: status.pack,
            buffered_logs: status.logs,
            last_seen,
        }
    }
}

impl StoreStatus {
    fn from_node_status(
        name: &'static str,
        status: NodeStatus,
        peer_last_seen: impl Fn(NodeId) -> Vec<(NodeId, u64)>,
    ) -> Self {
        Self {
            name,
            node_id: status.id,
            n_keys: status.n_kvs,
            next_seq: status.next_seq,
            dirty: status.dirty,
            wal_enabled: status.wal,
            peers: status
                .peers
                .into_iter()
                .map(|p| {
                    let last_seen = peer_last_seen(p.id);
                    PeerSyncStatus::from_peer_status(p, last_seen)
                })
                .collect(),
        }
    }
}

/// Overall WaveKV sync status
#[derive(Debug, Clone, Serialize)]
pub struct WaveKvStatus {
    pub enabled: bool,
    pub persistent: Option<StoreStatus>,
    pub ephemeral: Option<StoreStatus>,
}

/// Get WaveKV sync status
#[get("/wavekv/status")]
pub async fn status(state: &State<Proxy>) -> Json<WaveKvStatus> {
    let kv_store = state.kv_store();

    let persistent_status = kv_store.persistent().read().status();
    let ephemeral_status = kv_store.ephemeral().read().status();

    // Get peer last_seen from ephemeral store
    let get_peer_last_seen = |peer_id: NodeId| -> Vec<(NodeId, u64)> {
        kv_store
            .get_node_last_seen_by_all(peer_id)
            .into_iter()
            .collect()
    };

    Json(WaveKvStatus {
        enabled: true,
        persistent: Some(StoreStatus::from_node_status(
            "persistent",
            persistent_status,
            get_peer_last_seen,
        )),
        ephemeral: Some(StoreStatus::from_node_status(
            "ephemeral",
            ephemeral_status,
            get_peer_last_seen,
        )),
    })
}
