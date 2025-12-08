// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dstack_gateway_rpc::{
    admin_server::{AdminRpc, AdminServer},
    GetInfoRequest, GetInfoResponse, GetInstanceHandshakesRequest, GetInstanceHandshakesResponse,
    GetMetaResponse, GetNodeStatusesResponse, GlobalConnectionsStats, HandshakeEntry, HostInfo,
    LastSeenEntry, NodeStatusEntry, PeerSyncStatus as ProtoPeerSyncStatus, RenewCertResponse,
    SetNodeStatusRequest, SetNodeUrlRequest, StatusResponse, StoreSyncStatus,
    WaveKvStatusResponse,
};
use ra_rpc::{CallContext, RpcCall};
use tracing::info;
use wavekv::node::NodeStatus as WaveKvNodeStatus;

use crate::{kv::NodeStatus, main_service::Proxy, proxy::NUM_CONNECTIONS};

pub struct AdminRpcHandler {
    state: Proxy,
}

impl AdminRpcHandler {
    pub(crate) async fn status(self) -> Result<StatusResponse> {
        let mut state = self.state.lock();
        state.refresh_state()?;
        let base_domain = &state.config.proxy.base_domain;
        let hosts = state
            .state
            .instances
            .values()
            .map(|instance| {
                // Get global latest_handshake from KvStore (max across all nodes)
                let latest_handshake = state
                    .get_instance_latest_handshake(&instance.id)
                    .unwrap_or(0);
                HostInfo {
                    instance_id: instance.id.clone(),
                    ip: instance.ip.to_string(),
                    app_id: instance.app_id.clone(),
                    base_domain: base_domain.clone(),
                    port: state.config.proxy.listen_port as u32,
                    latest_handshake,
                    num_connections: instance.num_connections(),
                }
            })
            .collect::<Vec<_>>();
        Ok(StatusResponse {
            id: state.config.sync.node_id,
            url: state.config.sync.my_url.clone(),
            uuid: state.config.uuid(),
            bootnode_url: state.config.sync.bootnode.clone(),
            nodes: state.get_all_nodes(),
            hosts,
            num_connections: NUM_CONNECTIONS.load(Ordering::Relaxed),
        })
    }
}

impl AdminRpc for AdminRpcHandler {
    async fn exit(self) -> Result<()> {
        self.state.lock().exit();
    }

    async fn renew_cert(self) -> Result<RenewCertResponse> {
        let renewed = self.state.renew_cert(true).await?;
        Ok(RenewCertResponse { renewed })
    }

    async fn set_caa(self) -> Result<()> {
        self.state
            .certbot
            .as_ref()
            .context("Certbot is not enabled")?
            .set_caa()
            .await?;
        Ok(())
    }

    async fn reload_cert(self) -> Result<()> {
        self.state.reload_certificates()
    }

    async fn status(self) -> Result<StatusResponse> {
        self.status().await
    }

    async fn get_info(self, request: GetInfoRequest) -> Result<GetInfoResponse> {
        let state = self.state.lock();
        let base_domain = &state.config.proxy.base_domain;
        let handshakes = state.latest_handshakes(None)?;

        if let Some(instance) = state.state.instances.get(&request.id) {
            let host_info = HostInfo {
                instance_id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain: base_domain.clone(),
                port: state.config.proxy.listen_port as u32,
                latest_handshake: {
                    let (ts, _) = handshakes
                        .get(&instance.public_key)
                        .copied()
                        .unwrap_or_default();
                    ts
                },
                num_connections: instance.num_connections(),
            };
            Ok(GetInfoResponse {
                found: true,
                info: Some(host_info),
            })
        } else {
            Ok(GetInfoResponse {
                found: false,
                info: None,
            })
        }
    }

    async fn get_meta(self) -> Result<GetMetaResponse> {
        let state = self.state.lock();
        let handshakes = state.latest_handshakes(None)?;

        // Total registered instances
        let registered = state.state.instances.len();

        // Get current timestamp
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before Unix epoch")?
            .as_secs();

        // Count online instances (those with handshakes in last 5 minutes)
        let online = handshakes
            .values()
            .filter(|(ts, _)| {
                // Skip instances that never connected (ts == 0)
                *ts != 0 && (now - *ts) < 300
            })
            .count();

        Ok(GetMetaResponse {
            registered: registered as u32,
            online: online as u32,
        })
    }

    async fn set_node_url(self, request: SetNodeUrlRequest) -> Result<()> {
        let kv_store = self.state.kv_store();
        kv_store.register_peer_url(request.id, &request.url)?;
        info!("Updated peer URL: node {} -> {}", request.id, request.url);
        Ok(())
    }

    async fn set_node_status(self, request: SetNodeStatusRequest) -> Result<()> {
        let kv_store = self.state.kv_store();
        let status = match request.status.as_str() {
            "up" => NodeStatus::Up,
            "down" => NodeStatus::Down,
            _ => anyhow::bail!("invalid status: expected 'up' or 'down'"),
        };
        kv_store.set_node_status(request.id, status)?;
        info!("Updated node status: node {} -> {:?}", request.id, status);
        Ok(())
    }

    async fn wave_kv_status(self) -> Result<WaveKvStatusResponse> {
        let kv_store = self.state.kv_store();

        let persistent_status = kv_store.persistent().read().status();
        let ephemeral_status = kv_store.ephemeral().read().status();

        let get_peer_last_seen = |peer_id: u32| -> Vec<(u32, u64)> {
            kv_store
                .get_node_last_seen_by_all(peer_id)
                .into_iter()
                .collect()
        };

        Ok(WaveKvStatusResponse {
            enabled: self.state.config.sync.enabled,
            persistent: Some(build_store_status(
                "persistent",
                persistent_status,
                &get_peer_last_seen,
            )),
            ephemeral: Some(build_store_status(
                "ephemeral",
                ephemeral_status,
                &get_peer_last_seen,
            )),
        })
    }

    async fn get_instance_handshakes(
        self,
        request: GetInstanceHandshakesRequest,
    ) -> Result<GetInstanceHandshakesResponse> {
        let kv_store = self.state.kv_store();
        let handshakes = kv_store.get_instance_handshakes(&request.instance_id);

        let entries = handshakes
            .into_iter()
            .map(|(observer_node_id, timestamp)| HandshakeEntry {
                observer_node_id,
                timestamp,
            })
            .collect();

        Ok(GetInstanceHandshakesResponse {
            handshakes: entries,
        })
    }

    async fn get_global_connections(self) -> Result<GlobalConnectionsStats> {
        let state = self.state.lock();
        let kv_store = self.state.kv_store();

        let mut node_connections = std::collections::HashMap::new();
        let mut total_connections = 0u64;

        // Iterate through all instances and sum up connections per node
        for instance_id in state.state.instances.keys() {
            // Get connection counts from ephemeral KV for this instance
            let conn_prefix = format!("conn/{}/", instance_id);
            for (key, count) in kv_store
                .ephemeral()
                .read()
                .iter_by_prefix(&conn_prefix)
                .filter_map(|(k, entry)| {
                    let value = entry.value.as_ref()?;
                    let count: u64 = rmp_serde::decode::from_slice(value).ok()?;
                    Some((k.to_string(), count))
                })
            {
                // Parse node_id from key: "conn/{instance_id}/{node_id}"
                if let Some(node_id_str) = key.strip_prefix(&conn_prefix) {
                    if let Ok(node_id) = node_id_str.parse::<u32>() {
                        *node_connections.entry(node_id).or_insert(0) += count;
                        total_connections += count;
                    }
                }
            }
        }

        Ok(GlobalConnectionsStats {
            total_connections,
            node_connections,
        })
    }

    async fn get_node_statuses(self) -> Result<GetNodeStatusesResponse> {
        let kv_store = self.state.kv_store();
        let statuses = kv_store.load_all_node_statuses();

        let entries = statuses
            .into_iter()
            .map(|(node_id, status)| {
                let status_str = match status {
                    NodeStatus::Up => "up",
                    NodeStatus::Down => "down",
                };
                NodeStatusEntry {
                    node_id,
                    status: status_str.to_string(),
                }
            })
            .collect();

        Ok(GetNodeStatusesResponse { statuses: entries })
    }
}

fn build_store_status(
    name: &str,
    status: WaveKvNodeStatus,
    get_peer_last_seen: &impl Fn(u32) -> Vec<(u32, u64)>,
) -> StoreSyncStatus {
    StoreSyncStatus {
        name: name.to_string(),
        node_id: status.id,
        n_keys: status.n_kvs as u64,
        next_seq: status.next_seq,
        dirty: status.dirty,
        wal_enabled: status.wal,
        peers: status
            .peers
            .into_iter()
            .map(|p| {
                let last_seen = get_peer_last_seen(p.id)
                    .into_iter()
                    .map(|(node_id, timestamp)| LastSeenEntry { node_id, timestamp })
                    .collect();
                ProtoPeerSyncStatus {
                    id: p.id,
                    local_ack: p.ack,
                    peer_ack: p.pack,
                    buffered_logs: p.logs as u64,
                    last_seen,
                }
            })
            .collect(),
    }
}

impl RpcCall<Proxy> for AdminRpcHandler {
    type PrpcService = AdminServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(AdminRpcHandler {
            state: context.state.clone(),
        })
    }
}
