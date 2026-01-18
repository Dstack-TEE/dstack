// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Debug service for testing - runs on a separate port when debug.enabled=true

use anyhow::Result;
use dstack_gateway_rpc::{
    debug_server::{DebugRpc, DebugServer},
    DebugProxyStateResponse, DebugRegisterCvmRequest, DebugSyncDataResponse, InfoResponse,
    InstanceEntry, NodeInfoEntry, PeerAddrEntry, ProxyStateInstance, RegisterCvmResponse,
};
use ra_rpc::{CallContext, RpcCall};
use tracing::warn;

use crate::main_service::Proxy;

pub struct DebugRpcHandler {
    state: Proxy,
}

impl DebugRpcHandler {
    pub fn new(state: Proxy) -> Self {
        Self { state }
    }
}

impl DebugRpc for DebugRpcHandler {
    async fn register_cvm(self, request: DebugRegisterCvmRequest) -> Result<RegisterCvmResponse> {
        warn!(
            "Debug register CVM: app_id={}, instance_id={}",
            request.app_id, request.instance_id
        );
        self.state.do_register_cvm(
            &request.app_id,
            &request.instance_id,
            &request.client_public_key,
        )
    }

    async fn info(self) -> Result<InfoResponse> {
        let config = &self.state.config;
        let todo = "What the base domain now?";
        let todo = "What the port now?";
        Ok(InfoResponse {
            base_domain: "".into(),
            external_port: 0,
            app_address_ns_prefix: config.proxy.app_address_ns_prefix.clone(),
        })
    }

    async fn get_sync_data(self) -> Result<DebugSyncDataResponse> {
        let kv_store = self.state.kv_store();
        let my_node_id = kv_store.my_node_id();

        // Get all peer addresses
        let peer_addrs: Vec<PeerAddrEntry> = kv_store
            .get_all_peer_addrs()
            .into_iter()
            .map(|(node_id, url)| PeerAddrEntry {
                node_id: node_id as u64,
                url,
            })
            .collect();

        // Get all node info
        let nodes: Vec<NodeInfoEntry> = kv_store
            .load_all_nodes()
            .into_iter()
            .map(|(node_id, data)| NodeInfoEntry {
                node_id: node_id as u64,
                url: data.url,
                wg_public_key: data.wg_public_key,
                wg_endpoint: data.wg_endpoint,
                wg_ip: data.wg_ip,
            })
            .collect();

        // Get all instances
        let instances: Vec<InstanceEntry> = kv_store
            .load_all_instances()
            .into_iter()
            .map(|(instance_id, data)| InstanceEntry {
                instance_id,
                app_id: data.app_id,
                ip: data.ip.to_string(),
                public_key: data.public_key,
            })
            .collect();

        // Get key counts
        let persistent_keys = kv_store.persistent().read().status().n_kvs as u64;
        let ephemeral_keys = kv_store.ephemeral().read().status().n_kvs as u64;

        Ok(DebugSyncDataResponse {
            my_node_id: my_node_id as u64,
            peer_addrs,
            nodes,
            instances,
            persistent_keys,
            ephemeral_keys,
        })
    }

    async fn get_proxy_state(self) -> Result<DebugProxyStateResponse> {
        let state = self.state.lock();

        // Get all instances from ProxyState
        let instances: Vec<ProxyStateInstance> = state
            .state
            .instances
            .values()
            .map(|inst| {
                let reg_time = inst
                    .reg_time
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                ProxyStateInstance {
                    instance_id: inst.id.clone(),
                    app_id: inst.app_id.clone(),
                    ip: inst.ip.to_string(),
                    public_key: inst.public_key.clone(),
                    reg_time,
                }
            })
            .collect();

        // Get all allocated addresses
        let allocated_addresses: Vec<String> = state
            .state
            .allocated_addresses
            .iter()
            .map(|ip| ip.to_string())
            .collect();

        Ok(DebugProxyStateResponse {
            instances,
            allocated_addresses,
        })
    }
}

impl RpcCall<Proxy> for DebugRpcHandler {
    type PrpcService = DebugServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(DebugRpcHandler::new(context.state.clone()))
    }
}
