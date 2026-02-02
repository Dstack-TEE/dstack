// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dstack_gateway_rpc::{
    admin_server::{AdminRpc, AdminServer},
    GetInfoRequest, GetInfoResponse, GetMetaResponse, HostInfo, RenewCertResponse, StatusResponse,
};
use ra_rpc::{CallContext, RpcCall};

use crate::{
    main_service::{encode_ts, Proxy},
    proxy::NUM_CONNECTIONS,
};

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
            .map(|instance| HostInfo {
                instance_id: instance.id.clone(),
                ip: instance.ip.to_string(),
                app_id: instance.app_id.clone(),
                base_domain: base_domain.clone(),
                latest_handshake: encode_ts(instance.last_seen),
                num_connections: instance.num_connections(),
            })
            .collect::<Vec<_>>();
        let nodes = state
            .state
            .nodes
            .values()
            .cloned()
            .map(Into::into)
            .collect::<Vec<_>>();
        Ok(StatusResponse {
            url: state.config.sync.my_url.clone(),
            id: state.config.id(),
            bootnode_url: state.config.sync.bootnode.clone(),
            nodes,
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
}

impl RpcCall<Proxy> for AdminRpcHandler {
    type PrpcService = AdminServer<Self>;

    fn construct(context: CallContext<'_, Proxy>) -> Result<Self> {
        Ok(AdminRpcHandler {
            state: context.state.clone(),
        })
    }
}
