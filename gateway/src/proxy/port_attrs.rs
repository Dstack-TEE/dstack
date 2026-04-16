// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-port attribute lookup with lazy fetch from legacy CVMs.

use std::{collections::BTreeMap, net::Ipv4Addr};

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::dstack_guest_client::DstackGuestClient;
use dstack_types::AppCompose;
use http_client::prpc::PrpcClient;
use tracing::{debug, warn};

use crate::{kv::PortFlags, main_service::Proxy};

/// Decide whether the gateway should send a PROXY protocol header on the
/// outbound connection to (`instance_id`, `port`).
///
/// Lookup order:
///
/// 1. In-memory `port_attrs` populated at registration (new CVMs).
/// 2. Lazy fetch via the agent's `Info()` RPC (legacy CVMs that didn't report
///    attributes at registration). Result is cached on success.
/// 3. Default `false` on any failure.
pub(crate) async fn should_send_pp(state: &Proxy, instance_id: &str, port: u16) -> bool {
    if let Some(attrs) = state.lock().instance_port_attrs(instance_id) {
        return attrs.get(&port).map(|f| f.pp).unwrap_or(false);
    }
    match lazy_fetch(state, instance_id).await {
        Ok(attrs) => attrs.get(&port).map(|f| f.pp).unwrap_or(false),
        Err(err) => {
            warn!("port_attrs lazy fetch for instance {instance_id} failed: {err:#}");
            false
        }
    }
}

async fn lazy_fetch(state: &Proxy, instance_id: &str) -> Result<BTreeMap<u16, PortFlags>> {
    let (ip, agent_port) = {
        let guard = state.lock();
        let ip = guard.instance_ip(instance_id).context("unknown instance")?;
        (ip, guard.config.proxy.agent_port)
    };

    let attrs = fetch_port_attrs(ip, agent_port).await?;
    state
        .lock()
        .update_instance_port_attrs(instance_id, attrs.clone());
    debug!(
        "fetched port_attrs for legacy instance {instance_id} via Info(): {} entries",
        attrs.len()
    );
    Ok(attrs)
}

async fn fetch_port_attrs(ip: Ipv4Addr, agent_port: u16) -> Result<BTreeMap<u16, PortFlags>> {
    let url = format!("http://{ip}:{agent_port}/prpc");
    let client = DstackGuestClient::new(PrpcClient::new(url));
    let info = client.info().await.context("agent Info() rpc failed")?;
    if info.tcb_info.is_empty() {
        // Legacy CVM with public_tcbinfo=false; we cannot inspect app-compose
        // remotely. Cache an empty map so we don't keep retrying.
        return Ok(BTreeMap::new());
    }
    let tcb: serde_json::Value =
        serde_json::from_str(&info.tcb_info).context("invalid tcb_info json")?;
    let raw = tcb
        .get("app_compose")
        .and_then(|v| v.as_str())
        .context("tcb_info missing app_compose")?;
    let app_compose: AppCompose =
        serde_json::from_str(raw).context("failed to parse app_compose from tcb_info")?;
    Ok(app_compose
        .ports
        .into_iter()
        .map(|p| (p.port, PortFlags { pp: p.pp }))
        .collect())
}
