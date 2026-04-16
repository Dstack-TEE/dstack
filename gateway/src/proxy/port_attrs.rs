// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-port attribute lookup with background lazy fetch from legacy CVMs.
//!
//! Two paths:
//!
//! - Fast path (`should_send_pp`): a synchronous, non-blocking lookup. On a
//!   cache miss it enqueues the instance for the background worker and
//!   optimistically returns `pp = false` so the connection isn't blocked.
//! - Slow path ([`spawn_fetcher`]): a single background task that drains the
//!   queue, dedupes in-flight instances, calls the agent's `Info()` RPC with
//!   a timeout, and writes the result back to WaveKV.

use std::collections::{BTreeMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::dstack_guest_client::DstackGuestClient;
use dstack_types::AppCompose;
use http_client::prpc::PrpcClient;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, warn};

use crate::{kv::PortFlags, main_service::Proxy};

/// Decide whether the gateway should send a PROXY protocol header on the
/// outbound connection to (`instance_id`, `port`).
///
/// Cache hit returns the declared value. Cache miss returns `false` and asks
/// the background worker to populate the cache for the next request — this
/// keeps the data path off the critical Info() RPC.
pub(crate) fn should_send_pp(state: &Proxy, instance_id: &str, port: u16) -> bool {
    if let Some(attrs) = state.lock().instance_port_attrs(instance_id) {
        return attrs.get(&port).map(|f| f.pp).unwrap_or(false);
    }
    // Best-effort enqueue. If the channel is closed (shutdown) or the worker
    // is gone, silently drop — `false` is the conservative default anyway.
    let _ = state.port_attrs_tx.send(instance_id.to_string());
    false
}

/// Spawn the background lazy-fetch worker. Should be called once at startup.
pub(crate) fn spawn_fetcher(state: Proxy, mut rx: UnboundedReceiver<String>) {
    let in_flight: Arc<Mutex<HashSet<String>>> = Default::default();
    tokio::spawn(async move {
        while let Some(instance_id) = rx.recv().await {
            // Dedupe: only one fetch per instance at a time. The entry is
            // removed once the retry loop terminates (success, exhausted,
            // or unknown-instance), so a later registration with a new
            // compose_hash can re-trigger via the same path.
            {
                let mut in_flight = in_flight.lock().expect("port_attrs in_flight poisoned");
                if !in_flight.insert(instance_id.clone()) {
                    continue;
                }
            }
            let state = state.clone();
            let in_flight = in_flight.clone();
            let id = instance_id.clone();
            tokio::spawn(async move {
                fetch_with_retry(&state, &id).await;
                in_flight
                    .lock()
                    .expect("port_attrs in_flight poisoned")
                    .remove(&id);
            });
        }
    });
}

async fn fetch_with_retry(state: &Proxy, instance_id: &str) {
    let cfg = &state.config.proxy.port_attrs_fetch;
    let mut attempt = 0u32;
    let mut backoff = cfg.backoff_initial;
    loop {
        match tokio::time::timeout(cfg.timeout, fetch_and_store(state, instance_id)).await {
            Ok(Ok(())) => {
                debug!("port_attrs cached for instance {instance_id} (attempt {attempt})");
                return;
            }
            Ok(Err(err)) if is_unknown_instance(&err) => {
                // Instance was recycled while the fetch was queued. No
                // point retrying — the instance is gone.
                debug!("port_attrs fetch for {instance_id}: instance no longer exists, giving up");
                return;
            }
            Ok(Err(err)) => {
                warn!("port_attrs fetch for {instance_id} failed (attempt {attempt}): {err:#}");
            }
            Err(_) => {
                warn!(
                    "port_attrs fetch for {instance_id} timed out after {:?} (attempt {attempt})",
                    cfg.timeout
                );
            }
        }
        if attempt >= cfg.max_retries {
            warn!(
                "port_attrs fetch for {instance_id} giving up after {} attempts",
                attempt + 1
            );
            return;
        }
        tokio::time::sleep(backoff).await;
        attempt += 1;
        backoff = (backoff * 2).min(cfg.backoff_max);
    }
}

fn is_unknown_instance(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|e| e.to_string().contains("unknown instance"))
}

async fn fetch_and_store(state: &Proxy, instance_id: &str) -> Result<()> {
    let (ip, agent_port) = {
        let guard = state.lock();
        let ip = guard.instance_ip(instance_id).context("unknown instance")?;
        (ip, guard.config.proxy.agent_port)
    };
    let attrs = fetch_port_attrs(ip, agent_port).await?;
    state.lock().update_instance_port_attrs(instance_id, attrs);
    Ok(())
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
