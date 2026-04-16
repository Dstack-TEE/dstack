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

/// Outcome of a single fetch attempt, distinguishing what we can usefully retry.
enum FetchError {
    /// Transient: connection failed, RPC timed out, agent returned 5xx, etc.
    /// The CVM might just be warming up — retry with backoff.
    Transient(anyhow::Error),
    /// Permanent: instance is gone, or the CVM responded with data we can't
    /// parse (malformed tcb_info, schema mismatch). Retrying won't help.
    Permanent(anyhow::Error),
}

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
        let result =
            match tokio::time::timeout(cfg.timeout, fetch_and_store(state, instance_id)).await {
                Ok(r) => r,
                // The Info() RPC took too long. Treat as transient — the CVM
                // may just be slow to come up.
                Err(_) => Err(FetchError::Transient(anyhow::anyhow!(
                    "Info() rpc timed out after {:?}",
                    cfg.timeout
                ))),
            };
        match result {
            Ok(()) => {
                debug!("port_attrs cached for instance {instance_id} (attempt {attempt})");
                return;
            }
            Err(FetchError::Permanent(err)) => {
                // Either the instance was recycled while queued, or the
                // agent responded with data we can't parse. Retrying won't
                // change either; bail.
                debug!("port_attrs fetch for {instance_id}: permanent failure: {err:#}");
                return;
            }
            Err(FetchError::Transient(err)) => {
                warn!("port_attrs fetch for {instance_id} failed (attempt {attempt}): {err:#}");
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

async fn fetch_and_store(state: &Proxy, instance_id: &str) -> Result<(), FetchError> {
    let (ip, agent_port) = {
        let guard = state.lock();
        let ip = guard
            .instance_ip(instance_id)
            // Instance was recycled — never coming back under this id.
            .ok_or_else(|| FetchError::Permanent(anyhow::anyhow!("unknown instance")))?;
        (ip, guard.config.proxy.agent_port)
    };
    let attrs = fetch_port_attrs(ip, agent_port).await?;
    state.lock().update_instance_port_attrs(instance_id, attrs);
    Ok(())
}

async fn fetch_port_attrs(
    ip: Ipv4Addr,
    agent_port: u16,
) -> Result<BTreeMap<u16, PortFlags>, FetchError> {
    let url = format!("http://{ip}:{agent_port}/prpc");
    let client = DstackGuestClient::new(PrpcClient::new(url));
    // Network/RPC errors here are transient: agent might still be coming up.
    let info = client
        .info()
        .await
        .context("agent Info() rpc failed")
        .map_err(FetchError::Transient)?;

    // Anything below this point is the agent telling us something we can't
    // turn into port_attrs — treat as permanent.
    if info.tcb_info.is_empty() {
        // Legacy CVM with public_tcbinfo=false; we cannot inspect app-compose
        // remotely. Cache an empty map so we don't keep retrying.
        return Ok(BTreeMap::new());
    }
    let tcb: serde_json::Value = serde_json::from_str(&info.tcb_info)
        .context("invalid tcb_info json")
        .map_err(FetchError::Permanent)?;
    let raw = tcb
        .get("app_compose")
        .and_then(|v| v.as_str())
        .ok_or_else(|| FetchError::Permanent(anyhow::anyhow!("tcb_info missing app_compose")))?;
    let app_compose: AppCompose = serde_json::from_str(raw)
        .context("failed to parse app_compose from tcb_info")
        .map_err(FetchError::Permanent)?;
    Ok(app_compose
        .ports
        .into_iter()
        .map(|p| (p.port, PortFlags { pp: p.pp }))
        .collect())
}
