// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Per-instance port policy lookup with background lazy fetch from legacy CVMs.
//!
//! Two paths:
//!
//! - Fast path: synchronous, non-blocking lookups used by the proxy data path:
//!     - [`is_port_allowed`] enforces `restrict_mode` (fail-close on cache miss).
//!     - [`should_send_pp`] decides whether to prepend a PROXY protocol header.
//! - Slow path ([`spawn_fetcher`]): a single background task that drains the
//!   queue, dedupes in-flight instances, calls the agent's `Info()` RPC with
//!   a timeout, and writes the result back to WaveKV.

use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use dstack_guest_agent_rpc::dstack_guest_client::DstackGuestClient;
use dstack_types::AppCompose;
use http_client::ConnectionReuse;
use or_panic::ResultOrPanic;
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::{debug, warn};

use crate::{
    kv::{PortFlags, PortPolicy},
    main_service::Proxy,
    proxy::AddressGroup,
};

/// Outcome of a single fetch attempt, distinguishing what we can usefully retry.
#[derive(Debug)]
enum FetchError {
    /// Transient: connection failed, RPC timed out, agent returned 5xx, etc.
    /// The CVM might just be warming up — retry with backoff.
    Transient(anyhow::Error),
    /// Permanent: instance is gone, or the CVM responded with data we can't
    /// parse (malformed tcb_info, schema mismatch). Retrying won't help.
    Permanent(anyhow::Error),
}

/// Reason a port was denied. Used only for log messages.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DenyReason {
    /// `restrict_mode` is enabled and the port isn't in the allowed list.
    PortNotAllowed,
    /// The CVM hasn't reported a policy yet; we fail-close while a background
    /// fetch is in flight.
    PolicyUnknown,
}

/// Decide whether the gateway should accept an inbound connection for
/// (`instance_id`, `port`). Fail-close: an unknown policy (cache miss) denies
/// the connection and triggers a background fetch so subsequent connections
/// can proceed once the policy is known.
///
/// Instances not present in state (e.g. the `localhost` shortcut) bypass the
/// check — the policy machinery only applies to registered CVMs.
pub(crate) fn is_port_allowed(
    state: &Proxy,
    instance_id: &str,
    port: u16,
) -> Result<(), DenyReason> {
    let guard = state.lock();
    let Some(policy) = guard.instance_port_policy(instance_id) else {
        // Two cases land here:
        //   1) `instance_id` isn't a registered CVM (e.g. `localhost`): no
        //      policy applies, allow.
        //   2) Registered CVM but no policy reported yet: fail-close, schedule
        //      a fetch.
        let known = guard.instance_ip(instance_id).is_some();
        drop(guard);
        if !known {
            return Ok(());
        }
        let _ = state.port_policy_tx.send(instance_id.to_string());
        return Err(DenyReason::PolicyUnknown);
    };
    if !policy.restrict_mode {
        return Ok(());
    }
    if policy.ports.contains_key(&port) {
        Ok(())
    } else {
        Err(DenyReason::PortNotAllowed)
    }
}

/// Filter the candidate address group down to instances that allow `port`.
///
/// Bails with a descriptive error (which the caller turns into a TCP close)
/// when no candidate is allowed. Logs each rejected candidate at debug level.
pub(crate) fn filter_allowed_addresses(
    state: &Proxy,
    addresses: AddressGroup,
    app_id: &str,
    port: u16,
) -> Result<AddressGroup> {
    let total = addresses.len();
    // Nothing was offered, so nothing was denied here -- and `port` has not
    // been looked at yet, so naming it would send whoever reads this log at
    // the wrong subsystem entirely. Selection knows why it came back empty;
    // ask it instead of guessing.
    if total == 0 {
        bail!("{}", state.lock().describe_empty_selection(app_id));
    }
    let allowed: AddressGroup = addresses
        .into_iter()
        .filter(|a| match is_port_allowed(state, &a.instance_id, port) {
            Ok(()) => true,
            Err(reason) => {
                debug!(
                    "denied port {port} for instance {} (app {app_id}): {reason:?}",
                    a.instance_id
                );
                false
            }
        })
        .collect();
    if allowed.is_empty() {
        bail!("port {port} denied by app port policy for {app_id} ({total} candidate(s))");
    }
    Ok(allowed)
}

/// Decide whether the gateway should send a PROXY protocol header on the
/// outbound connection to (`instance_id`, `port`).
///
/// Cache hit returns the declared value. Cache miss returns `false` (no PP) —
/// `is_port_allowed` runs first under fail-close and would have rejected the
/// connection if the policy were truly unknown, so by the time we get here the
/// cache is normally populated. The default-false fallback is conservative
/// because a missing PP header is safer than a forged one.
pub(crate) fn should_send_pp(state: &Proxy, instance_id: &str, port: u16) -> bool {
    state
        .lock()
        .instance_port_policy(instance_id)
        .and_then(|p| p.ports.get(&port))
        .map(|f| f.pp)
        .unwrap_or(false)
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
                let mut in_flight = in_flight.lock().or_panic("port_policy in_flight poisoned");
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
                    .or_panic("port_policy in_flight poisoned")
                    .remove(&id);
            });
        }
    });
}

async fn fetch_with_retry(state: &Proxy, instance_id: &str) {
    let cfg = &state.config.proxy.port_policy_fetch;
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
                debug!("port_policy cached for instance {instance_id} (attempt {attempt})");
                return;
            }
            Err(FetchError::Permanent(err)) => {
                // Either the instance was recycled while queued, or the
                // agent responded with data we can't parse. Retrying won't
                // change either; bail.
                debug!("port_policy fetch for {instance_id}: permanent failure: {err:#}");
                return;
            }
            Err(FetchError::Transient(err)) => {
                warn!("port_policy fetch for {instance_id} failed (attempt {attempt}): {err:#}");
            }
        }
        if attempt >= cfg.max_retries {
            warn!(
                "port_policy fetch for {instance_id} giving up after {} attempts",
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
    let policy = fetch_port_policy(ip, agent_port).await?;
    state
        .lock()
        .update_instance_port_policy(instance_id, policy);
    Ok(())
}

async fn fetch_port_policy(ip: Ipv4Addr, agent_port: u16) -> Result<PortPolicy, FetchError> {
    let url = format!("http://{ip}:{agent_port}/prpc");
    // Same untrusted peer as the health poller; see `guest_agent_client`.
    // Pooled, unlike the poller: this fills a cache rather than deciding
    // anything, it fires once per instance instead of on a timer, and a
    // connection that died while idle costs one retry of a lazy fetch.
    let client = DstackGuestClient::new(super::guest_agent_client(url, ConnectionReuse::Pooled));
    // Network/RPC errors here are transient: agent might still be coming up.
    let info = client
        .info()
        .await
        .context("agent Info() rpc failed")
        .map_err(FetchError::Transient)?;

    parse_info_port_policy(&info.tcb_info)
}

fn parse_info_port_policy(tcb_info: &str) -> Result<PortPolicy, FetchError> {
    // Legacy CVM with public_tcbinfo=false; we cannot inspect app-compose
    // remotely. Cache the default (open) policy so we don't keep retrying.
    // Apps that need restrict_mode must report policy during registration.
    if tcb_info.is_empty() {
        return Ok(PortPolicy::default());
    }
    let tcb: serde_json::Value = serde_json::from_str(tcb_info)
        .context("invalid tcb_info json")
        .map_err(FetchError::Permanent)?;
    let raw = tcb
        .get("app_compose")
        .and_then(|value| value.as_str())
        .ok_or_else(|| FetchError::Permanent(anyhow::anyhow!("tcb_info missing app_compose")))?;
    let app_compose: AppCompose = serde_json::from_str(raw)
        .context("failed to parse app_compose from tcb_info")
        .map_err(FetchError::Permanent)?;
    let ports = app_compose
        .port_policy
        .ports
        .into_iter()
        .map(|port| (port.port, PortFlags { pp: port.pp }))
        .collect();
    Ok(PortPolicy {
        ports,
        restrict_mode: app_compose.port_policy.restrict_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_info_port_policy, FetchError};

    #[test]
    fn legacy_empty_info_uses_bounded_open_compatibility_policy() {
        let policy = parse_info_port_policy("").expect("legacy empty info rejected");
        assert!(!policy.restrict_mode);
        assert!(policy.ports.is_empty());
    }

    #[test]
    fn reported_policy_wins_and_preserves_proxy_protocol_flags() {
        let compose = serde_json::json!({
            "manifest_version": "3",
            "name": "port-policy-fixture",
            "runner": "docker-compose",
            "gateway_enabled": true,
            "port_policy": {
                "restrict_mode": true,
                "ports": [
                    {"port": 443, "pp": true},
                    {"port": 8080, "pp": false}
                ]
            }
        });
        let tcb = serde_json::json!({"app_compose": compose.to_string()}).to_string();
        let policy = parse_info_port_policy(&tcb).expect("reported policy rejected");
        assert!(policy.restrict_mode);
        assert!(policy.ports.get(&443).expect("443 missing").pp);
        assert!(!policy.ports.get(&8080).expect("8080 missing").pp);
    }

    #[test]
    fn malformed_or_missing_compose_is_permanent_failure() {
        for value in [
            "not-json",
            r#"{"other":"value"}"#,
            r#"{"app_compose":"bad"}"#,
        ] {
            assert!(matches!(
                parse_info_port_policy(value),
                Err(FetchError::Permanent(_))
            ));
        }
    }
}
