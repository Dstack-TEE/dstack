// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Application-level health polling of registered CVMs.
//!
//! A CVM registers from `dstack-util setup`, during boot, before
//! `app-compose.service` has started a single container. From that moment it is
//! eligible for traffic, and the only thing standing between it and a request
//! is the WireGuard handshake age -- which says the tunnel is up and nothing
//! about whether anything is listening behind it.
//!
//! The gateway polls rather than having the CVM push. A guest agent that is
//! wedged, OOM-killed or mid-crash then shows up as a failed poll, instead of
//! as silence that has to be told apart from "nothing changed" with a
//! timestamp and a staleness heuristic. It also means "I could not reach it"
//! is a per-node observation, exactly like the WireGuard handshakes this sits
//! next to, rather than shared state that outlives whatever wrote it.
//!
//! Reachability is plain HTTP over the WireGuard tunnel, the same way
//! [`super::port_policy`] already fetches port policy from the agent.

use std::net::Ipv4Addr;
use std::time::Duration;

use dstack_guest_agent_rpc::worker_client::WorkerClient;
use futures::StreamExt;
use http_client::prpc::PrpcClient;
use tokio::time::MissedTickBehavior;
use tracing::info;

use crate::config::HealthCheckConfig;
use crate::main_service::Proxy;
use crate::models::HealthState;

/// One poll's verdict, plus why, for the line logged when the verdict changes.
pub(crate) struct Observation {
    pub state: HealthState,
    pub reason: String,
}

/// Start the polling loop. Called once at startup.
pub(crate) fn spawn_poller(state: Proxy) {
    let config = state.config.proxy.health_check.clone();
    if !config.enabled {
        info!("application health polling is disabled; every instance stays eligible");
        return;
    }
    info!(
        "polling application health every {:?} (timeout {:?})",
        config.interval, config.timeout
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(config.interval);
        // A round that overruns the interval must not leave catch-up rounds
        // queued behind it; skip to the next tick instead.
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            poll_round(&state, &config).await;
        }
    });
}

async fn poll_round(state: &Proxy, config: &HealthCheckConfig) {
    // Snapshot under the lock and poll outside it. These are network round
    // trips, and holding `ProxyState` across them would stall every connection
    // being routed.
    let targets = {
        let guard = state.lock();
        guard
            .state
            .instances
            .values()
            // Instances that never declared the capability cannot answer, so
            // polling them would only produce failures to misread.
            .filter(|instance| instance.has_health_endpoint)
            .map(|instance| (instance.id.clone(), instance.ip))
            .collect::<Vec<_>>()
    };
    if targets.is_empty() {
        return;
    }
    let agent_port = state.config.proxy.agent_port;
    let timeout = config.timeout;
    let observations = futures::stream::iter(targets)
        .map(|(instance_id, ip)| async move {
            (instance_id, poll_instance(ip, agent_port, timeout).await)
        })
        .buffer_unordered(config.concurrency.max(1))
        .collect::<Vec<_>>()
        .await;

    let mut guard = state.lock();
    for (instance_id, observation) in observations {
        guard.record_instance_health(&instance_id, observation);
    }
}

/// Ask one agent whether its app is serving.
///
/// Any failure to get an answer counts as unhealthy. That is safe to be strict
/// about because the caller fails open when it would empty an app's candidate
/// set, and because instances whose agent cannot answer at all were filtered
/// out before we got here.
async fn poll_instance(ip: Ipv4Addr, agent_port: u16, timeout: Duration) -> Observation {
    let url = format!("http://{ip}:{agent_port}/prpc");
    let client = WorkerClient::new(PrpcClient::new(url));
    let response = match tokio::time::timeout(timeout, client.health()).await {
        Err(_) => {
            return Observation {
                state: HealthState::Unhealthy,
                reason: format!("health poll timed out after {timeout:?}"),
            }
        }
        Ok(Err(err)) => {
            return Observation {
                state: HealthState::Unhealthy,
                reason: format!("health poll failed: {err:#}"),
            }
        }
        Ok(Ok(response)) => response,
    };
    if response.healthy {
        return Observation {
            state: HealthState::Healthy,
            reason: String::new(),
        };
    }
    Observation {
        state: HealthState::Unhealthy,
        reason: describe_unhealthy(&response),
    }
}

fn describe_unhealthy(response: &dstack_guest_agent_rpc::HealthResponse) -> String {
    if !response.error.is_empty() {
        return format!("agent could not inspect containers: {}", response.error);
    }
    if response.unhealthy.is_empty() {
        return "agent reported unhealthy without naming a container".to_string();
    }
    response
        .unhealthy
        .iter()
        .map(|container| format!("{} is {}", container.name, container.status))
        .collect::<Vec<_>>()
        .join(", ")
}
