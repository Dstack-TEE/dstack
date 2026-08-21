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
//! Only instances that asked to be gated are polled -- an app opts in with
//! `requirements.health_check.enabled`, which reaches the gateway as
//! `RegisterCvmRequest.health_check`. That flag, not a probe, is what keeps an
//! older or uninterested CVM out of this: every failed poll counts as
//! unhealthy, so discovering support by trying would blackhole exactly the
//! instances that cannot answer.
//!
//! Reachability is plain HTTP over the WireGuard tunnel, the same way
//! [`super::port_policy`] already fetches port policy from the agent.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;

use dstack_guest_agent_rpc::worker_client::WorkerClient;
use futures::StreamExt;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::config::HealthCheckConfig;
use crate::main_service::Proxy;
use crate::models::HealthState;

use super::health_store;

/// How long to wait before restarting the poll loop after it dies.
const RESTART_DELAY: Duration = Duration::from_secs(5);

/// Shortest gap between two writes of the health snapshot.
///
/// The snapshot holds the whole fleet, so any one verdict changing rewrites
/// every entry. One instance flapping each round would otherwise rewrite the
/// file every interval: measured at 2000 instances that is ~39 KB/s sustained,
/// paid by the operator, triggered by whichever tenant flips. Losing up to this
/// much is free -- what it protects is a process restart, and anything missing
/// is re-derived by the next poll.
const SNAPSHOT_MIN_INTERVAL: Duration = Duration::from_secs(30);

/// One poll's verdict, plus why, for the line logged when the verdict changes.
pub(crate) struct Observation {
    pub state: HealthState,
    pub reason: String,
}

/// What one `Worker.Health` call produced.
///
/// "The agent said no" and "the agent did not answer" are different claims and
/// are treated differently by [`apply_hysteresis`], so they stay apart until
/// something decides what to do with them.
#[derive(Debug, PartialEq, Eq)]
enum PollResult {
    Healthy,
    /// The agent answered, and the answer was no.
    Unhealthy(String),
    /// No answer: timed out, refused, unparseable.
    Unreachable(String),
}

/// One instance as the round snapshotted it.
///
/// The WireGuard key and IP travel with the verdict so that
/// `record_instance_health` can tell whether the record it is about to write to
/// is still the one that was polled. A round takes as long as its slowest
/// instance, and a CVM can reboot and re-register inside that window.
#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub id: String,
    pub ip: Ipv4Addr,
    pub public_key: String,
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
        // Supervised rather than a bare spawn. If the loop ever dies -- a
        // poisoned `ProxyState` mutex is enough, since locking it panics --
        // polling would otherwise stop for the life of the process with nothing
        // logged, and every instance registered after that point would sit at
        // `Unknown` forever while the stale verdicts around it kept serving.
        loop {
            let task = tokio::spawn(poll_forever(state.clone(), config.clone()));
            match task.await {
                Ok(()) => error!("health poller returned unexpectedly; restarting"),
                Err(err) => error!("health poller died: {err}; restarting"),
            }
            tokio::time::sleep(RESTART_DELAY).await;
        }
    });
}

async fn poll_forever(state: Proxy, config: HealthCheckConfig) {
    let mut ticker = tokio::time::interval(config.interval);
    // A round that overruns the interval must not leave catch-up rounds queued
    // behind it; delay the next tick instead.
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Consecutive failures to reach each agent, so a single dropped packet does
    // not eject an instance. Rebuilt from the round's own targets each time, so
    // it cannot outlive the instances it describes.
    let mut failures = BTreeMap::<String, u32>::new();
    // Where the next round starts in the target list. See `poll_round`.
    let mut cursor = 0usize;
    let mut last_snapshot: Option<tokio::time::Instant> = None;
    loop {
        ticker.tick().await;
        cursor = poll_round(&state, &config, &mut failures, cursor, &mut last_snapshot).await;
    }
}

async fn poll_round(
    state: &Proxy,
    config: &HealthCheckConfig,
    failures: &mut BTreeMap<String, u32>,
    cursor: usize,
    last_snapshot: &mut Option<tokio::time::Instant>,
) -> usize {
    // Snapshot under the lock and poll outside it. These are network round
    // trips, and holding `ProxyState` across them would stall every connection
    // being routed.
    let mut targets = select_targets(state);
    failures.retain(|id, _| targets.iter().any(|target| &target.id == id));
    if targets.is_empty() {
        return 0;
    }
    // Start where the last round stopped. The round is bounded below, so
    // without rotating, the instances past the budget would never be polled at
    // all -- and which instances those are is decided by `BTreeMap` ordering,
    // i.e. by instance id, which a tenant chooses.
    let total = targets.len();
    targets.rotate_left(cursor % total);

    let agent_port = state.config.proxy.agent_port;
    let timeout = config.timeout;
    let mut polls = futures::stream::iter(targets)
        .map(|target| async move {
            let result = poll_instance(target.ip, agent_port, timeout).await;
            (target, result)
        })
        .buffer_unordered(config.concurrency.max(1));

    // The round gets one interval, no more. A poll that never answers costs a
    // full `timeout` slot, so a fleet with enough of them takes
    // `ceil(n / concurrency) * timeout` -- and `MissedTickBehavior::Delay` then
    // makes that the *interval*, so one tenant's mute CVMs become every other
    // tenant's detection latency. Measured on this transport: 256 such
    // instances take a 33s round at the shipped defaults.
    let deadline = tokio::time::Instant::now() + config.interval;
    let mut changed = false;
    let mut polled = 0usize;
    loop {
        let landed = tokio::select! {
            biased;
            landed = polls.next() => landed,
            _ = tokio::time::sleep_until(deadline) => break,
        };
        let Some((target, result)) = landed else {
            break;
        };
        polled += 1;
        // Each verdict is applied as its poll lands, not batched at the end of
        // the round. A batch would hold the first instance's answer for as long
        // as the slowest one takes and then write it onto whatever record
        // exists by then -- which, for a CVM that rebooted in between, is a
        // different boot of the app being told it is healthy on the strength of
        // the previous one.
        let Some(observation) = apply_hysteresis(result, &target, config, failures) else {
            // Not enough evidence yet; the instance keeps the verdict it has.
            continue;
        };
        changed |= state.lock().record_instance_health(&target, observation);
    }
    if polled < total {
        // Never silently. An operator whose fleet is not being fully polled has
        // to be able to see that, and the number is the signal that something
        // is absorbing the budget.
        warn!(
            "health round polled {polled} of {total} instances before its {:?} budget ran out; \
             the rest are first in line next round",
            config.interval
        );
    }
    let due = last_snapshot.is_none_or(|at| at.elapsed() >= SNAPSHOT_MIN_INTERVAL);
    if changed && due {
        save_snapshot(state);
        *last_snapshot = Some(tokio::time::Instant::now());
    }
    cursor.wrapping_add(polled)
}

/// The instances worth polling this round.
pub(crate) fn select_targets(state: &Proxy) -> Vec<Target> {
    // Reachability, from the same cache the routing path uses. A CVM that is
    // powered off stays in `state.instances` for up to `recycle.timeout` (10h
    // by default) while already being excluded from routing by handshake age;
    // polling it would burn a full `timeout` slot every round, and enough of
    // them stretch the round past the interval and slow health detection down
    // for every live instance in the fleet.
    let stale_after = state.config.proxy.timeouts.handshake_stale;
    // Fetched before the lock, not under it. Building this map clones every
    // peer's public key, and on a cold cache it shells out to `wg show`
    // synchronously -- neither belongs inside the mutex the routing path takes
    // once per connection.
    let handshakes = state.latest_handshakes(None).unwrap_or_default();
    let guard = state.lock();
    guard
        .state
        .instances
        .values()
        // Instances that never asked to be polled cannot be gated on the
        // answer, so polling them would only produce failures to misread.
        .filter(|instance| instance.health_check)
        .filter(|instance| {
            // No handshake recorded yet is not evidence of anything: a CVM that
            // just registered has not completed one. Only a handshake that
            // exists and has gone stale means "gone".
            handshakes
                .get(&instance.public_key)
                .is_none_or(|(_, elapsed)| *elapsed < stale_after)
        })
        .map(|instance| Target {
            id: instance.id.clone(),
            ip: instance.ip,
            public_key: instance.public_key.clone(),
        })
        .collect()
}

/// Require several consecutive failures to *reach* an agent before demoting.
///
/// An agent that answers "unhealthy" is believed immediately: it can see the
/// app and this gateway cannot. But a timed-out or refused poll is far more
/// often a transient than an outage, and acting on the first one ejects the
/// instance *and* recomputes the whole app's selection -- twice, once on the
/// way out and once on the way back.
///
/// `None` means "no verdict this round": the instance keeps whatever it had,
/// which is the whole point. Writing a provisional state instead would demote
/// it on the first failure through the back door.
fn apply_hysteresis(
    result: PollResult,
    target: &Target,
    config: &HealthCheckConfig,
    failures: &mut BTreeMap<String, u32>,
) -> Option<Observation> {
    let reason = match result {
        PollResult::Healthy => {
            failures.remove(&target.id);
            return Some(Observation {
                state: HealthState::Healthy,
                reason: String::new(),
            });
        }
        PollResult::Unhealthy(reason) => {
            failures.remove(&target.id);
            return Some(Observation {
                state: HealthState::Unhealthy,
                reason,
            });
        }
        PollResult::Unreachable(reason) => reason,
    };
    let seen = failures.entry(target.id.clone()).or_insert(0);
    // Counted before the comparison, so a configured zero or one both mean
    // "demote on the first failure" -- there is no way to demote before one has
    // been observed.
    *seen += 1;
    if *seen < config.failure_threshold {
        return None;
    }
    Some(Observation {
        state: HealthState::Unhealthy,
        reason: format!("{reason} ({seen} consecutive failures)"),
    })
}

/// Persist this node's verdicts so a process restart does not re-derive them.
pub(crate) fn save_snapshot(state: &Proxy) {
    let path = state.config.proxy.health_check.state_file.clone();
    if path.is_empty() {
        return;
    }
    let entries = {
        let guard = state.lock();
        guard
            .state
            .instances
            .values()
            .filter(|instance| instance.health_check)
            .map(|instance| {
                (
                    instance.id.clone(),
                    instance.public_key.clone(),
                    instance.health,
                )
            })
            .collect::<Vec<_>>()
    };
    // Written outside the lock: this touches the filesystem, and the routing
    // path is waiting on the same mutex.
    health_store::save(
        &path,
        entries
            .iter()
            .map(|(id, key, state)| (id.as_str(), key.as_str(), *state)),
    );
}

/// Ask one agent whether its app is serving.
///
/// A failure to get an answer comes back as [`PollResult::Unreachable`] rather
/// than as a verdict; [`apply_hysteresis`] decides when enough of them in a row
/// amount to one.
async fn poll_instance(ip: Ipv4Addr, agent_port: u16, timeout: Duration) -> PollResult {
    let url = format!("http://{ip}:{agent_port}/prpc");
    // `guest_agent_client` bounds the response: `health_check` is self-declared
    // by the CVM and this runs on a timer against the whole fleet, so an
    // unbounded body here is an out-of-memory the guest gets to schedule.
    let client = WorkerClient::new(super::guest_agent_client(url));
    let response = match tokio::time::timeout(timeout, client.health()).await {
        Err(_) => {
            return PollResult::Unreachable(format!("health poll timed out after {timeout:?}"))
        }
        Ok(Err(err)) => return PollResult::Unreachable(format!("health poll failed: {err:#}")),
        Ok(Ok(response)) => response,
    };
    if response.healthy {
        return PollResult::Healthy;
    }
    PollResult::Unhealthy(describe_unhealthy(&response))
}

/// Longest reason kept from an agent's answer.
///
/// This string ends up in a `info!` line. It is diagnostic only -- routing is
/// decided by `healthy` alone -- so there is nothing to lose by cutting it.
const MAX_REASON_BYTES: usize = 512;

/// How many unhealthy entries are named before the rest are counted.
const MAX_NAMED_CONTAINERS: usize = 8;

fn describe_unhealthy(response: &dstack_guest_agent_rpc::HealthResponse) -> String {
    if !response.error.is_empty() {
        return sanitize(&format!(
            "agent could not determine app health: {}",
            response.error
        ));
    }
    if response.unhealthy.is_empty() {
        return "agent reported unhealthy without naming anything".to_string();
    }
    let mut described = response
        .unhealthy
        .iter()
        .take(MAX_NAMED_CONTAINERS)
        .map(|container| format!("{} is {}", container.name, container.status))
        .collect::<Vec<_>>()
        .join(", ");
    if let Some(rest) = response.unhealthy.len().checked_sub(MAX_NAMED_CONTAINERS) {
        if rest > 0 {
            described.push_str(&format!(" (and {rest} more)"));
        }
    }
    sanitize(&described)
}

/// Make an agent's answer safe to log.
///
/// The guest agent sanitizes what it puts in a report, but a guest agent is
/// exactly the party this gateway does not trust -- that assumption is why
/// health is polled rather than pushed. So the bytes are re-bounded and
/// stripped here, where the log line is actually emitted. Otherwise a hostile
/// CVM alternating healthy and unhealthy gets one attacker-chosen log line per
/// interval, newlines and escapes included.
fn sanitize(reason: &str) -> String {
    dstack_types::sanitize_for_log(reason, MAX_REASON_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bound is a per-call-site opt-in now, not a property of the
    /// transport, so nothing but a test stops a refactor from dropping it --
    /// and dropping it restores an out-of-memory a hostile guest gets to
    /// schedule, since `health_check` is self-declared and this runs on a timer
    /// against the whole fleet.
    #[test]
    fn every_guest_agent_client_bounds_the_response() {
        let client = crate::proxy::guest_agent_client("http://10.0.0.2:8090/prpc".to_string());
        assert!(
            client.max_response_bytes().is_some(),
            "a guest agent is untrusted; its response must be bounded"
        );
    }

    fn config(failure_threshold: u32) -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            concurrency: 16,
            failure_threshold,
            state_file: String::new(),
        }
    }

    fn target() -> Target {
        Target {
            id: "inst-1".to_string(),
            ip: Ipv4Addr::new(10, 0, 0, 2),
            public_key: "key-1".to_string(),
        }
    }

    fn unreachable() -> PollResult {
        PollResult::Unreachable("health poll timed out after 2s".to_string())
    }

    /// One dropped packet must not eject an instance and recompute the app's
    /// whole selection.
    #[test]
    fn a_single_failure_does_not_demote() {
        let mut failures = BTreeMap::new();
        assert!(
            apply_hysteresis(unreachable(), &target(), &config(2), &mut failures).is_none(),
            "one dropped poll must leave the current verdict alone"
        );
    }

    #[test]
    fn consecutive_failures_reach_the_threshold_and_demote() {
        let mut failures = BTreeMap::new();
        let config = config(2);
        apply_hysteresis(unreachable(), &target(), &config, &mut failures);
        let observation = apply_hysteresis(unreachable(), &target(), &config, &mut failures)
            .expect("second failure should demote");
        assert_eq!(observation.state, HealthState::Unhealthy);
        assert!(observation.reason.contains("2 consecutive failures"));
    }

    #[test]
    fn one_successful_poll_clears_the_streak() {
        let mut failures = BTreeMap::new();
        let config = config(2);
        apply_hysteresis(unreachable(), &target(), &config, &mut failures);
        apply_hysteresis(PollResult::Healthy, &target(), &config, &mut failures);
        assert!(failures.is_empty(), "streak survived a healthy poll");
        assert!(
            apply_hysteresis(unreachable(), &target(), &config, &mut failures).is_none(),
            "the next failure must start counting from zero"
        );
    }

    /// The agent can see the app and this gateway cannot, so its own "no" is
    /// not something to sit on.
    #[test]
    fn an_agent_reporting_unhealthy_is_believed_immediately() {
        let mut failures = BTreeMap::new();
        let observation = apply_hysteresis(
            PollResult::Unhealthy("web is starting".to_string()),
            &target(),
            &config(3),
            &mut failures,
        )
        .expect("an answered poll is a verdict");
        assert_eq!(observation.state, HealthState::Unhealthy);
        assert_eq!(observation.reason, "web is starting");
    }

    /// An answer also clears a streak, so an app that flaps between "cannot
    /// reach" and "reachable but unhealthy" still demotes on the answer.
    #[test]
    fn an_answered_poll_clears_the_streak_too() {
        let mut failures = BTreeMap::new();
        let config = config(3);
        apply_hysteresis(unreachable(), &target(), &config, &mut failures);
        apply_hysteresis(
            PollResult::Unhealthy("db is unhealthy".to_string()),
            &target(),
            &config,
            &mut failures,
        );
        assert!(failures.is_empty());
    }

    /// Turning hysteresis off must demote on the first failure -- and cannot do
    /// anything sooner, since a failure is counted before it is compared.
    #[test]
    fn a_threshold_below_one_demotes_on_the_first_failure() {
        for threshold in [0, 1] {
            let mut failures = BTreeMap::new();
            let observation =
                apply_hysteresis(unreachable(), &target(), &config(threshold), &mut failures)
                    .unwrap_or_else(|| panic!("threshold {threshold} should demote"));
            assert_eq!(observation.state, HealthState::Unhealthy);
            assert!(observation.reason.contains("1 consecutive failures"));
        }
    }

    #[test]
    fn an_agent_error_is_described_rather_than_dropped() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: "failed to connect to docker".to_string(),
        };
        assert!(describe_unhealthy(&response).contains("failed to connect to docker"));
    }

    #[test]
    fn unhealthy_containers_are_named() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: vec![
                dstack_guest_agent_rpc::ContainerHealth {
                    name: "web".to_string(),
                    status: "starting".to_string(),
                },
                dstack_guest_agent_rpc::ContainerHealth {
                    name: "db".to_string(),
                    status: "unhealthy".to_string(),
                },
            ],
            error: String::new(),
        };
        assert_eq!(
            describe_unhealthy(&response),
            "web is starting, db is unhealthy"
        );
    }

    /// The guest agent sanitizes its own report, but a guest agent is exactly
    /// the party this gateway does not trust. A hostile one must not be able to
    /// forge a log line or repaint a terminal.
    #[test]
    fn control_characters_from_an_agent_never_reach_a_log_line() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: vec![dstack_guest_agent_rpc::ContainerHealth {
                name: "web\n2026-01-01 INFO forged".to_string(),
                status: "\x1b[31mstarting\r".to_string(),
            }],
            error: String::new(),
        };
        let described = describe_unhealthy(&response);
        assert!(!described.contains('\n'), "newline survived: {described:?}");
        assert!(!described.contains('\r'), "CR survived: {described:?}");
        assert!(
            !described.contains('\x1b'),
            "escape survived: {described:?}"
        );
    }

    /// `char::is_control` alone lets these through, and both change what a
    /// reader sees: U+2028 is a line break to most log viewers, U+202E reverses
    /// the rendering of everything after it.
    #[test]
    fn line_separators_and_bidi_overrides_are_stripped_too() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: "web\u{2028}Jan 01 INFO ok\u{202E}desrever".to_string(),
        };
        let described = describe_unhealthy(&response);
        assert!(!described.contains('\u{2028}'), "{described:?}");
        assert!(!described.contains('\u{202E}'), "{described:?}");
    }

    /// The only bound on the response body is a megabyte, and this line is
    /// emitted every time the verdict flips.
    #[test]
    fn an_oversized_reason_is_truncated() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: "x".repeat(64 * 1024),
        };
        let described = describe_unhealthy(&response);
        assert!(
            described.len() < MAX_REASON_BYTES * 2,
            "reason was {} bytes",
            described.len()
        );
        assert!(described.ends_with("(truncated)"));
    }

    /// A thousand containers must not become a thousand-entry log line.
    #[test]
    fn only_the_first_few_containers_are_named() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: (0..50)
                .map(|index| dstack_guest_agent_rpc::ContainerHealth {
                    name: format!("svc-{index}"),
                    status: "starting".to_string(),
                })
                .collect(),
            error: String::new(),
        };
        let described = describe_unhealthy(&response);
        assert!(described.contains("svc-0"));
        assert!(!described.contains("svc-40"));
        assert!(described.contains("and 42 more"), "got: {described}");
    }

    /// An agent that says "not healthy" but names nothing must still produce a
    /// reason an operator can act on.
    #[test]
    fn an_unhealthy_response_naming_nothing_still_has_a_reason() {
        let response = dstack_guest_agent_rpc::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: String::new(),
        };
        assert!(!describe_unhealthy(&response).is_empty());
    }
}
