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
//! `requirements.health_check`, which reaches the gateway as
//! `RegisterCvmRequest.health_check`. That flag, not a probe, is what keeps an
//! older or uninterested CVM out of this: every failed poll counts as
//! unhealthy, so discovering support by trying would blackhole exactly the
//! instances that cannot answer.
//!
//! Reachability is plain HTTP over the WireGuard tunnel, the same way
//! [`super::port_policy`] already fetches port policy from the agent.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;
use std::time::Duration;

use dstack_guest_agent_rpc::v1::worker_client::WorkerClient as WorkerV1Client;
use futures::StreamExt;
use http_client::ConnectionReuse;
use tokio::time::MissedTickBehavior;
use tracing::{error, info, warn};

use crate::config::HealthCheckConfig;
use crate::main_service::Proxy;
use crate::models::HealthState;

/// How long to wait before restarting the poll loop after it dies.
const RESTART_DELAY: Duration = Duration::from_secs(5);

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
    /// The agent answered, and the answer was no. Build with
    /// [`PollResult::unhealthy`]; the reason is app-authored.
    Unhealthy(String),
    /// No answer: timed out, refused, unparseable. Build with
    /// [`PollResult::unreachable`]; the reason quotes a transport error, which
    /// is not the same as being free of guest-controlled bytes.
    Unreachable(String),
}

impl PollResult {
    /// The agent answered "no", for `reason`.
    fn unhealthy(reason: impl AsRef<str>) -> Self {
        Self::Unhealthy(sanitize(reason.as_ref()))
    }

    /// No usable answer arrived, because of `reason`.
    ///
    /// Sanitizing in the constructor rather than at each call site, because the
    /// obvious-looking call sites are the dangerous ones. A decode failure
    /// stringifies a `serde_json` error, and serde renders a type mismatch by
    /// quoting the offending value in full: a CVM answering `{"healthy":"<16
    /// MiB>"}` turns into a 16 MiB log line, newlines and terminal escapes
    /// intact. That is the same attack the answered-unhealthy path is bounded
    /// against, arriving through the branch that reads like plumbing.
    fn unreachable(reason: impl AsRef<str>) -> Self {
        Self::Unreachable(sanitize(reason.as_ref()))
    }
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
    loop {
        ticker.tick().await;
        cursor = poll_round(&state, &config, &mut failures, cursor).await;
    }
}

async fn poll_round(
    state: &Proxy,
    config: &HealthCheckConfig,
    failures: &mut BTreeMap<String, u32>,
    cursor: usize,
) -> usize {
    // Snapshot under the lock and poll outside it. These are network round
    // trips, and holding `ProxyState` across them would stall every connection
    // being routed.
    let mut targets = select_targets(state);
    // Set membership rather than a scan per entry: both sides are the fleet, so
    // the nested form is quadratic in it, re-run every interval.
    let live = targets
        .iter()
        .map(|target| target.id.as_str())
        .collect::<BTreeSet<_>>();
    failures.retain(|id, _| live.contains(id.as_str()));
    drop(live);
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
        state.lock().record_instance_health(&target, observation);
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
        .filter(|instance| instance.health_check())
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

/// Ask one agent whether its app is serving.
///
/// A failure to get an answer comes back as [`PollResult::Unreachable`] rather
/// than as a verdict; [`apply_hysteresis`] decides when enough of them in a row
/// amount to one.
async fn poll_instance(ip: Ipv4Addr, agent_port: u16, timeout: Duration) -> PollResult {
    let client = WorkerV1Client::new(prober_transport(ip, agent_port));
    let response = match tokio::time::timeout(timeout, client.health(Default::default())).await {
        Err(_) => {
            return PollResult::unreachable(format!("health poll timed out after {timeout:?}"))
        }
        Ok(Err(err)) => return PollResult::unreachable(format!("health poll failed: {err:#}")),
        Ok(Ok(response)) => response,
    };
    if response.healthy {
        return PollResult::Healthy;
    }
    PollResult::unhealthy(describe_unhealthy(&response))
}

/// How the poller talks to one agent.
///
/// Named, rather than built inline, so the two decisions it makes can be
/// asserted. Both are the kind a refactor drops without anything failing.
///
/// `guest_agent_client` bounds the response: `health_check` is self-declared by
/// the CVM and this runs on a timer against the whole fleet, so an unbounded
/// body here is an out-of-memory the guest gets to schedule.
///
/// The connection is fresh rather than pooled, because opening it is half of
/// what this call asks. An agent out of file descriptors, or with a full accept
/// backlog, keeps answering whoever is already connected while refusing
/// everyone new -- and every connection the gateway proxies to the app is a new
/// one. A probe riding a pooled connection would report healthy for an instance
/// no real request can reach. Only the connection is unshared; the client
/// itself is process-wide. See `http_client::ConnectionReuse`.
fn prober_transport(ip: Ipv4Addr, agent_port: u16) -> http_client::prpc::PrpcClient {
    // `/prpc/v1`, not `/prpc`: `Health` is a `WorkerV1` method.
    //
    // No released agent is affected. `Health` never shipped in a release, and a
    // pre-0.6 gateway does not poll, so the only guests that can be asked are
    // 0.6+ ones that opted in via `RegisterCvmRequest.health_check`.
    //
    // The one skew that does exist is unreleased: an interim `next` build that
    // served `Health` at `/prpc` and registered with `health_check = true` will
    // now 404 every poll, and a 404 counts as unreachable, so after
    // `failure_threshold` polls the instance drops out of app-id rotation.
    // Instance-id routing keeps working and a restart on a current build fixes
    // it. Not worth a compatibility probe on every poll for a build nobody was
    // asked to run.
    let url = format!("http://{ip}:{agent_port}/prpc/v1");
    super::guest_agent_client(url, ConnectionReuse::Fresh)
}

/// Longest reason kept from an agent's answer.
///
/// This string ends up in a `info!` line. It is diagnostic only -- routing is
/// decided by `healthy` alone -- so there is nothing to lose by cutting it.
const MAX_REASON_BYTES: usize = 512;

/// How many unhealthy entries are named before the rest are counted.
const MAX_NAMED_CONTAINERS: usize = 8;

/// Summarize an agent's "no" for the log line. The caller sanitizes.
fn describe_unhealthy(response: &dstack_guest_agent_rpc::v1::HealthResponse) -> String {
    if !response.error.is_empty() {
        return format!("agent could not determine app health: {}", response.error);
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
    described
}

/// Make an agent's answer safe to log.
///
/// The guest agent sanitizes what it puts in a report, but a guest agent is
/// exactly the party this gateway does not trust -- that assumption is why
/// health is polled rather than pushed. So the bytes are re-bounded and
/// stripped here, where the log line is actually emitted. Otherwise a hostile
/// CVM alternating healthy and unhealthy gets one attacker-chosen log line per
/// interval, newlines and escapes included.
///
/// Called from [`PollResult::unhealthy`] and [`PollResult::unreachable`] rather
/// than from each site that formats a reason, because the site that was missed
/// was the one that looked like plumbing rather than like an answer.
fn sanitize(reason: &str) -> String {
    dstack_types::sanitize_for_log(reason, MAX_REASON_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The bound is a per-call-site opt-in now, not a property of the
    /// transport, so nothing but a test stops a refactor from dropping it --
    /// and dropping it restores an out-of-memory a hostile guest gets to
    /// schedule, since `health_check` is self-declared and this runs on a timer
    /// against the whole fleet.
    #[test]
    fn every_guest_agent_client_bounds_the_response() {
        let client = crate::proxy::guest_agent_client(
            "http://10.0.0.2:8090/prpc".to_string(),
            ConnectionReuse::Pooled,
        );
        assert!(
            client.max_response_bytes().is_some(),
            "a guest agent is untrusted; its response must be bounded"
        );
    }

    /// A stand-in for a CVM's guest agent, on loopback.
    ///
    /// `poll_instance` is handed an address and does everything else itself:
    /// forms the pRPC request, reads the answer under a bound, and turns a
    /// transport failure into `Unreachable` rather than into a verdict. None of
    /// that is reachable from a unit test that injects a `PollResult`, and it
    /// is the one hop between the gateway and an untrusted peer -- so it gets a
    /// real socket.
    ///
    /// `answer` of `None` accepts the connection and then says nothing, which
    /// is what a wedged agent looks like from here: not a refusal, which fails
    /// fast, but silence that has to be timed out.
    async fn fake_agent(answer: Option<Vec<u8>>) -> u16 {
        fake_agent_capturing(answer, None).await
    }

    /// The same stand-in, optionally reporting the request line it was sent.
    ///
    /// Kept as one implementation because the drain below is what stops this
    /// fixture flaking: answering into a socket the peer is still writing to is
    /// a reset on some platforms.
    async fn fake_agent_capturing(
        answer: Option<Vec<u8>>,
        request_line: Option<tokio::sync::oneshot::Sender<String>>,
    ) -> u16 {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            // Drain the request first. Answering into a socket the peer is
            // still writing to is a reset on some platforms, which would show
            // up as a flake rather than as the case under test.
            let mut pending = Vec::new();
            let mut buf = [0u8; 1024];
            let headers_end = loop {
                if let Some(at) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
                    break at + 4;
                }
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                }
            };
            let content_length = String::from_utf8_lossy(&pending[..headers_end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            while pending.len() < headers_end + content_length {
                match socket.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => pending.extend_from_slice(&buf[..n]),
                }
            }
            if let Some(tx) = request_line {
                let head = String::from_utf8_lossy(&pending[..headers_end]).into_owned();
                let _ = tx.send(head.lines().next().unwrap_or_default().to_string());
            }
            let Some(answer) = answer else {
                std::future::pending::<()>().await;
                return;
            };
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                answer.len()
            );
            // Ignored: an oversized answer is refused mid-body, so the client
            // is gone long before the last chunk goes out. That is the case
            // under test, not a failure of the fixture.
            let _ = socket.write_all(head.as_bytes()).await;
            let _ = socket.write_all(&answer).await;
        });
        port
    }

    /// The poller must ask the versioned surface. `Health` lives on `WorkerV1`
    /// at `/prpc/v1`; the unversioned `Worker` at `/prpc` is closed at v0.5.11
    /// and has no such method, so a poller pointed there gets a 400 that
    /// `apply_hysteresis` eventually turns into "unhealthy" for every instance
    /// in the fleet at once.
    #[tokio::test]
    async fn the_poller_asks_the_v1_surface() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let port = fake_agent_capturing(Some(br#"{"healthy":true}"#.to_vec()), Some(tx)).await;

        let _ = poll_instance(Ipv4Addr::LOCALHOST, port, Duration::from_secs(5)).await;

        let request_line = rx.await.expect("the poller sent no request");
        assert!(
            request_line.contains("/prpc/v1/Health"),
            "expected the v1 Health path, got: {request_line}"
        );
    }

    async fn poll_fake(answer: Option<Vec<u8>>) -> PollResult {
        let port = fake_agent(answer).await;
        poll_instance(Ipv4Addr::LOCALHOST, port, Duration::from_secs(5)).await
    }

    #[tokio::test]
    async fn an_agent_that_says_yes_is_healthy() {
        assert_eq!(
            poll_fake(Some(br#"{"healthy":true}"#.to_vec())).await,
            PollResult::Healthy
        );
    }

    /// The answer has to survive being decoded, not just being received: the
    /// container list is what an operator reads to find out which container is
    /// holding the instance out of rotation.
    #[tokio::test]
    async fn an_agent_that_says_no_is_believed_and_names_what_failed() {
        let answer = br#"{"healthy":false,"unhealthy":[{"name":"web","status":"unhealthy"}]}"#;
        let PollResult::Unhealthy(reason) = poll_fake(Some(answer.to_vec())).await else {
            panic!("an agent answering `no` must be believed on the spot");
        };
        assert!(reason.contains("web is unhealthy"), "unexpected: {reason}");
    }

    /// Silence is not a verdict. It has to arrive as `Unreachable`, because
    /// that is the only thing `apply_hysteresis` will make an app wait
    /// `failure_threshold` rounds for -- an `Unhealthy` here would demote on
    /// the first dropped packet.
    #[tokio::test]
    async fn an_agent_that_accepts_and_then_says_nothing_times_out() {
        let port = fake_agent(None).await;
        let result = poll_instance(Ipv4Addr::LOCALHOST, port, Duration::from_millis(100)).await;
        let PollResult::Unreachable(reason) = result else {
            panic!("a silent agent must not produce a verdict, got {result:?}");
        };
        assert!(reason.contains("timed out"), "unexpected: {reason}");
    }

    #[tokio::test]
    async fn nothing_listening_is_unreachable_rather_than_unhealthy() {
        // Bound and dropped, so the port is one nothing answers on.
        let port = {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
                .await
                .expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let result = poll_instance(Ipv4Addr::LOCALHOST, port, Duration::from_secs(5)).await;
        assert!(
            matches!(result, PollResult::Unreachable(_)),
            "a refused connection must not read as an agent saying no, got {result:?}"
        );
    }

    /// The bound the whole "a guest agent is untrusted" argument rests on,
    /// asserted where it is actually applied rather than where it is set.
    /// `every_guest_agent_client_bounds_the_response` proves the call site asks
    /// for one and the transport has its own test that it enforces one; this is
    /// the test that they are wired to each other.
    #[tokio::test]
    async fn an_oversized_answer_is_refused_instead_of_buffered() {
        let mut answer = br#"{"healthy":true,"padding":""#.to_vec();
        answer.resize(crate::proxy::MAX_GUEST_RESPONSE_BYTES + 4096, b'A');
        answer.extend_from_slice(br#""}"#);
        let result = poll_fake(Some(answer)).await;
        assert!(
            matches!(result, PollResult::Unreachable(_)),
            "an unbounded answer is an out-of-memory the guest gets to schedule, got {result:?}"
        );
    }

    /// A decode failure is the sanitizer's worst case and the one that was
    /// missed once: serde renders a type mismatch by quoting the offending
    /// value, so the guest picks the bytes. Covered in isolation already --
    /// this is the same thing arriving over a socket, which is how it would
    /// actually happen.
    #[tokio::test]
    async fn a_hostile_answer_cannot_write_its_own_log_line() {
        let answer = format!(
            r#"{{"healthy":"{}"}}"#,
            "\\u000a[ERROR] fabricated\\u0000".repeat(64)
        );
        let result = poll_fake(Some(answer.into_bytes())).await;
        let PollResult::Unreachable(reason) = result else {
            panic!("an undecodable answer is not a verdict, got {result:?}");
        };
        assert!(
            !reason.contains('\n') && !reason.contains('\u{0}'),
            "control characters reached a log line: {reason:?}"
        );
        // The marker truncation appends is allowed past the bound, the same
        // way `an_unreachable_reason_is_bounded_and_stripped_too` has it.
        const MARKER: &str = "... (truncated)";
        assert!(
            reason.len() <= MAX_REASON_BYTES + MARKER.len(),
            "reason was not bounded: {} bytes",
            reason.len()
        );
        // Asserted, not assumed: without it this test would also pass on a
        // reason that was simply short, which proves nothing about the bound.
        assert!(reason.ends_with(MARKER), "not truncated: {reason:?}");
    }

    /// The probe must open its own connection. Reuse is the cheaper default
    /// and would be adopted by anyone tidying this up, so the reason it is
    /// wrong here is written down in `prober_transport` and asserted here: a
    /// pooled connection reports on an agent's ability to serve a conversation
    /// it is already in, while the traffic this gates is every time a *new*
    /// one. An agent that has run out of descriptors passes the first and
    /// fails the second.
    #[test]
    fn the_probe_does_not_ride_a_connection_someone_else_opened() {
        assert_eq!(
            prober_transport(Ipv4Addr::new(10, 0, 0, 2), 8090).connection_reuse(),
            ConnectionReuse::Fresh,
            "a probe over a pooled connection cannot see an agent that refuses new ones"
        );
    }

    fn config(failure_threshold: u32) -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            interval: Duration::from_secs(5),
            timeout: Duration::from_secs(2),
            concurrency: 16,
            failure_threshold,
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
        PollResult::unreachable("health poll timed out after 2s")
    }

    /// The reason exactly as it reaches a log line.
    ///
    /// `describe_unhealthy` composes it and the constructor bounds it, and only
    /// the pair is ever what an operator sees -- asserting on `describe_unhealthy`
    /// alone would pass with the sanitizing dropped.
    fn unhealthy_reason(response: &dstack_guest_agent_rpc::v1::HealthResponse) -> String {
        match PollResult::unhealthy(describe_unhealthy(response)) {
            PollResult::Unhealthy(reason) => reason,
            other => panic!("expected an unhealthy verdict, got {other:?}"),
        }
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
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: "failed to connect to docker".to_string(),
        };
        assert!(describe_unhealthy(&response).contains("failed to connect to docker"));
    }

    #[test]
    fn unhealthy_containers_are_named() {
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: vec![
                dstack_guest_agent_rpc::v1::ContainerHealth {
                    name: "web".to_string(),
                    status: "starting".to_string(),
                },
                dstack_guest_agent_rpc::v1::ContainerHealth {
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
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: vec![dstack_guest_agent_rpc::v1::ContainerHealth {
                name: "web\n2026-01-01 INFO forged".to_string(),
                status: "\x1b[31mstarting\r".to_string(),
            }],
            error: String::new(),
        };
        let described = unhealthy_reason(&response);
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
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: "web\u{2028}Jan 01 INFO ok\u{202E}desrever".to_string(),
        };
        let described = unhealthy_reason(&response);
        assert!(!described.contains('\u{2028}'), "{described:?}");
        assert!(!described.contains('\u{202E}'), "{described:?}");
    }

    /// The only bound on the response body is a megabyte, and this line is
    /// emitted every time the verdict flips.
    #[test]
    fn an_oversized_reason_is_truncated() {
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: "x".repeat(64 * 1024),
        };
        let described = unhealthy_reason(&response);
        assert!(
            described.len() < MAX_REASON_BYTES * 2,
            "reason was {} bytes",
            described.len()
        );
        assert!(described.ends_with("(truncated)"));
    }

    /// The other half of the same rule, on the branch that reads like plumbing.
    ///
    /// An unreachable reason stringifies whatever failed, and a decode failure
    /// stringifies a `serde_json` error -- which renders a type mismatch by
    /// quoting the offending value *in full*. A CVM answering
    /// `{"healthy":"<16 MiB of text>"}` therefore emitted a 16 MiB log line
    /// with its newlines and terminal escapes intact, and could schedule one
    /// every interval by alternating healthy and garbage. The answered-unhealthy
    /// path was bounded from the start; this one was not, because nothing about
    /// a transport error looks guest-controlled.
    #[test]
    fn an_unreachable_reason_is_bounded_and_stripped_too() {
        // The marker the truncation appends, which is allowed past the bound.
        const MARKER: &str = "... (truncated)";
        let quoted = "\nlevel=fatal msg=owned\u{1b}[31m".repeat(4096);
        let hostile = format!("health poll failed: invalid type: string \"{quoted}\"");
        assert!(
            hostile.len() > MAX_REASON_BYTES * 4,
            "the fixture must exceed the bound, or this test proves nothing"
        );

        let PollResult::Unreachable(reason) = PollResult::unreachable(&hostile) else {
            panic!("unreachable() must build an Unreachable");
        };
        assert!(
            reason.len() <= MAX_REASON_BYTES + MARKER.len(),
            "reason was {} bytes",
            reason.len()
        );
        assert!(reason.ends_with(MARKER), "not truncated: {reason:?}");
        assert!(!reason.contains('\n'), "newline survived: {reason:?}");
        assert!(!reason.contains('\u{1b}'), "escape survived: {reason:?}");
    }

    /// A thousand containers must not become a thousand-entry log line.
    #[test]
    fn only_the_first_few_containers_are_named() {
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: (0..50)
                .map(|index| dstack_guest_agent_rpc::v1::ContainerHealth {
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
        let response = dstack_guest_agent_rpc::v1::HealthResponse {
            healthy: false,
            unhealthy: vec![],
            error: String::new(),
        };
        assert!(!describe_unhealthy(&response).is_empty());
    }
}
