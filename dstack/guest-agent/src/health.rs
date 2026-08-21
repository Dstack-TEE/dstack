// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Application health, refreshed on the agent's own timer.
//!
//! A CVM registers from `dstack-util setup`, during boot, before
//! `app-compose.service` has started a single container. From that moment the
//! gateway considers it eligible for traffic, and the only thing standing
//! between it and a request is the WireGuard handshake age -- which says the
//! tunnel is up and nothing about whether anything is listening behind it.
//! `Worker.Health` is how the gateway asks the second question.
//!
//! Everything expensive happens here, on a timer, and `Worker.Health` only
//! reads [`HealthMonitor::report`]'s cached answer. Two reasons that split is
//! not optional:
//!
//! - A fleet of gateway nodes polls the same instance. Doing the work per
//!   request would multiply one operator's cluster size into that many
//!   container-runtime queries inside every CVM.
//! - The RPC is served on the external listener, which is publicly reachable
//!   (see `docs/security/cvm-boundaries.md`). Any work it does per request is
//!   work an anonymous caller can ask for at an arbitrary rate.
//!
//! Which question gets asked is the app's choice, declared in
//! `requirements.health_check`: a `health_file` it writes itself, or -- by
//! default -- the state of the containers the runtime knows about.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dstack_types::{HealthCheck, HEALTH_FILE_MAX_AGE_SECS};
use or_panic::ResultOrPanic;
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::container_health::{self, HealthReport, UnhealthyContainer};

/// How often the verdict is recomputed.
///
/// The gateway polls on its own interval; total detection latency is the sum of
/// the two. Kept short enough that the sum stays inside the window an operator
/// would call "noticed it", and long enough that the container path is a
/// handful of runtime queries a minute rather than one per gateway request.
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);

/// How long one refresh may take before it is abandoned.
///
/// A wedged container runtime must not stall the loop forever, and the child
/// processes started underneath are spawned with `kill_on_drop`, so abandoning
/// the future actually reclaims them.
const REFRESH_TIMEOUT: Duration = Duration::from_secs(10);

/// How many consecutive refresh failures are tolerated before the verdict flips.
///
/// A single failure is far more often a container being recreated underneath us
/// than an app going down, and this loop gets another attempt in
/// [`REFRESH_INTERVAL`]. Ejecting an instance from rotation on the first one
/// would make every redeploy a brief outage.
const MAX_CONSECUTIVE_FAILURES: u32 = 3;

/// Largest `health_file` the agent will read.
///
/// The file is two short lines. Anything beyond this is either a mistake or an
/// attempt to make the agent allocate on the app's behalf.
const MAX_HEALTH_FILE_BYTES: u64 = 4096;

/// Longest state token echoed back into a report.
///
/// The token is a word. Bounding it keeps app-controlled bytes from reaching
/// the gateway's logs in quantity; [`sanitize`] handles the rest.
const MAX_STATE_BYTES: usize = 64;

/// Reported in place of a container name, so an operator reading gateway logs
/// can tell an app-written verdict from a container that failed its healthcheck.
const HEALTH_FILE_NAME: &str = "<health_file>";

/// Reported before either source has been consulted for the first time.
const PENDING_NAME: &str = "<health>";

/// The latest verdict, in the shape `Worker.Health` answers with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Verdict {
    pub healthy: bool,
    pub unhealthy: Vec<UnhealthyContainer>,
    /// Set when the agent could not reach the source of truth at all, as
    /// opposed to reaching it and being told something is wrong.
    pub error: String,
}

impl Verdict {
    fn healthy() -> Self {
        Self {
            healthy: true,
            unhealthy: vec![],
            error: String::new(),
        }
    }

    /// Unhealthy for a reason the agent can name, attributed to `name`.
    fn unhealthy(name: &str, status: String) -> Self {
        Self {
            healthy: false,
            unhealthy: vec![UnhealthyContainer {
                name: name.to_string(),
                status,
            }],
            error: String::new(),
        }
    }

    /// Unhealthy because the agent could not see the app at all.
    fn failed(error: String) -> Self {
        Self {
            healthy: false,
            unhealthy: vec![],
            error,
        }
    }

    fn from_report(report: HealthReport) -> Self {
        Self {
            healthy: report.healthy,
            unhealthy: report.unhealthy,
            error: String::new(),
        }
    }

    /// One line, for the log emitted when the verdict changes.
    fn summary(&self) -> String {
        if self.healthy {
            return "healthy".to_string();
        }
        if !self.error.is_empty() {
            return format!("unhealthy: {}", self.error);
        }
        let detail = self
            .unhealthy
            .iter()
            .map(|container| format!("{} is {}", container.name, container.status))
            .collect::<Vec<_>>()
            .join(", ");
        format!("unhealthy: {detail}")
    }
}

/// What the container fallback needs to find the app's own containers.
#[derive(Clone, Debug)]
pub(crate) struct ContainerSource {
    /// `app_compose.runner`: which runtime started them.
    runner: String,
    /// The Compose project the app's containers carry, so only they are judged.
    project: String,
}

impl ContainerSource {
    /// Resolve the project name once, from the compose file the app shipped.
    pub(crate) fn new(runner: String, compose_file: Option<&str>) -> Self {
        Self {
            runner,
            project: container_health::compose_project(compose_file),
        }
    }
}

/// The cached verdict plus the loop that refreshes it.
pub(crate) struct HealthMonitor {
    latest: RwLock<Verdict>,
}

impl HealthMonitor {
    /// Start the refresh loop and hand back the handle the RPC reads.
    ///
    /// Only called when the app opted in; an app that did not is never polled
    /// by the gateway, so there is nothing to keep up to date.
    pub(crate) fn spawn(check: HealthCheck, source: ContainerSource) -> Arc<Self> {
        match &check.health_file {
            Some(path) => info!("app health is read from {path} every {REFRESH_INTERVAL:?}"),
            None => info!(
                "app health is judged from {} containers every {REFRESH_INTERVAL:?}",
                source.runner
            ),
        }
        let monitor = Arc::new(Self {
            // The same rule the gateway applies to an instance that has
            // registered but not yet answered a poll: not having run is not a
            // pass. Registration happens long before the app is up.
            latest: RwLock::new(Verdict::unhealthy(
                PENDING_NAME,
                "health has not been determined yet".to_string(),
            )),
        });
        let task = monitor.clone();
        tokio::spawn(async move {
            let mut failures = 0;
            loop {
                match refresh(&check, &source).await {
                    Ok(verdict) => {
                        failures = 0;
                        task.store(verdict);
                    }
                    Err(err) => {
                        // Hold the previous verdict for a few rounds: a
                        // container being recreated underneath us looks exactly
                        // like this, and it resolves itself by the next tick.
                        failures += 1;
                        let error = format!("{err:#}");
                        if failures < MAX_CONSECUTIVE_FAILURES {
                            debug!(
                                "health refresh failed ({failures}), keeping last verdict: {error}"
                            );
                        } else {
                            warn!("health refresh has failed {failures} times: {error}");
                            task.store(Verdict::failed(error));
                        }
                    }
                }
                tokio::time::sleep(REFRESH_INTERVAL).await;
            }
        });
        monitor
    }

    /// The cached verdict. This is the whole cost of one `Worker.Health` call.
    pub(crate) fn report(&self) -> Verdict {
        self.latest
            .read()
            .or_panic("health monitor lock poisoned")
            .clone()
    }

    fn store(&self, verdict: Verdict) {
        let mut latest = self.latest.write().or_panic("health monitor lock poisoned");
        if *latest != verdict {
            info!("app health is now {}", verdict.summary());
        }
        *latest = verdict;
    }
}

/// One refresh, from whichever source the app declared.
///
/// `Err` means "could not tell", which the caller tolerates for a few rounds.
/// A verdict of unhealthy is a different thing and comes back as `Ok`.
async fn refresh(check: &HealthCheck, source: &ContainerSource) -> anyhow::Result<Verdict> {
    let work = async {
        match &check.health_file {
            Some(path) => Ok(read_health_file(path).await),
            None => container_health::collect(&source.runner, &source.project)
                .await
                .map(Verdict::from_report),
        }
    };
    match tokio::time::timeout(REFRESH_TIMEOUT, work).await {
        Ok(result) => result,
        Err(_) => anyhow::bail!("health refresh timed out after {REFRESH_TIMEOUT:?}"),
    }
}

/// Read the app's own verdict out of the file it declared.
///
/// Never returns `Err`: an unreadable or malformed file is the app failing to
/// hold up its end, which is a verdict, not an inability to reach one.
async fn read_health_file(path: &str) -> Verdict {
    let contents = match read_bounded(path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Verdict::unhealthy(HEALTH_FILE_NAME, format!("{path} has not been written yet"))
        }
        Err(err) => {
            return Verdict::unhealthy(HEALTH_FILE_NAME, format!("cannot read {path}: {err}"))
        }
    };
    judge_health_file(&contents, now_secs())
}

async fn read_bounded(path: &str) -> std::io::Result<String> {
    let file = tokio::fs::File::open(path).await?;
    let mut contents = String::new();
    file.take(MAX_HEALTH_FILE_BYTES)
        .read_to_string(&mut contents)
        .await?;
    Ok(contents)
}

/// Apply the two-line contract to what the file actually contained.
///
/// Split out so the rule can be tested without a filesystem, and so the
/// staleness bound is tested against an injected clock rather than a sleep.
fn judge_health_file(contents: &str, now: u64) -> Verdict {
    let mut lines = contents.lines();
    let Some(state) = lines.next().map(str::trim) else {
        return Verdict::unhealthy(HEALTH_FILE_NAME, "health file is empty".to_string());
    };
    let Some(timestamp) = lines.next().map(str::trim) else {
        return Verdict::unhealthy(
            HEALTH_FILE_NAME,
            "health file must have two lines: state and unix timestamp".to_string(),
        );
    };
    let Ok(written) = timestamp.parse::<u64>() else {
        return Verdict::unhealthy(
            HEALTH_FILE_NAME,
            format!(
                "health file timestamp is not a unix time in seconds: {}",
                sanitize(timestamp)
            ),
        );
    };
    // A clock that ran backwards, or an app stamping slightly ahead, is not
    // evidence of anything. Only age counts.
    let age = now.saturating_sub(written);
    if age > HEALTH_FILE_MAX_AGE_SECS {
        return Verdict::unhealthy(
            HEALTH_FILE_NAME,
            format!(
                "health file is stale: written {age}s ago, limit is {HEALTH_FILE_MAX_AGE_SECS}s"
            ),
        );
    }
    match state.to_ascii_lowercase().as_str() {
        "healthy" => Verdict::healthy(),
        "unhealthy" => Verdict::unhealthy(HEALTH_FILE_NAME, "app reports unhealthy".to_string()),
        // Anything else is the app saying something this agent does not
        // understand, which is not a pass.
        _ => Verdict::unhealthy(
            HEALTH_FILE_NAME,
            format!("unrecognized health state: {}", sanitize(state)),
        ),
    }
}

/// Make an app-controlled token safe to put in a report.
///
/// The report is served to anonymous callers on the external listener and is
/// logged by the gateway, so control characters -- newlines that forge a log
/// line, ANSI escapes that rewrite a terminal -- must not survive, and the
/// length must be bounded.
fn sanitize(token: &str) -> String {
    let cleaned = token
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect::<String>();
    let cleaned = cleaned.trim();
    if cleaned.is_empty() {
        return "<empty>".to_string();
    }
    if cleaned.len() <= MAX_STATE_BYTES {
        return cleaned.to_string();
    }
    // Slice on a char boundary so a multi-byte character is never cut in half.
    let mut end = MAX_STATE_BYTES;
    while end > 0 && !cleaned.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &cleaned[..end])
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_771_234_567;

    fn file(contents: &str) -> Verdict {
        judge_health_file(contents, NOW)
    }

    fn reason(verdict: &Verdict) -> String {
        verdict
            .unhealthy
            .first()
            .map(|container| container.status.clone())
            .unwrap_or_default()
    }

    #[test]
    fn a_fresh_healthy_file_is_healthy() {
        let verdict = file(&format!("healthy\n{NOW}\n"));
        assert_eq!(verdict, Verdict::healthy());
    }

    #[test]
    fn the_state_is_case_insensitive_and_whitespace_tolerant() {
        assert!(file(&format!("  HEALTHY  \n  {NOW}  \n")).healthy);
    }

    #[test]
    fn a_fresh_unhealthy_file_is_unhealthy() {
        let verdict = file(&format!("unhealthy\n{NOW}"));
        assert!(!verdict.healthy);
        assert_eq!(reason(&verdict), "app reports unhealthy");
    }

    /// The whole point of the timestamp: an app that stopped updating the file
    /// must not keep its instance in rotation on the strength of the last thing
    /// it wrote.
    #[test]
    fn a_stale_healthy_file_is_not_healthy() {
        let written = NOW - HEALTH_FILE_MAX_AGE_SECS - 1;
        let verdict = file(&format!("healthy\n{written}"));
        assert!(!verdict.healthy);
        assert!(
            reason(&verdict).contains("stale"),
            "unexpected reason: {}",
            reason(&verdict)
        );
    }

    #[test]
    fn a_file_written_exactly_at_the_limit_is_still_fresh() {
        let written = NOW - HEALTH_FILE_MAX_AGE_SECS;
        assert!(file(&format!("healthy\n{written}")).healthy);
    }

    /// A clock that jumped, or an app stamping a moment ahead, is not a failure.
    #[test]
    fn a_timestamp_in_the_future_is_treated_as_fresh() {
        assert!(file(&format!("healthy\n{}", NOW + 3600)).healthy);
    }

    #[test]
    fn a_missing_timestamp_line_is_not_healthy() {
        let verdict = file("healthy\n");
        assert!(!verdict.healthy);
        assert!(reason(&verdict).contains("two lines"));
    }

    #[test]
    fn an_unparseable_timestamp_is_not_healthy() {
        let verdict = file("healthy\nyesterday");
        assert!(!verdict.healthy);
        assert!(reason(&verdict).contains("unix time"));
    }

    #[test]
    fn an_empty_file_is_not_healthy() {
        let verdict = file("");
        assert!(!verdict.healthy);
        assert!(reason(&verdict).contains("empty"));
    }

    /// Unknown states hold traffic back rather than pass, the same way an
    /// unknown container health string does.
    #[test]
    fn an_unrecognized_state_is_not_healthy() {
        let verdict = file(&format!("degraded\n{NOW}"));
        assert!(!verdict.healthy);
        assert!(reason(&verdict).contains("degraded"));
    }

    /// The state reaches anonymous callers and the gateway's logs, so it must
    /// not be able to carry a newline or an escape sequence there.
    #[test]
    fn control_characters_in_the_state_are_stripped() {
        let verdict = file(&format!("\x1b[31mbad\r\n{NOW}"));
        let reason = reason(&verdict);
        assert!(!reason.contains('\x1b'), "escape survived: {reason:?}");
        assert!(
            !reason.contains('\r'),
            "carriage return survived: {reason:?}"
        );
    }

    #[test]
    fn a_long_state_is_truncated() {
        let long = "x".repeat(MAX_STATE_BYTES * 4);
        let verdict = file(&format!("{long}\n{NOW}"));
        assert!(reason(&verdict).len() < MAX_STATE_BYTES * 2);
    }

    #[tokio::test]
    async fn a_missing_health_file_is_not_healthy() {
        let verdict = read_health_file("/nonexistent/dstack-health-test").await;
        assert!(!verdict.healthy);
        assert!(reason(&verdict).contains("has not been written yet"));
    }

    #[tokio::test]
    async fn a_health_file_is_read_from_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("health");
        std::fs::write(&path, format!("healthy\n{}\n", now_secs())).expect("write");
        let verdict = read_health_file(path.to_str().expect("utf8")).await;
        assert!(verdict.healthy, "{verdict:?}");
    }

    /// An app cannot make the agent allocate an arbitrary amount by pointing
    /// `health_file` at something huge.
    #[tokio::test]
    async fn an_oversized_health_file_is_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("health");
        let mut contents = format!("healthy\n{}\n", now_secs());
        contents.push_str(&"padding\n".repeat(4096));
        std::fs::write(&path, &contents).expect("write");
        let read = read_bounded(path.to_str().expect("utf8"))
            .await
            .expect("read");
        assert!(read.len() as u64 <= MAX_HEALTH_FILE_BYTES);
        // The two lines that matter are inside the bound, so the verdict is
        // still reached.
        assert!(judge_health_file(&read, now_secs()).healthy);
    }

    /// The monitor must not start out vouching for an app that has not been
    /// looked at yet.
    #[tokio::test]
    async fn the_first_report_is_not_healthy() {
        let monitor = HealthMonitor::spawn(
            HealthCheck {
                enabled: true,
                health_file: Some("/nonexistent/dstack-health-test".to_string()),
            },
            ContainerSource::new("docker-compose".to_string(), None),
        );
        let verdict = monitor.report();
        assert!(!verdict.healthy, "{verdict:?}");
    }
}
