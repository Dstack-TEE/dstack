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
//! `requirements.health_check`: a `health_status_file` it writes itself, or -- by
//! default -- the state of the containers the runtime knows about.

use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dstack_types::HEALTH_FILE_MAX_AGE_SECS;
use or_panic::ResultOrPanic;
use tracing::{debug, info, warn};

use dstack_guest_agent_rpc::ContainerHealth;

use crate::container_health;

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

/// Largest `health_status_file` the agent will read.
///
/// The file is two short lines. Anything beyond this is either a mistake or an
/// attempt to make the agent allocate on the app's behalf.
const MAX_HEALTH_FILE_BYTES: u64 = 4096;

/// Longest app-authored text echoed back into a report.
///
/// Only the `health_status_file` path reaches a report now -- the file's *contents*
/// deliberately do not, since whatever sits at that path is not what was
/// measured. A path is short; bounding it keeps app-controlled bytes out of the
/// gateway's logs in quantity, and [`sanitize`] handles the rest.
const MAX_REPORTED_BYTES: usize = 256;

/// Reported in place of a container name, so an operator reading gateway logs
/// can tell an app-written verdict from a container that failed its healthcheck.
const HEALTH_FILE_NAME: &str = "<health_file>";

/// Reported before either source has been consulted for the first time.
const PENDING_NAME: &str = "<health>";

/// The latest verdict, in the shape `Worker.Health` answers with.
///
/// Carries the generated `ContainerHealth` rather than a local twin of it. The
/// two were copied field by field on the way out, which is a conversion whose
/// only failure mode is silent.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct Verdict {
    pub healthy: bool,
    pub unhealthy: Vec<ContainerHealth>,
    /// Set when the agent could not reach the source of truth at all, as
    /// opposed to reaching it and being told something is wrong.
    pub error: String,
}

impl Verdict {
    pub(crate) fn healthy() -> Self {
        Self {
            healthy: true,
            unhealthy: vec![],
            error: String::new(),
        }
    }

    /// Unhealthy for a reason the agent can name, attributed to `name`.
    pub(crate) fn unhealthy(name: &str, status: String) -> Self {
        Self {
            healthy: false,
            unhealthy: vec![ContainerHealth {
                name: name.to_string(),
                status,
            }],
            error: String::new(),
        }
    }

    /// Healthy exactly when nothing was found wrong.
    pub(crate) fn from_containers(unhealthy: Vec<ContainerHealth>) -> Self {
        Self {
            healthy: unhealthy.is_empty(),
            unhealthy,
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

/// The cached verdict plus the loop that refreshes it.
pub(crate) struct HealthMonitor {
    latest: RwLock<Verdict>,
}

impl HealthMonitor {
    /// Start the refresh loop and hand back the handle the RPC reads.
    ///
    /// Only called when the app opted in; an app that did not is never polled
    /// by the gateway, so there is nothing to keep up to date.
    pub(crate) fn spawn(status_file: Option<String>, runner: String) -> Arc<Self> {
        match &status_file {
            Some(path) => info!("app health is read from {path} every {REFRESH_INTERVAL:?}"),
            None => {
                info!("app health is judged from {runner} containers every {REFRESH_INTERVAL:?}")
            }
        }
        let monitor = Arc::new(Self {
            // The same rule the gateway applies to an instance that has
            // registered but not yet answered a poll: not having run is not a
            // pass. Registration happens long before the app is up.
            //
            // This seed is indistinguishable, over the wire, from a completed
            // refresh that found the app unhealthy -- and the gateway believes
            // an answered "no" immediately, without the hysteresis it applies
            // to a failure to reach us. So a poll that lands in the window
            // between this task starting and its first refresh finishing takes
            // a healthy instance out of rotation for a round or two. The window
            // is normally sub-second and only opens when the agent itself
            // restarts, and it self-corrects; closing it properly means a third
            // state ("starting") in `HealthResponse` that the gateway can run
            // through its hysteresis, which is a protocol change, not a
            // default. Erring the other way -- seeding `healthy` -- would let a
            // genuinely broken app serve for a round on every agent restart,
            // which is the failure this feature exists to prevent.
            latest: RwLock::new(Verdict::unhealthy(
                PENDING_NAME,
                "health has not been determined yet".to_string(),
            )),
        });
        let task = monitor.clone();
        tokio::spawn(async move {
            // Supervised, for the same reason the gateway's poller is: if this
            // task ever died, `report()` would keep serving the last verdict
            // forever and nothing in the response says how old it is, so an
            // instance frozen on `healthy` would stay in rotation through any
            // later failure.
            loop {
                let refresher = tokio::spawn(refresh_forever(
                    status_file.clone(),
                    runner.clone(),
                    task.clone(),
                ));
                match refresher.await {
                    Ok(()) => warn!("health refresh loop returned unexpectedly; restarting"),
                    Err(err) => warn!("health refresh loop died: {err}; restarting"),
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

/// The refresh loop itself, in its own task so a panic in it is observable to
/// the supervisor above rather than ending health reporting silently.
async fn refresh_forever(status_file: Option<String>, runner: String, monitor: Arc<HealthMonitor>) {
    let mut failures = 0;
    loop {
        match refresh(status_file.as_deref(), &runner).await {
            Ok(verdict) => {
                failures = 0;
                monitor.store(verdict);
            }
            Err(err) => {
                // Hold the previous verdict for a few rounds: a container being
                // recreated underneath us looks exactly like this, and it
                // resolves itself by the next tick.
                failures += 1;
                let error = format!("{err:#}");
                if failures < MAX_CONSECUTIVE_FAILURES {
                    debug!("health refresh failed ({failures}), keeping last verdict: {error}");
                } else {
                    // Once, on the way in. A runtime that stays down would
                    // otherwise be a warning every interval, forever --
                    // `store` deduplicates the verdict it logs, and this has
                    // to do the same.
                    if failures == MAX_CONSECUTIVE_FAILURES {
                        warn!("health refresh has failed {failures} times: {error}");
                    }
                    monitor.store(Verdict::failed(error));
                }
            }
        }
        tokio::time::sleep(REFRESH_INTERVAL).await;
    }
}

/// One refresh, from whichever source the app declared.
///
/// `Err` means "could not tell", which the caller tolerates for a few rounds.
/// A verdict of unhealthy is a different thing and comes back as `Ok`.
async fn refresh(status_file: Option<&str>, runner: &str) -> anyhow::Result<Verdict> {
    let work = async {
        match status_file {
            Some(path) => Ok(read_health_file(path).await),
            None => container_health::collect(runner).await,
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
            return Verdict::unhealthy(
                HEALTH_FILE_NAME,
                format!("{} has not been written yet", sanitize(path)),
            )
        }
        Err(err) => {
            // The path is measured into the compose hash, so echoing it tells
            // an anonymous caller nothing it could not read there -- but it is
            // still app-authored text on its way to a log line.
            return Verdict::unhealthy(
                HEALTH_FILE_NAME,
                format!("cannot read {}: {err}", sanitize(path)),
            );
        }
    };
    judge_health_file(&contents, now_secs())
}

/// Open and read the health file, refusing anything that is not a plain file.
///
/// Symlinks are followed. That is a decision, not an oversight: `O_NOFOLLOW`
/// only refuses a symlink as the *final* path component, so it never delivered
/// the property it looked like it delivered -- a container that can replace any
/// directory along the path redirects the read either way, and closing that
/// properly needs `openat2(RESOLVE_NO_SYMLINKS)` and a resolved-path check.
/// Buying the whole guarantee is not worth it here, because there is little
/// behind it: the read is bounded, and the contents are never echoed back (see
/// [`judge_health_file`]) -- what an app gets from redirecting it is the right
/// to lie about its own health, which it already has, since it writes the file.
/// Meanwhile refusing the last component alone breaks the ordinary case of a
/// health file living under a symlinked data directory.
///
/// The regular-file check stays, and is load-bearing for a different reason. A
/// FIFO is worse than it looks: `tokio::fs` opens on the blocking pool, and a
/// blocking task cannot be cancelled, so `open(2)` on a reader-less FIFO parks
/// that thread forever while the outer timeout merely abandons the future. One
/// thread leaks per refresh, silently -- the systemd watchdog probes over HTTP
/// and never touches the pool -- until the agent can no longer do any
/// filesystem work at all. `O_NONBLOCK` makes that open return immediately
/// instead, and the file-type check rejects what it opened.
async fn read_bounded(path: &str) -> std::io::Result<String> {
    let path = path.to_string();
    tokio::task::spawn_blocking(move || {
        use std::io::Read as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)?;
        let kind = file.metadata()?.file_type();
        if !kind.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "health file is not a regular file",
            ));
        }
        let mut contents = String::new();
        file.take(MAX_HEALTH_FILE_BYTES)
            .read_to_string(&mut contents)?;
        Ok(contents)
    })
    .await
    .unwrap_or_else(|err| Err(std::io::Error::other(err)))
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
        // Deliberately not quoting the line. The report is served to anonymous
        // callers on the external listener, and the bytes on line 2 are
        // whatever was at that path -- which, if something replaced the file,
        // is not what the app wrote and not what was measured.
        return Verdict::unhealthy(
            HEALTH_FILE_NAME,
            "health file line 2 is not a unix time in seconds".to_string(),
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
        // understand, which is not a pass. Not quoted, for the same reason as
        // the timestamp above.
        _ => Verdict::unhealthy(
            HEALTH_FILE_NAME,
            "health file line 1 is neither healthy nor unhealthy".to_string(),
        ),
    }
}

/// Make app-authored text safe to put in a report.
///
/// The report is served to anonymous callers on the external listener and is
/// logged by the gateway, so control characters -- newlines that forge a log
/// line, escapes that repaint a terminal, bidi overrides that reverse what a
/// reader sees -- must not survive, and the length must be bounded. The gateway
/// does the same again on receipt, because it does not trust this agent to have
/// done it.
fn sanitize(token: &str) -> String {
    let cleaned = dstack_types::sanitize_for_log(token.trim(), MAX_REPORTED_BYTES);
    if cleaned.is_empty() {
        return "<empty>".to_string();
    }
    cleaned
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

    /// The report goes to anonymous callers on the external listener, and the
    /// bytes at that path are not the bytes that were measured -- a symlink or
    /// a replaced file makes them something else entirely. Naming the rule that
    /// failed is enough to debug with; quoting the line is an exfiltration
    /// channel.
    #[test]
    fn a_malformed_file_is_never_quoted_back() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let verdict = file(&format!("healthy\n{secret}"));
        assert!(!reason(&verdict).contains(secret), "{}", reason(&verdict));

        let verdict = file(&format!("{secret}\n{NOW}"));
        assert!(!reason(&verdict).contains(secret), "{}", reason(&verdict));
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
        assert!(reason(&verdict).contains("neither healthy nor unhealthy"));
    }

    /// The `health_status_file` path is app-authored and reaches both an anonymous
    /// caller and a log line, so it is bounded and stripped like anything else
    /// that crosses that boundary.
    #[tokio::test]
    async fn a_hostile_path_cannot_forge_a_log_line() {
        let forged = "/nonexistent/\u{1b}[31mx\nlevel=fatal msg=owned";
        let verdict = read_health_file(forged).await;
        let reason = reason(&verdict);
        assert!(!reason.contains('\n'), "newline survived: {reason:?}");
        assert!(!reason.contains('\u{1b}'), "escape survived: {reason:?}");
    }

    #[tokio::test]
    async fn a_very_long_path_is_truncated() {
        let long = format!("/nonexistent/{}", "x".repeat(MAX_REPORTED_BYTES * 4));
        let verdict = read_health_file(&long).await;
        assert!(reason(&verdict).len() < MAX_REPORTED_BYTES * 2);
    }

    /// A health file under a symlinked data directory is the ordinary case, not
    /// an attack, and refusing it was breaking working apps for nothing:
    /// `O_NOFOLLOW` only ever refused a symlink as the *final* path component,
    /// so anything that could swap a parent directory redirected the read
    /// regardless. What is left behind the guarantee is small -- the read is
    /// bounded and the contents are never echoed back -- so all an app buys by
    /// redirecting it is the right to lie about its own health, which it
    /// already has, since it writes the file.
    #[tokio::test]
    async fn a_symlinked_health_file_is_followed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, format!("healthy\n{}\n", now_secs())).expect("write");
        assert!(
            read_health_file(target.to_str().expect("utf8"))
                .await
                .healthy,
            "the target must read healthy, or this test proves nothing"
        );

        let link = dir.path().join("health");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        let verdict = read_health_file(link.to_str().expect("utf8")).await;
        assert!(
            verdict.healthy,
            "the link should read through to its target: {verdict:?}"
        );
    }

    /// `tokio::fs` opens on the blocking pool and a blocking task cannot be
    /// cancelled, so a reader-less FIFO would park a thread forever -- one per
    /// refresh, until the agent can do no filesystem work at all. `O_NONBLOCK`
    /// makes the open fail instead. This test hangs if that flag is dropped.
    #[tokio::test]
    async fn a_fifo_health_file_does_not_park_a_thread() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("health");
        let path = std::ffi::CString::new(fifo.to_str().expect("utf8")).expect("cstring");
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);

        let verdict = tokio::time::timeout(
            Duration::from_secs(5),
            read_health_file(fifo.to_str().expect("utf8")),
        )
        .await
        .expect("opening a FIFO must not block");
        assert!(!verdict.healthy, "{verdict:?}");
    }

    #[tokio::test]
    async fn a_directory_is_not_a_health_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let verdict = read_health_file(dir.path().to_str().expect("utf8")).await;
        assert!(!verdict.healthy, "{verdict:?}");
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
    /// `health_status_file` at something huge.
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
            Some("/nonexistent/dstack-health-test".to_string()),
            "docker-compose".to_string(),
        );
        let verdict = monitor.report();
        assert!(!verdict.healthy, "{verdict:?}");
    }
}
