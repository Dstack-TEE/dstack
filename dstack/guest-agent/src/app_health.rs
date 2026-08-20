// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The health probe an app declares for itself in `app-compose.json`.
//!
//! [`super::container_health`] can only judge apps whose containers declare a
//! Compose `healthcheck`, which leaves out the `bash` runner entirely -- it has
//! no containers to inspect -- and any runner added later. This is the hook for
//! those: the app names a program, the guest agent runs it on a timer, and the
//! exit status is the verdict.
//!
//! Run on a local timer rather than on each gateway poll, for two reasons: a
//! fleet of gateway nodes polling the same instance must not multiply into that
//! many executions of the app's probe, and the probe's cadence belongs to the
//! app rather than to whatever interval the operator configured on the gateway.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use dstack_types::HealthCheck;
use or_panic::ResultOrPanic;
use tokio::process::Command;
use tracing::{debug, info};

use crate::container_health::{HealthReport, UnhealthyContainer};

/// Name reported in place of a container, so an operator reading gateway logs
/// can tell an app-declared probe from a container that failed its healthcheck.
const PROBE_NAME: &str = "<health_check>";

/// How much of a failing probe's stderr to keep. Bounded so a probe that dumps
/// a stack trace, or an HTML error page, cannot flood the gateway's logs.
const MAX_REASON_BYTES: usize = 512;

/// The latest verdict, refreshed on its own schedule.
pub(crate) struct AppHealthProbe {
    latest: RwLock<Verdict>,
}

#[derive(Clone)]
struct Verdict {
    healthy: bool,
    reason: String,
}

impl AppHealthProbe {
    /// Start the probe loop and hand back the handle the RPC reads.
    pub(crate) fn spawn(check: HealthCheck) -> Arc<Self> {
        info!(
            "app declares a health check: {} (every {}s, {}s timeout)",
            check.path, check.interval_secs, check.timeout_secs
        );
        let probe = Arc::new(Self {
            latest: RwLock::new(Verdict {
                healthy: false,
                // Same rule the gateway applies to an instance that has
                // registered but not yet answered a poll: not having run is
                // not a pass. Registration happens long before the app is up.
                reason: "health check has not run yet".to_string(),
            }),
        });
        let task = probe.clone();
        tokio::spawn(async move {
            // Zero would busy-loop on the app's behalf.
            let interval = Duration::from_secs(check.interval_secs.max(1));
            loop {
                let verdict = run_once(&check).await;
                debug!(
                    "health check verdict: healthy={} {}",
                    verdict.healthy, verdict.reason
                );
                *task.latest.write().or_panic("app health lock poisoned") = verdict;
                tokio::time::sleep(interval).await;
            }
        });
        probe
    }

    /// The cached verdict, in the shape the RPC reports.
    pub(crate) fn report(&self) -> HealthReport {
        let verdict = self
            .latest
            .read()
            .or_panic("app health lock poisoned")
            .clone();
        if verdict.healthy {
            return HealthReport {
                healthy: true,
                unhealthy: vec![],
            };
        }
        HealthReport {
            healthy: false,
            unhealthy: vec![UnhealthyContainer {
                name: PROBE_NAME.to_string(),
                status: verdict.reason,
            }],
        }
    }
}

async fn run_once(check: &HealthCheck) -> Verdict {
    let timeout = Duration::from_secs(check.timeout_secs.max(1));
    let mut command = Command::new(&check.path);
    command.args(&check.args);
    let output = match tokio::time::timeout(timeout, command.output()).await {
        Err(_) => {
            return Verdict {
                healthy: false,
                reason: format!("health check timed out after {}s", timeout.as_secs()),
            }
        }
        Ok(Err(err)) => {
            return Verdict {
                healthy: false,
                reason: format!("failed to run {}: {err}", check.path),
            }
        }
        Ok(Ok(output)) => output,
    };
    if output.status.success() {
        return Verdict {
            healthy: true,
            reason: String::new(),
        };
    }
    Verdict {
        healthy: false,
        reason: describe_failure(&output),
    }
}

fn describe_failure(output: &std::process::Output) -> String {
    let code = match output.status.code() {
        Some(code) => format!("exit code {code}"),
        // No code means a signal killed it.
        None => "killed by signal".to_string(),
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    if stderr.is_empty() {
        return code;
    }
    format!("{code}: {}", truncate(stderr))
}

fn truncate(text: &str) -> String {
    if text.len() <= MAX_REASON_BYTES {
        return text.to_string();
    }
    // Slice on a char boundary so a multi-byte character is never cut in half.
    let mut end = MAX_REASON_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... (truncated)", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &str, args: &[&str]) -> HealthCheck {
        HealthCheck {
            path: path.to_string(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            interval_secs: 1,
            timeout_secs: 2,
        }
    }

    #[tokio::test]
    async fn exit_zero_is_healthy() {
        let verdict = run_once(&check("/bin/true", &[])).await;
        assert!(verdict.healthy);
        assert!(verdict.reason.is_empty());
    }

    #[tokio::test]
    async fn a_non_zero_exit_reports_the_code() {
        let verdict = run_once(&check("/bin/sh", &["-c", "exit 3"])).await;
        assert!(!verdict.healthy);
        assert_eq!(verdict.reason, "exit code 3");
    }

    #[tokio::test]
    async fn stderr_is_carried_into_the_reason() {
        let verdict = run_once(&check(
            "/bin/sh",
            &["-c", "echo 'db unreachable' >&2; exit 1"],
        ))
        .await;
        assert!(!verdict.healthy);
        assert_eq!(verdict.reason, "exit code 1: db unreachable");
    }

    /// A probe that hangs must not be mistaken for one that passes.
    #[tokio::test]
    async fn a_hanging_probe_times_out_as_unhealthy() {
        let mut hang = check("/bin/sh", &["-c", "sleep 30"]);
        hang.timeout_secs = 1;
        let verdict = run_once(&hang).await;
        assert!(!verdict.healthy);
        assert_eq!(verdict.reason, "health check timed out after 1s");
    }

    #[tokio::test]
    async fn a_missing_program_is_unhealthy_rather_than_an_error() {
        let verdict = run_once(&check("/nonexistent/health-probe", &[])).await;
        assert!(!verdict.healthy);
        assert!(verdict
            .reason
            .starts_with("failed to run /nonexistent/health-probe"));
    }

    /// The gateway must not be handed an unbounded blob of app output.
    #[tokio::test]
    async fn a_noisy_probe_has_its_output_bounded() {
        let verdict = run_once(&check(
            "/bin/sh",
            &["-c", "head -c 4000 /dev/zero | tr '\\0' 'x' >&2; exit 1"],
        ))
        .await;
        assert!(!verdict.healthy);
        assert!(verdict.reason.len() < MAX_REASON_BYTES + 64);
        assert!(verdict.reason.ends_with("... (truncated)"));
    }

    /// Before the first run there is no evidence the app works, and a CVM
    /// registers long before its app is up.
    #[test]
    fn the_first_report_is_not_healthy() {
        let probe = AppHealthProbe {
            latest: RwLock::new(Verdict {
                healthy: false,
                reason: "health check has not run yet".to_string(),
            }),
        };
        let report = probe.report();
        assert!(!report.healthy);
        assert_eq!(report.unhealthy[0].name, PROBE_NAME);
        assert_eq!(report.unhealthy[0].status, "health check has not run yet");
    }
}
