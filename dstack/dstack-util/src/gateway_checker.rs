// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Keeps this CVM's dstack-gateway registration alive after boot.
//!
//! Boot registers the CVM once, but that registration is not durable: the
//! gateway can be restarted, the WireGuard peers can change, and — since boot
//! no longer treats a gateway outage as fatal — the CVM may reach the
//! application start with no route at all. This supervisor closes that gap by
//! re-running the same registration whenever the observable state says it is
//! needed.
//!
//! There are exactly three reasons to refresh, in priority order:
//!
//! 1. **No WireGuard config.** Boot-time registration never succeeded, so the
//!    CVM has no route. Retried on a backoff (see [`Backoff`]).
//! 2. **Periodic re-registration.** The gateway expires idle registrations, so
//!    re-register every [`REFRESH_INTERVAL`] even when everything looks fine.
//! 3. **Stale WireGuard handshake.** The tunnel exists but the peer stopped
//!    answering for [`HANDSHAKE_TIMEOUT`], which usually means the gateway
//!    restarted and forgot us.
//!
//! The decision logic is a pure function of an [`Observation`] so it can be
//! unit tested without a gateway, a KMS, or a WireGuard interface; all I/O
//! lives in [`cmd_gateway_checker`].

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use cmd_lib::run_fun as cmd;
use tracing::{error, info, warn};

use crate::system_setup::{GatewayRefresher, WG_CONFIG_PATH, WG_INTERFACE};

/// How often the loop samples the world.
const POLL_INTERVAL: Duration = Duration::from_secs(10);
/// Unconditional re-registration interval.
const REFRESH_INTERVAL: i64 = 180;
/// A tunnel with no handshake for this long is considered dead.
const HANDSHAKE_TIMEOUT: i64 = 180;
/// First retry delay when the CVM has no WireGuard config at all.
const MISSING_CONFIG_RETRY_INTERVAL: i64 = 30;
/// Upper bound for the retry backoff.
const MAX_RETRY_INTERVAL: i64 = 120;

/// Exit code meaning "the gateway config is broken in a way retrying cannot
/// fix". Pinned by `RestartPreventExitStatus` in wg-checker.service, so
/// changing it requires changing the unit too.
const EXIT_MISCONFIGURED: i32 = 3;

#[derive(clap::Parser)]
/// Keep the dstack-gateway registration fresh
pub struct GatewayCheckerArgs {
    /// dstack work directory
    #[arg(long)]
    work_dir: PathBuf,
}

/// Exponential backoff over consecutive refresh failures.
///
/// A refresh is not cheap: on a cold cache it costs a KMS round-trip, two
/// certificate signing requests and a TDX quote. A gateway outage is typically
/// fleet-wide, so a fixed short retry interval would have every CVM hammering
/// the KMS in lockstep and turn a gateway outage into a KMS outage. Backing off
/// to [`MAX_RETRY_INTERVAL`] keeps recovery prompt while bounding that load.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Backoff {
    consecutive_failures: u32,
}

impl Backoff {
    /// Minimum seconds that must elapse after the last attempt before the next
    /// one. Zero while the last attempt succeeded.
    fn delay(&self) -> i64 {
        match self.consecutive_failures {
            0 => 0,
            n => {
                let shift = (n - 1).min(u32::BITS - 1);
                MISSING_CONFIG_RETRY_INTERVAL
                    .checked_shl(shift)
                    .unwrap_or(MAX_RETRY_INTERVAL)
                    .min(MAX_RETRY_INTERVAL)
            }
        }
    }

    fn record(&mut self, succeeded: bool) {
        self.consecutive_failures = if succeeded {
            0
        } else {
            self.consecutive_failures.saturating_add(1)
        };
    }
}

/// Everything the decision logic is allowed to look at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    /// Seconds since the UNIX epoch.
    now: i64,
    /// Whether `/etc/wireguard/dstack-wg0.conf` exists.
    config_present: bool,
    /// Most recent handshake as a UNIX timestamp; `None` if the interface has
    /// never completed one (or does not exist yet).
    latest_handshake: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Refresh {
    /// Force `wg-quick` to be reapplied even if the rendered config is
    /// byte-identical to what is already on disk.
    force: bool,
    reason: &'static str,
}

#[derive(Debug, Default)]
struct Checker {
    /// Timestamp of the last refresh attempt; `None` if none has run yet.
    last_attempt: Option<i64>,
    /// When the tunnel was first seen without any handshake; `None` while a
    /// handshake exists or the config is absent.
    handshake_missing_since: Option<i64>,
    backoff: Backoff,
}

impl Checker {
    /// Decide whether to refresh now. Pure: same state plus same observation
    /// always yields the same answer.
    fn decide(&mut self, obs: Observation) -> Option<Refresh> {
        // An attempt that has not cooled down yet blocks every reason below, so
        // repeated failures cannot bypass the backoff by changing category.
        let elapsed = match self.last_attempt {
            // Nothing tried yet: act immediately.
            None => return Some(Self::first_refresh(obs)),
            Some(last) => obs.now.saturating_sub(last),
        };
        if elapsed < self.backoff.delay() {
            return None;
        }

        if !obs.config_present {
            self.handshake_missing_since = None;
            return (elapsed >= MISSING_CONFIG_RETRY_INTERVAL).then_some(Refresh {
                force: true,
                reason: "WireGuard config is missing",
            });
        }

        if elapsed >= REFRESH_INTERVAL {
            self.handshake_missing_since = None;
            return Some(Refresh {
                force: false,
                reason: "periodic re-registration",
            });
        }

        // The tunnel is configured and recently re-registered; the only thing
        // left that can be wrong is the tunnel itself going quiet.
        let silent_since = match obs.latest_handshake {
            Some(handshake) => {
                self.handshake_missing_since = None;
                handshake
            }
            // No handshake yet. Time it from when we first noticed rather than
            // from process start, so a freshly created interface gets a full
            // HANDSHAKE_TIMEOUT to complete its first handshake.
            None => *self.handshake_missing_since.get_or_insert(obs.now),
        };
        (obs.now.saturating_sub(silent_since) >= HANDSHAKE_TIMEOUT).then_some(Refresh {
            force: true,
            reason: "WireGuard handshake is stale",
        })
    }

    /// The first poll always acts: boot may have left the CVM unregistered, and
    /// re-registering an already-healthy CVM is cheap and idempotent.
    fn first_refresh(obs: Observation) -> Refresh {
        if obs.config_present {
            Refresh {
                force: false,
                reason: "initial re-registration",
            }
        } else {
            Refresh {
                force: true,
                reason: "WireGuard config is missing",
            }
        }
    }

    /// Record the outcome of a refresh triggered by [`Checker::decide`].
    fn record(&mut self, now: i64, succeeded: bool) {
        self.last_attempt = Some(now);
        self.handshake_missing_since = None;
        self.backoff.record(succeeded);
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Read the most recent handshake across all peers of the interface.
///
/// `wg show <if> latest-handshakes` prints one `<pubkey>\t<unix-ts>` line per
/// peer, with `0` meaning "never". Returns `None` when the interface is absent,
/// has no peers, or no peer has ever completed a handshake — all of which the
/// caller treats the same way.
fn latest_handshake(interface: &str) -> Option<i64> {
    let output = cmd!(wg show $interface latest-handshakes).ok()?;
    parse_latest_handshake(&output)
}

fn parse_latest_handshake(output: &str) -> Option<i64> {
    output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .filter_map(|ts| ts.parse::<i64>().ok())
        .filter(|ts| *ts > 0)
        .max()
}

fn observe(now: i64) -> Observation {
    Observation {
        now,
        config_present: Path::new(WG_CONFIG_PATH).exists(),
        latest_handshake: latest_handshake(WG_INTERFACE),
    }
}

pub async fn cmd_gateway_checker(args: GatewayCheckerArgs) -> Result<()> {
    let refresher =
        GatewayRefresher::load(&args.work_dir).context("failed to load gateway configuration")?;

    // Nothing to supervise for an app that never asked for a gateway. Exit
    // successfully instead of polling forever; the unit is Restart=on-failure
    // so systemd leaves the service alone. gateway_enabled is fixed by the
    // measured app-compose and cannot change without a reboot.
    if !refresher.gateway_enabled() {
        info!("dstack-gateway is not enabled; nothing to check");
        return Ok(());
    }

    // A missing app id or gateway URL is a deployment mistake, not an outage.
    // Both come from data fixed for the lifetime of the VM (app keys and the
    // host-shared copy taken at setup), so no amount of retrying can fix it.
    // Returning a plain error would have systemd restart us every RestartSec
    // forever, so exit with the code the unit pins in RestartPreventExitStatus:
    // that stops the respawn while still leaving the unit in `failed` state,
    // which is what makes the mistake visible to the operator.
    if let Err(error) = refresher.check_config() {
        error!("dstack-gateway is enabled but misconfigured: {error:#}");
        error!("not retrying; this cannot be fixed without redeploying the CVM");
        std::process::exit(EXIT_MISCONFIGURED);
    }

    info!("watching dstack-gateway registration");
    let mut checker = Checker::default();
    loop {
        let now = now_secs();
        if let Some(refresh) = checker.decide(observe(now)) {
            info!("refreshing dstack-gateway: {}", refresh.reason);
            let succeeded = match refresher.refresh(refresh.force).await {
                Ok(()) => {
                    info!("dstack-gateway refresh succeeded");
                    true
                }
                Err(error) => {
                    // now_secs() is re-read below: the refresh itself can block
                    // on network timeouts for a long time, and the backoff must
                    // count from when the attempt ended.
                    warn!("dstack-gateway refresh failed: {error:#}");
                    false
                }
            };
            checker.record(now_secs(), succeeded);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_700_000_000;

    fn obs(now_offset: i64, config_present: bool, latest_handshake: Option<i64>) -> Observation {
        Observation {
            now: T0 + now_offset,
            config_present,
            latest_handshake,
        }
    }

    #[test]
    fn parses_max_handshake_across_peers() {
        let output = "aaa\t1700000000\nbbb\t1700000042\nccc\t0\n";
        assert_eq!(parse_latest_handshake(output), Some(1_700_000_042));
    }

    #[test]
    fn treats_never_handshaked_peers_as_no_handshake() {
        assert_eq!(parse_latest_handshake("aaa\t0\nbbb\t0\n"), None);
        assert_eq!(parse_latest_handshake(""), None);
        assert_eq!(parse_latest_handshake("garbage\n"), None);
    }

    #[test]
    fn acts_immediately_on_first_poll() {
        let mut checker = Checker::default();
        let refresh = checker.decide(obs(0, false, None)).expect("should refresh");
        assert!(refresh.force);

        let mut checker = Checker::default();
        let refresh = checker.decide(obs(0, true, None)).expect("should refresh");
        assert!(!refresh.force, "an existing config needs no forced reapply");
    }

    #[test]
    fn retries_missing_config_with_backoff_up_to_the_cap() {
        let mut checker = Checker::default();
        let mut t = 0;
        // First attempt fires immediately and fails.
        assert!(checker.decide(obs(t, false, None)).is_some());
        checker.record(T0 + t, false);

        // 30s base delay, then 60s, then capped at MAX_RETRY_INTERVAL.
        for expected_delay in [30, 60, 120, 120] {
            for early in [10, expected_delay - 10] {
                assert!(
                    checker.decide(obs(t + early, false, None)).is_none(),
                    "must not retry after {early}s while waiting {expected_delay}s"
                );
            }
            t += expected_delay;
            assert!(
                checker.decide(obs(t, false, None)).is_some(),
                "must retry once {expected_delay}s have passed"
            );
            checker.record(T0 + t, false);
        }
    }

    #[test]
    fn backoff_resets_after_a_success() {
        let mut backoff = Backoff::default();
        assert_eq!(backoff.delay(), 0);
        backoff.record(false);
        assert_eq!(backoff.delay(), 30);
        backoff.record(false);
        assert_eq!(backoff.delay(), 60);
        backoff.record(true);
        assert_eq!(backoff.delay(), 0);
    }

    #[test]
    fn backoff_saturates_instead_of_overflowing() {
        let backoff = Backoff {
            consecutive_failures: u32::MAX,
        };
        assert_eq!(backoff.delay(), MAX_RETRY_INTERVAL);
    }

    #[test]
    fn re_registers_periodically_while_healthy() {
        let mut checker = Checker::default();
        checker.record(T0, true);

        // Healthy tunnel, fresh handshake: quiet until REFRESH_INTERVAL.
        assert!(checker.decide(obs(170, true, Some(T0 + 170))).is_none());
        let refresh = checker
            .decide(obs(180, true, Some(T0 + 180)))
            .expect("periodic refresh is due");
        assert!(
            !refresh.force,
            "periodic refresh must not disrupt the tunnel"
        );
    }

    #[test]
    fn forces_refresh_when_the_handshake_goes_stale() {
        let mut checker = Checker::default();
        checker.record(T0, true);

        // Handshake 179s old: still within tolerance.
        assert!(checker.decide(obs(170, true, Some(T0 - 9))).is_none());
        // 180s old and we have not hit the periodic interval yet.
        let refresh = checker
            .decide(obs(170, true, Some(T0 - 10)))
            .expect("stale handshake must force a refresh");
        assert!(refresh.force);
        assert_eq!(refresh.reason, "WireGuard handshake is stale");
    }

    #[test]
    fn gives_a_new_interface_a_full_timeout_to_handshake() {
        let mut checker = Checker::default();
        // Config appeared at t=0 but no handshake yet.
        checker.record(T0, true);

        assert!(checker.decide(obs(10, true, None)).is_none());
        assert!(checker.decide(obs(179, true, None)).is_none());
        // The timeout runs from t=10, when the missing handshake was first
        // observed, not from the refresh at t=0.
        assert!(checker.decide(obs(189, true, None)).is_some());
    }

    #[test]
    fn a_recovered_handshake_clears_the_missing_timer() {
        let mut checker = Checker::default();
        checker.record(T0, true);

        assert!(checker.decide(obs(10, true, None)).is_none());
        // Handshake completes.
        assert!(checker.decide(obs(20, true, Some(T0 + 20))).is_none());
        assert_eq!(checker.handshake_missing_since, None);
        // Losing it again restarts the clock instead of firing immediately.
        assert!(checker.decide(obs(30, true, None)).is_none());
        assert_eq!(checker.handshake_missing_since, Some(T0 + 30));
    }

    #[test]
    fn backoff_outranks_the_missing_config_interval() {
        let mut checker = Checker::default();
        // Three consecutive failures put the backoff at the 120s cap, which is
        // longer than the 30s missing-config interval.
        checker.backoff.consecutive_failures = 3;
        checker.record(T0, false);
        assert_eq!(checker.backoff.consecutive_failures, 4);

        assert!(checker.decide(obs(30, false, None)).is_none());
        assert!(checker.decide(obs(119, false, None)).is_none());
        assert!(checker.decide(obs(120, false, None)).is_some());
    }
}
