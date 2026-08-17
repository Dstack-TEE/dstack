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
//! There are exactly three reasons to refresh. The order matters, because
//! [`HANDSHAKE_TIMEOUT`] equals [`REFRESH_INTERVAL`] and the deadlines collide:
//!
//! 1. **No WireGuard config.** Boot-time registration never succeeded, so the
//!    CVM has no route. Retried on a backoff (see [`Backoff`]).
//! 2. **Stale WireGuard handshake.** The tunnel exists but the peer stopped
//!    answering for [`HANDSHAKE_TIMEOUT`], which usually means the gateway
//!    restarted and forgot us. Checked *before* the periodic refresh and rate
//!    limited to one attempt per timeout, because only this forced path can
//!    rebuild a tunnel whose config is unchanged, and it is the expensive one.
//! 3. **Periodic re-registration.** The gateway expires idle registrations, so
//!    re-register every [`REFRESH_INTERVAL`] even when everything looks fine.
//!
//! The decision logic is a pure function of an [`Observation`] so it can be
//! unit tested without a gateway, a KMS, or a WireGuard interface; all I/O
//! lives in [`cmd_gateway_checker`].

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use cmd_lib::run_fun as cmd;
use sd_notify::NotifyState;
use tracing::{error, info, warn};

use crate::system_setup::GatewayRefresher;

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
/// fix". Pinned by `RestartPreventExitStatus` in dstack-gateway-checker.service, so
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
    /// Whether at least one `/etc/wireguard/dstack-wg*.conf` exists.
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
    /// Timestamp of the last *forced* refresh; `None` if none has run yet.
    /// Tracked separately from `last_attempt` so a cheap periodic refresh does
    /// not re-arm the rate limit that protects the expensive forced path.
    last_force: Option<i64>,
    /// When the tunnel was first seen without any handshake; `None` while a
    /// handshake exists or the config is absent. Means exactly one thing: when
    /// we first observed a peer with no handshake.
    handshake_missing_since: Option<i64>,
    backoff: Backoff,
}

const MISSING_CONFIG: Refresh = Refresh {
    force: true,
    reason: "WireGuard config is missing",
};
const STALE_HANDSHAKE: Refresh = Refresh {
    force: true,
    reason: "WireGuard handshake is stale",
};
const PERIODIC: Refresh = Refresh {
    force: false,
    reason: "periodic re-registration",
};

impl Checker {
    /// Build the starting state for a checker coming up at `now`.
    ///
    /// If the WireGuard config is already on disk, boot registered this CVM
    /// moments ago: `/etc` is a volatile overlay, so the file can only exist
    /// because *this* boot wrote it. Start the periodic clock from now instead
    /// of re-registering immediately. Otherwise a fleet rebooting together
    /// would hit the gateway with a second full round of registrations seconds
    /// after the first — piling onto the component this checker exists to
    /// tolerate the loss of. With no config, boot's registration failed and
    /// recovering fast is the whole point, so leave the clock unset and act on
    /// the first poll.
    fn starting(now: i64, config_present: bool) -> Self {
        Self {
            last_attempt: config_present.then_some(now),
            ..Self::default()
        }
    }

    /// Decide whether to refresh now. Pure: same state plus same observation
    /// always yields the same answer.
    fn decide(&mut self, obs: Observation) -> Option<Refresh> {
        if !obs.config_present {
            // No config means no interface, so there is no handshake to age.
            self.handshake_missing_since = None;
            let Some(last) = self.last_attempt else {
                return Some(MISSING_CONFIG);
            };
            let delay = MISSING_CONFIG_RETRY_INTERVAL.max(self.backoff.delay());
            return (obs.now.saturating_sub(last) >= delay).then_some(MISSING_CONFIG);
        }

        // Staleness is checked BEFORE the periodic refresh, and the
        // missing-handshake timer is cleared ONLY by an observed handshake --
        // never by a refresh. HANDSHAKE_TIMEOUT equals REFRESH_INTERVAL, so if
        // a periodic refresh reset the timer it would re-arm at 0 while the
        // timer had only reached REFRESH_INTERVAL - POLL_INTERVAL, and the
        // forced branch would be unreachable for a peer that never handshakes.
        // That matters because gateway setup short-circuits on an unchanged
        // config unless force is set: a CVM whose WireGuard config is correct
        // but whose tunnel is dead can only recover through a forced refresh.
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
        if obs.now.saturating_sub(silent_since) >= HANDSHAKE_TIMEOUT {
            // A forced refresh bounces the interface and re-requests
            // certificates, so cap it at one attempt per HANDSHAKE_TIMEOUT.
            // Unthrottled, a gateway that stays down would be hit on every
            // poll: a self-inflicted flood aimed at something already broken.
            let due = match self.last_force {
                None => true,
                Some(last) => obs.now.saturating_sub(last) >= HANDSHAKE_TIMEOUT,
            };
            // Return either way. While the tunnel is dead a periodic refresh
            // is pointless, since only the forced path can rebuild it.
            return due.then_some(STALE_HANDSHAKE);
        }

        // The first poll always re-registers: boot may have left the CVM
        // unregistered, and re-registering a healthy CVM is cheap.
        let Some(last) = self.last_attempt else {
            return Some(PERIODIC);
        };
        (obs.now.saturating_sub(last) >= REFRESH_INTERVAL).then_some(PERIODIC)
    }

    /// Record the outcome of a refresh triggered by [`Checker::decide`].
    fn record(&mut self, now: i64, refresh: Refresh, succeeded: bool) {
        self.last_attempt = Some(now);
        if refresh.force {
            self.last_force = Some(now);
        }
        // handshake_missing_since is deliberately NOT cleared here; see decide().
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

fn configured_gateway_interfaces() -> Vec<String> {
    let Ok(entries) = std::fs::read_dir("/etc/wireguard") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| {
            name.strip_suffix(".conf")
                .filter(|name| name.starts_with("dstack-wg"))
                .map(str::to_string)
        })
        .collect()
}

fn observe(now: i64) -> Observation {
    let interfaces = configured_gateway_interfaces();
    let config_present = !interfaces.is_empty();
    let handshakes = interfaces
        .iter()
        .map(|interface| latest_handshake(interface))
        .collect::<Option<Vec<_>>>();
    Observation {
        now,
        config_present,
        // Without a config the interface was never brought up, so there is no
        // handshake to read and `decide` would not look at one anyway. Skipping
        // the probe matters because that is precisely the state a gateway
        // outage parks the CVM in: otherwise we would fork `wg` every poll for
        // the entire outage to answer a question nobody asks.
        // The least healthy cluster drives recovery. A missing handshake on
        // any configured interface is represented as None; otherwise the
        // oldest cluster handshake is the staleness boundary.
        latest_handshake: handshakes.and_then(|values| values.into_iter().min()),
    }
}

/// systemd liveness reporting, inert when the unit has no `WatchdogSec`.
///
/// The recovery paths in this loop only work while the loop runs, and nothing
/// below it can guarantee that: a wedged refresh leaves a healthy-looking
/// process that systemd will never restart. Handing liveness to systemd covers
/// a hang wherever it comes from, including causes not anticipated here.
struct Watchdog {
    enabled: bool,
}

impl Watchdog {
    /// Report readiness and arm the watchdog. Readiness is sent before the
    /// checker decides whether it has anything to do, so the paths that exit
    /// straight away are still a started service that then stopped, not a
    /// service that failed to start.
    fn arm() -> Self {
        let mut usec = 0;
        let enabled = sd_notify::watchdog_enabled(false, &mut usec);
        if let Err(error) = sd_notify::notify(false, &[NotifyState::Ready]) {
            warn!("failed to report readiness to systemd: {error}");
        }
        if enabled {
            info!("systemd watchdog armed, timeout={usec}us");
        }
        Self { enabled }
    }

    fn ping(&self) {
        if !self.enabled {
            return;
        }
        if let Err(error) = sd_notify::notify(false, &[NotifyState::Watchdog]) {
            warn!("failed to ping the systemd watchdog: {error}");
        }
    }
}

pub async fn cmd_gateway_checker(args: GatewayCheckerArgs) -> Result<()> {
    let watchdog = Watchdog::arm();
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
    // The checker does not report gateway state to the host. Boot already
    // reports the one signal that matters -- this CVM came up without a route
    // -- and mirroring every later transition would mean tracking what the host
    // has been told, which is state this loop should not have to carry. The
    // consequence is that a boot error stays on the VMM after the checker
    // recovers, until the VM restarts.
    let mut checker = Checker::starting(now_secs(), !configured_gateway_interfaces().is_empty());
    loop {
        // Ping before the work, not after, so a refresh that never returns
        // stops the pings. Nothing else can do this for us: a refresh spends
        // most of its time in blocking `cmd!` shell-outs (`wg-quick up` alone
        // resolves peer endpoints), which occupy a runtime worker with no await
        // point. tokio::time::timeout cannot cancel that, and a watchdog task
        // on another worker would happily keep pinging while this loop is
        // wedged. Only the loop itself can prove the loop is alive.
        watchdog.ping();

        let now = now_secs();
        if let Some(refresh) = checker.decide(observe(now)) {
            info!("refreshing dstack-gateway: {}", refresh.reason);
            let succeeded = match refresher.refresh(refresh.force).await {
                Ok(()) => {
                    info!("dstack-gateway refresh succeeded");
                    true
                }
                Err(error) => {
                    warn!("dstack-gateway refresh failed: {error:#}");
                    false
                }
            };
            // now_secs() is re-read here rather than reusing `now`: a refresh can
            // block on network timeouts for a long time, and the backoff has to
            // count from when the attempt ended, not when it started.
            checker.record(now_secs(), refresh, succeeded);
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

    /// Replay the checker against a scripted world for `duration` seconds at the
    /// production poll interval, returning (forced, periodic) refresh counts.
    ///
    /// `handshake` maps elapsed seconds to what `wg show ... latest-handshakes`
    /// would report at that moment. Every refresh is treated as succeeding, so
    /// the counts isolate the decision logic from the backoff.
    ///
    /// Deliberately starts from `Checker::default()`, not `Checker::starting`:
    /// the upstream harness began with `LAST_REFRESH=0`, so this reproduces its
    /// cadence exactly. The startup grace period is covered separately.
    fn replay(duration: i64, handshake: impl Fn(i64) -> Option<i64>) -> (usize, usize) {
        let mut checker = Checker::default();
        let (mut forced, mut periodic) = (0, 0);
        let mut elapsed = 0;
        while elapsed < duration {
            let observation = obs(elapsed, true, handshake(elapsed));
            if let Some(refresh) = checker.decide(observation) {
                if refresh.force {
                    forced += 1;
                } else {
                    periodic += 1;
                }
                checker.record(T0 + elapsed, refresh, true);
            }
            elapsed += POLL_INTERVAL.as_secs() as i64;
        }
        (forced, periodic)
    }

    /// The scenario table from the upstream fix that made the forced branch
    /// reachable and rate limited it (`fix(guest): let the missing-handshake
    /// timer actually expire`). These counts are the contract that commit
    /// established by replaying the shell checker against a mocked clock; the
    /// Rust port has to reproduce them exactly or it has silently regressed.
    #[test]
    fn reproduces_the_upstream_forced_refresh_scenarios() {
        // Healthy tunnel: handshakes keep landing, nothing is ever forced.
        assert_eq!(replay(900, |t| Some(T0 + t)).0, 0, "healthy handshakes");

        // A peer that never handshakes must still reach the forced path, once
        // per HANDSHAKE_TIMEOUT: at 180, 360, 540 and 720 seconds.
        assert_eq!(replay(900, |_| None).0, 4, "never handshakes");

        // Frozen handshake with the gateway down: the timestamp never advances,
        // so it ages past the timeout and is forced on the same cadence. Before
        // the rate limit this was one forced refresh per poll.
        assert_eq!(
            replay(900, |_| Some(T0)).0,
            4,
            "handshake frozen, gateway down"
        );

        // Handshakes land for the first 180s, then the peer goes silent. The
        // timer runs from the last real handshake, so forcing starts at 360.
        let (forced, _) = replay(900, |t| Some(T0 + if t < 180 { t } else { 180 }));
        assert_eq!(forced, 3, "handshake then peer gone");

        // No handshake, then the gateway recovers at 540s. Two forced attempts
        // (180, 360) and then the periodic cadence resumes.
        let (forced, periodic) = replay(900, |t| (t >= 540).then_some(T0 + t));
        assert_eq!(forced, 2, "no handshake, gateway recovers");
        assert!(periodic >= 1, "periodic refresh must resume after recovery");
    }

    /// The regression the upstream fix was about: a periodic refresh must not
    /// reset the missing-handshake timer. HANDSHAKE_TIMEOUT == REFRESH_INTERVAL,
    /// so clearing it on every periodic refresh re-arms the timer one poll
    /// before it can expire and the forced branch becomes unreachable.
    #[test]
    fn periodic_refresh_does_not_re_arm_the_missing_handshake_timer() {
        assert_eq!(
            HANDSHAKE_TIMEOUT, REFRESH_INTERVAL,
            "this regression only bites while the two intervals are equal"
        );
        let mut checker = Checker::default();
        // First poll: no handshake yet, so the timer starts and we re-register.
        assert_eq!(checker.decide(obs(0, true, None)), Some(PERIODIC));
        checker.record(T0, PERIODIC, true);
        assert_eq!(checker.handshake_missing_since, Some(T0));

        // Still no handshake one full timeout later. The forced branch must
        // fire; if the refresh above had cleared the timer it would not.
        assert_eq!(
            checker.decide(obs(HANDSHAKE_TIMEOUT, true, None)),
            Some(STALE_HANDSHAKE)
        );
        assert_eq!(
            checker.handshake_missing_since,
            Some(T0),
            "the timer must survive the refresh that ran at t=0"
        );
    }

    #[test]
    fn staleness_outranks_the_periodic_refresh() {
        let mut checker = Checker::default();
        checker.record(T0, PERIODIC, true);
        checker.handshake_missing_since = Some(T0);
        // At exactly REFRESH_INTERVAL both deadlines are due. The forced path
        // must win: only it can rebuild a tunnel whose config is unchanged.
        assert_eq!(
            checker.decide(obs(REFRESH_INTERVAL, true, None)),
            Some(STALE_HANDSHAKE)
        );
    }

    #[test]
    fn forced_refresh_is_rate_limited_while_the_tunnel_stays_dead() {
        let mut checker = Checker::default();
        checker.record(T0, PERIODIC, true);
        checker.handshake_missing_since = Some(T0);

        let refresh = checker.decide(obs(180, true, None)).expect("forced");
        assert!(refresh.force);
        checker.record(T0 + 180, refresh, true);

        // Every poll in the next window is still stale, but must stay quiet --
        // and must not fall through to a periodic refresh either.
        let mut elapsed = 190;
        while elapsed < 360 {
            assert_eq!(
                checker.decide(obs(elapsed, true, None)),
                None,
                "forced refresh must not repeat at t={elapsed}"
            );
            elapsed += 10;
        }
        assert_eq!(
            checker.decide(obs(360, true, None)),
            Some(STALE_HANDSHAKE),
            "one forced attempt per handshake timeout"
        );
    }

    #[test]
    fn an_observed_handshake_is_the_only_thing_that_clears_the_timer() {
        let mut checker = Checker::default();
        checker.record(T0, PERIODIC, true);

        assert!(checker.decide(obs(10, true, None)).is_none());
        assert_eq!(checker.handshake_missing_since, Some(T0 + 10));
        // A handshake lands.
        assert!(checker.decide(obs(20, true, Some(T0 + 20))).is_none());
        assert_eq!(checker.handshake_missing_since, None);
        // Losing it again restarts the clock rather than firing immediately.
        assert!(checker.decide(obs(30, true, None)).is_none());
        assert_eq!(checker.handshake_missing_since, Some(T0 + 30));
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
    fn acts_immediately_when_boot_left_no_config() {
        let mut checker = Checker::starting(T0, false);
        assert_eq!(checker.decide(obs(0, false, None)), Some(MISSING_CONFIG));
    }

    /// Boot registers the CVM, then this checker starts. Re-registering right
    /// away would double the gateway's registration load on every fleet reboot
    /// for no gain, so a config that is already on disk starts the periodic
    /// clock rather than triggering an immediate refresh.
    #[test]
    fn does_not_re_register_a_cvm_boot_just_registered() {
        let mut checker = Checker::starting(T0, true);
        assert_eq!(checker.decide(obs(0, true, Some(T0))), None);
        assert_eq!(checker.decide(obs(170, true, Some(T0 + 170))), None);
        assert_eq!(
            checker.decide(obs(180, true, Some(T0 + 180))),
            Some(PERIODIC),
            "the periodic clock still runs from process start"
        );
    }

    /// A checker that comes up with no config must not inherit the grace period
    /// above: that state means boot's registration failed and the CVM has no
    /// route at all.
    #[test]
    fn a_missing_config_overrides_the_startup_grace_period() {
        let mut checker = Checker::starting(T0, false);
        assert_eq!(checker.decide(obs(0, false, None)), Some(MISSING_CONFIG));
        checker.record(T0, MISSING_CONFIG, true);
        // Once it lands, the periodic clock takes over from the refresh.
        assert_eq!(checker.decide(obs(10, true, Some(T0 + 10))), None);
        assert_eq!(
            checker.decide(obs(180, true, Some(T0 + 180))),
            Some(PERIODIC)
        );
    }

    #[test]
    fn retries_missing_config_with_backoff_up_to_the_cap() {
        let mut checker = Checker::default();
        let mut t = 0;
        // First attempt fires immediately and fails.
        assert_eq!(checker.decide(obs(t, false, None)), Some(MISSING_CONFIG));
        checker.record(T0 + t, MISSING_CONFIG, false);

        // 30s base delay, then 60s, then capped at MAX_RETRY_INTERVAL.
        for expected_delay in [30, 60, 120, 120] {
            for early in [10, expected_delay - 10] {
                assert_eq!(
                    checker.decide(obs(t + early, false, None)),
                    None,
                    "must not retry after {early}s while waiting {expected_delay}s"
                );
            }
            t += expected_delay;
            assert_eq!(
                checker.decide(obs(t, false, None)),
                Some(MISSING_CONFIG),
                "must retry once {expected_delay}s have passed"
            );
            checker.record(T0 + t, MISSING_CONFIG, false);
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
        checker.record(T0, PERIODIC, true);

        assert_eq!(checker.decide(obs(170, true, Some(T0 + 170))), None);
        assert_eq!(
            checker.decide(obs(180, true, Some(T0 + 180))),
            Some(PERIODIC),
            "periodic refresh must not disrupt a healthy tunnel"
        );
    }

    #[test]
    fn gives_a_new_interface_a_full_timeout_to_handshake() {
        let mut checker = Checker::default();
        checker.record(T0, PERIODIC, true);

        // The timer runs from t=10, when the missing handshake was first
        // observed, not from the refresh at t=0.
        assert_eq!(checker.decide(obs(10, true, None)), None);
        assert_eq!(checker.decide(obs(170, true, None)), None);
        // At t=180 the timer has only reached 170, so the periodic refresh is
        // what comes due. It must not disturb the timer.
        assert_eq!(checker.decide(obs(180, true, None)), Some(PERIODIC));
        checker.record(T0 + 180, PERIODIC, true);
        assert_eq!(checker.handshake_missing_since, Some(T0 + 10));
        // One poll later the timer finally expires and forces a refresh.
        assert_eq!(checker.decide(obs(190, true, None)), Some(STALE_HANDSHAKE));
    }
}
