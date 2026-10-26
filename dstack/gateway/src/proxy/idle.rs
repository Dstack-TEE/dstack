// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One idle watchdog for every relay path.
//!
//! `timeouts.idle` used to be enforced per read, which meant a connection died
//! when *one* direction went quiet even while the other was busy. It is now a
//! connection-level watchdog that samples a monotonic progress counter: if
//! neither direction has moved for the idle window, the connection is stalled.
//! That costs one timer per window rather than one per operation, which is why
//! the fast paths can afford it.
//!
//! It lives here rather than inside a relay because every relay needs it and
//! they are shaped differently: the buffered bridge and the pre-gate relays are
//! `select!` loops that can poll it as one more branch, while a spliced
//! connection has no loop to hang it on and races it against the transfer
//! instead. Both call the same sampling logic, so the three paths cannot drift
//! into enforcing different things -- which is exactly what happened when
//! splice and kTLS silently had no idle timeout at all.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::{interval, Interval, MissedTickBehavior};

/// Samples a progress counter a few times per idle window.
pub(crate) struct IdleWatchdog {
    ticker: Interval,
    /// Consecutive ticks that saw no progress.
    idle_ticks: u32,
    /// Ticks without progress that add up to the configured idle window.
    max_idle_ticks: u32,
    last_seen: u64,
}

impl IdleWatchdog {
    pub(crate) fn new(idle: Duration) -> Self {
        // Four samples per window bounds the overshoot at 25% while keeping the
        // timer rate proportional to the window rather than to the traffic. The
        // floor stops a tiny `idle` turning into a busy loop.
        let tick = (idle / 4).max(Duration::from_millis(500));
        let mut ticker = interval(tick);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        Self {
            ticker,
            idle_ticks: 0,
            max_idle_ticks: (idle.as_millis() / tick.as_millis()).max(1) as u32,
            last_seen: 0,
        }
    }

    /// Wait for the next sample point.
    ///
    /// Cancel-safe: `Interval::tick` is, and nothing else is held across it, so
    /// this can sit in a `select!` arm that loses the race.
    pub(crate) async fn tick(&mut self) {
        self.ticker.tick().await;
    }

    /// Record where the relay has got to. `true` means it has been stalled for
    /// the whole idle window.
    pub(crate) fn stalled(&mut self, progress: u64) -> bool {
        if progress == self.last_seen {
            self.idle_ticks += 1;
            self.idle_ticks >= self.max_idle_ticks
        } else {
            self.idle_ticks = 0;
            self.last_seen = progress;
            false
        }
    }

    /// Resolve once the relay has been idle for the whole window.
    ///
    /// For relays with no loop of their own to poll from -- a spliced
    /// connection is two joined transfers, not a `select!` -- so this is raced
    /// against the transfer instead.
    pub(crate) async fn wait_until_stalled(mut self, progress: &AtomicU64) {
        // The first tick completes immediately; consume it so the first real
        // sample is a full tick away.
        self.tick().await;
        loop {
            self.tick().await;
            if self.stalled(progress.load(Ordering::Relaxed)) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test(start_paused = true)]
    async fn a_stalled_relay_is_reported_after_the_window() {
        let progress = Arc::new(AtomicU64::new(0));
        let watchdog = IdleWatchdog::new(Duration::from_secs(4));
        let start = tokio::time::Instant::now();
        watchdog.wait_until_stalled(&progress).await;
        // Sampling four times per window means it fires within one tick of the
        // window, never before it.
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_secs(4) && waited <= Duration::from_secs(6),
            "fired after {waited:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_keeps_moving_is_never_reported() {
        let progress = Arc::new(AtomicU64::new(0));
        let bump = progress.clone();
        tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                bump.fetch_add(1, Ordering::Relaxed);
            }
        });
        let watchdog = IdleWatchdog::new(Duration::from_secs(4));
        let fired = tokio::time::timeout(
            Duration::from_secs(15),
            watchdog.wait_until_stalled(&progress),
        )
        .await;
        assert!(
            fired.is_err(),
            "watchdog fired on a connection that was moving"
        );
    }
}
