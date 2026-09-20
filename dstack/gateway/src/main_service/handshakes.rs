// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use anyhow::{bail, Context, Result};
use cached_cell::TtlCell;
use tracing::warn;

type HandshakeTimestamps = BTreeMap<String, u64>;
type HandshakesWithAge = BTreeMap<String, (u64, Duration)>;

/// Domain-specific wrapper around the generic TTL cell.
///
/// The cache framework lives in `cached-cell`; this type only knows how to
/// produce and interpret WireGuard `latest-handshakes` snapshots.
pub(crate) struct LatestHandshakesCache {
    interface: String,
    cell: Arc<TtlCell<HandshakeTimestamps>>,
}

impl LatestHandshakesCache {
    pub(crate) fn new(interface: String, ttl: Duration) -> Self {
        Self {
            interface,
            cell: Arc::new(TtlCell::new(ttl)),
        }
    }

    pub(crate) fn spawn_refresh_task(self: Arc<Self>, interval: Duration) {
        let interface = self.interface.clone();
        self.cell.clone().spawn_refresh_task(
            interval,
            move || fetch_latest_handshake_timestamps(&interface),
            |err| warn!("failed to refresh WireGuard latest-handshakes cache: {err}"),
        );
    }

    pub(crate) async fn refresh(&self) -> Result<()> {
        let interface = self.interface.clone();
        self.cell
            .refresh_blocking(move || fetch_latest_handshake_timestamps(&interface))
            .await
            .map_err(|err| anyhow::anyhow!("{err}"))?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_for_test(&self, timestamps: HandshakeTimestamps) {
        self.cell.set(timestamps);
    }

    /// The cached snapshot, never a freshly produced one.
    ///
    /// The routing path reaches this from `select_top_n_hosts` once per
    /// proxied connection, holding the `ProxyState` mutex every tenant's
    /// traffic takes. Producing a value here means forking `wg show` under
    /// that lock -- and the cell only ever fills on success, so a host where
    /// `wg show` cannot work (wrong `core.wg.interface`, no WireGuard module,
    /// a container without `CAP_NET_ADMIN`) would fork once per inbound
    /// connection, for as long as the traffic lasts. The producer runs in
    /// [`Self::refresh`] and in the periodic task instead, both off the
    /// routing path and on the blocking pool.
    ///
    /// Serving an expired snapshot rather than nothing is deliberate: every
    /// consumer compares handshake *age* against its own threshold, so a stale
    /// snapshot ages the whole fleet uniformly, while an empty map reads as
    /// "no instance has ever handshaked" and would drain routing on the first
    /// refresh that fails. Empty is only what a node that has never had a
    /// snapshot actually knows.
    pub(crate) fn latest(&self, stale_timeout: Option<Duration>) -> Result<HandshakesWithAge> {
        let timestamps = match self.cell.get_allow_stale() {
            Ok(snapshot) => snapshot.into_value(),
            Err(_) => Arc::new(BTreeMap::new()),
        };
        add_elapsed_time(timestamps.as_ref(), stale_timeout)
    }
}

fn fetch_latest_handshake_timestamps(interface: &str) -> Result<HandshakeTimestamps> {
    /*
    $wg show ds-gw-kvin1 latest-handshakes
    eHBq6OjihPy1IZ2cFDomSesjeD+new7KNdWn9MHdQC8=    1730190589
    SRuIdjZ1CkR54jJ1g7JC4cy9nxHPezXf2bZlkZHjFxE=    1732085583
    YobeKV6YpmuTAQd0+Tx30Pe4JP12fPFwftC04Umt6Bw=    1731214390
    9pgMHikM4onpoiNPJkya003BFAdzRMiD2WMDSMb64zo=    1731213050
    oZppF/Rk7NgnuPkkfGUiBpY9HbThJvq3jACNGW2vnVA=    1731213485
    3OxwGWcnC+4TZ31rnmDpfgbLBi8DCWdEk4k/7gFG5HU=    1732085521
    */
    let output = cmd_lib::run_fun!(wg show $interface latest-handshakes)?;
    parse_latest_handshake_timestamps(&output)
}

fn parse_latest_handshake_timestamps(output: &str) -> Result<HandshakeTimestamps> {
    let mut handshakes = BTreeMap::new();

    for line in output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }
        if parts.len() != 2 {
            bail!("invalid latest-handshakes line: {line:?}");
        }

        let pubkey = parts[0].trim().to_string();
        let timestamp = parts[1]
            .trim()
            .parse::<u64>()
            .context("invalid WireGuard latest-handshake timestamp")?;
        handshakes.insert(pubkey, timestamp);
    }

    Ok(handshakes)
}

fn add_elapsed_time(
    timestamps: &HandshakeTimestamps,
    stale_timeout: Option<Duration>,
) -> Result<HandshakesWithAge> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before Unix epoch")?;
    let mut handshakes = BTreeMap::new();

    for (pubkey, timestamp) in timestamps {
        if *timestamp == 0 {
            handshakes.insert(pubkey.clone(), (0, Duration::MAX));
            continue;
        }

        let timestamp_duration = Duration::from_secs(*timestamp);
        let elapsed = now.checked_sub(timestamp_duration).unwrap_or_default();
        match stale_timeout {
            Some(min_duration) if elapsed < min_duration => continue,
            _ => (),
        }
        handshakes.insert(pubkey.clone(), (*timestamp, elapsed));
    }

    Ok(handshakes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A cold cache must not fork a process on the routing path.
    ///
    /// `latest` is reached from `select_top_n_hosts` while `ProxyState`'s mutex
    /// is held, once per proxied connection. A host where `wg show` can never
    /// succeed -- a misconfigured `core.wg.interface`, no WireGuard module, a
    /// container without `CAP_NET_ADMIN` -- never fills the cell, so a `latest`
    /// that produces its own value forks once per inbound connection while
    /// holding the lock every tenant's traffic takes.
    #[test]
    fn a_cold_cache_does_not_shell_out_on_the_routing_path() {
        const CONNECTIONS: usize = 500;
        let cache = LatestHandshakesCache::new(
            "dstack-no-such-iface0".to_string(),
            Duration::from_secs(30),
        );

        let started = std::time::Instant::now();
        for _ in 0..CONNECTIONS {
            assert!(
                cache
                    .latest(None)
                    .expect("a cold cache still answers")
                    .is_empty(),
                "a host with no WireGuard data knows of no fresh handshake"
            );
        }
        let elapsed = started.elapsed();

        assert!(
            elapsed < Duration::from_millis(100),
            "{CONNECTIONS} cold reads took {elapsed:?}: the routing path is spawning \
             a process per connection"
        );
    }

    /// An expired snapshot still routes.
    ///
    /// Consumers threshold on handshake *age*, so serving a stale map ages the
    /// whole fleet uniformly. Returning nothing instead would read as "no
    /// instance has ever handshaked" and drain routing on the first refresh
    /// that fails.
    #[test]
    fn an_expired_snapshot_is_still_served() {
        let cache = LatestHandshakesCache::new("dstack-no-such-iface0".to_string(), Duration::ZERO);
        cache.set_for_test(BTreeMap::from([("pubkey-a".to_string(), 1730190589)]));

        assert!(cache
            .latest(None)
            .expect("an expired snapshot still answers")
            .contains_key("pubkey-a"));
    }

    #[test]
    fn parses_latest_handshake_timestamps() {
        let handshakes = parse_latest_handshake_timestamps(
            "pubkey-a 1730190589\n\
             pubkey-b 0\n",
        )
        .unwrap();

        assert_eq!(handshakes.get("pubkey-a"), Some(&1730190589));
        assert_eq!(handshakes.get("pubkey-b"), Some(&0));
    }
}
