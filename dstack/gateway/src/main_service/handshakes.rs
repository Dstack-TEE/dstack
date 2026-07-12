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

    pub(crate) fn latest(&self, stale_timeout: Option<Duration>) -> Result<HandshakesWithAge> {
        let snapshot = self.cell.get()?;
        add_elapsed_time(snapshot.value(), stale_timeout)
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
