// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Epoch-seconds conversions shared across the gateway.
//!
//! Timestamps cross the KV boundary as `u64` seconds since the Unix epoch and
//! are held in memory as `SystemTime`, so both directions are needed in several
//! modules. Keeping one pair of them means the saturating behaviour — a time
//! before the epoch reads as 0, a count of seconds `SystemTime` cannot
//! represent clamps to the epoch — is decided once instead of at each call
//! site.
//!
//! Call sites that would rather fail than saturate keep their own
//! `duration_since(UNIX_EPOCH)?`: a clock behind the epoch is a real fault, and
//! whether to report it or carry on is the caller's decision, not this
//! module's.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch for `ts`, or 0 if `ts` predates the epoch.
pub(crate) fn encode_ts(ts: SystemTime) -> u64 {
    ts.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// The instant `ts` seconds after the Unix epoch, clamped to the epoch when
/// that instant is not representable.
pub(crate) fn decode_ts(ts: u64) -> SystemTime {
    UNIX_EPOCH
        .checked_add(Duration::from_secs(ts))
        .unwrap_or(UNIX_EPOCH)
}

/// The local wall clock, as seconds since the Unix epoch.
pub(crate) fn now_secs() -> u64 {
    encode_ts(SystemTime::now())
}
