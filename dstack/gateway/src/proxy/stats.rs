// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! What the data path is actually doing with kTLS and splice.
//!
//! Neither option is simply on or off. kTLS can be cleared at startup by the
//! capability probe, and both engage per connection only once their gate fires,
//! so the configured value does not tell an operator what is running -- and the
//! difference is worth 2-4x in per-connection memory. Two things are reported:
//! the effective mode, which answers "is it on at all", and per-connection
//! counters, which answer "is it engaging".
//!
//! All counters are monotonic since process start and are read without
//! synchronisation, so a snapshot can be marginally inconsistent between
//! fields. That is the right trade for numbers whose purpose is to be watched
//! over time; the alternative costs an ordering on the connection path.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use dstack_gateway_rpc::ProxyAccelStatus;

use crate::config::{EngageAfter, ProxyConfig};

/// Connections handed to the kernel's TLS ULP.
static KTLS_OFFLOADED: AtomicU64 = AtomicU64::new(0);
/// Connections where that handover failed. Non-zero here means connections are
/// being dropped or truncated at the gate, not merely running unaccelerated.
static KTLS_OFFLOAD_FAILED: AtomicU64 = AtomicU64::new(0);
/// Connections that entered a zero-copy splice relay. Counted on both paths --
/// TLS passthrough, and terminate once kTLS has handed the socket over -- since
/// from the relay's point of view they are the same thing.
static SPLICE_ENGAGED: AtomicU64 = AtomicU64::new(0);
/// Set when the startup probe finds no TLS ULP. Without it a probe-disabled
/// gateway is indistinguishable from one that was never configured for kTLS,
/// because both end up with `ProxyConfig::ktls` unset.
static KTLS_UNSUPPORTED: AtomicBool = AtomicBool::new(false);

/// Record that the kernel cannot do kTLS, so the reported mode can say why it
/// is off rather than just that it is.
pub(crate) fn mark_ktls_unsupported() {
    KTLS_UNSUPPORTED.store(true, Ordering::Relaxed);
}

/// Record the outcome of handing one connection to the kernel.
///
/// Takes the result so both offload sites -- immediate and gated -- count the
/// same way without repeating the match.
pub(crate) fn record_ktls_offload<T, E>(result: Result<T, E>) -> Result<T, E> {
    let counter = if result.is_ok() {
        &KTLS_OFFLOADED
    } else {
        &KTLS_OFFLOAD_FAILED
    };
    counter.fetch_add(1, Ordering::Relaxed);
    result
}

/// Record that one connection started splice relaying.
pub(crate) fn record_splice_engaged() {
    SPLICE_ENGAGED.fetch_add(1, Ordering::Relaxed);
}

/// Snapshot the effective acceleration state for the `Status` RPC.
pub fn accel_status(config: &ProxyConfig) -> ProxyAccelStatus {
    ProxyAccelStatus {
        ktls_mode: ktls_mode(config),
        splice_mode: match &config.tcp_splice {
            Some(splice) => splice.engage.to_string(),
            None => "off".to_string(),
        },
        ktls_offloaded: KTLS_OFFLOADED.load(Ordering::Relaxed),
        ktls_offload_failed: KTLS_OFFLOAD_FAILED.load(Ordering::Relaxed),
        splice_engaged: SPLICE_ENGAGED.load(Ordering::Relaxed),
    }
}

fn ktls_mode(config: &ProxyConfig) -> String {
    describe_ktls(
        config.ktls.as_ref(),
        KTLS_UNSUPPORTED.load(Ordering::Relaxed),
    )
}

/// Split out from the statics so it can be tested without mutating global state
/// that other tests in this process would then see.
fn describe_ktls(ktls: Option<&EngageAfter>, unsupported: bool) -> String {
    match ktls {
        Some(engage) => engage.to_string(),
        None if unsupported => "disabled (kernel has no TLS ULP)".to_string(),
        None => "off".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gates_read_as_when_they_engage() {
        let gate = |bytes, secs: Option<u64>| EngageAfter {
            after_bytes: bytes,
            after_duration: secs.map(std::time::Duration::from_secs),
        };
        assert_eq!(gate(None, None).to_string(), "immediate");
        assert_eq!(gate(Some(65536), None).to_string(), "after 64 KiB");
        assert_eq!(gate(Some(1 << 20), None).to_string(), "after 1 MiB");
        assert_eq!(gate(Some(1000), None).to_string(), "after 1000 B");
        assert_eq!(gate(None, Some(5)).to_string(), "after 5s");
        assert_eq!(gate(Some(65536), Some(5)).to_string(), "after 64 KiB or 5s");
    }

    #[test]
    fn a_probe_disabled_gateway_does_not_look_unconfigured() {
        assert_eq!(describe_ktls(None, false), "off");
        assert_eq!(
            describe_ktls(None, true),
            "disabled (kernel has no TLS ULP)"
        );
        // A kernel that cannot do kTLS is only interesting while kTLS is off;
        // once it is on, the gate is the useful thing to report.
        let gate = EngageAfter::default();
        assert_eq!(describe_ktls(Some(&gate), true), "immediate");
    }
}
