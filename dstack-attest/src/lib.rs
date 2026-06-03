// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{LazyLock, Mutex};

use anyhow::Context;
use cc_eventlog::RuntimeEvent;

pub use cc_eventlog as ccel;
pub use tdx_attest as tdx;

use crate::attestation::AttestationMode;

pub mod attestation;
mod v1;

/// Serializes runtime event emission within this process.
///
/// Appending to the event log and extending RTMR3 must happen atomically as a
/// unit: the order of log entries has to match the order of RTMR extensions,
/// otherwise the RTMR replay performed during quote verification will not
/// reproduce the measured value. Concurrent callers (e.g. multiple
/// `emit_event` RPCs hitting the guest-agent at once) would otherwise be able
/// to interleave their log writes and `extend_rtmr` calls.
static EMIT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Emit a runtime event that extends RTMR3 and logs the event.
pub fn emit_runtime_event(event: &str, payload: &[u8]) -> anyhow::Result<()> {
    let event = RuntimeEvent::new(event.to_string(), payload.to_vec());

    let mode = AttestationMode::detect()?;

    // Hold the lock across both the log append and the register extension so
    // that the on-disk log order always matches the RTMR extension order.
    let _guard = EMIT_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    event.emit().context("Failed to emit runtime event")?;

    if mode.has_tdx() {
        let digest = event.sha384_digest();
        let event_type = event.cc_event_type();
        tdx_attest::extend_rtmr(3, event_type, digest).context("Failed to extend TDX RTMR")?;
    }
    Ok(())
}
