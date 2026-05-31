// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use anyhow::Context;
use cc_eventlog::RuntimeEvent;

pub use cc_eventlog as ccel;
pub use tdx_attest as tdx;
pub use tpm_attest as tpm;

use crate::attestation::AttestationMode;

pub mod attestation;
mod v1;

/// Emit a runtime event that extends RTMR3 and logs the event.
pub fn emit_runtime_event(event: &str, payload: &[u8]) -> anyhow::Result<()> {
    let event = RuntimeEvent::new(event.to_string(), payload.to_vec());

    let mode = AttestationMode::detect()?;

    event.emit().context("Failed to emit runtime event")?;

    if mode.has_tdx() {
        let digest = event.sha384_digest();
        let event_type = event.cc_event_type();
        tdx_attest::extend_rtmr(3, event_type, digest).context("Failed to extend TDX RTMR")?;
    }
    if let Some(pcr) = mode.tpm_runtime_pcr() {
        let digest = event.sha256_digest();
        let tpm = tpm_attest::TpmContext::detect().context("Failed to detect TPM device")?;
        tpm.pcr_extend_sha256(pcr, &digest)
            .context("Failed to extend TPM RTMR")?;
    }
    Ok(())
}
