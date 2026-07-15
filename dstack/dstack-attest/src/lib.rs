// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{LazyLock, Mutex};

use anyhow::Context;
use cc_eventlog::RuntimeEvent;

pub use cc_eventlog as ccel;
pub use tdx_attest as tdx;
pub use tpm_attest as tpm;

use crate::attestation::AttestationMode;

pub mod amd_sev_snp;
pub mod attestation;
#[cfg(feature = "quote")]
mod aws_nitro_tpm;
#[cfg(feature = "quote")]
mod sev_snp;
mod v1;

/// Serializes measured event emission within this process.
///
/// Appending to the event log and extending the platform measurement register
/// must happen atomically as a unit: the log order has to match the extension
/// order, otherwise replay during quote verification will not reproduce the
/// measured value. Concurrent callers, for example multiple `emit_event` RPCs
/// hitting the guest-agent at once, would otherwise be able to interleave their
/// log writes and register extensions.
static EMIT_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Emit a dstack measured event and log the event.
///
/// Semantics match bare TDX RTMR3: every dstack event extends a single
/// append-only measurement register.
///
/// - TDX-family: RTMR3
/// - GCP TPM: SHA256 PCR14
/// - AWS NitroTPM: SHA384 PCR14 (not PCR23; no launch/runtime PCR split)
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
    if let Some((pcr, bank)) = mode.tpm_event_pcr_and_bank() {
        let tpm = tpm_attest::TpmContext::detect().context("Failed to detect TPM device")?;
        match bank {
            "sha256" => {
                let digest = event.sha256_digest();
                tpm.pcr_extend_sha256(pcr, &digest)
                    .context("failed to extend TPM PCR")?;
            }
            "sha384" => {
                let digest = event.sha384_digest();
                tpm.pcr_extend(pcr, &digest, "sha384")
                    .context("failed to extend TPM PCR")?;
            }
            bank => anyhow::bail!("unsupported TPM PCR bank: {bank}"),
        }
    }
    Ok(())
}

/// Measure the AWS config commitment into PCR8 (mr_config analogue).
///
/// `config_id` is the `MrConfig` id the guest computed from its measured app
/// identity during setup. Extends PCR8 exactly once from zero and reads the
/// register back, so a polluted or double-extended PCR8 fails at boot instead
/// of producing quotes that can never verify. Does **not** append to the
/// dstack event log / PCR14 lane — config is a separate register.
pub fn measure_aws_config_pcr(config_id: &[u8; 48]) -> anyhow::Result<()> {
    let mode = AttestationMode::detect()?;
    if mode != AttestationMode::DstackAwsNitroTpm {
        return Ok(());
    }
    let config_pcr = u32::from(crate::attestation::AWS_NITRO_TPM_CONFIG_PCR);
    let tpm = tpm_attest::TpmContext::detect().context("Failed to detect TPM device")?;
    tpm.pcr_extend(config_pcr, config_id, "sha384")
        .context("failed to extend AWS NitroTPM config PCR8")?;
    let quoted = tpm
        .pcr_read_single(config_pcr, "sha384")
        .context("failed to read back AWS config PCR8")?;
    let expected = expected_aws_config_pcr(config_id);
    if quoted.as_slice() != expected.as_slice() {
        anyhow::bail!(
            "invalid AWS config PCR8 after extend (polluted or double-extended), quoted: {}, expected: {}",
            hex::encode(&quoted),
            hex::encode(expected)
        );
    }
    Ok(())
}

/// Expected PCR8 value after a single SHA384 extend of the raw `config_id`
/// from zero: `sha384(0^48 || config_id)`.
///
/// The config id is extended as-is (it is already 48 bytes, the SHA384 bank
/// digest size), so a verifier that recovers the claimed `config_id` can parse
/// its version byte and recompute this value directly.
pub fn expected_aws_config_pcr(config_id: &[u8; 48]) -> [u8; 48] {
    use sha2::{Digest, Sha384};
    let mut material = [0u8; 96];
    material[48..].copy_from_slice(config_id);
    Sha384::digest(material).into()
}
