// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use cc_eventlog::{EventLogVersion, RuntimeEvent};

pub use cc_eventlog as ccel;
pub use tdx_attest as tdx;
pub use tpm_attest as tpm;

use crate::attestation::{detect_tee_variant, TeeVariant};

pub mod amd_sev_snp;
pub mod attestation;
#[cfg(feature = "quote")]
mod aws_nitro_tpm;
#[cfg(feature = "quote")]
mod sev_snp;
mod v1;

const RUNTIME_EVENT_DIR: &str = "/run/log/dstack";
const RUNTIME_EVENT_VERSION_FILE: &str = "/run/log/dstack/runtime_event_version";
const RUNTIME_EVENT_LOCK_FILE: &str = "/run/log/dstack/runtime_event.lock";

fn runtime_event_lock() -> anyhow::Result<fs_err::File> {
    fs_err::create_dir_all(RUNTIME_EVENT_DIR)
        .context("failed to create runtime event log directory")?;
    let lock = fs_err::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(RUNTIME_EVENT_LOCK_FILE)
        .context("failed to open runtime event lock")?;
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
        .context("failed to lock runtime event emission")?;
    Ok(lock)
}

/// Configure the system-wide digest format used by subsequently emitted events.
///
/// The setting is persisted under `/run/log/dstack`, so separate dstack-util
/// processes share it. This must be called before [`emit_runtime_event`].
/// Repeating the same configuration is allowed; changing it is rejected.
pub fn set_runtime_event_version(version: EventLogVersion) -> anyhow::Result<()> {
    let value = match version {
        EventLogVersion::V1 => "1",
        EventLogVersion::V2 => "2",
    };
    let _lock = runtime_event_lock()?;
    match fs_err::read_to_string(RUNTIME_EVENT_VERSION_FILE) {
        Ok(configured) => {
            anyhow::ensure!(
                configured.trim() == value,
                "runtime event version already set to {}",
                configured.trim()
            );
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            safe_write::safe_write(RUNTIME_EVENT_VERSION_FILE, value.as_bytes())
                .context("failed to write runtime event version")
        }
        Err(err) => Err(err).context("failed to read runtime event version"),
    }
}

fn runtime_event_version() -> anyhow::Result<EventLogVersion> {
    let value = fs_err::read_to_string(RUNTIME_EVENT_VERSION_FILE)
        .context("runtime event version is not configured")?;
    match value.trim() {
        "1" => Ok(EventLogVersion::V1),
        "2" => Ok(EventLogVersion::V2),
        value => anyhow::bail!("invalid runtime event version: {value}"),
    }
}

/// Emit a dstack measured event using the legacy V1 digest format.
///
/// - TDX-family: RTMR3
/// - GCP TPM: SHA256 PCR14
/// - AWS NitroTPM: SHA384 PCR14
pub fn emit_runtime_event(event: &str, payload: &[u8]) -> anyhow::Result<()> {
    // Hold the system-wide lock across both the log append and register
    // extension so separate processes cannot make their ordering diverge.
    let _lock = runtime_event_lock()?;
    let version = runtime_event_version()?;
    let event = RuntimeEvent::new(event.to_string(), payload.to_vec(), version);
    let mode = detect_tee_variant()?;

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
    let mode = detect_tee_variant()?;
    if mode != TeeVariant::DstackAwsNitroTpm {
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
fn expected_aws_config_pcr(config_id: &[u8; 48]) -> [u8; 48] {
    use sha2::{Digest, Sha384};
    let mut material = [0u8; 96];
    material[48..].copy_from_slice(config_id);
    Sha384::digest(material).into()
}
