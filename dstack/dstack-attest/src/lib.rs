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
pub mod collateral;
#[cfg(feature = "quote")]
mod sev_snp;
pub mod trust_anchors;
mod v1;

const RUNTIME_EVENT_DIR: &str = "/run/log/dstack";
const RUNTIME_EVENT_VERSION_FILE: &str = "/run/log/dstack/runtime_event_version";
const RUNTIME_EVENT_LOCK_FILE: &str = "/run/log/dstack/runtime_event.lock";

/// Build the verifier a guest authenticates the KMS and the gateway with.
///
/// Trust anchors are taken from [`trust_anchors::ANCHOR_DIR`] when that
/// directory holds a set published inside this guest. When it does not — the
/// only outcome on a production image — the vendor production roots apply.
///
/// `collateral_urls` selects where signed collateral is fetched from; the trust
/// anchor still has to sign it.
pub fn default_verifier(
    collateral_urls: &attestation::CollateralUrls,
) -> anyhow::Result<attestation::AttestationVerifier> {
    use attestation::{AttestationVerifier, AttestationVerifierConfig};

    let Some(root_ca) =
        trust_anchors::load_anchors(std::path::Path::new(trust_anchors::ANCHOR_DIR))
            .context("failed to load local attestation anchors")?
    else {
        return AttestationVerifier::new_prod(Some(collateral_urls));
    };
    tracing::warn!(
        dir = trust_anchors::ANCHOR_DIR,
        "verifying attestation against external trust anchors published by the in-guest TEE \
         simulator; this guest cannot verify production evidence"
    );
    AttestationVerifier::load(&AttestationVerifierConfig {
        // The opt-in exists to make an operator acknowledge a non-production
        // root in a hand-written service config. Nothing here is hand-written:
        // the roots came from a guest-local directory `load_anchors` already
        // authenticated, so the flag has no one left to warn.
        insecure_allow_external_trust_anchors: true,
        urls: collateral_urls.clone(),
        root_ca,
    })
}

/// Acquire the system-wide runtime event lock, blocking until it is available.
///
/// The wait is deliberately unbounded. The lock serializes the event-log append
/// with the measurement-register extension, and that ordering is what makes
/// replay reproduce the quoted register value. Proceeding after a timeout would
/// break the invariant, and failing after one would abort a boot that is merely
/// slow, so waiting is the only safe option. A holder that dies releases the
/// lock automatically (flock is dropped when the file descriptor closes), which
/// leaves a live but wedged holder as the sole way to block emission.
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
    let _lock = runtime_event_lock()?;
    set_runtime_event_version_file(RUNTIME_EVENT_VERSION_FILE, version)
}

fn set_runtime_event_version_file(
    path: impl AsRef<std::path::Path>,
    version: EventLogVersion,
) -> anyhow::Result<()> {
    let path = path.as_ref();
    let value = match version {
        EventLogVersion::V1 => "1",
        EventLogVersion::V2 => "2",
    };
    match fs_err::read_to_string(path) {
        Ok(configured) => {
            anyhow::ensure!(
                configured.trim() == value,
                "runtime event version is already set to {} for this boot and cannot be \
                 changed to {value}; the setting is fixed when system setup runs, so restart \
                 the CVM to apply a new app-compose `event_log_version`",
                configured.trim()
            );
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            safe_write::safe_write(path, value.as_bytes())
                .context("failed to write runtime event version")
        }
        Err(err) => Err(err).context("failed to read runtime event version"),
    }
}

fn runtime_event_version() -> anyhow::Result<EventLogVersion> {
    runtime_event_version_file(RUNTIME_EVENT_VERSION_FILE)
}

fn runtime_event_version_file(
    path: impl AsRef<std::path::Path>,
) -> anyhow::Result<EventLogVersion> {
    let value = fs_err::read_to_string(path).context(
        "runtime event version is not configured; complete dstack system setup before emitting events",
    )?;
    match value.trim() {
        "1" => Ok(EventLogVersion::V1),
        "2" => Ok(EventLogVersion::V2),
        value => anyhow::bail!("invalid runtime event version: {value}"),
    }
}

#[cfg(test)]
mod runtime_event_version_tests {
    use super::*;

    fn temp_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("dstack-{name}-{}", std::process::id()))
    }

    #[test]
    fn rejects_conflicting_runtime_event_version() {
        let path = temp_path("event-version-conflict");
        let _ = fs_err::remove_file(&path);
        set_runtime_event_version_file(&path, EventLogVersion::V1).unwrap();
        set_runtime_event_version_file(&path, EventLogVersion::V1).unwrap();
        let err = set_runtime_event_version_file(&path, EventLogVersion::V2).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("already set to 1"), "{message}");
        assert!(
            message.contains("restart the CVM"),
            "the conflict error must tell the operator how to apply a new version: {message}"
        );
        let _ = fs_err::remove_file(path);
    }

    #[test]
    fn reports_unconfigured_runtime_event_version() {
        let path = temp_path("event-version-missing");
        let _ = fs_err::remove_file(&path);
        let err = runtime_event_version_file(path).unwrap_err();
        assert!(err.to_string().contains("complete dstack system setup"));
    }
}

/// Emit a dstack measured event using the system-configured digest format.
///
/// The event-log append and platform-register extension are serialized by a
/// system-wide file lock so their ordering cannot diverge across processes.
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

    // Commit the userspace log only after the platform register accepted the
    // measurement. A device failure must never leave an unmeasured event in
    // the trusted replay log.
    event.emit().context("Failed to emit runtime event")?;
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
