// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 session management

use anyhow::{Context, Result};

use super::constants::*;
use super::device::*;
use super::marshal::*;
use super::types::*;

/// Authorization session handle
#[derive(Debug, Clone, Copy)]
pub struct AuthSession {
    pub handle: u32,
    pub session_type: TpmSe,
    pub hash_alg: TpmAlgId,
}

impl AuthSession {
    /// Start a new authorization session
    pub fn start(device: &mut TpmDevice, session_type: TpmSe, hash_alg: TpmAlgId) -> Result<Self> {
        // TPM2_StartAuthSession command
        let mut cmd = TpmCommand::new(TpmCc::StartAuthSession);

        const ZERO_NONCE: [u8; 16] = [0u8; 16];

        // tpmKey (TPM_RH_NULL for unbound session)
        cmd.add_handle(tpm_rh::NULL);
        // bind (TPM_RH_NULL for unbound session)
        cmd.add_handle(tpm_rh::NULL);
        // nonceCaller (16-byte nonce as required by TPM spec)
        cmd.add_tpm2b(&ZERO_NONCE);
        // encryptedSalt (empty - no salt)
        cmd.add_tpm2b_empty();
        // sessionType
        cmd.add_u8(session_type as u8);
        // symmetric (AES-128-CFB, matches TPM default expectation)
        cmd.add(&TpmtSymDef::aes_128_cfb());
        // authHash
        cmd.add_u16(hash_alg.to_u16());

        let cmd_bytes = cmd.finalize();
        tracing::debug!("StartAuthSession command: {} bytes", cmd_bytes.len());
        let response = device.execute(&cmd_bytes)?;
        if !response.is_success() {
            anyhow::bail!(
                "StartAuthSession failed with TPM error: 0x{:08x}",
                response.response_code
            );
        }

        let mut buf = response.data_buffer();
        let handle = buf.get_u32()?;
        let _nonce_tpm = buf.get_tpm2b()?; // nonceTPM

        Ok(Self {
            handle,
            session_type,
            hash_alg,
        })
    }

    /// Start a policy session
    pub fn start_policy(device: &mut TpmDevice, hash_alg: TpmAlgId) -> Result<Self> {
        Self::start(device, TpmSe::Policy, hash_alg)
    }

    /// Start a trial policy session (for computing policy digest)
    pub fn start_trial(device: &mut TpmDevice, hash_alg: TpmAlgId) -> Result<Self> {
        Self::start(device, TpmSe::Trial, hash_alg)
    }

    /// Apply PCR policy to this session
    pub fn policy_pcr(
        &self,
        device: &mut TpmDevice,
        pcr_digest: &[u8],
        pcr_selection: &TpmlPcrSelection,
    ) -> Result<()> {
        let mut cmd = TpmCommand::new(TpmCc::PolicyPcr);

        // policySession
        cmd.add_handle(self.handle);
        // pcrDigest
        cmd.add_tpm2b(pcr_digest);
        // pcrs
        cmd.add(pcr_selection);

        let response = device.execute(&cmd.finalize())?;
        response.ensure_success().context("PolicyPCR failed")?;

        Ok(())
    }

    /// Get the current policy digest
    pub fn get_digest(&self, device: &mut TpmDevice) -> Result<Vec<u8>> {
        let mut cmd = TpmCommand::new(TpmCc::PolicyGetDigest);
        cmd.add_handle(self.handle);

        let response = device.execute(&cmd.finalize())?;
        response
            .ensure_success()
            .context("PolicyGetDigest failed")?;

        let mut buf = response.data_buffer();
        let digest = buf.get_tpm2b()?;

        Ok(digest)
    }

    /// Flush (close) this session
    pub fn flush(self, device: &mut TpmDevice) -> Result<()> {
        let mut cmd = TpmCommand::new(TpmCc::FlushContext);
        cmd.add_handle(self.handle);

        let response = device.execute(&cmd.finalize())?;
        response.ensure_success().context("FlushContext failed")?;

        Ok(())
    }
}

/// Compute the PCR digest for a given PCR selection
pub fn compute_pcr_digest(
    device: &mut TpmDevice,
    pcr_selection: &TpmlPcrSelection,
    hash_alg: TpmAlgId,
) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256, Sha384, Sha512};

    // Read PCR values
    let pcr_values = read_pcr_values(device, pcr_selection)?;

    // Concatenate all PCR values
    let mut concat = Vec::new();
    for value in &pcr_values {
        concat.extend_from_slice(value);
    }

    // Hash the concatenated values
    let digest = match hash_alg {
        TpmAlgId::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(&concat);
            hasher.finalize().to_vec()
        }
        TpmAlgId::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(&concat);
            hasher.finalize().to_vec()
        }
        TpmAlgId::Sha512 => {
            let mut hasher = Sha512::new();
            hasher.update(&concat);
            hasher.finalize().to_vec()
        }
        _ => anyhow::bail!("unsupported hash algorithm for PCR digest"),
    };

    Ok(digest)
}

/// Read PCR values for a selection
fn read_pcr_values(
    device: &mut TpmDevice,
    pcr_selection: &TpmlPcrSelection,
) -> Result<Vec<Vec<u8>>> {
    let mut cmd = TpmCommand::new(TpmCc::PcrRead);
    cmd.add(pcr_selection);

    let response = device.execute(&cmd.finalize())?;
    response.ensure_success().context("PCR_Read failed")?;

    let mut buf = response.data_buffer();
    let _update_counter = buf.get_u32()?;
    let _pcr_selection_out = TpmlPcrSelection::unmarshal(&mut buf)?;
    let digest_list = TpmlDigest::unmarshal(&mut buf)?;

    Ok(digest_list.digests.into_iter().map(|d| d.buffer).collect())
}
