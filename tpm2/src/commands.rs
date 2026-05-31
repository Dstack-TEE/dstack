// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 command implementations
//!
//! This module provides high-level TPM operations.

use anyhow::{Context, Result};
use tracing::debug;

use super::constants::*;
use super::device::*;
use super::marshal::*;
use super::session::*;
use super::types::*;

/// Pure Rust TPM context
pub struct TpmContext {
    device: TpmDevice,
}

impl TpmContext {
    /// Create a new TPM context with the given device path
    pub fn new(tcti_path: Option<&str>) -> Result<Self> {
        let device = match tcti_path {
            Some(path) => TpmDevice::open(path)?,
            None => TpmDevice::detect()?,
        };

        Ok(Self { device })
    }

    /// Get the device path
    pub fn device_path(&self) -> &str {
        self.device.path()
    }

    // ==================== NV Operations ====================

    /// Check if an NV index exists
    pub fn nv_exists(&mut self, index: u32) -> Result<bool> {
        let mut cmd = TpmCommand::new(TpmCc::NvReadPublic);
        cmd.add_handle(index);

        let response = self.device.execute(&cmd.finalize())?;

        // If successful, the NV index exists
        Ok(response.is_success())
    }

    /// Read NV public area to get size
    pub fn nv_read_public(&mut self, index: u32) -> Result<TpmsNvPublic> {
        let mut cmd = TpmCommand::new(TpmCc::NvReadPublic);
        cmd.add_handle(index);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("NV_ReadPublic failed")?;

        let mut buf = response.data_buffer();
        let nv_public = Tpm2bNvPublic::unmarshal(&mut buf)?;

        Ok(nv_public.nv_public)
    }

    /// Read data from an NV index
    pub fn nv_read(&mut self, index: u32) -> Result<Option<Vec<u8>>> {
        // First get the NV public to know the size
        let nv_public = match self.nv_read_public(index) {
            Ok(p) => p,
            Err(_) => return Ok(None), // NV index doesn't exist
        };

        let total_size = nv_public.data_size as usize;
        let mut result = Vec::with_capacity(total_size);
        let mut offset = 0u16;

        // Read in chunks (max ~1024 bytes per read)
        const MAX_READ_SIZE: u16 = 1024;

        while (offset as usize) < total_size {
            let remaining = total_size - offset as usize;
            let read_size = (remaining as u16).min(MAX_READ_SIZE);

            let mut cmd = TpmCommand::with_sessions(TpmCc::NvRead);
            // authHandle (owner for owner-readable NV)
            cmd.add_handle(tpm_rh::OWNER);
            // nvIndex
            cmd.add_handle(index);
            // Authorization area (null auth)
            cmd.add_null_auth_area();
            // size
            cmd.add_u16(read_size);
            // offset
            cmd.add_u16(offset);

            let response = self.device.execute(&cmd.finalize())?;
            if !response.is_success() {
                // Try with NV index as auth handle instead
                let mut cmd = TpmCommand::with_sessions(TpmCc::NvRead);
                cmd.add_handle(index);
                cmd.add_handle(index);
                cmd.add_null_auth_area();
                cmd.add_u16(read_size);
                cmd.add_u16(offset);

                let response = self.device.execute(&cmd.finalize())?;
                if !response.is_success() {
                    return Ok(None);
                }

                let mut buf = response.skip_parameter_size()?;
                let data = buf.get_tpm2b()?;
                result.extend_from_slice(&data);
            } else {
                let mut buf = response.skip_parameter_size()?;
                let data = buf.get_tpm2b()?;
                result.extend_from_slice(&data);
            }

            offset += read_size;
        }

        Ok(Some(result))
    }

    /// Write data to an NV index
    pub fn nv_write(&mut self, index: u32, data: &[u8]) -> Result<bool> {
        const MAX_WRITE_SIZE: usize = 1024;
        let mut offset = 0u16;

        while (offset as usize) < data.len() {
            let remaining = data.len() - offset as usize;
            let write_size = remaining.min(MAX_WRITE_SIZE);
            let chunk = &data[offset as usize..offset as usize + write_size];

            let mut cmd = TpmCommand::with_sessions(TpmCc::NvWrite);
            // authHandle
            cmd.add_handle(tpm_rh::OWNER);
            // nvIndex
            cmd.add_handle(index);
            // Authorization area
            cmd.add_null_auth_area();
            // data
            cmd.add_tpm2b(chunk);
            // offset
            cmd.add_u16(offset);

            let response = self.device.execute(&cmd.finalize())?;
            response
                .ensure_success()
                .with_context(|| format!("NV_Write failed at offset {}", offset))?;

            offset += write_size as u16;
        }

        debug!("wrote {} bytes to NV index 0x{:08x}", data.len(), index);
        Ok(true)
    }

    /// Define a new NV index
    pub fn nv_define(&mut self, index: u32, size: usize, owner_read_write: bool) -> Result<bool> {
        let mut attributes = TpmaNv::new();
        if owner_read_write {
            attributes = attributes.with_owner_write().with_owner_read();
        }

        let nv_public = TpmsNvPublic::new(index, size as u16, attributes);

        let mut cmd = TpmCommand::with_sessions(TpmCc::NvDefineSpace);
        // authHandle (owner)
        cmd.add_handle(tpm_rh::OWNER);
        // Authorization area
        cmd.add_null_auth_area();
        // auth (empty)
        cmd.add_tpm2b_empty();
        // publicInfo
        cmd.add(&Tpm2bNvPublic { nv_public });

        let response = self.device.execute(&cmd.finalize())?;

        if response.is_success() {
            debug!("defined NV index 0x{:08x} with size {}", index, size);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Undefine (delete) an NV index
    pub fn nv_undefine(&mut self, index: u32) -> Result<bool> {
        let mut cmd = TpmCommand::with_sessions(TpmCc::NvUndefineSpace);
        // authHandle (owner)
        cmd.add_handle(tpm_rh::OWNER);
        // nvIndex
        cmd.add_handle(index);
        // Authorization area
        cmd.add_null_auth_area();

        let response = self.device.execute(&cmd.finalize())?;

        if response.is_success() {
            debug!("undefined NV index 0x{:08x}", index);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ==================== PCR Operations ====================

    /// Read PCR values for the given selection
    pub fn pcr_read(&mut self, pcr_selection: &TpmlPcrSelection) -> Result<Vec<(u32, Vec<u8>)>> {
        let mut cmd = TpmCommand::new(TpmCc::PcrRead);
        cmd.add(pcr_selection);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("PCR_Read failed")?;

        let mut buf = response.data_buffer();
        let _update_counter = buf.get_u32()?;
        let pcr_selection_out = TpmlPcrSelection::unmarshal(&mut buf)?;
        let digest_list = TpmlDigest::unmarshal(&mut buf)?;

        // Map digests to PCR indices
        let mut result = Vec::new();
        let mut digest_idx = 0;

        for sel in &pcr_selection_out.pcr_selections {
            for (byte_idx, &byte) in sel.pcr_select.iter().enumerate() {
                for bit in 0..8 {
                    if byte & (1 << bit) != 0 {
                        let pcr_idx = (byte_idx * 8 + bit) as u32;
                        if digest_idx < digest_list.digests.len() {
                            result.push((pcr_idx, digest_list.digests[digest_idx].buffer.clone()));
                            digest_idx += 1;
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Read a single PCR value
    pub fn pcr_read_single(&mut self, pcr_idx: u32, hash_alg: TpmAlgId) -> Result<Vec<u8>> {
        let selection = TpmlPcrSelection::single(hash_alg, &[pcr_idx]);
        let values = self.pcr_read(&selection)?;

        values
            .into_iter()
            .find(|(idx, _)| *idx == pcr_idx)
            .map(|(_, v)| v)
            .ok_or_else(|| anyhow::anyhow!("PCR {} not found in response", pcr_idx))
    }

    /// Extend a PCR with a hash value
    pub fn pcr_extend(&mut self, pcr: u32, hash: &[u8], hash_alg: TpmAlgId) -> Result<()> {
        let digest_values = TpmlDigestValues::single(TpmtHa {
            hash_alg,
            digest: hash.to_vec(),
        });

        let mut cmd = TpmCommand::with_sessions(TpmCc::PcrExtend);
        // pcrHandle
        cmd.add_handle(pcr);
        // Authorization area
        cmd.add_null_auth_area();
        // digests
        cmd.add(&digest_values);

        let response = self.device.execute(&cmd.finalize())?;
        response
            .ensure_success()
            .with_context(|| format!("PCR_Extend failed for PCR {}", pcr))?;

        debug!("extended PCR {}", pcr);
        Ok(())
    }

    // ==================== Random Number Generation ====================

    /// Generate random bytes using the TPM's hardware RNG
    pub fn get_random(&mut self, num_bytes: usize) -> Result<Vec<u8>> {
        let mut result = Vec::with_capacity(num_bytes);

        // TPM may return fewer bytes than requested, so loop
        while result.len() < num_bytes {
            let remaining = num_bytes - result.len();
            let request_size = remaining.min(48) as u16; // TPM typically limits to 48-64 bytes

            let mut cmd = TpmCommand::new(TpmCc::GetRandom);
            cmd.add_u16(request_size);

            let response = self.device.execute(&cmd.finalize())?;
            response.ensure_success().context("GetRandom failed")?;

            let mut buf = response.data_buffer();
            let random_bytes = buf.get_tpm2b()?;
            result.extend_from_slice(&random_bytes);
        }

        result.truncate(num_bytes);
        Ok(result)
    }

    /// Generate random bytes into a fixed-size array
    pub fn get_random_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.get_random(N)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("unexpected random bytes length"))
    }

    // ==================== Primary Key Operations ====================

    /// Check if a persistent handle exists
    pub fn handle_exists(&mut self, handle: u32) -> Result<bool> {
        let mut cmd = TpmCommand::new(TpmCc::ReadPublic);
        cmd.add_handle(handle);

        let response = self.device.execute(&cmd.finalize())?;
        Ok(response.is_success())
    }

    /// Create a primary key in the specified hierarchy
    pub fn create_primary(
        &mut self,
        hierarchy: u32,
        template: &TpmtPublic,
    ) -> Result<(u32, Vec<u8>)> {
        let public = Tpm2bPublic::from_template(template);

        let mut cmd = TpmCommand::with_sessions(TpmCc::CreatePrimary);
        // primaryHandle (hierarchy)
        cmd.add_handle(hierarchy);
        // Authorization area
        cmd.add_null_auth_area();
        // inSensitive (empty)
        cmd.add(&Tpm2bSensitiveCreate::empty());
        // inPublic
        cmd.add(&public);
        // outsideInfo (empty)
        cmd.add_tpm2b_empty();
        // creationPCR (empty)
        cmd.add(&TpmlPcrSelection::default());

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("CreatePrimary failed")?;

        // For commands with sessions, the response format is:
        // - Handle (4 bytes) - BEFORE parameter size
        // - Parameter size (4 bytes)
        // - Parameters...
        let mut buf = response.data_buffer();
        let handle = buf.get_u32()?;

        // Skip parameter size
        let _param_size = buf.get_u32()?;

        let out_public = Tpm2bPublic::unmarshal(&mut buf)?;

        debug!("created primary key with handle 0x{:08x}", handle);
        Ok((handle, out_public.public_area))
    }

    /// Create a primary key from raw public template bytes (for GCP AK)
    pub fn create_primary_from_template(
        &mut self,
        hierarchy: u32,
        template_bytes: &[u8],
    ) -> Result<(u32, Vec<u8>)> {
        let mut cmd = TpmCommand::with_sessions(TpmCc::CreatePrimary);
        // primaryHandle (hierarchy)
        cmd.add_handle(hierarchy);
        // Authorization area
        cmd.add_null_auth_area();
        // inSensitive (empty)
        cmd.add(&Tpm2bSensitiveCreate::empty());
        // inPublic (raw template with size prefix)
        cmd.add_tpm2b(template_bytes);
        // outsideInfo (empty)
        cmd.add_tpm2b_empty();
        // creationPCR (empty)
        cmd.add(&TpmlPcrSelection::default());

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("CreatePrimary failed")?;

        // For commands with sessions, the response format is:
        // - Handle (4 bytes) - BEFORE parameter size
        // - Parameter size (4 bytes)
        // - Parameters...
        let mut buf = response.data_buffer();
        let handle = buf.get_u32()?;

        // Skip parameter size
        let _param_size = buf.get_u32()?;

        let out_public = Tpm2bPublic::unmarshal(&mut buf)?;

        debug!("created primary key with handle 0x{:08x}", handle);
        Ok((handle, out_public.public_area))
    }

    /// Make a key persistent at a given handle
    pub fn evict_control(&mut self, object_handle: u32, persistent_handle: u32) -> Result<bool> {
        let mut cmd = TpmCommand::with_sessions(TpmCc::EvictControl);
        // auth (owner)
        cmd.add_handle(tpm_rh::OWNER);
        // objectHandle
        cmd.add_handle(object_handle);
        // Authorization area
        cmd.add_null_auth_area();
        // persistentHandle
        cmd.add_handle(persistent_handle);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("EvictControl failed")?;

        debug!("made key persistent at 0x{:08x}", persistent_handle);
        Ok(true)
    }

    /// Ensure a persistent primary key exists at the given handle
    pub fn ensure_primary_key(&mut self, handle: u32) -> Result<bool> {
        if self.handle_exists(handle)? {
            return Ok(true);
        }

        debug!("creating TPM primary key at 0x{:08x}...", handle);
        let template = TpmtPublic::rsa_storage_key();
        let (transient, _) = self.create_primary(tpm_rh::OWNER, &template)?;
        self.evict_control(transient, handle)?;

        // Flush the transient handle
        self.flush_context(transient)?;

        Ok(true)
    }

    /// Flush a context (handle)
    pub fn flush_context(&mut self, handle: u32) -> Result<()> {
        let mut cmd = TpmCommand::new(TpmCc::FlushContext);
        cmd.add_handle(handle);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("FlushContext failed")?;

        Ok(())
    }

    // ==================== Seal/Unseal Operations ====================

    /// Seal data to TPM with PCR policy
    pub fn seal(
        &mut self,
        data: &[u8],
        parent_handle: u32,
        pcr_selection: &TpmlPcrSelection,
        hash_alg: TpmAlgId,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        // Compute policy digest if PCR selection is not empty
        let policy_digest = if pcr_selection.pcr_selections.is_empty() {
            // No PCR policy - use empty authPolicy (zero length, not zero-filled)
            vec![]
        } else {
            // First, compute the policy digest using a trial session
            let trial_session = AuthSession::start_trial(&mut self.device, hash_alg)?;

            // Compute PCR digest
            let pcr_digest = compute_pcr_digest(&mut self.device, pcr_selection, hash_alg)?;

            // Apply PCR policy to trial session
            trial_session.policy_pcr(&mut self.device, &pcr_digest, pcr_selection)?;

            // Get the policy digest
            let digest = trial_session.get_digest(&mut self.device)?;

            // Flush trial session
            trial_session.flush(&mut self.device)?;

            digest
        };

        // Create sealed object template
        let template = TpmtPublic::sealed_object(Tpm2bDigest::new(policy_digest));
        let public = Tpm2bPublic::from_template(&template);

        // Create the sealed object
        let mut cmd = TpmCommand::with_sessions(TpmCc::Create);
        // parentHandle
        cmd.add_handle(parent_handle);
        // Authorization area
        cmd.add_null_auth_area();
        // inSensitive (contains the data to seal)
        cmd.add(&Tpm2bSensitiveCreate::with_data(data.to_vec()));
        // inPublic
        cmd.add(&public);
        // outsideInfo (empty)
        cmd.add_tpm2b_empty();
        // creationPCR (empty)
        cmd.add(&TpmlPcrSelection::default());

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("Create (seal) failed")?;

        let mut buf = response.skip_parameter_size()?;
        let out_private = Tpm2bPrivate::unmarshal(&mut buf)?;
        let out_public = Tpm2bPublic::unmarshal(&mut buf)?;

        debug!("sealed {} bytes to TPM with PCR policy", data.len());

        Ok((out_public.public_area, out_private.buffer))
    }

    /// Unseal data from TPM with PCR policy
    pub fn unseal(
        &mut self,
        pub_bytes: &[u8],
        priv_bytes: &[u8],
        parent_handle: u32,
        pcr_selection: &TpmlPcrSelection,
        hash_alg: TpmAlgId,
    ) -> Result<Vec<u8>> {
        // Load the sealed object
        let mut cmd = TpmCommand::with_sessions(TpmCc::Load);
        // parentHandle
        cmd.add_handle(parent_handle);
        // Authorization area
        cmd.add_null_auth_area();
        // inPrivate
        cmd.add_tpm2b(priv_bytes);
        // inPublic
        cmd.add_tpm2b(pub_bytes);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("Load failed")?;

        // For commands with sessions, handle comes BEFORE parameter size
        let mut buf = response.data_buffer();
        let object_handle = buf.get_u32()?;
        let _param_size = buf.get_u32()?; // Skip parameter size

        debug!("loaded sealed object with handle 0x{:08x}", object_handle);

        // Unseal - use policy session if PCR selection is not empty
        let response = if pcr_selection.pcr_selections.is_empty() {
            // No PCR policy - use null auth
            let mut cmd = TpmCommand::with_sessions(TpmCc::Unseal);
            cmd.add_handle(object_handle);
            cmd.add_null_auth_area();
            self.device.execute(&cmd.finalize())?
        } else {
            // Start a policy session
            let policy_session = AuthSession::start_policy(&mut self.device, hash_alg)?;

            // Compute and apply PCR policy
            let pcr_digest = compute_pcr_digest(&mut self.device, pcr_selection, hash_alg)?;
            policy_session.policy_pcr(&mut self.device, &pcr_digest, pcr_selection)?;

            // Unseal with policy session
            let mut cmd = TpmCommand::with_sessions(TpmCc::Unseal);
            cmd.add_handle(object_handle);
            cmd.add_policy_auth(policy_session.handle);

            let response = self.device.execute(&cmd.finalize())?;
            let _ = policy_session.flush(&mut self.device);
            response
        };

        // Clean up object handle
        let _ = self.flush_context(object_handle);

        if !response.is_success() {
            anyhow::bail!(
                "Unseal failed with TPM error: 0x{:08x}",
                response.response_code
            );
        }

        let mut buf = response.skip_parameter_size()?;
        let data = buf.get_tpm2b()?;

        debug!("unsealed {} bytes from TPM", data.len());
        Ok(data)
    }

    // ==================== Quote Operations ====================

    /// Generate a TPM quote
    pub fn quote(
        &mut self,
        sign_handle: u32,
        qualifying_data: &[u8],
        pcr_selection: &TpmlPcrSelection,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut cmd = TpmCommand::with_sessions(TpmCc::Quote);
        // signHandle
        cmd.add_handle(sign_handle);
        // Authorization area
        cmd.add_null_auth_area();
        // qualifyingData
        cmd.add_tpm2b(qualifying_data);
        // inScheme (NULL - use key's default scheme)
        cmd.add(&TpmtSigScheme::null());
        // PCRselect
        cmd.add(pcr_selection);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("Quote failed")?;

        let mut buf = response.skip_parameter_size()?;
        let quoted = buf.get_tpm2b()?; // TPM2B_ATTEST
        let signature = buf.get_remaining(); // TPMT_SIGNATURE

        debug!("generated TPM quote");
        Ok((quoted, signature))
    }

    /// Read public area of a key
    pub fn read_public(&mut self, handle: u32) -> Result<Vec<u8>> {
        let mut cmd = TpmCommand::new(TpmCc::ReadPublic);
        cmd.add_handle(handle);

        let response = self.device.execute(&cmd.finalize())?;
        response.ensure_success().context("ReadPublic failed")?;

        let mut buf = response.data_buffer();
        let out_public = Tpm2bPublic::unmarshal(&mut buf)?;

        Ok(out_public.public_area)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_selection() {
        let sel = TpmsPcrSelection::sha256(&[0, 1, 2, 7]);
        assert_eq!(sel.hash, TpmAlgId::Sha256);
        // PCR 0, 1, 2, 7 = bits 0, 1, 2, 7 = 0b10000111 = 0x87
        assert_eq!(sel.pcr_select[0], 0x87);
    }
}
