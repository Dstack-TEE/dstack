// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::{PcrSelection, PcrValue};
use anyhow::{bail, Result};
use tpm2::{TpmAlgId, TpmContext as RawTpmContext, TpmlPcrSelection, TpmsNvPublic};

pub struct EsapiContext {
    context: RawTpmContext,
}

impl EsapiContext {
    /// Create a new ESAPI context with the given TCTI path
    pub fn new(tcti_path: Option<&str>) -> Result<Self> {
        let context = RawTpmContext::new(tcti_path)?;
        Ok(Self { context })
    }

    // ==================== NV Operations ====================

    /// Check if an NV index exists
    pub fn nv_exists(&mut self, index: u32) -> Result<bool> {
        self.context.nv_exists(index)
    }

    /// Read NV public area (to determine the defined size, attributes, etc.)
    pub fn nv_read_public(&mut self, index: u32) -> Result<TpmsNvPublic> {
        self.context.nv_read_public(index)
    }

    /// Read data from an NV index
    pub fn nv_read(&mut self, index: u32) -> Result<Option<Vec<u8>>> {
        self.context.nv_read(index)
    }

    /// Write data to an NV index
    pub fn nv_write(&mut self, index: u32, data: &[u8]) -> Result<bool> {
        self.context.nv_write(index, data)
    }

    /// Define a new NV index
    pub fn nv_define(&mut self, index: u32, size: usize, owner_read_write: bool) -> Result<bool> {
        self.context.nv_define(index, size, owner_read_write)
    }

    /// Undefine (delete) an NV index
    pub fn nv_undefine(&mut self, index: u32) -> Result<bool> {
        self.context.nv_undefine(index)
    }

    // ==================== PCR Operations ====================

    /// Read PCR values for the given selection
    pub fn pcr_read(&mut self, pcr_selection: &PcrSelection) -> Result<Vec<PcrValue>> {
        let hash_alg = Self::parse_hash_alg(&pcr_selection.bank)?;
        let tpm_selection = TpmlPcrSelection::single(hash_alg, &pcr_selection.pcrs);

        let values = self.context.pcr_read(&tpm_selection)?;

        Ok(values
            .into_iter()
            .map(|(index, value)| PcrValue {
                index,
                algorithm: pcr_selection.bank.clone(),
                value,
            })
            .collect())
    }

    /// Extend a PCR with a hash value
    pub fn pcr_extend(&mut self, pcr: u32, hash: &[u8], bank: &str) -> Result<()> {
        let hash_alg = Self::parse_hash_alg(bank)?;
        self.context.pcr_extend(pcr, hash, hash_alg)
    }

    // ==================== Random Number Generation ====================

    /// Generate random bytes using the TPM's hardware RNG
    pub fn get_random<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.context.get_random_array::<N>()
    }

    // ==================== Primary Key Operations ====================

    /// Check if a persistent handle exists
    pub fn handle_exists(&mut self, handle: u32) -> Result<bool> {
        self.context.handle_exists(handle)
    }

    /// Ensure a persistent primary key exists at the given handle
    pub fn ensure_primary_key(&mut self, handle: u32) -> Result<bool> {
        self.context.ensure_primary_key(handle)
    }

    // ==================== Seal/Unseal Operations ====================

    /// Seal data to TPM with PCR policy
    pub fn seal(
        &mut self,
        data: &[u8],
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let hash_alg = Self::parse_hash_alg(&pcr_selection.bank)?;
        let tpm_selection = TpmlPcrSelection::single(hash_alg, &pcr_selection.pcrs);

        self.context
            .seal(data, parent_handle, &tpm_selection, hash_alg)
    }

    /// Unseal data from TPM with PCR policy
    pub fn unseal(
        &mut self,
        pub_bytes: &[u8],
        priv_bytes: &[u8],
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Vec<u8>> {
        let hash_alg = Self::parse_hash_alg(&pcr_selection.bank)?;
        let tpm_selection = TpmlPcrSelection::single(hash_alg, &pcr_selection.pcrs);

        self.context.unseal(
            pub_bytes,
            priv_bytes,
            parent_handle,
            &tpm_selection,
            hash_alg,
        )
    }

    // ==================== Helper Functions ====================

    fn parse_hash_alg(bank: &str) -> Result<TpmAlgId> {
        match bank {
            "sha256" => Ok(TpmAlgId::Sha256),
            "sha384" => Ok(TpmAlgId::Sha384),
            "sha512" => Ok(TpmAlgId::Sha512),
            "sha1" => Ok(TpmAlgId::Sha1),
            _ => bail!("unsupported hash algorithm: {}", bank),
        }
    }
}
