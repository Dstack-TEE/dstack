// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! TPM 2.0 Attestation Library
//!
//! This module provides functionality for generating TPM attestation quotes
//! on the device side. It handles PCR operations, sealing, unsealing, NV storage,
//! and quote generation.
//!
//! This follows the same architecture as tdx-attest: device-side attestation only.
//! For quote verification, see the tpm-qvl crate.

use anyhow::{bail, Context, Result};
use scale::{Decode, Encode};
use std::path::Path;
use tracing::{debug, warn};

// Re-export tpm-types
pub use tpm_types::{PcrSelection, PcrValue, TpmEvent, TpmEventLog, TpmQuote};

mod esapi;
use esapi::EsapiContext;

pub const PRIMARY_KEY_HANDLE: u32 = 0x81000100;
pub const SEALED_NV_INDEX: u32 = 0x01801101;

/// PCR selection for DStack
/// 0: The firmware version and NonHostInfo (representing the memory encryption technology)
/// 2: The uki image (kernel + initrd + initramfs)
/// 14: The app compose hash
const APP_PCR: u32 = 14;
pub fn dstack_pcr_policy() -> PcrSelection {
    PcrSelection::sha256(&[0, 2, APP_PCR])
}

pub struct TpmContext {
    tcti: String,
}

impl std::fmt::Debug for TpmContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TpmContext")
            .field("tcti", &self.tcti)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct SealedBlob {
    pub data: Vec<u8>,
}

impl SealedBlob {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    pub fn from_parts(pub_data: &[u8], priv_data: &[u8]) -> Self {
        let data = (pub_data, priv_data).encode();
        Self { data }
    }

    pub fn split(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        if self.data.len() < 4 {
            bail!("sealed blob too small");
        }
        let (pub_data, priv_data) = Decode::decode(&mut &self.data[..])?;
        Ok((pub_data, priv_data))
    }
}

impl TpmContext {
    pub fn open(tcti: Option<&str>) -> Result<Self> {
        match tcti {
            Some(t) => Self::new(t),
            None => Self::detect(),
        }
    }

    pub fn detect() -> Result<Self> {
        let tcti = if Path::new("/dev/tpmrm0").exists() {
            "/dev/tpmrm0"
        } else if Path::new("/dev/tpm0").exists() {
            "/dev/tpm0"
        } else {
            bail!("TPM device not found");
        };
        Self::new(tcti)
    }

    pub fn new(tcti: &str) -> Result<Self> {
        Ok(Self {
            tcti: tcti.to_string(),
        })
    }

    fn create_esapi_context(&self) -> Result<EsapiContext> {
        EsapiContext::new(Some(&self.tcti))
    }

    pub fn nv_exists(&self, index: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_exists(index)
    }

    pub fn nv_define(&self, index: u32, size: usize, _attributes: &str) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_define(index, size, true)
    }

    pub fn nv_undefine(&self, index: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_undefine(index)
    }

    pub fn nv_read(&self, index: u32) -> Result<Option<Vec<u8>>> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_read(index)
    }

    pub fn nv_write(&self, index: u32, data: &[u8]) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.nv_write(index, data)
    }

    pub fn handle_exists(&self, handle: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.handle_exists(handle)
    }

    pub fn ensure_primary_key(&self, handle: u32) -> Result<bool> {
        let mut ctx = self.create_esapi_context()?;
        ctx.ensure_primary_key(handle)
    }

    pub fn pcr_extend(&self, pcr: u32, hash: &[u8], bank: &str) -> Result<()> {
        let mut ctx = self.create_esapi_context()?;
        ctx.pcr_extend(pcr, hash, bank)
    }

    pub fn pcr_extend_sha256(&self, pcr: u32, hash: &[u8; 32]) -> Result<()> {
        self.pcr_extend(pcr, hash, "sha256")
    }

    pub fn dump_pcr_values(&self, selection: &PcrSelection) {
        match self
            .create_esapi_context()
            .and_then(|mut ctx| ctx.pcr_read(selection))
        {
            Ok(values) => {
                debug!("PCR values ({}):", selection.to_arg());
                for pv in values {
                    debug!("  PCR[{}] = {}", pv.index, hex::encode(&pv.value));
                }
            }
            Err(e) => {
                warn!("failed to read PCR values: {e}");
            }
        }
    }

    pub fn get_random<const N: usize>(&self) -> Result<[u8; N]> {
        let mut ctx = self.create_esapi_context()?;
        ctx.get_random::<N>()
    }

    pub fn seal(
        &self,
        data: &[u8],
        nv_index: u32,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<()> {
        let mut ctx = self.create_esapi_context()?;

        ctx.ensure_primary_key(parent_handle)?;

        let (pub_bytes, priv_bytes) = ctx.seal(data, parent_handle, pcr_selection)?;

        let sealed_blob = SealedBlob::from_parts(&pub_bytes, &priv_bytes);

        let needed_size = sealed_blob.data.len();
        if ctx.nv_exists(nv_index)? {
            let nv_public = ctx.nv_read_public(nv_index)?;
            if (nv_public.data_size as usize) < needed_size {
                ctx.nv_undefine(nv_index)?;
                ctx.nv_define(nv_index, needed_size, true)?;
            }
        } else {
            ctx.nv_define(nv_index, needed_size, true)?;
        }

        ctx.nv_write(nv_index, &sealed_blob.data)?;

        debug!("sealed data to NV index 0x{nv_index:08x}");
        Ok(())
    }

    pub fn unseal_to_vec(
        &self,
        nv_index: u32,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Option<Vec<u8>>> {
        let mut ctx = self.create_esapi_context()?;

        let sealed_data = match ctx.nv_read(nv_index)? {
            Some(data) => data,
            None => return Ok(None),
        };

        let sealed_blob = SealedBlob::new(sealed_data);
        let (pub_bytes, priv_bytes) = match sealed_blob.split() {
            Ok(v) => v,
            Err(e) => {
                warn!("sealed blob in NV index 0x{nv_index:08x} is invalid ({e}); regenerating");
                let _ = ctx.nv_undefine(nv_index);
                return Ok(None);
            }
        };

        let data = ctx.unseal(&pub_bytes, &priv_bytes, parent_handle, pcr_selection)?;

        debug!("unsealed data from NV index 0x{nv_index:08x}");
        Ok(Some(data))
    }

    pub fn unseal<const N: usize>(
        &self,
        nv_index: u32,
        parent_handle: u32,
        pcr_selection: &PcrSelection,
    ) -> Result<Option<[u8; N]>> {
        match self.unseal_to_vec(nv_index, parent_handle, pcr_selection)? {
            Some(data) => {
                let array: [u8; N] = data
                    .try_into()
                    .ok()
                    .context("unsealed data size mismatch")?;
                Ok(Some(array))
            }
            None => Ok(None),
        }
    }

    pub fn create_quote(
        &self,
        qualifying_data: &[u8; 32],
        pcr_selection: &PcrSelection,
    ) -> Result<TpmQuote> {
        gcp_ak::create_quote_with_gcp_ak(Some(&self.tcti), qualifying_data, pcr_selection)
    }

    pub fn create_quote_with_algo(
        &self,
        qualifying_data: &[u8; 32],
        pcr_selection: &PcrSelection,
        key_algo: KeyAlgorithm,
    ) -> Result<TpmQuote> {
        gcp_ak::create_quote_with_gcp_ak_algo(
            Some(&self.tcti),
            qualifying_data,
            pcr_selection,
            key_algo,
        )
    }

    pub fn read_ak_cert(&self) -> Result<Option<Vec<u8>>> {
        const AK_RSA_CERT_NV_INDEX: u32 = 0x01C10000;
        const AK_ECC_CERT_NV_INDEX: u32 = 0x01C10002;

        let mut ctx = self.create_esapi_context()?;

        if let Some(cert) = ctx.nv_read(AK_RSA_CERT_NV_INDEX)? {
            debug!(
                "read AK certificate from NV index 0x{AK_RSA_CERT_NV_INDEX:08x} ({} bytes)",
                cert.len()
            );
            return Ok(Some(cert));
        }

        if let Some(cert) = ctx.nv_read(AK_ECC_CERT_NV_INDEX)? {
            debug!(
                "read AK certificate from NV index 0x{AK_ECC_CERT_NV_INDEX:08x} ({} bytes)",
                cert.len()
            );
            return Ok(Some(cert));
        }

        warn!("AK certificate not found in TPM NV storage (expected on GCP vTPM)");
        Ok(None)
    }

    pub fn read_event_log(&self, pcr_index: u32) -> Result<Vec<TpmEvent>> {
        let event_log =
            TpmEventLog::from_kernel_file().context("Failed to read TPM Event Log from kernel")?;

        Ok(event_log.filter_by_pcr(pcr_index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcr_selection_to_string() {
        let sel = PcrSelection::sha256(&[0, 1, 2, 7]);
        assert_eq!(sel.to_arg(), "sha256:0,1,2,7");
    }

    #[test]
    fn test_sealed_blob_split() {
        let pub_data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let priv_data = vec![0xAA, 0xBB, 0xCC];

        let blob = SealedBlob::from_parts(&pub_data, &priv_data);
        let (pub_part, priv_part) = blob.split().unwrap();

        assert_eq!(pub_part, pub_data);
        assert_eq!(priv_part, priv_data);
    }

    #[test]
    fn test_default_pcr_policy() {
        let policy = dstack_pcr_policy();
        assert_eq!(policy.to_arg(), "sha256:0,2,14");
    }
}

mod gcp_ak;
pub use gcp_ak::{
    create_quote_with_gcp_ak, create_quote_with_gcp_ak_algo, gcp_nv_index, load_gcp_ak_ecc,
    load_gcp_ak_rsa, KeyAlgorithm,
};
