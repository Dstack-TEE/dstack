// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! AWS Nitro Enclave NSM (Nitro Security Module) Attestation Library
//!
//! This crate wraps the official `aws-nitro-enclaves-nsm-api` crate and provides
//! additional utilities for attestation document parsing.
//!
//! The NSM device is available at `/dev/nsm` inside a Nitro Enclave and
//! provides attestation, PCR operations, and entropy generation.

use anyhow::{bail, Result};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver;
use std::path::Path;

mod types;

pub use types::*;

/// NSM device path
pub const NSM_DEVICE_PATH: &str = "/dev/nsm";

/// Check if running inside a Nitro Enclave
pub fn is_nitro_enclave() -> bool {
    Path::new(NSM_DEVICE_PATH).exists()
}

/// NSM Context for interacting with the Nitro Security Module
#[derive(Debug)]
pub struct NsmContext {
    fd: i32,
}

impl NsmContext {
    /// Open the NSM device
    pub fn new() -> Result<Self> {
        let fd = driver::nsm_init();
        if fd < 0 {
            bail!("Failed to open NSM device");
        }
        Ok(Self { fd })
    }

    /// Get attestation document from NSM
    ///
    /// # Arguments
    /// * `user_data` - Optional user data to include in attestation (max 512 bytes)
    /// * `nonce` - Optional nonce for freshness (max 512 bytes)
    /// * `public_key` - Optional public key to include (max 1024 bytes)
    pub fn get_attestation_doc(
        &self,
        user_data: Option<&[u8]>,
        nonce: Option<&[u8]>,
        public_key: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        let request = Request::Attestation {
            user_data: user_data.map(|d| d.to_vec().into()),
            nonce: nonce.map(|d| d.to_vec().into()),
            public_key: public_key.map(|d| d.to_vec().into()),
        };

        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::Attestation { document } => Ok(document),
            Response::Error(err) => bail!("NSM attestation failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }

    /// Describe the NSM module
    pub fn describe(&self) -> Result<NsmDescription> {
        let request = Request::DescribeNSM;
        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::DescribeNSM {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs,
                digest,
            } => Ok(NsmDescription {
                version_major,
                version_minor,
                version_patch,
                module_id,
                max_pcrs,
                locked_pcrs: locked_pcrs.into_iter().collect(),
                digest: format!("{:?}", digest),
            }),
            Response::Error(err) => bail!("NSM describe failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }

    /// Get random bytes from NSM
    pub fn get_random(&self) -> Result<Vec<u8>> {
        let request = Request::GetRandom;
        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::GetRandom { random } => Ok(random),
            Response::Error(err) => bail!("NSM get_random failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }

    /// Extend a PCR with data
    ///
    /// # Arguments
    /// * `index` - PCR index (0-15 for user PCRs)
    /// * `data` - Data to extend into PCR (will be hashed)
    pub fn pcr_extend(&self, index: u16, data: &[u8]) -> Result<Vec<u8>> {
        let request = Request::ExtendPCR {
            index,
            data: data.to_vec(),
        };
        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::ExtendPCR { data } => Ok(data),
            Response::Error(err) => bail!("NSM PCR extend failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }

    /// Lock a PCR (prevent further extensions)
    pub fn pcr_lock(&self, index: u16) -> Result<()> {
        let request = Request::LockPCR { index };
        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::LockPCR => Ok(()),
            Response::Error(err) => bail!("NSM PCR lock failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }

    /// Lock multiple PCRs
    pub fn pcr_lock_range(&self, range: u16) -> Result<()> {
        let request = Request::LockPCRs { range };
        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::LockPCRs => Ok(()),
            Response::Error(err) => bail!("NSM PCR lock range failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }

    /// Describe a specific PCR
    pub fn describe_pcr(&self, index: u16) -> Result<PcrInfo> {
        let request = Request::DescribePCR { index };
        let response = driver::nsm_process_request(self.fd, request);

        match response {
            Response::DescribePCR { lock, data } => Ok(PcrInfo { lock, data }),
            Response::Error(err) => bail!("NSM describe PCR failed: {:?}", err),
            _ => bail!("Unexpected NSM response"),
        }
    }
}

impl Drop for NsmContext {
    fn drop(&mut self) {
        driver::nsm_exit(self.fd);
    }
}

/// PCR information
#[derive(Debug, Clone)]
pub struct PcrInfo {
    /// Whether the PCR is locked
    pub lock: bool,
    /// Current PCR value
    pub data: Vec<u8>,
}

/// Create an attestation document with report data
///
/// This is a convenience function that creates an attestation document
/// with the given report data as user_data.
pub fn get_attestation(report_data: &[u8]) -> Result<Vec<u8>> {
    let ctx = NsmContext::new()?;
    ctx.get_attestation_doc(Some(report_data), None, None)
}

/// Get random bytes from NSM
pub fn get_random() -> Result<Vec<u8>> {
    let ctx = NsmContext::new()?;
    ctx.get_random()
}
