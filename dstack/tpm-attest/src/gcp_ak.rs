// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! GCP vTPM pre-provisioned AK loading
//!
//! This module provides native Rust implementation for loading GCP's
//! pre-provisioned Attestation Key without C library dependencies.

use std::str::FromStr;

use anyhow::{Context as _, Result};
use tracing::debug;

use crate::{PcrSelection, PcrValue, TpmEventLog, TpmQuote};
use tpm2::{tpm_rh, TpmAlgId, TpmContext, TpmlPcrSelection};

/// GCP vTPM NV indices for pre-provisioned AK
pub mod gcp_nv_index {
    /// RSA AK certificate (DER format)
    pub const AK_RSA_CERT: u32 = 0x01C10000;
    /// RSA AK template (TPM2B_PUBLIC format)
    pub const AK_RSA_TEMPLATE: u32 = 0x01C10001;
    /// ECC AK certificate (DER format)
    pub const AK_ECC_CERT: u32 = 0x01C10002;
    /// ECC AK template (TPM2B_PUBLIC format)
    pub const AK_ECC_TEMPLATE: u32 = 0x01C10003;
}

/// Loaded AK information
pub struct LoadedAk {
    pub context: TpmContext,
    pub handle: u32,
    pub cert_nv_index: u32,
    /// Marshaled TPMT_PUBLIC public area of the AK.
    ///
    /// Derived deterministically from the per-instance Endorsement seed, so it is
    /// stable across reboot/stop-start but fresh on a disk clone. Unlike the AK
    /// certificate it carries no serial/validity/signature, so it is immune to
    /// certificate re-issuance.
    pub pub_area: Vec<u8>,
}

/// Load GCP pre-provisioned ECC AK
///
/// This function:
/// 1. Reads the AK template from NV index 0x01C10003
/// 2. Creates a primary key under Endorsement hierarchy with the template
/// 3. TPM deterministically recreates the same key pair (same template + same parent)
pub fn load_gcp_ak_ecc(tcti_path: Option<&str>) -> Result<LoadedAk> {
    debug!("loading GCP pre-provisioned ECC AK...");

    let mut context = TpmContext::new(tcti_path)?;

    let template_bytes = context
        .nv_read(gcp_nv_index::AK_ECC_TEMPLATE)?
        .ok_or_else(|| anyhow::anyhow!("ECC AK template not found at NV 0x01C10003"))?;

    debug!(
        "read ECC AK template from NV: {} bytes",
        template_bytes.len()
    );

    // Create primary key under Endorsement hierarchy
    let (handle, pub_area) =
        context.create_primary_from_template(tpm_rh::ENDORSEMENT, &template_bytes)?;

    debug!(
        "✓ successfully loaded GCP pre-provisioned ECC AK (handle: 0x{:08x})",
        handle
    );

    Ok(LoadedAk {
        context,
        handle,
        cert_nv_index: gcp_nv_index::AK_ECC_CERT,
        pub_area,
    })
}

/// Load GCP pre-provisioned RSA AK
///
/// This function:
/// 1. Reads the AK template from NV index 0x01C10001
/// 2. Creates a primary key under Endorsement hierarchy with the template
/// 3. TPM deterministically recreates the same key pair (same template + same parent)
pub fn load_gcp_ak_rsa(tcti_path: Option<&str>) -> Result<LoadedAk> {
    debug!("loading GCP pre-provisioned RSA AK...");

    let mut context = TpmContext::new(tcti_path)?;

    let template_bytes = context
        .nv_read(gcp_nv_index::AK_RSA_TEMPLATE)?
        .ok_or_else(|| anyhow::anyhow!("RSA AK template not found at NV 0x01C10001"))?;

    debug!(
        "read RSA AK template from NV: {} bytes",
        template_bytes.len()
    );

    // Create primary key under Endorsement hierarchy
    let (handle, pub_area) =
        context.create_primary_from_template(tpm_rh::ENDORSEMENT, &template_bytes)?;

    debug!(
        "✓ successfully loaded GCP pre-provisioned RSA AK (handle: 0x{:08x})",
        handle
    );

    Ok(LoadedAk {
        context,
        handle,
        cert_nv_index: gcp_nv_index::AK_RSA_CERT,
        pub_area,
    })
}

/// Key algorithm preference for quote generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// Prefer ECC, fallback to RSA
    Auto,
    /// Use ECC only (fails if not available)
    Ecc,
    /// Use RSA only (fails if not available)
    Rsa,
}

impl FromStr for KeyAlgorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "auto" => Ok(KeyAlgorithm::Auto),
            "ecc" | "ecdsa" => Ok(KeyAlgorithm::Ecc),
            "rsa" | "rsassa" => Ok(KeyAlgorithm::Rsa),
            _ => anyhow::bail!("invalid key algorithm: {s}. Use 'auto', 'ecc', or 'rsa'"),
        }
    }
}

/// Generate a TPM quote using GCP pre-provisioned AK (prefers ECC)
pub fn create_quote_with_gcp_ak(
    tcti_path: Option<&str>,
    qualifying_data: &[u8; 32],
    pcr_selection: &PcrSelection,
) -> Result<TpmQuote> {
    create_quote_with_gcp_ak_algo(
        tcti_path,
        qualifying_data,
        pcr_selection,
        KeyAlgorithm::Auto,
    )
}

/// Generate a TPM quote using GCP pre-provisioned AK with manual algorithm selection
pub fn create_quote_with_gcp_ak_algo(
    tcti_path: Option<&str>,
    qualifying_data: &[u8; 32],
    pcr_selection: &PcrSelection,
    key_algo: KeyAlgorithm,
) -> Result<TpmQuote> {
    let platform = dstack_types::Platform::detect().context("unsupported platform")?;
    if platform != dstack_types::Platform::Gcp {
        anyhow::bail!("GCP pre-provisioned AK quote is only supported on GCP");
    }

    debug!("generating TPM quote with GCP pre-provisioned AK...");

    let mut loaded_ak = load_ak_for_algo(tcti_path, key_algo)?;
    let hash_alg = hash_alg_for_bank(&pcr_selection.bank)?;
    let tpm_pcr_selection = TpmlPcrSelection::single(hash_alg, &pcr_selection.pcrs);

    debug!("calling TPM Quote command...");
    let (message, signature) =
        loaded_ak
            .context
            .quote(loaded_ak.handle, qualifying_data, &tpm_pcr_selection)?;
    debug!("✓ quote generated successfully");

    let pcr_values = read_pcr_values(
        &mut loaded_ak.context,
        &tpm_pcr_selection,
        &pcr_selection.bank,
    )?;
    let ak_cert = read_ak_cert_from_nv(&mut loaded_ak)?;

    let _ = loaded_ak.context.flush_context(loaded_ak.handle);

    let event_log = TpmEventLog::from_kernel_file()
        .context("failed to read TPM event log")?
        .events;

    Ok(TpmQuote {
        message,
        signature,
        pcr_values,
        ak_cert,
        platform,
        event_log,
    })
}

/// Load the GCP pre-provisioned AK matching the requested algorithm preference.
fn load_ak_for_algo(tcti_path: Option<&str>, key_algo: KeyAlgorithm) -> Result<LoadedAk> {
    match key_algo {
        // ECC is preferred for performance; RSA is the fallback when the instance
        // only provisioned an RSA AK.
        KeyAlgorithm::Auto => match load_gcp_ak_ecc(tcti_path) {
            Ok(ak) => {
                debug!("✓ using ECC AK for quote");
                Ok(ak)
            }
            Err(e) => {
                debug!("ECC AK not available, falling back to RSA: {e}");
                let ak = load_gcp_ak_rsa(tcti_path)?;
                debug!("✓ using RSA AK for quote");
                Ok(ak)
            }
        },
        KeyAlgorithm::Ecc => {
            let ak = load_gcp_ak_ecc(tcti_path).context(
                "failed to load ECC AK (use --key-algo=rsa or --key-algo=auto for fallback)",
            )?;
            debug!("✓ using ECC AK for quote");
            Ok(ak)
        }
        KeyAlgorithm::Rsa => {
            let ak = load_gcp_ak_rsa(tcti_path).context("failed to load RSA AK")?;
            debug!("✓ using RSA AK for quote");
            Ok(ak)
        }
    }
}

/// Map a PCR bank name to its TPM hash algorithm id.
fn hash_alg_for_bank(bank: &str) -> Result<TpmAlgId> {
    match bank {
        "sha256" => Ok(TpmAlgId::Sha256),
        "sha384" => Ok(TpmAlgId::Sha384),
        "sha512" => Ok(TpmAlgId::Sha512),
        _ => anyhow::bail!("unsupported hash algorithm: {bank}"),
    }
}

/// Read the selected PCR values and tag each with the bank name.
fn read_pcr_values(
    context: &mut TpmContext,
    tpm_pcr_selection: &TpmlPcrSelection,
    bank: &str,
) -> Result<Vec<PcrValue>> {
    let pcr_values_raw = context.pcr_read(tpm_pcr_selection)?;
    Ok(pcr_values_raw
        .into_iter()
        .map(|(index, value)| PcrValue {
            index,
            algorithm: bank.to_string(),
            value,
        })
        .collect())
}

/// Read the AK certificate (DER) from the NV index it was provisioned at.
fn read_ak_cert_from_nv(loaded_ak: &mut LoadedAk) -> Result<Vec<u8>> {
    let ak_cert = loaded_ak
        .context
        .nv_read(loaded_ak.cert_nv_index)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "AK certificate not found at NV 0x{:08x}",
                loaded_ak.cert_nv_index
            )
        })?;
    debug!(
        "✓ AK certificate read from NV 0x{:08x}: {} bytes",
        loaded_ak.cert_nv_index,
        ak_cert.len()
    );
    Ok(ak_cert)
}
