// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{Context, Result};
use dstack_attest::emit_runtime_event;
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use fs_err as fs;
use ra_rpc::Attestation;
use ra_tls::attestation::{VersionedAttestation, TDX_QUOTE_REPORT_DATA_RANGE};

pub trait PlatformBackend: Send + Sync {
    fn attestation_for_info(&self) -> Result<Option<Attestation>>;
    fn attestation_override(&self) -> Result<Option<VersionedAttestation>>;
    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse>;
    fn attest_response(&self, report_data: [u8; 64]) -> Result<AttestResponse>;
    fn emit_event(&self, event: &str, payload: &[u8]) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct RealPlatform;

impl PlatformBackend for RealPlatform {
    fn attestation_for_info(&self) -> Result<Option<Attestation>> {
        Ok(Attestation::local().ok())
    }

    fn attestation_override(&self) -> Result<Option<VersionedAttestation>> {
        Ok(None)
    }

    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse> {
        let attestation = Attestation::quote(&report_data).context("Failed to get quote")?;
        let tdx_quote = attestation.get_tdx_quote_bytes();
        let tdx_event_log = attestation.get_tdx_event_log_string();
        Ok(GetQuoteResponse {
            quote: tdx_quote.unwrap_or_default(),
            event_log: tdx_event_log.unwrap_or_default(),
            report_data: report_data.to_vec(),
            vm_config: vm_config.to_string(),
        })
    }

    fn attest_response(&self, report_data: [u8; 64]) -> Result<AttestResponse> {
        let attestation = Attestation::quote(&report_data).context("Failed to get attestation")?;
        Ok(AttestResponse {
            attestation: attestation.into_versioned().to_scale(),
        })
    }

    fn emit_event(&self, event: &str, payload: &[u8]) -> Result<()> {
        emit_runtime_event(event, payload)
    }
}

pub fn load_versioned_attestation(path: impl AsRef<Path>) -> Result<VersionedAttestation> {
    let path = path.as_ref();
    let attestation_bytes = fs::read(path).with_context(|| {
        format!(
            "Failed to read simulator attestation file: {}",
            path.display()
        )
    })?;
    VersionedAttestation::from_scale(&attestation_bytes)
        .context("Failed to decode simulator attestation")
}

pub fn simulated_quote_response(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    vm_config: &str,
) -> Result<GetQuoteResponse> {
    let VersionedAttestation::V0 { attestation } = attestation.clone();
    let mut attestation = attestation;
    let Some(quote) = attestation.tdx_quote_mut() else {
        return Err(anyhow::anyhow!("Quote not found"));
    };

    quote.quote[TDX_QUOTE_REPORT_DATA_RANGE].copy_from_slice(&report_data);
    Ok(GetQuoteResponse {
        quote: quote.quote.to_vec(),
        event_log: serde_json::to_string(&quote.event_log)
            .context("Failed to serialize event log")?,
        report_data: report_data.to_vec(),
        vm_config: vm_config.to_string(),
    })
}

pub fn simulated_attest_response(attestation: &VersionedAttestation) -> AttestResponse {
    AttestResponse {
        attestation: attestation.to_scale(),
    }
}

pub fn simulated_info_attestation(attestation: &VersionedAttestation) -> Attestation {
    attestation.clone().into_inner()
}
