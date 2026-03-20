// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_attest::emit_runtime_event;
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_rpc::Attestation;
use ra_tls::attestation::{QuoteContentType, VersionedAttestation};

pub trait PlatformBackend: Send + Sync {
    fn attestation_for_info(&self) -> Result<Attestation>;
    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation>;
    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse>;
    fn attest_response(&self, report_data: [u8; 64]) -> Result<AttestResponse>;
    fn emit_event(&self, event: &str, payload: &[u8]) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct RealPlatform;

impl PlatformBackend for RealPlatform {
    fn attestation_for_info(&self) -> Result<Attestation> {
        Attestation::local().context("Failed to get local attestation")
    }

    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation> {
        let report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
        Ok(Attestation::quote(&report_data)
            .context("Failed to get quote for cert pubkey")?
            .into_versioned())
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
