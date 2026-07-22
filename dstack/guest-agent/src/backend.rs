// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_tls::attestation::Attestation;
use ra_tls::attestation::{QuoteContentType, VersionedAttestation};
use tracing::warn;

fn event_log_ccel_or_empty(result: Result<Vec<u8>>) -> Vec<u8> {
    match result {
        Ok(event_log) => event_log,
        Err(err) => {
            warn!(error = ?err, "failed to build TDX CCEL event log");
            Vec::new()
        }
    }
}

pub trait PlatformBackend: Send + Sync {
    fn attestation_for_info(&self) -> Result<VersionedAttestation>;
    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation>;
    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse>;
    fn attest_response(&self, report_data: [u8; 64]) -> Result<AttestResponse>;
}

#[derive(Debug, Default)]
pub struct RealPlatform;

impl PlatformBackend for RealPlatform {
    fn attestation_for_info(&self) -> Result<VersionedAttestation> {
        Ok(Attestation::local()
            .context("Failed to get local attestation")?
            .into_versioned())
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
        let event_log_ccel = event_log_ccel_or_empty(attestation.get_tdx_event_log_ccel());
        let versioned = if tdx_quote.is_some() {
            Vec::new()
        } else {
            attestation
                .into_versioned()
                .to_bytes()
                .context("Failed to encode versioned attestation")?
        };
        Ok(GetQuoteResponse {
            quote: tdx_quote.unwrap_or_default(),
            event_log: tdx_event_log.unwrap_or_default(),
            report_data: report_data.to_vec(),
            vm_config: vm_config.to_string(),
            attestation: versioned,
            event_log_ccel,
        })
    }

    fn attest_response(&self, report_data: [u8; 64]) -> Result<AttestResponse> {
        let mut attestation =
            Attestation::quote(&report_data).context("Failed to get attestation")?;
        attestation.fill_event_preimages();
        Ok(AttestResponse {
            attestation: attestation.into_versioned().to_bytes()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccel_export_failure_is_fail_open() {
        let event_log = event_log_ccel_or_empty(Err(anyhow::anyhow!("CCEL unavailable")));
        assert!(event_log.is_empty());
    }
}
