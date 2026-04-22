// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_attest::emit_runtime_event;
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use dstack_types::EventLogVersion;
use ra_tls::attestation::Attestation;
use ra_tls::attestation::{QuoteContentType, VersionedAttestation};

pub trait PlatformBackend: Send + Sync {
    fn attestation_for_info(&self) -> Result<VersionedAttestation>;
    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation>;
    fn quote_response(
        &self,
        report_data: [u8; 64],
        vm_config: &str,
        include_hash_inputs: bool,
    ) -> Result<GetQuoteResponse>;
    fn attest_response(
        &self,
        report_data: [u8; 64],
        include_hash_inputs: bool,
    ) -> Result<AttestResponse>;
    fn emit_event(&self, event: &str, payload: &[u8], version: EventLogVersion) -> Result<()>;
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

    fn quote_response(
        &self,
        report_data: [u8; 64],
        vm_config: &str,
        include_hash_inputs: bool,
    ) -> Result<GetQuoteResponse> {
        let attestation = Attestation::quote(&report_data).context("Failed to get quote")?;
        let tdx_quote = attestation.get_tdx_quote_bytes();
        let tdx_event_log = attestation.get_tdx_event_log_string(include_hash_inputs);
        let event_log_ccel = attestation.get_tdx_event_log_ccel().unwrap_or_default();
        Ok(GetQuoteResponse {
            quote: tdx_quote.unwrap_or_default(),
            event_log: tdx_event_log.unwrap_or_default(),
            report_data: report_data.to_vec(),
            vm_config: vm_config.to_string(),
            event_log_ccel,
        })
    }

    fn attest_response(
        &self,
        report_data: [u8; 64],
        include_hash_inputs: bool,
    ) -> Result<AttestResponse> {
        let mut attestation =
            Attestation::quote(&report_data).context("Failed to get attestation")?;
        if include_hash_inputs {
            attestation.fill_event_hash_inputs();
        }
        Ok(AttestResponse {
            attestation: attestation.into_versioned().to_bytes()?,
        })
    }

    fn emit_event(&self, event: &str, payload: &[u8], version: EventLogVersion) -> Result<()> {
        emit_runtime_event(event, payload, version)
    }
}
