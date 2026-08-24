// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::GetQuoteResponse;
use ra_tls::attestation::Attestation;
use ra_tls::attestation::{QuoteContentType, VersionedAttestation};

pub trait PlatformBackend: Send + Sync {
    fn attestation_for_info(&self) -> Result<VersionedAttestation>;
    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation>;
    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse>;
    /// Attest the CVM itself: the attestation `Attest` and `AttestAppKey`
    /// return, with digest preimages filled in. Encoding it is the RPC
    /// layer's job.
    fn attest_cvm(&self, report_data: [u8; 64]) -> Result<VersionedAttestation>;
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
        let quote = attestation
            .get_tdx_quote_bytes()
            .context("GetQuote is Intel TDX only, use Attest on this platform")?;
        Ok(GetQuoteResponse {
            quote,
            event_log: attestation.get_tdx_event_log_string().unwrap_or_default(),
            report_data: report_data.to_vec(),
            vm_config: vm_config.to_string(),
        })
    }

    fn attest_cvm(&self, report_data: [u8; 64]) -> Result<VersionedAttestation> {
        let mut attestation =
            Attestation::quote(&report_data).context("Failed to get attestation")?;
        attestation.fill_event_preimages();
        Ok(attestation.into_versioned())
    }
}
