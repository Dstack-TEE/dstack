// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_rpc::Attestation;
use ra_tls::attestation::{QuoteContentType, VersionedAttestation, TDX_QUOTE_REPORT_DATA_RANGE};
use std::fs;

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

pub fn simulated_certificate_attestation(
    attestation: &VersionedAttestation,
    pubkey: &[u8],
) -> VersionedAttestation {
    let mut attestation = attestation.clone();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
    attestation.set_report_data(report_data);
    attestation
}
