// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_rpc::Attestation;
use ra_tls::attestation::{QuoteContentType, VersionedAttestation, TDX_QUOTE_REPORT_DATA_RANGE};
use std::fs;
use tracing::warn;

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
    patch_report_data: bool,
) -> Result<GetQuoteResponse> {
    let VersionedAttestation::V0 { attestation } =
        maybe_patch_report_data(attestation, report_data, patch_report_data, "quote");
    let mut attestation = attestation;
    let Some(quote) = attestation.tdx_quote_mut() else {
        return Err(anyhow::anyhow!("Quote not found"));
    };

    Ok(GetQuoteResponse {
        quote: quote.quote.to_vec(),
        event_log: serde_json::to_string(&quote.event_log)
            .context("Failed to serialize event log")?,
        report_data: report_data.to_vec(),
        vm_config: vm_config.to_string(),
    })
}

pub fn simulated_attest_response(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
) -> AttestResponse {
    AttestResponse {
        attestation: maybe_patch_report_data(attestation, report_data, patch_report_data, "attest")
            .to_scale(),
    }
}

pub fn simulated_info_attestation(attestation: &VersionedAttestation) -> Attestation {
    attestation.clone().into_inner()
}

pub fn simulated_certificate_attestation(
    attestation: &VersionedAttestation,
    pubkey: &[u8],
    patch_report_data: bool,
) -> VersionedAttestation {
    let report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
    maybe_patch_report_data(
        attestation,
        report_data,
        patch_report_data,
        "certificate_attestation",
    )
}

fn maybe_patch_report_data(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
    context: &str,
) -> VersionedAttestation {
    if !patch_report_data {
        warn!(
            context = context,
            requested_report_data = ?report_data,
            "simulator is preserving fixture report_data; returned attestation may not match the current request"
        );
        return attestation.clone();
    }

    let VersionedAttestation::V0 { attestation } = attestation.clone();
    let mut attestation = attestation;
    attestation.report_data = report_data;
    if let Some(tdx_quote) = attestation.tdx_quote_mut() {
        if tdx_quote.quote.len() >= TDX_QUOTE_REPORT_DATA_RANGE.end {
            tdx_quote.quote[TDX_QUOTE_REPORT_DATA_RANGE].copy_from_slice(&report_data);
        } else {
            warn!(
                "TDX quote too short to patch report_data ({} < {})",
                tdx_quote.quote.len(),
                TDX_QUOTE_REPORT_DATA_RANGE.end
            );
        }
    }
    VersionedAttestation::V0 { attestation }
}
