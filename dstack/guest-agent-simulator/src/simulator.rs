// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_tls::attestation::{
    AttestationV1, QuoteContentType, TdxAttestationExt, VersionedAttestation,
};
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
    VersionedAttestation::from_bytes(&attestation_bytes)
        .context("Failed to decode simulator attestation")
}

pub fn simulated_quote_response(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    vm_config: &str,
    patch_report_data: bool,
    include_hash_inputs: bool,
) -> Result<GetQuoteResponse> {
    let attestation = maybe_patch_report_data(attestation, report_data, patch_report_data, "quote");
    let Some(quote) = attestation.tdx_quote_bytes() else {
        return Err(anyhow!("Quote not found"));
    };

    Ok(GetQuoteResponse {
        quote,
        event_log: attestation
            .tdx_event_log_string(include_hash_inputs)
            .unwrap_or_default(),
        report_data: report_data.to_vec(),
        vm_config: vm_config.to_string(),
        event_log_ccel: Vec::new(),
    })
}

pub fn simulated_attest_response(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
    include_hash_inputs: bool,
) -> Result<AttestResponse> {
    let mut attestation =
        maybe_patch_report_data(attestation, report_data, patch_report_data, "attest");
    if include_hash_inputs {
        if let Some(event_log) = attestation.platform.tdx_event_log_mut() {
            for event in event_log {
                event.fill_hash_input();
            }
        }
    }
    Ok(AttestResponse {
        attestation: VersionedAttestation::V1 { attestation }.to_bytes()?,
    })
}

pub fn simulated_info_attestation(attestation: &VersionedAttestation) -> VersionedAttestation {
    attestation.clone()
}

pub fn simulated_certificate_attestation(
    attestation: &VersionedAttestation,
    pubkey: &[u8],
    patch_report_data: bool,
) -> Result<VersionedAttestation> {
    let report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
    let attestation = maybe_patch_report_data(
        attestation,
        report_data,
        patch_report_data,
        "certificate_attestation",
    );
    Ok(VersionedAttestation::V1 { attestation })
}

fn maybe_patch_report_data(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
    context: &str,
) -> AttestationV1 {
    if !patch_report_data {
        warn!(
            context = context,
            requested_report_data = ?report_data,
            "simulator is preserving fixture report_data; returned attestation may not match the current request"
        );
        return attestation.clone().into_v1();
    }
    attestation.clone().into_v1().with_report_data(report_data)
}
