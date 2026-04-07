// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use ra_tls::attestation::{
    AttestationV1, PlatformEvidence, QuoteContentType, StackEvidence, TdxAttestationExt,
    VersionedAttestation, TDX_QUOTE_REPORT_DATA_RANGE,
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
) -> Result<GetQuoteResponse> {
    let attestation = maybe_patch_report_data(attestation, report_data, patch_report_data, "quote");
    let Some(quote) = attestation.tdx_quote_bytes() else {
        return Err(anyhow!("Quote not found"));
    };

    Ok(GetQuoteResponse {
        quote,
        event_log: attestation.tdx_event_log_string().unwrap_or_default(),
        report_data: report_data.to_vec(),
        vm_config: vm_config.to_string(),
    })
}

pub fn simulated_attest_response(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
) -> Result<AttestResponse> {
    let attestation =
        maybe_patch_report_data(attestation, report_data, patch_report_data, "attest");
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
    patch_v1_report_data(attestation.clone().into_v1(), report_data)
}

fn patch_v1_report_data(attestation: AttestationV1, report_data: [u8; 64]) -> AttestationV1 {
    let AttestationV1 {
        version,
        platform,
        stack,
    } = attestation;
    let platform = match platform {
        PlatformEvidence::Tdx {
            mut quote,
            event_log,
        } => {
            if quote.len() >= TDX_QUOTE_REPORT_DATA_RANGE.end {
                quote[TDX_QUOTE_REPORT_DATA_RANGE].copy_from_slice(&report_data);
            }
            PlatformEvidence::Tdx { quote, event_log }
        }
        other => other,
    };
    let stack = match stack {
        StackEvidence::Dstack {
            runtime_events,
            config,
            ..
        } => StackEvidence::Dstack {
            report_data: report_data.to_vec(),
            runtime_events,
            config,
        },
        StackEvidence::DstackPod {
            runtime_events,
            config,
            report_data_payload,
            ..
        } => StackEvidence::DstackPod {
            report_data: report_data.to_vec(),
            runtime_events,
            config,
            report_data_payload,
        },
    };
    AttestationV1 {
        version,
        platform,
        stack,
    }
}
