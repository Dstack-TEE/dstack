// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{anyhow, Context, Result};
use dcap_qvl::quote::Quote;
use dstack_guest_agent_rpc::{AttestResponse, GetQuoteResponse};
use mock_attestation::tdx::TdxGenerator;
use ra_tls::attestation::{
    AttestationV1, PlatformEvidence, QuoteContentType, TdxAttestationExt, VersionedAttestation,
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
    generator: Option<&TdxGenerator>,
) -> Result<GetQuoteResponse> {
    let attestation = prepare_attestation(
        attestation,
        report_data,
        patch_report_data,
        generator,
        "quote",
    )?;
    let Some(quote) = attestation.tdx_quote_bytes() else {
        return Err(anyhow!(
            "GetQuote is Intel TDX only, use Attest on this platform"
        ));
    };

    Ok(GetQuoteResponse {
        quote,
        event_log: attestation.tdx_event_log_string().unwrap_or_default(),
        report_data: report_data.to_vec(),
        vm_config: vm_config.to_string(),
    })
}

pub fn simulated_attest_response(
    source: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
    generator: Option<&TdxGenerator>,
) -> Result<AttestResponse> {
    let preserve_legacy = matches!(source, VersionedAttestation::V0 { .. });
    let mut attestation =
        prepare_attestation(source, report_data, patch_report_data, generator, "attest")?;
    if let Some(event_log) = attestation.platform.tdx_event_log_mut() {
        cc_eventlog::tdx::fill_v2_preimages(event_log);
    }
    let attestation = if preserve_legacy {
        attestation.try_into_legacy()?.into_versioned()
    } else {
        VersionedAttestation::V1 { attestation }
    };
    Ok(AttestResponse {
        attestation: attestation.to_bytes()?,
    })
}

pub fn simulated_info_attestation(attestation: &VersionedAttestation) -> VersionedAttestation {
    attestation.clone()
}

pub fn simulated_certificate_attestation(
    source: &VersionedAttestation,
    pubkey: &[u8],
    patch_report_data: bool,
    generator: Option<&TdxGenerator>,
) -> Result<VersionedAttestation> {
    let preserve_legacy = matches!(source, VersionedAttestation::V0 { .. });
    let report_data = QuoteContentType::RaTlsCert.to_report_data(pubkey);
    let attestation = prepare_attestation(
        source,
        report_data,
        patch_report_data,
        generator,
        "certificate_attestation",
    )?;
    if preserve_legacy {
        return Ok(attestation.try_into_legacy()?.into_versioned());
    }
    Ok(VersionedAttestation::V1 { attestation })
}

fn prepare_attestation(
    attestation: &VersionedAttestation,
    report_data: [u8; 64],
    patch_report_data: bool,
    generator: Option<&TdxGenerator>,
    context: &str,
) -> Result<AttestationV1> {
    let Some(generator) = generator else {
        return Ok(maybe_patch_report_data(
            attestation,
            report_data,
            patch_report_data,
            context,
        ));
    };
    let mut attestation = attestation.clone().into_v1().with_report_data(report_data);
    let quote = attestation
        .platform
        .tdx_quote()
        .context("TDX quote is unavailable in simulator fixture")?;
    let quote = Quote::parse(quote).context("invalid simulator fixture TDX quote")?;
    let report = quote
        .report
        .as_td10()
        .context("simulator fixture does not contain a TDX 1.0 report")?;
    let evidence = generator.attest_with_measurements(
        report_data,
        report.mr_td,
        [report.rt_mr0, report.rt_mr1, report.rt_mr2, report.rt_mr3],
    )?;
    match &mut attestation.platform {
        PlatformEvidence::Tdx { quote, .. } => *quote = evidence.quote,
        _ => return Err(anyhow!("seeded simulator requires dstack TDX evidence")),
    }
    Ok(attestation)
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
