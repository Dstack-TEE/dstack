// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use cc_eventlog::TdxEvent;
use dstack_guest_agent_rpc::v0::GetQuoteResponse;
use ra_tls::attestation::Attestation;
use ra_tls::attestation::{
    AttestationV1, QuoteContentType, TdxAttestationExt, VersionedAttestation,
};
use tdx_attest::TdxMeasurements;

/// The TDX measurements and event log legacy `Info` reports.
pub struct TcbInfo {
    pub measurements: Option<TdxMeasurements>,
    pub event_log: Vec<TdxEvent>,
}

impl From<AttestationV1> for TcbInfo {
    fn from(attestation: AttestationV1) -> Self {
        Self {
            measurements: attestation.td10_report().map(|report| TdxMeasurements {
                mrtd: report.mr_td,
                rtmrs: [report.rt_mr0, report.rt_mr1, report.rt_mr2, report.rt_mr3],
            }),
            event_log: attestation.tdx_event_log().unwrap_or_default().to_vec(),
        }
    }
}

pub trait PlatformBackend: Send + Sync {
    /// Read the TCB info without a quote, or `None` to fall back to
    /// [`Self::attestation_for_info`].
    fn local_tcb_info(&self) -> Result<Option<TcbInfo>> {
        Ok(None)
    }

    fn attestation_for_info(&self) -> Result<VersionedAttestation>;
    fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation>;
    fn quote_response(&self, report_data: [u8; 64], vm_config: &str) -> Result<GetQuoteResponse>;
    /// Attest the CVM itself: the attestation `Attest` returns, with digest
    /// preimages filled in. Encoding it is the RPC layer's job.
    fn attest_cvm(&self, report_data: [u8; 64]) -> Result<VersionedAttestation>;
}

#[derive(Debug, Default)]
pub struct RealPlatform;

impl PlatformBackend for RealPlatform {
    fn local_tcb_info(&self) -> Result<Option<TcbInfo>> {
        let Some(measurements) =
            tdx_attest::read_measurements().context("failed to read TDX measurements")?
        else {
            return Ok(None);
        };
        let mut event_log =
            cc_eventlog::tdx::read_event_log().context("failed to read event log")?;
        cc_eventlog::tdx::fill_v2_preimages(&mut event_log);
        Ok(Some(TcbInfo {
            measurements: Some(measurements),
            event_log,
        }))
    }

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
