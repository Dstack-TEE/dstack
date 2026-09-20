// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dcap_qvl::{
    collateral::CollateralClient,
    quote::{Quote, TDReport10},
};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::{
    crypto::{derive_key, public_key, seal},
    error::ProviderError,
    gramine,
    protocol::QuoteResponse,
};

pub struct KeyProvider {
    collateral: CollateralClient,
}

impl KeyProvider {
    pub fn from_env() -> Result<Self, ProviderError> {
        let collateral = CollateralClient::from_env()
            .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?;

        Ok(Self { collateral })
    }

    pub async fn provision(&self, raw_tdx_quote: &[u8]) -> Result<QuoteResponse, ProviderError> {
        info!(quote_len = raw_tdx_quote.len(), "processing TDX quote");
        let tdx_report = self.verify_tdx_quote(raw_tdx_quote).await?;
        let tdx_quote = parse_quote("TDX", raw_tdx_quote)?;

        // Obtain an initial quote before reading the sealing key. Its QE ID
        // must match the TDX quote's QE ID.
        let initial_sgx_quote = gramine::quote(&[])?;
        let sgx_quote = parse_quote("SGX", &initial_sgx_quote)?;
        require_sgx_report(&sgx_quote)?;
        verify_same_qe_id(&sgx_quote, &tdx_quote)?;

        let sealing_key = gramine::sealing_key()?;
        let measurements = measurements(&tdx_report);
        let derived_key = derive_key(&sealing_key, &measurements);
        let recipient = public_key(&tdx_report.report_data)?;
        let encrypted_key = seal(&derived_key, &recipient)?;

        let mut report_data = [0_u8; 64];
        report_data[..32].copy_from_slice(&Sha256::digest(&encrypted_key));
        let provider_quote = gramine::quote(&report_data)?;

        info!("sealing key provisioned successfully");
        Ok(QuoteResponse {
            encrypted_key,
            provider_quote,
        })
    }

    async fn verify_tdx_quote(&self, raw_quote: &[u8]) -> Result<TDReport10, ProviderError> {
        let report = self
            .collateral
            .fetch_and_verify(raw_quote)
            .await
            .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?;
        let tdx_report = report.report.as_td10().copied().ok_or_else(|| {
            ProviderError::QuoteVerification("verified quote is not a TDX quote".into())
        })?;
        require_production_td(&tdx_report)?;
        debug!(
            tcb_status = %report.status,
            advisories = ?report.advisory_ids,
            "TDX quote verified"
        );
        Ok(tdx_report)
    }
}

/// Refuse a TD the host launched in a state that does not protect it.
///
/// A debug TD lets the host read and write its memory through the TDX debug
/// interface, so handing one the sealing key hands the key to the host. The
/// key does not distinguish the two either: `measurements()` covers MRTD and
/// the RTMRs but not `td_attributes`, and that derivation is frozen -- it is
/// what every existing local-key-provider deployment sealed its disk with --
/// so a debug TD booting the same image derives exactly the production TD's
/// key. This gate is the only thing standing between the two.
///
/// This is the TD-side counterpart of the check the guest already applies to
/// this provider's SGX quote (`ra_tls::attestation::validate_tcb`). It is
/// spelled out again instead of depending on `dstack-attest` so the enclave
/// keeps its small dependency footprint.
fn require_production_td(report: &TDReport10) -> Result<(), ProviderError> {
    if report.td_attributes[0] & 0x01 != 0 {
        return Err(ProviderError::DebugTd);
    }
    if report.mr_signer_seam != [0_u8; 48] {
        return Err(ProviderError::QuoteVerification(
            "TD was launched by a non-production TDX module".into(),
        ));
    }
    Ok(())
}

fn parse_quote(kind: &'static str, raw_quote: &[u8]) -> Result<Quote, ProviderError> {
    Quote::parse(raw_quote).map_err(|error| ProviderError::QuoteParse {
        kind,
        reason: error.to_string(),
    })
}

fn require_sgx_report(quote: &Quote) -> Result<(), ProviderError> {
    if quote.report.as_sgx().is_none() {
        return Err(ProviderError::QuoteParse {
            kind: "SGX",
            reason: "quote contains a non-SGX report".into(),
        });
    }
    Ok(())
}

fn verify_same_qe_id(sgx_quote: &Quote, tdx_quote: &Quote) -> Result<(), ProviderError> {
    if sgx_quote.qeid() != tdx_quote.qeid() {
        return Err(ProviderError::QeIdMismatch);
    }
    debug!("SGX and TDX quotes carry the same QE ID");
    Ok(())
}

fn measurements(report: &TDReport10) -> Vec<u8> {
    let mut output = Vec::with_capacity(48 * 5);
    output.extend_from_slice(&report.mr_td);
    output.extend_from_slice(&report.rt_mr0);
    output.extend_from_slice(&report.rt_mr1);
    output.extend_from_slice(&report.rt_mr2);
    output.extend_from_slice(&report.rt_mr3);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    const TDX_QUOTE: &[u8] = include_bytes!("../../ra-tls/assets/tdx_quote");
    /// `td_attributes` starts 120 bytes into the TD report body, which itself
    /// starts 48 bytes into the quote. `td_attributes_offset_is_the_recorded_one`
    /// pins this against the parsed report.
    const TD_ATTRIBUTES_OFFSET: usize = 48 + 120;

    fn report(quote: &[u8]) -> TDReport10 {
        Quote::parse(quote)
            .unwrap()
            .report
            .as_td10()
            .copied()
            .unwrap()
    }

    /// The recorded quote with the TD debug bit set, as a host gets by asking
    /// the VMM to launch the same image with debug enabled.
    fn debug_quote() -> Vec<u8> {
        let mut quote = TDX_QUOTE.to_vec();
        quote[TD_ATTRIBUTES_OFFSET] |= 0x01;
        quote
    }

    #[test]
    fn td_attributes_offset_is_the_recorded_one() {
        assert_eq!(
            report(TDX_QUOTE).td_attributes,
            TDX_QUOTE[TD_ATTRIBUTES_OFFSET..TD_ATTRIBUTES_OFFSET + 8]
        );
        assert_eq!(report(&debug_quote()).td_attributes[0] & 0x01, 0x01);
    }

    #[test]
    fn accepts_the_recorded_production_td() {
        assert!(require_production_td(&report(TDX_QUOTE)).is_ok());
    }

    #[test]
    fn refuses_to_provision_a_debug_mode_td() {
        assert!(matches!(
            require_production_td(&report(&debug_quote())),
            Err(ProviderError::DebugTd)
        ));
    }

    #[test]
    fn refuses_a_td_from_a_non_production_tdx_module() {
        let mut report = report(TDX_QUOTE);
        report.mr_signer_seam[0] = 0x01;
        assert!(matches!(
            require_production_td(&report),
            Err(ProviderError::QuoteVerification(_))
        ));
    }

    /// Why `refuses_to_provision_a_debug_mode_td` is load-bearing rather than
    /// defence in depth: the derivation cannot tell a debug TD apart, and it
    /// cannot be changed without invalidating every sealed disk in the field.
    #[test]
    fn a_debug_td_derives_the_production_key_so_only_the_gate_separates_them() {
        assert_eq!(
            measurements(&report(TDX_QUOTE)),
            measurements(&report(&debug_quote()))
        );
    }

    #[test]
    fn extracts_all_key_derivation_measurements_in_wire_order() {
        let quote = Quote::parse(TDX_QUOTE).unwrap();
        let report = quote.report.as_td10().unwrap();
        let output = measurements(report);

        assert_eq!(output.len(), 48 * 5);
        assert_eq!(&output[..48], &report.mr_td);
        assert_eq!(&output[48..96], &report.rt_mr0);
        assert_eq!(&output[192..240], &report.rt_mr3);
    }
}
