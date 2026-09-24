// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dcap_qvl::{
    collateral::CollateralClient,
    quote::{Quote, TDAttributes, TDReport10},
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

/// Refuse a TD that the host launched in a state that does not protect it.
///
/// `fetch_and_verify` already rejects these TDs under dcap-qvl's default
/// policy. The check is repeated here, following dcap-qvl's `validate_td10`,
/// so that the sealing key does not depend on that default: the key
/// derivation does not cover `td_attributes`, so a debug TD running the same
/// image would derive the production TD's key. The `mr_signer_seam` check
/// matches the guest's `validate_tcb`.
fn require_production_td(report: &TDReport10) -> Result<(), ProviderError> {
    let attributes = TDAttributes::parse(report.td_attributes)
        .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?;
    if attributes.tud & 0x01 != 0 {
        return Err(ProviderError::UntrustedTd("debug mode is enabled"));
    }
    if attributes.tud != 0
        || attributes.sec.reserved_lower != 0
        || attributes.sec.reserved_bit29
        || attributes.other.reserved != 0
    {
        return Err(ProviderError::UntrustedTd(
            "reserved bits in TD attributes are set",
        ));
    }
    if !attributes.sec.sept_ve_disable {
        return Err(ProviderError::UntrustedTd("SEPT_VE_DISABLE is not enabled"));
    }
    if report.mr_signer_seam != [0_u8; 48] {
        return Err(ProviderError::UntrustedTd(
            "TD was launched by a non-production TDX module",
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
    /// starts 48 bytes into the quote.
    const TD_ATTRIBUTES_OFFSET: usize = 48 + 120;

    fn report(quote: &[u8]) -> TDReport10 {
        Quote::parse(quote)
            .unwrap()
            .report
            .as_td10()
            .copied()
            .unwrap()
    }

    /// The recorded quote with `td_attributes[byte]` XOR'd with `mask`.
    fn quote_with_attributes(byte: usize, mask: u8) -> Vec<u8> {
        let mut quote = TDX_QUOTE.to_vec();
        quote[TD_ATTRIBUTES_OFFSET + byte] ^= mask;
        quote
    }

    fn rejection(quote: &[u8]) -> Option<&'static str> {
        match require_production_td(&report(quote)) {
            Err(ProviderError::UntrustedTd(reason)) => Some(reason),
            _ => None,
        }
    }

    #[test]
    fn td_attributes_offset_is_the_recorded_one() {
        assert_eq!(
            report(TDX_QUOTE).td_attributes,
            TDX_QUOTE[TD_ATTRIBUTES_OFFSET..TD_ATTRIBUTES_OFFSET + 8]
        );
    }

    #[test]
    fn accepts_the_recorded_production_td() {
        assert!(require_production_td(&report(TDX_QUOTE)).is_ok());
    }

    #[test]
    fn refuses_untrusted_td_attributes() {
        let cases = [
            (0, 0x01, "debug mode is enabled"),
            (0, 0x02, "reserved bits in TD attributes are set"),
            (1, 0x01, "reserved bits in TD attributes are set"),
            (3, 0x20, "reserved bits in TD attributes are set"),
            (4, 0x01, "reserved bits in TD attributes are set"),
            (3, 0x10, "SEPT_VE_DISABLE is not enabled"),
        ];
        for (byte, mask, reason) in cases {
            assert_eq!(rejection(&quote_with_attributes(byte, mask)), Some(reason));
        }
    }

    #[test]
    fn refuses_a_td_from_a_non_production_tdx_module() {
        let mut report = report(TDX_QUOTE);
        report.mr_signer_seam[0] = 0x01;
        assert!(matches!(
            require_production_td(&report),
            Err(ProviderError::UntrustedTd(_))
        ));
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
