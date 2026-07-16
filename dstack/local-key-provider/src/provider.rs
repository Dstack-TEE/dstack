// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dcap_qvl::quote::{Quote, TDReport10};
use dcap_qvl::{collateral::CollateralClient, quote::Report};
use sha2::{Digest, Sha256};
use tracing::{debug, info};

use crate::{
    crypto::{derive_key, public_key, seal},
    error::ProviderError,
    gramine,
    protocol::QuoteResponse,
};

const PLATFORM_ID_SIZE: usize = 16;

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
        self.verify_tdx_quote(raw_tdx_quote).await?;
        let tdx_quote = parse_quote("TDX", raw_tdx_quote)?;
        let tdx_report = tdx_report(&tdx_quote)?;

        // Obtain a cheap initial quote before reading the sealing key. Its QE
        // user data identifies the physical platform and must match the TDX QE.
        let initial_sgx_quote = gramine::quote(&[])?;
        let sgx_quote = parse_quote("SGX", &initial_sgx_quote)?;
        require_sgx_report(&sgx_quote)?;
        verify_same_platform(&sgx_quote, &tdx_quote)?;

        let sealing_key = gramine::sealing_key()?;
        let measurements = measurements(tdx_report);
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

    async fn verify_tdx_quote(&self, raw_quote: &[u8]) -> Result<(), ProviderError> {
        let report = self
            .collateral
            .fetch_and_verify(raw_quote)
            .await
            .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?;
        if !matches!(report.report, Report::TD10(_) | Report::TD15(_)) {
            return Err(ProviderError::QuoteVerification(
                "verified quote is not a TDX quote".into(),
            ));
        }
        debug!(
            tcb_status = %report.status,
            advisories = ?report.advisory_ids,
            "TDX quote verified"
        );
        Ok(())
    }
}

fn parse_quote(kind: &'static str, raw_quote: &[u8]) -> Result<Quote, ProviderError> {
    Quote::parse(raw_quote).map_err(|error| ProviderError::QuoteParse {
        kind,
        reason: error.to_string(),
    })
}

fn tdx_report(quote: &Quote) -> Result<&TDReport10, ProviderError> {
    quote
        .report
        .as_td10()
        .ok_or_else(|| ProviderError::QuoteParse {
            kind: "TDX",
            reason: "quote contains a non-TDX report".into(),
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

fn verify_same_platform(sgx_quote: &Quote, tdx_quote: &Quote) -> Result<(), ProviderError> {
    let sgx_id = &sgx_quote.header.user_data[..PLATFORM_ID_SIZE];
    let tdx_id = &tdx_quote.header.user_data[..PLATFORM_ID_SIZE];
    if sgx_id != tdx_id {
        return Err(ProviderError::PlatformMismatch);
    }
    debug!("SGX and TDX quotes originate from the same platform");
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

    #[test]
    fn extracts_all_key_derivation_measurements_in_wire_order() {
        let quote = Quote::parse(include_bytes!("../../ra-tls/assets/tdx_quote")).unwrap();
        let report = tdx_report(&quote).unwrap();
        let output = measurements(report);

        assert_eq!(output.len(), 48 * 5);
        assert_eq!(&output[..48], &report.mr_td);
        assert_eq!(&output[48..96], &report.rt_mr0);
        assert_eq!(&output[192..240], &report.rt_mr3);
    }
}
