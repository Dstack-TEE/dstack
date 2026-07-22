// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dcap_qvl::{
    collateral::CollateralClient,
    quote::{Quote, TDReport10},
    QuotePolicy, TcbStatus,
};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime};
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
        let collateral = self
            .collateral
            .fetch(raw_quote)
            .await
            .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?
            .as_secs();
        let policy = tdx_quote_policy(now);
        let claims = dcap_qvl::verify::QuoteVerifier::new_prod()
            .verify_with_policy(raw_quote, collateral, now, &policy)
            .map_err(|error| ProviderError::QuoteVerification(error.to_string()))?;
        let tdx_report = claims.report.as_td10().copied().ok_or_else(|| {
            ProviderError::QuoteVerification("verified quote is not a TDX quote".into())
        })?;
        debug!(
            tcb_status = %claims.tcb.status,
            advisories = ?claims.tcb.advisory_ids,
            "TDX quote verified"
        );
        Ok(tdx_report)
    }
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

const TCB_OUT_OF_DATE_GRACE_PERIOD: Duration = Duration::from_secs(15 * 24 * 60 * 60);

fn tdx_quote_policy(now: u64) -> QuotePolicy {
    QuotePolicy::strict(now)
        .allow_status(TcbStatus::SWHardeningNeeded)
        .allow_status(TcbStatus::ConfigurationNeeded)
        .allow_status(TcbStatus::ConfigurationAndSWHardeningNeeded)
        .allow_status(TcbStatus::OutOfDate)
        .allow_status(TcbStatus::OutOfDateConfigurationNeeded)
        .platform_grace_period(TCB_OUT_OF_DATE_GRACE_PERIOD)
        .qe_grace_period(TCB_OUT_OF_DATE_GRACE_PERIOD)
        .allow_dynamic_platform(true)
        .allow_cached_keys(true)
        .allow_smt(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_all_key_derivation_measurements_in_wire_order() {
        let quote = Quote::parse(include_bytes!("../../ra-tls/assets/tdx_quote")).unwrap();
        let report = quote.report.as_td10().unwrap();
        let output = measurements(report);

        assert_eq!(output.len(), 48 * 5);
        assert_eq!(&output[..48], &report.mr_td);
        assert_eq!(&output[48..96], &report.rt_mr0);
        assert_eq!(&output[192..240], &report.rt_mr3);
    }
}
