// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP guest report adapter for dstack attestation.

use std::path::Path;

use anyhow::Result;

use crate::attestation::SnpQuote;

pub fn get_report(report_data: [u8; 64]) -> Result<SnpQuote> {
    let quote = sev_snp_attest::get_report(report_data)?;
    Ok(SnpQuote {
        report: quote.report,
        cert_chain: quote.cert_chain,
        mr_config: String::new(),
    })
}

pub fn has_sev_snp_tsm_provider(root: &Path) -> bool {
    sev_snp_attest::has_sev_snp_tsm_provider(root)
}
