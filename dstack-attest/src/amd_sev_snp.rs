// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! AMD SEV-SNP attestation verification helpers.
//!
//! This module intentionally implements only the hardware report signature
//! verification slice. KMS/app authorization must still bind the verified
//! measurement to app/config identity before production key release.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use sev::firmware::guest::AttestationReport;

/// AMD Genoa ARK certificate (DER, base64-encoded).
/// Source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
const GENOA_ARK_DER_B64: &str = "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";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAmdSnpReport {
    pub measurement: [u8; 48],
    pub report_data: [u8; 64],
    pub chip_id: [u8; 64],
}

pub struct AmdSnpAttestationInput<'a> {
    pub report: &'a [u8],
    pub ask_pem: &'a [u8],
    pub vcek_pem: &'a [u8],
}

pub fn verify_amd_snp_attestation(
    input: &AmdSnpAttestationInput<'_>,
) -> Result<VerifiedAmdSnpReport> {
    if input.report.len() != 1184 {
        bail!(
            "invalid amd sev-snp report length: expected 1184 bytes, got {}",
            input.report.len()
        );
    }
    let report = AttestationReport::from_bytes(input.report)
        .map_err(|err| anyhow::anyhow!("failed to parse amd sev-snp report: {err}"))?;

    let ark_der = STANDARD
        .decode(GENOA_ARK_DER_B64)
        .context("failed to decode amd genoa ark")?;
    let ark = Certificate::from_der(&ark_der)
        .map_err(|err| anyhow::anyhow!("failed to parse amd genoa ark: {err:?}"))?;
    let ask = Certificate::from_pem(input.ask_pem)
        .map_err(|err| anyhow::anyhow!("failed to parse amd ask certificate: {err:?}"))?;
    let vcek = Certificate::from_pem(input.vcek_pem)
        .map_err(|err| anyhow::anyhow!("failed to parse amd vcek certificate: {err:?}"))?;

    let chain = Chain {
        ca: ca::Chain { ark, ask },
        vek: vcek.clone(),
    };
    chain
        .verify()
        .map_err(|err| anyhow::anyhow!("amd cert chain verification failed: {err:?}"))?;
    (&vcek, &report).verify().map_err(|err| {
        anyhow::anyhow!("amd sev-snp report signature verification failed: {err:?}")
    })?;

    let mut measurement = [0u8; 48];
    measurement.copy_from_slice(
        report
            .measurement
            .as_ref()
            .get(..48)
            .context("amd sev-snp measurement too short")?,
    );
    let mut report_data = [0u8; 64];
    report_data.copy_from_slice(
        report
            .report_data
            .as_ref()
            .get(..64)
            .context("amd sev-snp report_data too short")?,
    );
    let mut chip_id = [0u8; 64];
    chip_id.copy_from_slice(
        report
            .chip_id
            .as_ref()
            .get(..64)
            .context("amd sev-snp chip_id too short")?,
    );

    Ok(VerifiedAmdSnpReport {
        measurement,
        report_data,
        chip_id,
    })
}

pub fn verify_amd_snp_evidence(
    report: &[u8],
    cert_chain: &[Vec<u8>],
    expected_report_data: &[u8; 64],
) -> Result<VerifiedAmdSnpReport> {
    let (ask_pem, vcek_pem) = split_ask_vcek_pem_chain(cert_chain)?;
    let verified = verify_amd_snp_attestation(&AmdSnpAttestationInput {
        report,
        ask_pem,
        vcek_pem,
    })?;
    if &verified.report_data != expected_report_data {
        bail!("amd sev-snp report_data mismatch");
    }
    Ok(verified)
}

fn split_ask_vcek_pem_chain(cert_chain: &[Vec<u8>]) -> Result<(&[u8], &[u8])> {
    match cert_chain {
        [ask_pem, vcek_pem] => Ok((ask_pem.as_slice(), vcek_pem.as_slice())),
        _ => bail!("amd sev-snp cert_chain must contain exactly ASK and VCEK PEM certificates"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_cert_chain_fails_closed() {
        let report = vec![0u8; 1184];
        let expected_report_data = [0u8; 64];
        let err = verify_amd_snp_evidence(&report, &[], &expected_report_data).unwrap_err();
        assert!(
            err.to_string()
                .contains("cert_chain must contain exactly ASK and VCEK"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn malformed_report_fails_closed_before_success() {
        let cert_chain = vec![b"not ask".to_vec(), b"not vcek".to_vec()];
        let expected_report_data = [0u8; 64];
        let err =
            verify_amd_snp_evidence(b"too short", &cert_chain, &expected_report_data).unwrap_err();
        assert!(
            err.to_string()
                .contains("invalid amd sev-snp report length"),
            "unexpected error: {err:#}"
        );
    }
}
