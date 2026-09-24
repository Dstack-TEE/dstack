// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Collateral retrieval module
//!
//! Extracts CRL distribution points from the device-provided cert chain and
//! downloads CRLs for revocation checking, similar to dcap-qvl/tpm-qvl.

use anyhow::{Context, Result};
use pki_fetch::Fetcher;
use tracing::debug;

use crate::{
    verify::verify_attestation_with_collateral, AttestationDocument, CoseSign1, NsmCollateral,
};

pub async fn get_collateral_and_verify(
    cose_sign1_bytes: &[u8],
    root_ca_pem: &str,
    now: Option<std::time::SystemTime>,
) -> Result<crate::NsmVerifiedReport> {
    let collateral = get_collateral(cose_sign1_bytes, root_ca_pem).await?;
    verify_attestation_with_collateral(cose_sign1_bytes, root_ca_pem, &collateral, now)
}

pub async fn get_collateral(cose_sign1_bytes: &[u8], root_ca_pem: &str) -> Result<NsmCollateral> {
    debug!("fetching NSM collateral (intermediate CRLs + root CA CRL)");

    let cose = CoseSign1::from_bytes(cose_sign1_bytes).context("failed to parse COSE Sign1")?;
    let doc =
        AttestationDocument::from_cbor(&cose.payload).context("failed to parse attestation doc")?;

    let mut fetcher = Fetcher::new()?;
    let crls = fetcher.crls(&build_chain_from_doc(&doc)).await?;
    let root_ca_crl = fetcher.root_ca_crl(root_ca_pem).await?;

    debug!(
        "✓ collateral fetched: {} CRL(s), root CA CRL: {}",
        crls.len(),
        if root_ca_crl.is_some() { "yes" } else { "no" }
    );

    Ok(NsmCollateral { crls, root_ca_crl })
}

fn build_chain_from_doc(doc: &AttestationDocument) -> Vec<Vec<u8>> {
    let mut chain = Vec::new();
    chain.push(doc.certificate.clone());
    chain.extend(doc.cabundle.iter().skip(1).cloned());
    chain
}
