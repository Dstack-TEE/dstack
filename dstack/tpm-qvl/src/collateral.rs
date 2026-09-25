// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Collateral retrieval module
//!
//! This module implements the first step of dcap-qvl architecture:
//! extracting certificate chain information and downloading CRLs.

use anyhow::{Context, Result};
use pki_fetch::{AllowedHosts, Fetcher};
use tracing::debug;
use x509_parser::prelude::*;

use tpm_types::TpmQuote;

use crate::{get_root_ca, verify::VerifiedReport, QuoteCollateral};

pub async fn get_collateral_and_verify(
    quote: &TpmQuote,
    allowed_hosts: &AllowedHosts,
) -> Result<VerifiedReport> {
    let root_ca_pem = get_root_ca(quote.platform).context("failed to get root CA")?;
    let collateral = get_collateral(quote, root_ca_pem, allowed_hosts).await?;
    crate::verify::verify_quote_with_ca(quote, &collateral, root_ca_pem).map_err(Into::into)
}

pub async fn get_collateral(
    quote: &TpmQuote,
    root_ca_pem: &str,
    allowed_hosts: &AllowedHosts,
) -> Result<QuoteCollateral> {
    debug!("fetching quote collateral (intermediate cert chain + CRLs)");
    let mut fetcher = Fetcher::new(allowed_hosts)?;
    let chain_ders = build_cert_chain(&mut fetcher, &quote.ak_cert).await?;
    let crls = fetcher.crls(&chain_ders).await?;
    let root_ca_crl = fetcher.root_ca_crl(root_ca_pem).await?;
    debug!(
        "✓ collateral fetched: {} intermediate CRL(s), root CA CRL: {}",
        crls.len(),
        if root_ca_crl.is_some() { "yes" } else { "no" }
    );
    Ok(QuoteCollateral {
        cert_chain_pem: ders_to_pem(&chain_ders)?,
        crls,
        root_ca_crl,
    })
}

/// Build certificate chain by following AIA links (stops before root)
async fn build_cert_chain(fetcher: &mut Fetcher, leaf_cert_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut chain_ders = Vec::new();
    chain_ders.push(leaf_cert_der.to_vec());
    let mut current_cert_der = leaf_cert_der.to_vec();

    loop {
        let Some(url) = extract_aia_ca_issuers(&current_cert_der)? else {
            debug!("no AIA found - reached end of AIA chain");
            break;
        };
        debug!("downloading parent cert from: {url}");
        let parent_der = fetcher.download(&url).await?;
        // Stop if we hit a self-signed cert (root CA)
        if is_self_signed(&parent_der)? {
            debug!("found self-signed cert - stopping (root CA should be provided by verifier)");
            break;
        }
        chain_ders.push(parent_der.clone());
        current_cert_der = parent_der;
    }

    debug!("built chain with {} certificate(s)", chain_ders.len());
    Ok(chain_ders)
}

/// Convert DER certificates to PEM format
fn ders_to_pem(ders: &[Vec<u8>]) -> Result<String> {
    let mut pem = String::new();
    for der in ders.iter() {
        pem.push_str(&der_to_pem(der, "CERTIFICATE")?);
    }
    Ok(pem)
}

/// Check if certificate is self-signed
fn is_self_signed(cert_der: &[u8]) -> Result<bool> {
    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;
    Ok(cert.subject() == cert.issuer())
}

fn extract_aia_ca_issuers(cert_der: &[u8]) -> Result<Option<String>> {
    use x509_parser::extensions::ParsedExtension;

    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;

    for ext in cert.extensions() {
        let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
            continue;
        };

        for access_desc in &aia.accessdescs {
            const OID_CA_ISSUERS: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 2];
            let oid_bytes: Vec<u64> = match access_desc.access_method.iter() {
                Some(iter) => iter.collect(),
                None => continue,
            };

            if oid_bytes == OID_CA_ISSUERS {
                if let x509_parser::extensions::GeneralName::URI(uri) = &access_desc.access_location
                {
                    debug!("found AIA CA Issuers URL: {uri}");
                    return Ok(Some(uri.to_string()));
                }
            }
        }
    }

    debug!("no AIA CA Issuers URL found in certificate");
    Ok(None)
}

fn der_to_pem(der: &[u8], label: &str) -> Result<String> {
    use base64::Engine;

    let b64 = base64::engine::general_purpose::STANDARD.encode(der);

    let mut pem = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk)?);
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {label}-----\n"));

    Ok(pem)
}
