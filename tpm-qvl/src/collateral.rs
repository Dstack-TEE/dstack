// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! Collateral retrieval module
//!
//! This module implements the first step of dcap-qvl architecture:
//! extracting certificate chain information and downloading CRLs.

use anyhow::{bail, Context, Result};
use tracing::{debug, warn};
use x509_parser::{extensions::DistributionPointName, prelude::*};

use tpm_types::TpmQuote;

use crate::{get_root_ca, verify::VerifiedReport, QuoteCollateral};

pub async fn get_collateral_and_verify(quote: &TpmQuote) -> Result<VerifiedReport> {
    let root_ca_pem = get_root_ca(quote.platform).context("failed to get root CA")?;
    let collateral = get_collateral(quote, root_ca_pem).await?;
    crate::verify::verify_quote_with_ca(quote, &collateral, root_ca_pem).map_err(Into::into)
}

pub async fn get_collateral(quote: &TpmQuote, root_ca_pem: &str) -> Result<QuoteCollateral> {
    debug!("fetching quote collateral (intermediate cert chain + CRLs)");

    let ak_cert_der = &quote.ak_cert;
    debug!("AK certificate (leaf) found: {} bytes", ak_cert_der.len());

    // Build certificate chain from device (via AIA)
    let chain_ders = build_cert_chain(ak_cert_der)?;
    // Download CRLs from device-provided cert chain
    let crls = download_crls_for_certs(&chain_ders)?;

    // Download CRL from verifier-provided root CA
    let root_ca_crl = {
        let root_ca_der =
            extract_certs_webpki(root_ca_pem.as_bytes()).context("failed to parse root CA PEM")?;
        if root_ca_der.len() != 1 {
            bail!("expected 1 root CA, found {}", root_ca_der.len());
        }
        download_crl_for_cert(&root_ca_der[0])?
    };

    debug!(
        "✓ collateral fetched: {} intermediate CRL(s), root CA CRL: {}",
        crls.len(),
        if root_ca_crl.is_some() { "yes" } else { "no" }
    );
    let cert_chain_pem = ders_to_pem(&chain_ders)?;
    Ok(QuoteCollateral {
        cert_chain_pem,
        crls,
        root_ca_crl,
    })
}

/// Build certificate chain by following AIA links (stops before root)
fn build_cert_chain(leaf_cert_der: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut chain_ders = Vec::new();
    chain_ders.push(leaf_cert_der.to_vec());
    let mut current_cert_der = leaf_cert_der.to_vec();

    loop {
        let Some(url) = extract_aia_ca_issuers(&current_cert_der)? else {
            debug!("no AIA found - reached end of AIA chain");
            break;
        };
        debug!("downloading parent cert from: {url}");
        let parent_der = download_cert(&url)?;
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

/// Download CRLs for given certificates
fn download_crls_for_certs(certs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    debug!("downloading CRLs from device-provided cert chain...");

    let mut crls = Vec::new();

    for cert_der in certs {
        let Some(crl) = download_crl_for_cert(cert_der).context("failed to download CRL")? else {
            continue;
        };
        crls.push(crl);
    }
    Ok(crls)
}

/// Download CRL for verifier-provided root CA
fn download_crl_for_cert(cert: &[u8]) -> Result<Option<Vec<u8>>> {
    let crl_urls = extract_crl_urls(cert)?;
    if crl_urls.is_empty() {
        debug!("verifier root CA has no CRL DP - will skip root CA CRL check");
        return Ok(None);
    }

    download_first_available_crl(&crl_urls).map(Some)
}

/// Download first available CRL from a list of URLs
fn download_first_available_crl(urls: &[String]) -> Result<Vec<u8>> {
    for url in urls {
        debug!("downloading CRL from {url}");
        match download_crl(url) {
            Ok(crl) => {
                return Ok(crl);
            }
            Err(e) => {
                warn!("✗ failed to download CRL from {url}: {e:?}");
                continue;
            }
        }
    }
    bail!("failed to download CRL")
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

fn extract_certs_webpki(cert_pem: &[u8]) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    use ::pem::parse_many;

    let pem_items = parse_many(cert_pem).context("failed to parse PEM")?;

    let certs = pem_items
        .into_iter()
        .map(|pem| rustls_pki_types::CertificateDer::from(pem.into_contents()))
        .collect();

    Ok(certs)
}

fn download_crl(url: &str) -> Result<Vec<u8>> {
    debug!("downloading CRL from {url}");

    let response =
        reqwest::blocking::get(url).context(format!("failed to download CRL from {url}"))?;

    if !response.status().is_success() {
        bail!("CRL download failed with status: {}", response.status());
    }

    let crl_bytes = response
        .bytes()
        .context("failed to read CRL response body")?
        .to_vec();

    debug!("downloaded {} bytes CRL from {}", crl_bytes.len(), url);

    Ok(crl_bytes)
}

fn extract_crl_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    use x509_parser::extensions::ParsedExtension;

    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;

    let mut crl_urls = Vec::new();

    for ext in cert.extensions() {
        let ParsedExtension::CRLDistributionPoints(crl_dist_points) = ext.parsed_extension() else {
            continue;
        };
        for dist_point in crl_dist_points.points.iter() {
            let Some(dist_point_name) = &dist_point.distribution_point else {
                continue;
            };

            let DistributionPointName::FullName(names) = dist_point_name else {
                continue;
            };
            for name in names.iter() {
                let x509_parser::extensions::GeneralName::URI(uri) = name else {
                    continue;
                };
                crl_urls.push(uri.to_string());
                debug!("found CRL URL: {uri}");
            }
        }
    }

    if crl_urls.is_empty() {
        debug!("no CRL Distribution Points found in certificate");
    }

    Ok(crl_urls)
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

fn download_cert(url: &str) -> Result<Vec<u8>> {
    debug!("downloading certificate from {url}");

    let response = reqwest::blocking::get(url)
        .context(format!("failed to download certificate from {url}"))?;

    if !response.status().is_success() {
        bail!(
            "certificate download failed with status: {}",
            response.status()
        );
    }

    let cert_bytes = response
        .bytes()
        .context("failed to read certificate response body")?
        .to_vec();

    debug!(
        "downloaded {} bytes certificate from {}",
        cert_bytes.len(),
        url
    );

    Ok(cert_bytes)
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
