// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! Collateral retrieval module
//!
//! Extracts CRL distribution points from the device-provided cert chain and
//! downloads CRLs for revocation checking, similar to dcap-qvl/tpm-qvl.

use anyhow::{bail, Context, Result};
use tracing::{debug, warn};
use x509_parser::{extensions::DistributionPointName, prelude::*};

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

    let certs = build_chain_from_doc(&doc);
    let crls = download_crls_for_certs(&certs).await?;

    let root_ca_crl = {
        let root_ca_der =
            extract_certs_webpki(root_ca_pem.as_bytes()).context("failed to parse root CA PEM")?;
        if root_ca_der.len() != 1 {
            bail!("expected 1 root CA, found {}", root_ca_der.len());
        }
        download_crl_for_cert(&root_ca_der[0]).await?
    };

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

async fn download_crls_for_certs(certs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
    debug!("downloading CRLs from device-provided cert chain...");

    let mut crls = Vec::new();

    for cert_der in certs {
        let Some(crl) = download_crl_for_cert(cert_der)
            .await
            .context("failed to download CRL")?
        else {
            continue;
        };
        crls.push(crl);
    }
    Ok(crls)
}

async fn download_crl_for_cert(cert: &[u8]) -> Result<Option<Vec<u8>>> {
    let crl_urls = extract_crl_urls(cert)?;
    if crl_urls.is_empty() {
        debug!("no CRL Distribution Points found in certificate");
        return Ok(None);
    }

    download_first_available_crl(&crl_urls).await.map(Some)
}

async fn download_first_available_crl(urls: &[String]) -> Result<Vec<u8>> {
    for url in urls {
        debug!("downloading CRL from {url}");
        match download_crl(url).await {
            Ok(crl) => return Ok(crl),
            Err(e) => {
                warn!("✗ failed to download CRL from {url}: {e:?}");
                continue;
            }
        }
    }
    bail!("failed to download CRL")
}

fn extract_certs_webpki(cert_pem: &[u8]) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let pem_items = ::pem::parse_many(cert_pem).context("failed to parse PEM")?;
    let certs = pem_items
        .into_iter()
        .map(|pem| rustls_pki_types::CertificateDer::from(pem.into_contents()))
        .collect();
    Ok(certs)
}

async fn download_crl(url: &str) -> Result<Vec<u8>> {
    debug!("downloading CRL from {url}");

    let response = reqwest::get(url)
        .await
        .context(format!("failed to download CRL from {url}"))?;

    if !response.status().is_success() {
        bail!("CRL download failed with status: {}", response.status());
    }

    let crl_bytes = response
        .bytes()
        .await
        .context("failed to read CRL response body")?
        .to_vec();

    debug!("downloaded {} bytes CRL from {}", crl_bytes.len(), url);

    Ok(crl_bytes)
}

fn extract_crl_urls(cert_der: &[u8]) -> Result<Vec<String>> {
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

    Ok(crl_urls)
}
