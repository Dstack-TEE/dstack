// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Failover across interchangeable collateral endpoints.
//!
//! Attestation verification depends on collateral that only the vendor
//! publishes: Intel's PCCS and AMD's KDS. Both were single points of failure
//! for verification until now -- one URL each, and no answer meant no
//! verification. AMD KDS in particular is a single global endpoint with no
//! official mirror, and it has been unreachable for hours at a time.
//!
//! Nothing here relaxes verification. Collateral is signed by the vendor and
//! checked against roots compiled into the binary, so an endpoint can serve a
//! stale or absent answer but cannot serve a forged one; which endpoint
//! answered has no bearing on whether the signature checks pass.

use anyhow::{bail, Context, Result};
use dcap_qvl::{
    collateral::{CollateralClient, PHALA_PCCS_URL},
    verify::VerifiedReport,
    QuoteCollateralV3,
};
use dstack_types::UrlList;
use sev_snp_qvl::{AmdKdsClient, AMD_KDS_DEFAULT_BASE_URL};

/// Build an AMD KDS client over the configured endpoints, or the vendor
/// default when none are configured.
pub(crate) fn amd_kds_client(urls: &UrlList) -> Result<AmdKdsClient> {
    if urls.is_empty() {
        return AmdKdsClient::with_base_url(AMD_KDS_DEFAULT_BASE_URL);
    }
    AmdKdsClient::with_base_urls(urls.as_slice())
}

/// Intel PCCS access over one or more interchangeable endpoints.
///
/// Endpoints are tried in order and the first success wins.
///
/// Unlike the AMD KDS client, this fails over on *any* error rather than only
/// on ones that look transient. `dcap-qvl` returns `anyhow::Error`, so there is
/// no status code to classify on, and inventing a classifier by matching error
/// strings would be worse than the thing it replaces. The cost of the coarser
/// rule is bounded: a genuinely absent FMSPC costs one extra request per
/// configured endpoint, and configuring an endpoint list is opt-in.
#[derive(Clone)]
pub struct PccsClient {
    clients: Vec<(String, CollateralClient)>,
}

impl PccsClient {
    pub fn new(urls: &UrlList) -> Result<Self> {
        let urls: Vec<&str> = if urls.is_empty() {
            vec![PHALA_PCCS_URL]
        } else {
            urls.as_slice().iter().map(String::as_str).collect()
        };
        let clients = urls
            .into_iter()
            .map(|url| {
                CollateralClient::with_default_http(url)
                    .with_context(|| format!("failed to create PCCS client for {url}"))
                    .map(|client| (url.to_string(), client))
            })
            .collect::<Result<Vec<_>>>()?;
        if clients.is_empty() {
            bail!("PCCS endpoint list is empty");
        }
        Ok(Self { clients })
    }

    pub async fn fetch(&self, quote: &[u8]) -> Result<QuoteCollateralV3> {
        self.failover("fetch", |client| client.fetch(quote)).await
    }

    pub async fn fetch_and_verify(&self, quote: &[u8]) -> Result<VerifiedReport> {
        self.failover("fetch_and_verify", |client| client.fetch_and_verify(quote))
            .await
    }

    async fn failover<'a, T, F, Fut>(&'a self, label: &str, mut call: F) -> Result<T>
    where
        F: FnMut(&'a CollateralClient) -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut errors: Vec<String> = Vec::new();
        for (url, client) in &self.clients {
            match call(client).await {
                Ok(value) => return Ok(value),
                Err(err) => errors.push(format!("{url}: {err:#}")),
            }
        }
        match errors.len() {
            0 => bail!("PCCS {label} had no endpoint to try"),
            1 => bail!("PCCS {label} failed: {}", errors[0]),
            n => bail!(
                "PCCS {label} failed on all {n} endpoints: {}",
                errors.join("; ")
            ),
        }
    }
}
