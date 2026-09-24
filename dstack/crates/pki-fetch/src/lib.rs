// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded download of PKI collateral (issuer certificates and CRLs).
//!
//! Collateral URLs come from certificates that have not been verified yet, so
//! whoever supplies the certificate chooses them. The endpoints are untrusted
//! transport: everything they serve still has to chain to a pinned root CA.
//! What they must not decide is how much work one verification does, so a
//! [`Fetcher`] spends a fixed budget of time, requests and bytes.

use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use tracing::{debug, warn};
use x509_parser::{
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    prelude::*,
};

const TOTAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Lets a hanging endpoint fall through to the next one within the budget.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUESTS: usize = 16;
const MAX_BYTES: usize = 4 * 1024 * 1024;

/// Downloads collateral for one verification within a fixed budget.
pub struct Fetcher {
    client: reqwest::Client,
    deadline: Instant,
    requests_left: usize,
    bytes_left: usize,
}

impl Fetcher {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .build()
                .context("failed to build HTTP client")?,
            deadline: Instant::now() + TOTAL_TIMEOUT,
            requests_left: MAX_REQUESTS,
            bytes_left: MAX_BYTES,
        })
    }

    /// GET `url`, charging the request, its time and its body to the budget.
    pub async fn download(&mut self, url: &str) -> Result<Vec<u8>> {
        ensure!(
            self.requests_left > 0,
            "collateral fetch exceeded {MAX_REQUESTS} requests"
        );
        self.requests_left -= 1;
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "collateral fetch exceeded {TOTAL_TIMEOUT:?}"
        );
        debug!("downloading {url}");
        let mut response = self
            .client
            .get(url)
            .timeout(remaining.min(REQUEST_TIMEOUT))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .with_context(|| format!("failed to download {url}"))?;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .with_context(|| format!("failed to read response body from {url}"))?
        {
            ensure!(
                chunk.len() <= self.bytes_left,
                "collateral fetch exceeded {MAX_BYTES} bytes"
            );
            self.bytes_left -= chunk.len();
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Download the CRLs of every certificate in `certs` that names one.
    pub async fn crls(&mut self, certs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>> {
        let mut crls = Vec::new();
        for cert in certs {
            crls.extend(self.crl(cert).await?);
        }
        Ok(crls)
    }

    /// Download the CRL of the single root CA in `root_ca_pem`, if it names one.
    pub async fn root_ca_crl(&mut self, root_ca_pem: &str) -> Result<Option<Vec<u8>>> {
        let roots = ::pem::parse_many(root_ca_pem).context("failed to parse root CA PEM")?;
        let [root] = roots.as_slice() else {
            bail!("expected 1 root CA, found {}", roots.len());
        };
        self.crl(root.contents()).await
    }

    /// Download the CRL from the first reachable distribution point of `cert`.
    async fn crl(&mut self, cert: &[u8]) -> Result<Option<Vec<u8>>> {
        let urls = crl_urls(cert)?;
        if urls.is_empty() {
            return Ok(None);
        }
        for url in &urls {
            match self.download(url).await {
                Ok(crl) => return Ok(Some(crl)),
                Err(e) => warn!("failed to download CRL: {e:#}"),
            }
        }
        bail!("no CRL distribution point was reachable: {urls:?}")
    }
}

fn crl_urls(cert_der: &[u8]) -> Result<Vec<String>> {
    let (_, cert) = X509Certificate::from_der(cert_der).context("failed to parse certificate")?;
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() else {
            continue;
        };
        for point in &points.points {
            let Some(DistributionPointName::FullName(names)) = &point.distribution_point else {
                continue;
            };
            for name in names {
                if let GeneralName::URI(uri) = name {
                    urls.push(uri.to_string());
                }
            }
        }
    }
    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[derive(Clone, Copy)]
    enum Reply {
        NotFound,
        Endless,
        Drip,
    }

    async fn serve(reply: Reply) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let _ = stream.read(&mut [0; 1024]).await;
                    let _ = match reply {
                        Reply::NotFound => {
                            stream
                                .write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\n\r\n")
                                .await
                        }
                        Reply::Endless => {
                            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
                            while stream.write_all(&[0; 64 * 1024]).await.is_ok() {}
                            Ok(())
                        }
                        Reply::Drip => {
                            let _ = stream
                                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n")
                                .await;
                            while stream.write_all(b"x").await.is_ok() {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                            }
                            Ok(())
                        }
                    };
                });
            }
        });
        url
    }

    #[tokio::test]
    async fn request_count_is_bounded() {
        let url = serve(Reply::NotFound).await;
        let mut fetcher = Fetcher::new().unwrap();
        for _ in 0..MAX_REQUESTS {
            fetcher.download(&url).await.unwrap_err();
        }
        let err = fetcher.download(&url).await.unwrap_err();
        assert!(format!("{err:#}").contains("requests"), "{err:#}");
    }

    #[tokio::test]
    async fn downloaded_bytes_are_bounded() {
        let url = serve(Reply::Endless).await;
        let err = Fetcher::new().unwrap().download(&url).await.unwrap_err();
        assert!(format!("{err:#}").contains("bytes"), "{err:#}");
    }

    #[tokio::test]
    async fn total_time_is_bounded() {
        let url = serve(Reply::Drip).await;
        let mut fetcher = Fetcher {
            deadline: Instant::now() + Duration::from_secs(1),
            ..Fetcher::new().unwrap()
        };
        let started = Instant::now();
        fetcher.download(&url).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
    }
}
