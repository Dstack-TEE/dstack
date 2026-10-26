// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Bounded download of PKI collateral (issuer certificates and CRLs).
//!
//! Collateral URLs come from certificates that have not been verified yet, so
//! whoever supplies the certificate chooses them. The endpoints are untrusted
//! transport: everything they serve still has to chain to a pinned root CA.
//! What they must not decide is how much work one verification does, so a
//! [`Fetcher`] spends a fixed budget of time, requests and bytes, nor where the
//! verifier connects to, so it only contacts [`AllowedHosts`].

use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};
use reqwest::{redirect, Url};
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
const MAX_REDIRECTS: usize = 5;

/// Where the vendors publish the collateral their certificates point to.
pub const DEFAULT_ALLOWED_HOSTS: &[&str] = &[
    // GCP vTPM: Google Private CA serves the AK chain and its CRLs.
    "privateca-content-*.storage.googleapis.com",
    // AWS Nitro Enclaves and NitroTPM CRLs.
    "aws-nitro-enclaves-crl.s3.amazonaws.com",
    "crl-*-aws-nitro-enclaves.s3.*.amazonaws.com",
];

/// Host patterns collateral may be fetched from. A `*` matches one or more
/// characters within a single DNS label.
#[derive(Debug, Clone)]
pub struct AllowedHosts(Vec<String>);

impl AllowedHosts {
    pub fn new(patterns: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self(
            patterns
                .into_iter()
                .map(|p| p.as_ref().to_ascii_lowercase())
                .collect(),
        )
    }

    fn check(&self, url: &Url) -> Result<()> {
        ensure!(
            matches!(url.scheme(), "http" | "https"),
            "unsupported URL scheme in {url}"
        );
        let host = url.host_str().context("URL has no host")?;
        ensure!(
            self.0.iter().any(|pattern| host_matches(pattern, host)),
            "collateral host {host} is not allowed"
        );
        Ok(())
    }
}

impl Default for AllowedHosts {
    fn default() -> Self {
        Self::new(DEFAULT_ALLOWED_HOSTS)
    }
}

fn host_matches(pattern: &str, host: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == host,
        Some((prefix, rest)) => {
            let Some(host) = host.strip_prefix(prefix) else {
                return false;
            };
            let label_len = host.find('.').unwrap_or(host.len());
            (1..=label_len).any(|n| host_matches(rest, &host[n..]))
        }
    }
}

/// Downloads collateral for one verification within a fixed budget.
pub struct Fetcher {
    client: reqwest::Client,
    allowed_hosts: AllowedHosts,
    deadline: Instant,
    requests_left: usize,
    bytes_left: usize,
}

impl Fetcher {
    pub fn new(allowed_hosts: &AllowedHosts) -> Result<Self> {
        let redirect_hosts = allowed_hosts.clone();
        let redirects = redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() > MAX_REDIRECTS {
                attempt.error("too many redirects")
            } else if let Err(e) = redirect_hosts.check(attempt.url()) {
                attempt.error(e)
            } else {
                attempt.follow()
            }
        });
        Ok(Self {
            client: reqwest::Client::builder()
                .redirect(redirects)
                .build()
                .context("failed to build HTTP client")?,
            allowed_hosts: allowed_hosts.clone(),
            deadline: Instant::now() + TOTAL_TIMEOUT,
            requests_left: MAX_REQUESTS,
            bytes_left: MAX_BYTES,
        })
    }

    /// GET `url`, charging the request, its time and its body to the budget.
    pub async fn download(&mut self, url: &str) -> Result<Vec<u8>> {
        let url = Url::parse(url).with_context(|| format!("invalid URL {url}"))?;
        self.allowed_hosts.check(&url)?;
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
            .get(url.clone())
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

    fn local() -> AllowedHosts {
        AllowedHosts::new(["127.0.0.1"])
    }

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
        let mut fetcher = Fetcher::new(&local()).unwrap();
        for _ in 0..MAX_REQUESTS {
            fetcher.download(&url).await.unwrap_err();
        }
        let err = fetcher.download(&url).await.unwrap_err();
        assert!(format!("{err:#}").contains("requests"), "{err:#}");
    }

    #[tokio::test]
    async fn downloaded_bytes_are_bounded() {
        let url = serve(Reply::Endless).await;
        let err = Fetcher::new(&local())
            .unwrap()
            .download(&url)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("bytes"), "{err:#}");
    }

    #[tokio::test]
    async fn total_time_is_bounded() {
        let url = serve(Reply::Drip).await;
        let mut fetcher = Fetcher {
            deadline: Instant::now() + Duration::from_secs(1),
            ..Fetcher::new(&local()).unwrap()
        };
        let started = Instant::now();
        fetcher.download(&url).await.unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn only_allowed_hosts_are_contacted() {
        let url = serve(Reply::NotFound).await;
        let mut fetcher = Fetcher::new(&AllowedHosts::default()).unwrap();
        let err = fetcher.download(&url).await.unwrap_err();
        assert!(format!("{err:#}").contains("not allowed"), "{err:#}");
        assert_eq!(fetcher.requests_left, MAX_REQUESTS);
    }

    #[test]
    fn host_patterns_match_within_one_label() {
        let hosts = AllowedHosts::default();
        for (url, allowed) in [
            (
                "http://privateca-content-62d7.storage.googleapis.com/a/ca.crt",
                true,
            ),
            (
                "http://crl-us-east-1-aws-nitro-enclaves.s3.us-east-1.amazonaws.com/c",
                true,
            ),
            (
                "http://aws-nitro-enclaves-crl.s3.amazonaws.com/crl/x.crl",
                true,
            ),
            ("http://privateca-content-.storage.googleapis.com/", false),
            (
                "http://privateca-content-x.evil.com.storage.googleapis.com/",
                false,
            ),
            (
                "http://privateca-content-x.storage.googleapis.com.evil.com/",
                false,
            ),
            (
                "http://evil.com/privateca-content-x.storage.googleapis.com",
                false,
            ),
            ("http://169.254.169.254/latest/meta-data/", false),
            ("file:///etc/passwd", false),
        ] {
            assert_eq!(
                hosts.check(&Url::parse(url).unwrap()).is_ok(),
                allowed,
                "{url}"
            );
        }
    }
}
