// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, warn};

use crate::dns01_client::Record;

use super::Dns01Api;

const DEFAULT_CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

/// How long a single call to the DNS provider may take.
///
/// `reqwest` has no default timeout, and `api_url` is an operator-settable
/// address that the gateway contacts while holding the cluster-wide ACME
/// rotation lock. A provider that accepts the connection and then says nothing
/// would park that lock, and with it every renewal in the cluster, forever.
const API_TIMEOUT: Duration = Duration::from_secs(30);

/// How many pages of zones are walked while resolving `base_domain`.
///
/// The page count comes out of the response body, so the number of requests
/// this loop makes is otherwise the provider's to choose. At the 50 zones a
/// page this asks for, the cap covers 5000 zones on one account.
const MAX_ZONE_PAGES: u32 = 100;

fn api_client(timeout: Duration) -> Result<Client> {
    Client::builder()
        .timeout(timeout)
        .build()
        .context("failed to build the cloudflare api client")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudflareClient {
    zone_id: String,
    api_token: String,
    #[serde(default = "default_api_url")]
    api_url: String,
}

fn default_api_url() -> String {
    DEFAULT_CLOUDFLARE_API_URL.to_string()
}

#[derive(Deserialize)]
struct Response {
    result: ApiResult,
}

#[derive(Deserialize)]
struct ApiResult {
    id: String,
}

#[derive(Deserialize, Debug)]
struct CloudflareListResponse {
    result: Vec<Record>,
    result_info: ResultInfo,
}

#[derive(Deserialize, Debug)]
struct ResultInfo {
    total_pages: u32,
}

#[derive(Deserialize, Debug)]
struct ZoneInfo {
    id: String,
    name: String,
}

#[derive(Deserialize, Debug)]
struct ZonesResultInfo {
    page: u32,
    per_page: u32,
    total_pages: u32,
    count: u32,
    total_count: u32,
}

impl CloudflareClient {
    pub async fn new(
        base_domain: String,
        api_token: String,
        api_url: Option<String>,
    ) -> Result<Self> {
        let api_url = api_url.unwrap_or_else(|| DEFAULT_CLOUDFLARE_API_URL.to_string());
        let zone_id = Self::resolve_zone_id(&api_token, &base_domain, &api_url).await?;
        Ok(Self {
            zone_id,
            api_token,
            api_url,
        })
    }

    async fn resolve_zone_id(api_token: &str, base_domain: &str, api_url: &str) -> Result<String> {
        let base = base_domain
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_lowercase();

        let client = api_client(API_TIMEOUT)?;
        let url = format!("{api_url}/zones");

        let per_page = 50u32;
        let mut zones: HashMap<String, String> = HashMap::new();

        for page in 1..=MAX_ZONE_PAGES {
            debug!(url = %url, base_domain = %base, page, per_page, "cloudflare list zones request");

            let response = client
                .get(&url)
                .header("Authorization", format!("Bearer {api_token}"))
                .query(&[
                    ("page", page.to_string()),
                    ("per_page", per_page.to_string()),
                ])
                .send()
                .await
                .context("failed to list zones")?;

            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed to read zones response body")?;
            if !status.is_success() {
                bail!("failed to list zones: {body}");
            }

            #[derive(Deserialize, Debug)]
            struct ZonesPageResponse {
                result: Vec<ZoneInfo>,
                result_info: ZonesResultInfo,
            }

            let zones_response: ZonesPageResponse =
                serde_json::from_str(&body).context("failed to parse zones response")?;

            let zone_names = zones_response
                .result
                .iter()
                .map(|z| z.name.as_str())
                .collect::<Vec<_>>();
            debug!(
                url = %url,
                status = %status,
                page = zones_response.result_info.page,
                per_page = zones_response.result_info.per_page,
                count = zones_response.result_info.count,
                total_count = zones_response.result_info.total_count,
                total_pages = zones_response.result_info.total_pages,
                zones = ?zone_names,
                "cloudflare list zones response"
            );

            let total_pages = zones_response.result_info.total_pages;
            for z in zones_response.result {
                zones.insert(z.name.to_lowercase(), z.id);
            }

            if page >= total_pages {
                break;
            }
            if page == MAX_ZONE_PAGES {
                warn!(
                    "stopped listing zones at page {MAX_ZONE_PAGES} of {total_pages}; \
                     a zone past that point cannot be resolved"
                );
            }
        }

        let parts: Vec<&str> = base.split('.').collect();
        for i in 0..parts.len() {
            let candidate = parts[i..].join(".");
            if let Some(zone_id) = zones.get(&candidate) {
                debug!(base_domain = %base, zone = %candidate, zone_id = %zone_id, "resolved cloudflare zone");
                return Ok(zone_id.clone());
            }
        }

        bail!("no matching zone found for base_domain: {base_domain}")
    }

    async fn add_record(&self, record: &impl Serialize) -> Result<Response> {
        let client = api_client(API_TIMEOUT)?;
        let url = format!("{}/zones/{}/dns_records", self.api_url, self.zone_id);
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(record)
            .send()
            .await
            .context("failed to send add_record request")?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read add_record response body")?;
        if !status.is_success() {
            anyhow::bail!("failed to add record: {body}");
        }
        let response = serde_json::from_str(&body).context("failed to parse response")?;
        Ok(response)
    }

    async fn remove_record_inner(&self, record_id: &str) -> Result<()> {
        let client = api_client(API_TIMEOUT)?;
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            self.api_url, self.zone_id, record_id
        );

        debug!(url = %url, "cloudflare remove_record request");

        let response = client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        let status = response.status();
        let body = response
            .text()
            .await
            .context("failed to read remove_record response body")?;
        if !status.is_success() {
            anyhow::bail!("failed to remove acme challenge: {body}");
        }
        Ok(())
    }

    async fn get_records_inner(&self, domain: &str) -> Result<Vec<Record>> {
        let client = api_client(API_TIMEOUT)?;
        let url = format!("{}/zones/{}/dns_records", self.api_url, self.zone_id);

        let per_page = 100u32;
        let mut records = Vec::new();
        let target = domain.trim_end_matches('.');

        for page in 1..20 {
            // Safety limit to prevent infinite loops
            let response = client
                .get(&url)
                .header("Authorization", format!("Bearer {}", self.api_token))
                .query(&[
                    ("name", domain),
                    ("page", &page.to_string()),
                    ("per_page", &per_page.to_string()),
                ])
                .send()
                .await?;

            let status = response.status();
            let body = response
                .text()
                .await
                .context("failed to read get_records response body")?;

            if !status.is_success() {
                anyhow::bail!("failed to get dns records: {body}");
            }

            let response: CloudflareListResponse =
                serde_json::from_str(&body).context("failed to parse response")?;

            records.extend(response.result.into_iter().filter(|record| {
                record
                    .name
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(target)
            }));

            if page >= response.result_info.total_pages {
                break;
            }
        }

        Ok(records)
    }
}

impl Dns01Api for CloudflareClient {
    async fn remove_record(&self, record_id: &str) -> Result<()> {
        self.remove_record_inner(record_id).await
    }

    async fn remove_txt_records(&self, domain: &str) -> Result<()> {
        let records = self.get_records_inner(domain).await?;
        let txt_records = records
            .into_iter()
            .filter(|r| r.r#type == "TXT")
            .collect::<Vec<_>>();
        let ids = txt_records.iter().map(|r| r.id.clone()).collect::<Vec<_>>();
        debug!(domain = %domain, zone_id = %self.zone_id, count = txt_records.len(), ids = ?ids, "removing txt records");

        for record in txt_records {
            debug!(domain = %domain, id = %record.id, "removing txt record");
            self.remove_record_inner(&record.id).await?;
        }
        Ok(())
    }

    async fn add_txt_record(&self, domain: &str, content: &str, ttl: u32) -> Result<String> {
        let response = self
            .add_record(&json!({
                "type": "TXT",
                "name": domain,
                "content": content,
                "ttl": ttl,
            }))
            .await?;
        Ok(response.result.id)
    }

    async fn add_caa_record(
        &self,
        domain: &str,
        flags: u8,
        tag: &str,
        value: &str,
    ) -> Result<String> {
        let response = self
            .add_record(&json!({
                "type": "CAA",
                "name": domain,
                "data": {
                    "flags": flags,
                    "tag": tag,
                    "value": value
                }
            }))
            .await?;
        Ok(response.result.id)
    }

    async fn get_records(&self, domain: &str) -> Result<Vec<Record>> {
        self.get_records_inner(domain).await
    }
}

#[cfg(test)]
mod tests {
    #![cfg(not(test))]

    use super::*;

    impl CloudflareClient {
        #[cfg(test)]
        async fn get_txt_records(&self, domain: &str) -> Result<Vec<Record>> {
            Ok(self
                .get_records(domain)
                .await?
                .into_iter()
                .filter(|r| r.r#type == "TXT")
                .collect())
        }

        #[cfg(test)]
        async fn get_caa_records(&self, domain: &str) -> Result<Vec<Record>> {
            Ok(self
                .get_records(domain)
                .await?
                .into_iter()
                .filter(|r| r.r#type == "CAA")
                .collect())
        }
    }

    async fn create_client() -> CloudflareClient {
        CloudflareClient::new(
            std::env::var("TEST_DOMAIN").expect("TEST_DOMAIN not set"),
            std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN not set"),
            std::env::var("CLOUDFLARE_API_URL").ok(),
        )
        .await
        .unwrap()
    }

    fn random_subdomain() -> String {
        format!(
            "_acme-challenge.{}.{}",
            rand::random::<u64>(),
            std::env::var("TEST_DOMAIN").expect("TEST_DOMAIN not set"),
        )
    }

    #[tokio::test]
    async fn can_add_txt_record() {
        let client = create_client().await;
        let subdomain = random_subdomain();
        println!("subdomain: {}", subdomain);
        let record_id = client
            .add_txt_record(&subdomain, "1234567890", 60)
            .await
            .unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert_eq!(record[0].id, record_id);
        assert_eq!(record[0].content, "1234567890");
        client.remove_record(&record_id).await.unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert!(record.is_empty());
    }

    #[tokio::test]
    async fn can_remove_txt_record() {
        let client = create_client().await;
        let subdomain = random_subdomain();
        println!("subdomain: {}", subdomain);
        let record_id = client
            .add_txt_record(&subdomain, "1234567890", 60)
            .await
            .unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert_eq!(record[0].id, record_id);
        assert_eq!(record[0].content, "1234567890");
        client.remove_txt_records(&subdomain).await.unwrap();
        let record = client.get_txt_records(&subdomain).await.unwrap();
        assert!(record.is_empty());
    }

    #[tokio::test]
    async fn can_add_caa_record() {
        let client = create_client().await;
        let subdomain = random_subdomain();
        let record_id = client
            .add_caa_record(&subdomain, 0, "issue", "letsencrypt.org;")
            .await
            .unwrap();
        let record = client.get_caa_records(&subdomain).await.unwrap();
        assert_eq!(record[0].id, record_id);
        assert_eq!(record[0].content, "0 issue \"letsencrypt.org;\"");
        client.remove_record(&record_id).await.unwrap();
        let record = client.get_caa_records(&subdomain).await.unwrap();
        assert!(record.is_empty());
    }
}

#[cfg(test)]
mod zone_discovery_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A page of zones that says there are a million more of them.
    const A_MILLION_PAGES: &str = r#"{"result":[],"result_info":{"page":1,"per_page":50,"total_pages":1000000,"count":0,"total_count":0}}"#;

    /// A stand-in provider that answers every request with the same page and
    /// counts how many it was asked for.
    async fn serve(body: &'static str) -> (String, Arc<AtomicU32>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicU32::new(0));
        let counter = requests.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    // Read to the end of the request head, so the response is
                    // not written into a peer that is still sending.
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        match socket.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(read) => request.extend_from_slice(&buffer[..read]),
                        }
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.ok();
                    socket.shutdown().await.ok();
                });
            }
        });
        (format!("http://{address}"), requests)
    }

    #[tokio::test]
    async fn zone_discovery_stops_at_the_page_cap() {
        let (api_url, requests) = serve(A_MILLION_PAGES).await;
        let result = tokio::time::timeout(
            Duration::from_secs(10),
            CloudflareClient::new("example.com".into(), "token".into(), Some(api_url)),
        )
        .await
        .expect("zone discovery never finished: the page count is the provider's to choose");
        assert!(
            result.is_err(),
            "no zone on the listing matches, so discovery has to fail"
        );
        let made = requests.load(Ordering::Relaxed);
        assert!(
            made <= MAX_ZONE_PAGES,
            "{made} requests for a cap of {MAX_ZONE_PAGES} pages"
        );
    }

    #[tokio::test]
    async fn an_api_call_gives_up_on_a_provider_that_never_answers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _accepted = listener.accept().await;
            std::future::pending::<()>().await;
        });
        let client = api_client(Duration::from_millis(200)).unwrap();
        let err = client
            .get(format!("http://{address}/zones"))
            .send()
            .await
            .expect_err("a silent provider must not hold the call open");
        assert!(err.is_timeout(), "{err:?}");
    }
}
