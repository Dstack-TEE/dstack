// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::debug;

use crate::dns01_client::Record;

use super::Dns01Api;

const DEFAULT_CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

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

        let client = Client::new();
        let url = format!("{api_url}/zones");

        let per_page = 50u32;
        let mut page = 1u32;
        let mut zones: HashMap<String, String> = HashMap::new();
        let mut total_pages = 1u32;

        while page <= total_pages {
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

            total_pages = zones_response.result_info.total_pages;
            for z in zones_response.result {
                zones.insert(z.name.to_lowercase(), z.id);
            }

            page += 1;
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
        let client = Client::new();
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
        let client = Client::new();
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
        let client = Client::new();
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
