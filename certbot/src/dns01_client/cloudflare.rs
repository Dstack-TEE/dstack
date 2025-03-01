use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::dns01_client::Record;

use super::Dns01Api;

const CLOUDFLARE_API_URL: &str = "https://api.cloudflare.com/client/v4";

#[derive(Debug, Serialize, Deserialize)]
pub struct CloudflareClient {
    zone_id: String,
    api_token: String,
}

#[derive(Deserialize)]
struct Response {
    result: ApiResult,
}

#[derive(Deserialize)]
struct ApiResult {
    id: String,
}

impl CloudflareClient {
    pub fn new(zone_id: String, api_token: String) -> Self {
        Self { zone_id, api_token }
    }

    async fn add_record(&self, record: &impl Serialize) -> Result<Response> {
        let client = Client::new();
        let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_URL, self.zone_id);
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&record)
            .send()
            .await
            .context("failed to send add_record request")?;
        if !response.status().is_success() {
            anyhow::bail!("failed to add record: {}", response.text().await?);
        }
        let response = response.json().await.context("failed to parse response")?;
        Ok(response)
    }
}

impl Dns01Api for CloudflareClient {
    async fn remove_record(&self, record_id: &str) -> Result<()> {
        let client = Client::new();
        let url = format!(
            "{}/zones/{}/dns_records/{}",
            CLOUDFLARE_API_URL, self.zone_id, record_id
        );

        let response = client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!(
                "failed to remove acme challenge: {}",
                response.text().await?
            );
        }

        Ok(())
    }

    async fn add_txt_record(&self, domain: &str, content: &str) -> Result<String> {
        let response = self
            .add_record(&json!({
                "type": "TXT",
                "name": domain,
                "content": content,
                "ttl": 120
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
                "ttl": 120,
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
        let client = Client::new();
        let url = format!("{}/zones/{}/dns_records", CLOUDFLARE_API_URL, self.zone_id);

        let response = client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("failed to get dns records: {}", response.text().await?);
        }

        #[derive(Deserialize, Debug)]
        struct CloudflareResponse {
            result: Vec<Record>,
        }

        let response: CloudflareResponse =
            response.json().await.context("failed to parse response")?;

        let records = response
            .result
            .into_iter()
            .filter(|record| record.name == domain)
            .collect();
        Ok(records)
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

    fn create_client() -> CloudflareClient {
        CloudflareClient::new(
            std::env::var("CLOUDFLARE_ZONE_ID").expect("CLOUDFLARE_ZONE_ID not set"),
            std::env::var("CLOUDFLARE_API_TOKEN").expect("CLOUDFLARE_API_TOKEN not set"),
        )
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
        let client = create_client();
        let subdomain = random_subdomain();
        println!("subdomain: {}", subdomain);
        let record_id = client
            .add_txt_record(&subdomain, "1234567890")
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
        let client = create_client();
        let subdomain = random_subdomain();
        println!("subdomain: {}", subdomain);
        let record_id = client
            .add_txt_record(&subdomain, "1234567890")
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
        let client = create_client();
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
