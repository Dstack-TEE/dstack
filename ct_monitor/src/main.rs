// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;
use std::time::Duration;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::*;

const BASE_URL: &str = "https://crt.sh";

/// Quoted public key with TDX quote
#[derive(Debug, Deserialize)]
struct QuotedPublicKey {
    /// Hex-encoded public key
    public_key: String,
    /// JSON-encoded GetQuoteResponse
    quote: String,
}

/// GetQuoteResponse from guest-agent
#[derive(Debug, Deserialize)]
struct GetQuoteResponse {
    /// TDX quote (hex-encoded in JSON)
    #[serde(with = "hex_bytes")]
    quote: Vec<u8>,
    /// JSON-encoded event log
    event_log: String,
    /// VM configuration
    vm_config: String,
}

/// Request for dstack-verifier
#[derive(Debug, Serialize)]
struct VerificationRequest {
    quote: String,
    event_log: String,
    vm_config: String,
    pccs_url: Option<String>,
}

/// Response from dstack-verifier
#[derive(Debug, Deserialize)]
struct VerificationResponse {
    is_valid: bool,
    details: VerificationDetails,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct VerificationDetails {
    #[allow(dead_code)]
    quote_verified: bool,
    #[allow(dead_code)]
    event_log_verified: bool,
    #[allow(dead_code)]
    os_image_hash_verified: bool,
    report_data: Option<String>,
    app_info: Option<AppInfo>,
}

/// App info from verification response
#[derive(Debug, Deserialize)]
struct AppInfo {
    #[serde(with = "hex_bytes")]
    app_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    compose_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    os_image_hash: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct AcmeInfoResponse {
    #[allow(dead_code)]
    account_uri: String,
    #[allow(dead_code)]
    hist_keys: Vec<String>,
    quoted_hist_keys: Vec<QuotedPublicKey>,
}

struct Monitor {
    gateway_uri: String,
    verifier_url: String,
    pccs_url: Option<String>,
    base_domain: String,
    known_keys: BTreeSet<Vec<u8>>,
    last_checked: Option<u64>,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct CTLog {
    id: u64,
    issuer_ca_id: u64,
    issuer_name: String,
    common_name: String,
    name_value: String,
    not_before: String,
    not_after: String,
    serial_number: String,
    result_count: u64,
    entry_timestamp: String,
}

impl Monitor {
    /// Create a new monitor
    /// `gateway` format: `base_domain[:port]`, e.g., `example.com` or `example.com:8443`
    fn new(gateway: String, verifier_url: String, pccs_url: Option<String>) -> Result<Self> {
        let (base_domain, gateway_uri) = Self::parse_gateway(&gateway)?;
        validate_domain(&base_domain)?;
        Ok(Self {
            gateway_uri,
            verifier_url,
            pccs_url,
            base_domain,
            known_keys: BTreeSet::new(),
            last_checked: None,
            client: reqwest::Client::new(),
        })
    }

    /// Parse gateway input into base_domain and gateway URI
    /// Input: `base_domain[:port]`, e.g., `example.com` or `example.com:8443`
    /// Output: (base_domain, gateway_uri)
    fn parse_gateway(gateway: &str) -> Result<(String, String)> {
        let (base_domain, port) = match gateway.rsplit_once(':') {
            Some((domain, port_str)) => {
                // Validate port is a number
                let _: u16 = port_str.parse().context("invalid port number")?;
                (domain.to_string(), Some(port_str.to_string()))
            }
            None => (gateway.to_string(), None),
        };

        let gateway_uri = match port {
            Some(p) => format!("https://gateway.{}:{}", base_domain, p),
            None => format!("https://gateway.{}", base_domain),
        };

        Ok((base_domain, gateway_uri))
    }

    /// Compute expected report_data for a public key using zt-cert content type
    fn compute_expected_report_data(public_key: &[u8]) -> [u8; 64] {
        // Format: sha512("zt-cert:" + public_key)
        let mut hasher = Sha512::new();
        hasher.update(b"zt-cert:");
        hasher.update(public_key);
        hasher.finalize().into()
    }

    /// Verify a quoted public key using the verifier service
    /// Returns (public_key, app_info)
    async fn verify_quoted_key(&self, quoted_key: &QuotedPublicKey) -> Result<(Vec<u8>, AppInfo)> {
        let public_key =
            hex::decode(&quoted_key.public_key).context("invalid hex in public_key")?;

        if quoted_key.quote.is_empty() {
            bail!("empty quote for public key");
        }

        // Parse the GetQuoteResponse from the quote field
        let quote_response: GetQuoteResponse =
            serde_json::from_str(&quoted_key.quote).context("failed to parse quote response")?;

        // Build verification request
        let verify_request = VerificationRequest {
            quote: hex::encode(&quote_response.quote),
            event_log: quote_response.event_log,
            vm_config: quote_response.vm_config,
            pccs_url: self.pccs_url.clone(),
        };

        // Call verifier
        let verify_url = format!("{}/verify", self.verifier_url.trim_end_matches('/'));
        let response = self
            .client
            .post(&verify_url)
            .json(&verify_request)
            .send()
            .await
            .context("failed to call verifier")?;

        if !response.status().is_success() {
            bail!("verifier returned HTTP {}", response.status().as_u16());
        }

        let verify_response: VerificationResponse = response
            .json()
            .await
            .context("failed to parse verifier response")?;

        if !verify_response.is_valid {
            bail!(
                "quote verification failed: {}",
                verify_response.reason.unwrap_or_default()
            );
        }

        // Verify report_data matches expected value
        let expected_report_data = Self::compute_expected_report_data(&public_key);
        let expected_hex = hex::encode(expected_report_data);

        let actual_report_data = verify_response
            .details
            .report_data
            .context("verifier did not return report_data")?;

        if actual_report_data != expected_hex {
            bail!(
                "report_data mismatch: expected {}, got {}",
                expected_hex,
                actual_report_data
            );
        }

        let app_info = verify_response
            .details
            .app_info
            .context("verifier did not return app_info")?;

        Ok((public_key, app_info))
    }

    async fn refresh_known_keys(&mut self) -> Result<()> {
        let acme_info_url = format!(
            "{}/.dstack/acme-info",
            self.gateway_uri.trim_end_matches('/')
        );
        info!("fetching known public keys from {}", acme_info_url);

        let response = self
            .client
            .get(&acme_info_url)
            .send()
            .await
            .context("failed to fetch acme-info")?;

        if !response.status().is_success() {
            bail!(
                "failed to fetch acme-info: HTTP {}",
                response.status().as_u16()
            );
        }

        let info: AcmeInfoResponse = response
            .json()
            .await
            .context("failed to parse acme-info response")?;

        info!(
            "got {} quoted public keys, verifying...",
            info.quoted_hist_keys.len()
        );

        let mut verified_keys = BTreeSet::new();
        for (i, quoted_key) in info.quoted_hist_keys.iter().enumerate() {
            match self.verify_quoted_key(quoted_key).await {
                Ok((public_key, app_info)) => {
                    info!(
                        "✅ verified public key {}: {}",
                        i,
                        hex_fmt::HexFmt(&public_key)
                    );
                    info!("   app_id: {}", hex_fmt::HexFmt(&app_info.app_id));
                    info!(
                        "   compose_hash: {}",
                        hex_fmt::HexFmt(&app_info.compose_hash)
                    );
                    info!(
                        "   os_image_hash: {}",
                        hex_fmt::HexFmt(&app_info.os_image_hash)
                    );
                    verified_keys.insert(public_key);
                }
                Err(e) => {
                    warn!(
                        "⚠️ failed to verify public key {}: {}",
                        i,
                        hex_fmt::HexFmt(&quoted_key.public_key)
                    );
                    warn!("   error: {:#}", e);
                    // Continue with other keys, but don't add this one
                }
            }
        }

        if verified_keys.is_empty() && !info.quoted_hist_keys.is_empty() {
            bail!("no public keys could be verified");
        }

        self.known_keys = verified_keys;
        info!("verified {} public keys", self.known_keys.len());
        for key in self.known_keys.iter() {
            debug!("    {}", hex_fmt::HexFmt(key));
        }
        Ok(())
    }

    async fn get_logs(&self, count: u32) -> Result<Vec<CTLog>> {
        let url = format!(
            "{}/?q={}&output=json&limit={}",
            BASE_URL, self.base_domain, count
        );
        let response = reqwest::get(&url).await?;
        Ok(response.json().await?)
    }

    async fn check_one_log(&self, log: &CTLog) -> Result<()> {
        let cert_url = format!("{}/?d={}", BASE_URL, log.id);
        let cert_data = reqwest::get(&cert_url).await?.text().await?;

        let pem = Pem::iter_from_buffer(cert_data.as_bytes())
            .next()
            .transpose()
            .context("failed to parse pem")?
            .context("empty pem")?;
        let cert = pem.parse_x509().context("invalid x509 certificate")?;

        let pubkey = cert.public_key().raw;
        if !self.known_keys.contains(pubkey) {
            error!("❌ error in {:?}", log);
            bail!(
                "certificate has issued to unknown pubkey: {:?}",
                hex_fmt::HexFmt(pubkey)
            );
        }
        info!("✅ checked log id={}", log.id);
        Ok(())
    }

    async fn check_new_logs(&mut self) -> Result<()> {
        let logs = self.get_logs(10000).await?;
        debug!("got {} logs", logs.len());
        let mut found_last_checked = false;

        for log in logs.iter() {
            let log_id = log.id;

            if let Some(last_checked) = self.last_checked {
                if log_id == last_checked {
                    found_last_checked = true;
                    break;
                }
            }
            debug!("🔍 checking log id={}", log_id);
            self.check_one_log(log).await?;
        }

        if !found_last_checked && self.last_checked.is_some() {
            bail!("last checked log not found, something went wrong");
        }

        if !logs.is_empty() {
            let last_log = &logs[0];
            debug!("last checked: {}", last_log.id);
            self.last_checked = Some(last_log.id);
        }

        Ok(())
    }

    async fn run(&mut self) {
        info!("monitoring {}...", self.base_domain);
        loop {
            if let Err(err) = self.refresh_known_keys().await {
                error!("error refreshing known keys: {}", err);
            }
            if let Err(err) = self.check_new_logs().await {
                error!("error: {}", err);
            }
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

fn validate_domain(domain: &str) -> Result<()> {
    let domain_regex =
        Regex::new(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
            .context("invalid regex")?;
    if !domain_regex.is_match(domain) {
        bail!("invalid domain name");
    }
    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Gateway address in format: base_domain[:port]
    /// e.g., "example.com" or "example.com:8443"
    #[arg(short, long, env = "GATEWAY")]
    gateway: String,

    /// The dstack-verifier URL
    #[arg(short, long, env = "VERIFIER_URL")]
    verifier_url: String,

    /// PCCS URL for TDX collateral fetching (optional)
    #[arg(long, env = "PCCS_URL")]
    pccs_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
    let args = Args::parse();
    let mut monitor = Monitor::new(args.gateway, args.verifier_url, args.pccs_url)?;
    monitor.run().await;
    Ok(())
}
