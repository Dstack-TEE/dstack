// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use clap::Parser;
use dstack_gateway_rpc::gateway_client::GatewayClient;
use ra_rpc::client::RaClient;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;
use tracing::{debug, error, info};
use x509_parser::prelude::*;

const BASE_URL: &str = "https://crt.sh";

struct Monitor {
    gateway_uri: String,
    domain: String,
    known_keys: BTreeSet<Vec<u8>>,
    last_checked: Option<u64>,
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
    fn new(gateway_uri: String, domain: String) -> Result<Self> {
        validate_domain(&domain)?;
        Ok(Self {
            gateway_uri,
            domain,
            known_keys: BTreeSet::new(),
            last_checked: None,
        })
    }

    async fn refresh_known_keys(&mut self) -> Result<()> {
        info!("fetching known public keys from {}", self.gateway_uri);
        // TODO: Use RA-TLS
        let tls_no_check = true;
        let rpc = GatewayClient::new(RaClient::new(self.gateway_uri.clone(), tls_no_check)?);
        let info = rpc.acme_info().await?;
        self.known_keys = info.hist_keys.into_iter().collect();
        info!("got {} known public keys", self.known_keys.len());
        for key in self.known_keys.iter() {
            debug!("    {}", hex_fmt::HexFmt(key));
        }
        Ok(())
    }

    async fn get_logs(&self, count: u32) -> Result<Vec<CTLog>> {
        let url = format!(
            "{}/?q={}&output=json&limit={}",
            BASE_URL, self.domain, count
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
        info!("monitoring {}...", self.domain);
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
    /// The gateway URI
    #[arg(short, long)]
    gateway_uri: String,
    /// Domain name to monitor
    #[arg(short, long)]
    domain: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).init();
    }
    let args = Args::parse();
    let mut monitor = Monitor::new(args.gateway_uri, args.domain)?;
    monitor.run().await;
    Ok(())
}
