// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
// SPDX-FileCopyrightText: © 2025 Test in Prod <contact@testinprod.io>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use certbot::{CertBotConfig, ChallengeKind, WorkDir, LETS_ENCRYPT_ISSUER_DOMAIN_NAME};
use clap::Parser;
use documented::DocumentedFields;
use fs_err as fs;
use or_panic::ResultOrPanic;
use serde::{Deserialize, Serialize};
use toml_edit::ser::to_document;

#[derive(Parser)]
enum Command {
    /// Automatically renew certificates if they are close to expiration
    Renew {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
        /// Run only once and exit
        #[arg(long)]
        once: bool,
        /// Force renewal
        #[arg(long)]
        force: bool,
    },
    /// Create the ACME account described by the configuration file
    Init {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
    },
    /// Set CAA record for the domain
    SetCaa {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
    },
    /// Print the DNS records the configured domains need
    ///
    /// With `challenge = "dns-persist-01"` these are not written by certbot and
    /// have to be published once, by hand, before the first issuance.
    DnsRecords {
        /// Path to the configuration file
        #[arg(short, long, default_value = "certbot.toml")]
        config: PathBuf,
    },
    /// Generate configuration template
    Cfg {
        /// Write to file
        #[arg(short, long)]
        write_to: Option<PathBuf>,
    },
}

#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Deserialize, Serialize, DocumentedFields)]
struct Config {
    /// Path to the working directory
    workdir: PathBuf,
    /// ACME server URL
    acme_url: String,
    /// ACME challenge used to prove control of the domains
    ///
    /// "dns-01" (default) writes a TXT record per order through the Cloudflare
    /// API and needs cf_api_token.
    ///
    /// "dns-persist-01" proves control with a _validation-persist TXT record
    /// published once, by hand: no API token, and the zone can be hosted
    /// anywhere. Run `certbot init` then `certbot dns-records` to get the
    /// records to publish. Experimental: the draft is still changing and
    /// Let's Encrypt serves this challenge on staging only.
    #[serde(default)]
    challenge: ChallengeKind,
    /// Issuer Domain Name naming the CA in dns-persist-01 and CAA records
    #[serde(default = "default_issuer_domain_name")]
    issuer_domain_name: String,
    /// Cloudflare API token (unused with dns-persist-01)
    #[serde(default)]
    cf_api_token: String,
    /// Optional Cloudflare-compatible API base URL
    #[serde(default)]
    cf_api_url: Option<String>,
    /// TTL for DNS TXT challenge records in seconds
    #[serde(default = "default_dns_txt_ttl")]
    dns_txt_ttl: u32,
    /// Auto set CAA record
    auto_set_caa: bool,
    /// List of domains to issue certificates for
    domains: Vec<String>,
    /// Renew interval in seconds
    renew_interval: u64,
    /// Number of days before expiration to trigger renewal
    renew_days_before: u64,
    /// Renew timeout in seconds
    renew_timeout: u64,
    /// Maximum time to wait for DNS propagation in seconds
    max_dns_wait: u64,
    /// Command to run after renewal
    #[serde(default)]
    renewed_hook: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            workdir: ".".into(),
            acme_url: "https://acme-staging-v02.api.letsencrypt.org/directory".into(),
            challenge: ChallengeKind::default(),
            issuer_domain_name: default_issuer_domain_name(),
            cf_api_token: "".into(),
            cf_api_url: None,
            dns_txt_ttl: default_dns_txt_ttl(),
            auto_set_caa: true,
            domains: vec!["example.com".into()],
            renew_interval: 3600,
            renew_days_before: 10,
            renew_timeout: 120,
            max_dns_wait: 300,
            renewed_hook: None,
        }
    }
}

const fn default_dns_txt_ttl() -> u32 {
    60
}

fn default_issuer_domain_name() -> String {
    LETS_ENCRYPT_ISSUER_DOMAIN_NAME.to_string()
}

impl Config {
    fn to_commented_toml(&self) -> Result<String> {
        let mut doc = to_document(self)?;

        for (mut key, _value) in doc.iter_mut() {
            // Look the doc comment up by name rather than by position: a `None`
            // option serializes to nothing, so the document's keys are a subset
            // of the struct's fields and indexing `FIELD_DOCS` positionally
            // attaches every comment after the first absent key to the wrong
            // one.
            let Ok(docstring) = Self::get_field_docs(key.get()) else {
                continue;
            };
            let decor = key.leaf_decor_mut();

            let mut comment = String::new();
            for line in docstring.lines() {
                let line = if line.is_empty() {
                    String::from("#\n")
                } else {
                    format!("# {line}\n")
                };
                comment.push_str(&line);
            }
            decor.set_prefix(comment);
        }
        Ok(doc.to_string())
    }
}

fn load_config(config: &PathBuf) -> Result<CertBotConfig> {
    let config: Config = toml_edit::de::from_str(&fs::read_to_string(config)?)?;
    let workdir = WorkDir::new(&config.workdir);
    let renew_interval = Duration::from_secs(config.renew_interval);
    let renew_expires_in = Duration::from_secs(config.renew_days_before * 24 * 60 * 60);
    let renew_timeout = Duration::from_secs(config.renew_timeout);
    let max_dns_wait = Duration::from_secs(config.max_dns_wait);
    let bot_config = CertBotConfig::builder()
        .acme_url(config.acme_url)
        .cert_dir(workdir.backup_dir())
        .cert_file(workdir.cert_path())
        .key_file(workdir.key_path())
        .auto_create_account(true)
        .cert_subject_alt_names(config.domains)
        .challenge(config.challenge)
        .issuer_domain_name(config.issuer_domain_name)
        .cf_api_token(config.cf_api_token)
        .maybe_cf_api_url(config.cf_api_url)
        .dns_txt_ttl(config.dns_txt_ttl)
        .renew_interval(renew_interval)
        .renew_timeout(renew_timeout)
        .renew_expires_in(renew_expires_in)
        .max_dns_wait(max_dns_wait)
        .credentials_file(workdir.account_credentials_path())
        .auto_set_caa(config.auto_set_caa)
        .maybe_renewed_hook(config.renewed_hook)
        .build();
    Ok(bot_config)
}

async fn renew(config: &PathBuf, once: bool, force: bool) -> Result<()> {
    let bot_config = load_config(config).context("Failed to load configuration")?;
    let bot = bot_config
        .build_bot()
        .await
        .context("Failed to build bot")?;
    if once {
        bot.renew_and_run_hook(force).await?;
    } else {
        tokio::select! {
            _ = bot.run() => unreachable!("certbot daemon returned"),
            result = shutdown_signal() => result?,
        }
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    {
        use tracing_subscriber::{fmt, EnvFilter};
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        fmt().with_env_filter(filter).with_ansi(false).init();
    }
    rustls::crypto::ring::default_provider()
        .install_default()
        .or_panic("Failed to install default crypto provider");

    let args = Args::parse();
    match args.command {
        Command::Renew {
            config,
            once,
            force,
        } => {
            renew(&config, once, force).await?;
        }
        Command::Init { config } => {
            let config = load_config(&config).context("Failed to load configuration")?;
            // The build_bot() will trigger the initialization and create Account if not exists
            let _bot = config.build_bot().await.context("Failed to build bot")?;
        }
        Command::SetCaa { config } => {
            let bot_config = load_config(&config).context("Failed to load configuration")?;
            let bot = bot_config
                .build_bot()
                .await
                .context("Failed to build bot")?;
            bot.set_caa().await?;
        }
        Command::DnsRecords { config } => {
            let bot_config = load_config(&config).context("Failed to load configuration")?;
            let bot = bot_config
                .build_bot()
                .await
                .context("Failed to build bot")?;
            for record in bot.required_dns_records() {
                println!("{record}");
            }
        }
        Command::Cfg { write_to } => {
            let toml_str = Config::default().to_commented_toml()?;
            match write_to {
                Some(path) => fs::write(path, toml_str)?,
                None => println!("{}", toml_str),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod config_template_tests {
    use super::*;

    /// Every key has to carry its own doc comment. `toml_edit` drops `None`
    /// fields from the serialized document -- `cf_api_url` is unset by default
    /// -- so indexing `FIELD_DOCS` by position shifts every comment after the
    /// gap onto the wrong setting.
    #[test]
    fn every_key_is_labelled_with_its_own_doc_comment() {
        let rendered = Config::default()
            .to_commented_toml()
            .expect("the default config renders");

        // Pair each key with the comment block immediately above it.
        let mut comment = String::new();
        let mut pairs = Vec::new();
        for line in rendered.lines() {
            match line.strip_prefix('#') {
                Some(text) => comment.push_str(text.trim()),
                None => {
                    if let Some((key, _)) = line.split_once('=') {
                        pairs.push((key.trim().to_string(), std::mem::take(&mut comment)));
                    }
                }
            }
        }
        assert!(!pairs.is_empty(), "no keys rendered:\n{rendered}");

        for (key, comment) in &pairs {
            let expected = Config::get_field_docs(key)
                .unwrap_or_else(|err| panic!("no doc comment for {key:?}: {err}"));
            let expected: String = expected.lines().map(str::trim).collect();
            assert_eq!(
                comment, &expected,
                "key {key:?} is labelled with another field's doc comment"
            );
        }
    }

    /// The field that made the misalignment visible: it sat after the dropped
    /// `cf_api_url` and was labelled "Renew timeout in seconds", next to the one
    /// value whose interaction with `renew_timeout` this crate clamps.
    #[test]
    fn max_dns_wait_is_not_labelled_as_a_renew_timeout() {
        let rendered = Config::default()
            .to_commented_toml()
            .expect("the default config renders");
        let (before, _) = rendered
            .split_once("max_dns_wait")
            .expect("max_dns_wait is rendered");
        let label = before.lines().last().expect("it has a comment above it");
        assert!(
            label.contains("DNS propagation"),
            "max_dns_wait is labelled {label:?}"
        );
    }
}
