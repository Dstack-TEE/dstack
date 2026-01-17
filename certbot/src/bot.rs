// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use fs_err as fs;
use tokio::time::sleep;
use tracing::{error, info};

use crate::acme_client::{acme_matches, read_pem};

use super::{AcmeClient, Dns01Client};

#[allow(clippy::duplicated_attributes)]
#[derive(Clone, Debug, bon::Builder)]
#[builder(on(String, into))]
#[builder(on(PathBuf, into))]
pub struct CertBotConfig {
    acme_url: String,
    auto_set_caa: bool,
    credentials_file: PathBuf,
    auto_create_account: bool,
    cf_api_token: String,
    cf_api_url: Option<String>,
    cert_file: PathBuf,
    key_file: PathBuf,
    cert_dir: PathBuf,
    cert_subject_alt_names: Vec<String>,
    renew_interval: Duration,
    renew_timeout: Duration,
    renew_expires_in: Duration,
    renewed_hook: Option<String>,
    max_dns_wait: Duration,
    /// TTL for DNS TXT records used in ACME challenges (in seconds).
    /// Minimum is 60 for Cloudflare.
    #[builder(default = 60)]
    dns_txt_ttl: u32,
}

impl CertBotConfig {
    pub async fn build_bot(&self) -> Result<CertBot> {
        CertBot::build(self.clone()).await
    }
}

pub struct CertBot {
    acme_client: AcmeClient,
    config: CertBotConfig,
}

async fn create_new_account(
    config: &CertBotConfig,
    dns01_client: Dns01Client,
) -> Result<AcmeClient> {
    info!("creating new ACME account");
    let client = AcmeClient::new_account(
        &config.acme_url,
        dns01_client,
        config.max_dns_wait,
        config.dns_txt_ttl,
    )
    .await
    .context("failed to create new account")?;
    let credentials = client
        .dump_credentials()
        .context("failed to dump credentials")?;
    info!("created new ACME account: {}", client.account_id());
    if config.auto_set_caa {
        client
            .set_caa_records(&config.cert_subject_alt_names)
            .await?;
    }
    if let Some(credential_dir) = config.credentials_file.parent() {
        fs::create_dir_all(credential_dir).context("failed to create credential directory")?;
    }
    fs::write(&config.credentials_file, credentials).context("failed to write credentials")?;
    Ok(client)
}

impl CertBot {
    /// Build a new `CertBot` from a `CertBotConfig`.
    pub async fn build(config: CertBotConfig) -> Result<Self> {
        let base_domain = config
            .cert_subject_alt_names
            .first()
            .context("cert_subject_alt_names is empty")?
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
            .to_string();
        let dns01_client = Dns01Client::new_cloudflare(
            base_domain,
            config.cf_api_token.clone(),
            config.cf_api_url.clone(),
        );
        let acme_client = match fs::read_to_string(&config.credentials_file) {
            Ok(credentials) => {
                if acme_matches(&credentials, &config.acme_url) {
                    AcmeClient::load(
                        dns01_client,
                        &credentials,
                        config.max_dns_wait,
                        config.dns_txt_ttl,
                    )
                    .await?
                } else {
                    create_new_account(&config, dns01_client).await?
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if !config.auto_create_account {
                    return Err(e).context("credentials file not found");
                }
                create_new_account(&config, dns01_client).await?
            }
            Err(e) => {
                return Err(e).context("failed to read credentials file");
            }
        };
        Ok(Self {
            acme_client,
            config,
        })
    }

    /// Get the ACME account ID.
    pub fn account_id(&self) -> &str {
        self.acme_client.account_id()
    }

    /// List all issued certificates.
    pub fn list_certs(&self) -> Result<Vec<PathBuf>> {
        list_certs(&self.config.cert_dir)
    }

    /// List all public keys.
    pub fn list_cert_public_keys(&self) -> Result<BTreeSet<Vec<u8>>> {
        list_cert_public_keys(&self.config.cert_dir)
    }

    /// Run the certbot.
    pub async fn run(&self) {
        loop {
            match self.renew(false).await {
                Ok(renewed) => {
                    if !renewed {
                        continue;
                    }
                    if let Some(hook) = &self.config.renewed_hook {
                        info!("running renewed hook");
                        let result = std::process::Command::new("/bin/sh")
                            .arg("-c")
                            .arg(hook)
                            .status();
                        match result {
                            Ok(status) => {
                                if !status.success() {
                                    error!("renewed hook failed with status: {status}");
                                }
                            }
                            Err(err) => {
                                error!("failed to run renewed hook: {err:?}");
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("failed to run certbot: {e:?}");
                }
            }
            sleep(self.config.renew_interval).await;
        }
    }

    /// Run the certbot once.
    pub async fn renew(&self, force: bool) -> Result<bool> {
        tokio::time::timeout(self.config.renew_timeout, self.renew_inner(force))
            .await
            .context("requesting cert timeout")?
    }

    pub fn renew_interval(&self) -> Duration {
        self.config.renew_interval
    }

    async fn renew_inner(&self, force: bool) -> Result<bool> {
        let created = self
            .acme_client
            .create_cert_if_needed(
                &self.config.cert_subject_alt_names,
                &self.config.cert_file,
                &self.config.key_file,
                &self.config.cert_dir,
            )
            .await?;
        if created {
            info!("created new certificate");
            return Ok(true);
        }
        info!("checking if certificate needs to be renewed");
        let renewed = self
            .acme_client
            .auto_renew(
                &self.config.cert_file,
                &self.config.key_file,
                &self.config.cert_dir,
                self.config.renew_expires_in,
                force,
            )
            .await?;

        match renewed {
            true => {
                info!(
                    "renewed certificate for {}",
                    self.config.cert_file.display()
                );
            }
            false => {
                info!(
                    "certificate {} is up to date",
                    self.config.cert_file.display()
                );
            }
        }
        Ok(renewed)
    }

    /// Set CAA record for the domain.
    pub async fn set_caa(&self) -> Result<()> {
        self.acme_client
            .set_caa_records(&self.config.cert_subject_alt_names)
            .await
    }
}

pub fn read_pubkey(cert_pem: &str) -> Result<Vec<u8>> {
    let cert = read_pem(cert_pem)?;
    let public_key = cert.parse_x509().context("failed to parse x509 cert")?;
    Ok(public_key.tbs_certificate.public_key().raw.to_vec())
}

pub fn list_certs(workdir: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
    let mut certs = vec![];
    let cert_dir = Path::new(workdir.as_ref());
    for entry in fs::read_dir(cert_dir)? {
        let entry = entry?;
        let path = entry.path();
        let cert_path = path.join("cert.pem");
        if path.is_dir() && cert_path.exists() {
            certs.push(cert_path);
        }
    }
    Ok(certs)
}

pub fn list_cert_public_keys(workdir: impl AsRef<Path>) -> Result<BTreeSet<Vec<u8>>> {
    list_certs(workdir)?
        .into_iter()
        .map(|cert_path| {
            let cert_pem = fs::read_to_string(&cert_path).context("failed to read cert")?;
            read_pubkey(&cert_pem).context("failed to parse cert")
        })
        .collect::<Result<_>>()
}

#[cfg(test)]
mod tests;
