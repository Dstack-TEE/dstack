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

use crate::acme_client::read_pem;

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
    cf_zone_id: String,
    cf_api_token: String,
    cert_file: PathBuf,
    key_file: PathBuf,
    cert_dir: PathBuf,
    cert_subject_alt_names: Vec<String>,
    renew_interval: Duration,
    renew_timeout: Duration,
    renew_expires_in: Duration,
    renewed_hook: Option<String>,
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

impl CertBot {
    /// Build a new `CertBot` from a `CertBotConfig`.
    pub async fn build(config: CertBotConfig) -> Result<Self> {
        let dns01_client =
            Dns01Client::new_cloudflare(config.cf_zone_id.clone(), config.cf_api_token.clone());
        let acme_client = match fs::read_to_string(&config.credentials_file) {
            Ok(credentials) => AcmeClient::load(dns01_client, &credentials).await?,
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if !config.auto_create_account {
                    return Err(e).context("credentials file not found");
                }
                info!("creating new ACME account");
                let client = AcmeClient::new_account(&config.acme_url, dns01_client)
                    .await
                    .context("failed to create new account")?;
                let credentials = client
                    .dump_credentials()
                    .context("failed to dump credentials")?;
                if let Some(credential_dir) = config.credentials_file.parent() {
                    fs::create_dir_all(credential_dir)
                        .context("failed to create credential directory")?;
                }
                fs::write(&config.credentials_file, credentials)
                    .context("failed to write credentials")?;
                info!("created new ACME account: {}", client.account_id());
                if config.auto_set_caa {
                    info!("setting CAA records");
                    client
                        .set_caa_records(&config.cert_subject_alt_names)
                        .await?;
                }
                client
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

fn read_pubkey(cert_pem: &str) -> Result<Vec<u8>> {
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
