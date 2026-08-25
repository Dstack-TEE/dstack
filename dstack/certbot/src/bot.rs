// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::BTreeSet,
    io::ErrorKind,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{bail, Context, Result};
use fs_err as fs;
use tokio::time::sleep;
use tracing::{error, info, warn};

use crate::acme_client::{acme_matches, read_pem, ChallengeKind, RequiredRecord, ValidationMethod};
use crate::dns_persist::{resolve_issuer_domain_name, LETS_ENCRYPT_ISSUER_DOMAIN_NAME};

use super::{AcmeClient, Dns01Client};
use crate::acme_client::advisory_dns_wait;

#[allow(clippy::duplicated_attributes)]
#[derive(Clone, Debug, bon::Builder)]
#[builder(on(String, into))]
#[builder(on(PathBuf, into))]
pub struct CertBotConfig {
    acme_url: String,
    auto_set_caa: bool,
    credentials_file: PathBuf,
    auto_create_account: bool,
    /// ACME challenge used to prove control of the domains.
    #[builder(default)]
    challenge: ChallengeKind,
    /// Issuer Domain Name naming the CA in `dns-persist-01` and CAA records.
    ///
    /// Must be one of the `issuer-domain-names` the CA sends in the challenge.
    #[builder(default = LETS_ENCRYPT_ISSUER_DOMAIN_NAME.to_string())]
    issuer_domain_name: String,
    /// Cloudflare API token. Unused, and warned about, under `dns-persist-01`.
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
    validation: ValidationMethod,
) -> Result<AcmeClient> {
    info!("creating new ACME account");
    let client = AcmeClient::new_account(&config.acme_url, validation, dns_wait(config))
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
        let validation = build_validation_method(&config).await?;
        let acme_client = match fs::read_to_string(&config.credentials_file) {
            Ok(credentials) => {
                if acme_matches(&credentials, &config.acme_url) {
                    AcmeClient::load(validation, &credentials, dns_wait(&config)).await?
                } else {
                    create_new_account(&config, validation).await?
                }
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                if !config.auto_create_account {
                    return Err(e).context("credentials file not found");
                }
                create_new_account(&config, validation).await?
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
            if let Err(error) = self.renew_and_run_hook(false).await {
                error!("failed to run certbot: {error:?}");
            }
            sleep(self.config.renew_interval).await;
        }
    }

    /// Run one renewal attempt and invoke the configured hook after a commit.
    pub async fn renew_and_run_hook(&self, force: bool) -> Result<bool> {
        let renewed = self.renew(force).await?;
        if !renewed {
            return Ok(false);
        }
        let Some(hook) = &self.config.renewed_hook else {
            return Ok(true);
        };
        info!("running renewed hook");
        match std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(hook)
            .status()
        {
            Ok(status) if status.success() => {}
            Ok(status) => error!("renewed hook failed with status: {status}"),
            Err(error) => error!("failed to run renewed hook: {error:?}"),
        }
        Ok(true)
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
        let live_cert_exists = self.config.cert_file.exists() && self.config.key_file.exists();
        let issued = self
            .acme_client
            .create_cert_if_needed(
                &self.config.cert_subject_alt_names,
                &self.config.cert_file,
                &self.config.key_file,
                &self.config.cert_dir,
            )
            .await;
        // A live certificate that does not cover the configured names is
        // reissued above, and that reissuance keeps failing for as long as the
        // configuration names something the CA will not validate -- a typo, a
        // zone the DNS credentials cannot write. Failing the run right here
        // would take the renewal check below down with it, so one name the
        // operator got wrong would stop renewing the certificate that is
        // actually being served, until it expires. The renewal still runs; the
        // error is reported, and returned below unless the renewal committed
        // something of its own.
        let reissue_error = match issued {
            Ok(true) => {
                info!("created new certificate");
                return Ok(true);
            }
            Ok(false) => None,
            // Nothing is being served yet, so there is no renewal to protect
            // and `auto_renew` has no certificate to read.
            Err(err) if !live_cert_exists => return Err(err),
            Err(err) => {
                error!("failed to issue a certificate for the configured domains: {err:#}");
                Some(err)
            }
        };
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

        match (renewed, reissue_error) {
            (true, _) => {
                info!(
                    "renewed certificate for {}",
                    self.config.cert_file.display()
                );
                Ok(true)
            }
            // The renewal committed nothing, so the reissue failure is the
            // whole outcome of this run and `renew --once` must report it.
            (false, Some(err)) => Err(err),
            (false, None) => {
                info!(
                    "certificate {} is up to date",
                    self.config.cert_file.display()
                );
                Ok(false)
            }
        }
    }

    /// Set CAA record for the domain.
    pub async fn set_caa(&self) -> Result<()> {
        self.acme_client
            .set_caa_records(&self.config.cert_subject_alt_names)
            .await
    }

    /// The DNS records that have to exist for the configured domains.
    pub fn required_dns_records(&self) -> Vec<RequiredRecord> {
        self.acme_client
            .required_dns_records(&self.config.cert_subject_alt_names)
    }
}

/// The DNS wait this configuration should actually use.
///
/// `renew_timeout` wraps the whole renewal here exactly as it does in the
/// gateway, and the defaults are skewed the same way -- further, in fact:
/// `max_dns_wait` defaults to 300s against a 120s renewal budget, so an
/// unanswered check runs the renewal into its timeout every time instead of
/// reporting the record it could not see.
fn dns_wait(config: &CertBotConfig) -> Duration {
    advisory_dns_wait(config.max_dns_wait, config.renew_timeout)
}

/// The Issuer Domain Name this configuration names, checked before it is used.
///
/// Both challenges read the same setting, so both get the same treatment: empty
/// means the default, and a value that would not survive being written into a
/// CAA or validation record is refused here rather than at the point it would
/// corrupt a zone.
fn issuer_domain_name(config: &CertBotConfig) -> Result<String> {
    resolve_issuer_domain_name(&config.issuer_domain_name)
        .context("invalid issuer_domain_name in the certbot configuration")
}

/// Resolve the configured challenge into a live validation method.
///
/// `dns-01` resolves the Cloudflare zone here, which is an authenticated call,
/// so a bad credential fails at startup rather than at the first renewal.
/// `dns-persist-01` talks to no provider at all.
async fn build_validation_method(config: &CertBotConfig) -> Result<ValidationMethod> {
    match config.challenge {
        ChallengeKind::Dns01 => {
            let base_domain = config
                .cert_subject_alt_names
                .first()
                .context("cert_subject_alt_names is empty")?
                .trim()
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_string();
            let client = Dns01Client::new_cloudflare(
                base_domain,
                config.cf_api_token.clone(),
                config.cf_api_url.clone(),
            )
            .await?;
            Ok(ValidationMethod::Dns01 {
                client,
                txt_ttl: config.dns_txt_ttl,
                issuer_domain_name: issuer_domain_name(config)?,
            })
        }
        ChallengeKind::DnsPersist01 => {
            // Refuse rather than silently skip: `auto_set_caa` promises the CAA
            // records are kept in sync, and without DNS write access nothing here
            // can keep that promise. `certbot dns-records` prints what to publish.
            if config.auto_set_caa {
                bail!(
                    "auto_set_caa is not supported with dns-persist-01, which has no DNS \
                     write access; set auto_set_caa = false and publish the records from \
                     `certbot dns-records` by hand"
                );
            }
            if !config.cf_api_token.is_empty() {
                warn!("ignoring cf_api_token: dns-persist-01 needs no DNS provider credential");
            }
            Ok(ValidationMethod::DnsPersist01 {
                issuer_domain_name: issuer_domain_name(config)?,
            })
        }
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
    certs.sort();
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

#[cfg(test)]
mod listing_tests {
    use super::list_certs;
    use fs_err as fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn certificate_directories_are_listed_in_stable_order() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dstack-certbot-list-{}-{nonce}",
            std::process::id()
        ));
        for name in ["0002", "0001"] {
            let directory = root.join(name);
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("cert.pem"), name).unwrap();
        }

        let listed = list_certs(&root).unwrap();

        assert_eq!(
            listed,
            ["0001", "0002"]
                .map(|name| root.join(name).join("cert.pem"))
                .to_vec()
        );
        fs::remove_dir_all(root).unwrap();
    }
}
