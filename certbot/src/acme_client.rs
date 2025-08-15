// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use fs_err as fs;
use hickory_resolver::error::ResolveErrorKind;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::sleep;
use tracing::{debug, error, info};
use x509_parser::prelude::{GeneralName, Pem};

use super::dns01_client::{Dns01Api, Dns01Client};

/// A AcmeClient instance.
pub struct AcmeClient {
    account: Account,
    credentials: Credentials,
    dns01_client: Dns01Client,
}

#[derive(Debug, Clone)]
struct Challenge {
    id: String,
    acme_domain: String,
    url: String,
    dns_value: String,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Credentials {
    pub(crate) account_id: String,
    #[serde(default)]
    acme_url: String,
    credentials: AccountCredentials,
}

pub(crate) fn acme_matches(encoded_credentials: &str, acme_url: &str) -> bool {
    let Ok(credentials) = serde_json::from_str::<Credentials>(encoded_credentials) else {
        return false;
    };
    credentials.acme_url == acme_url
}

impl AcmeClient {
    pub async fn load(dns01_client: Dns01Client, encoded_credentials: &str) -> Result<Self> {
        let credentials: Credentials = serde_json::from_str(encoded_credentials)?;
        let account = Account::from_credentials(credentials.credentials).await?;
        let credentials: Credentials = serde_json::from_str(encoded_credentials)?;
        Ok(Self {
            account,
            dns01_client,
            credentials,
        })
    }

    /// Create a new account.
    pub async fn new_account(acme_url: &str, dns01_client: Dns01Client) -> Result<Self> {
        let (account, credentials) = Account::create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme_url,
            None,
        )
        .await
        .with_context(|| format!("failed to create ACME account for {acme_url}"))?;
        let credentials = Credentials {
            acme_url: acme_url.to_string(),
            account_id: account.id().to_string(),
            credentials,
        };
        Ok(Self {
            account,
            dns01_client,
            credentials,
        })
    }

    /// Dump the account credentials to a JSON string.
    pub fn dump_credentials(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.credentials)?)
    }

    /// Read the account ID from the encoded credentials.
    pub fn account_id(&self) -> &str {
        &self.credentials.account_id
    }

    pub async fn set_caa_records(&self, domains: &[String]) -> Result<()> {
        let account_id = self.account_id();
        let content = format!("letsencrypt.org;validationmethods=dns-01;accounturi={account_id}");
        let base_names = domains
            .iter()
            .map(|name| name.strip_prefix("*.").unwrap_or(name))
            .collect::<BTreeSet<_>>();

        for base_name in base_names {
            // 1. Set ";" to guard timing gap between the operations.
            debug!("setting guard CAA records for {base_name}");
            let guard0 = self
                .dns01_client
                .add_caa_record(base_name, 0, "issue", ";")
                .await?;
            let guard1 = self
                .dns01_client
                .add_caa_record(base_name, 0, "issuewild", ";")
                .await?;
            // 2. Remove the existing constraints
            for record in self.dns01_client.get_records(base_name).await? {
                if record.id == guard0 || record.id == guard1 {
                    continue;
                }
                if record.r#type == "CAA" {
                    debug!(
                        "removing existing CAA record {} {}",
                        record.name, record.content
                    );
                    self.dns01_client.remove_record(&record.id).await?;
                }
            }
            // 3. Set the new constraints
            debug!("setting CAA records for {base_name}, 0 issue \"{content}\"");
            self.dns01_client
                .add_caa_record(base_name, 0, "issue", &content)
                .await?;
            debug!("setting CAA records for {base_name}, 0 issuewild \"{content}\"");
            self.dns01_client
                .add_caa_record(base_name, 0, "issuewild", &content)
                .await?;
            debug!("removing guard CAA records for {base_name}");
            // 4. Remove the guards
            self.dns01_client.remove_record(&guard0).await?;
            self.dns01_client.remove_record(&guard1).await?;
        }
        Ok(())
    }

    /// Request new certificates for the given domains.
    ///
    /// Returns the new certificates encoded in PEM format.
    pub async fn request_new_certificate(&self, key: &str, domains: &[String]) -> Result<String> {
        info!("requesting new certificates for {}", domains.join(", "));
        let mut challenges = Vec::new();
        let result = self
            .request_new_certificate_inner(key, domains, &mut challenges)
            .await;
        for challenge in &challenges {
            debug!("removing dns record {}", challenge.id);
            if let Err(err) = self.dns01_client.remove_record(&challenge.id).await {
                error!("failed to remove dns record {}: {err}", challenge.id);
            }
        }
        result
    }

    /// Auto renew given certificate
    ///
    /// Checks if the certificate is about to expire and renews it if necessary.
    pub async fn renew_cert_if_needed(
        &self,
        cert_pem: &str,
        key_pem: &str,
        expires_in: Duration,
    ) -> Result<Option<String>> {
        if !need_renew(cert_pem, expires_in)? {
            return Ok(None);
        }
        let cert = self
            .renew_cert(cert_pem, key_pem)
            .await
            .context("failed to renew cert")?;
        Ok(Some(cert))
    }

    /// Renew given certificate
    pub async fn renew_cert(&self, cert_pem: &str, key_pem: &str) -> Result<String> {
        let domains =
            extract_subject_alt_names(cert_pem).context("failed to extract subject alt names")?;
        let cert = self
            .request_new_certificate(key_pem, &domains)
            .await
            .context("failed to request new certificates")?;
        Ok(cert)
    }

    /// Auto renew given certificate
    pub async fn auto_renew(
        &self,
        live_cert_pem_path: impl AsRef<Path>,
        live_key_pem_path: impl AsRef<Path>,
        backup_dir: impl AsRef<Path>,
        expires_in: Duration,
        force: bool,
    ) -> Result<bool> {
        let live_cert_pem = fs::read_to_string(live_cert_pem_path.as_ref())?;
        let live_key_pem = fs::read_to_string(live_key_pem_path.as_ref())?;
        let new_cert = if force {
            self.renew_cert(&live_cert_pem, &live_key_pem).await?
        } else {
            let Some(new_cert) = self
                .renew_cert_if_needed(&live_cert_pem, &live_key_pem, expires_in)
                .await?
            else {
                return Ok(false);
            };
            new_cert
        };
        self.store_cert(
            live_cert_pem_path.as_ref(),
            live_key_pem_path.as_ref(),
            &new_cert,
            &live_key_pem,
            backup_dir.as_ref(),
        )?;
        info!(
            "renewed certificate for {}",
            live_cert_pem_path.as_ref().display()
        );
        Ok(true)
    }

    fn store_cert(
        &self,
        live_cert_pem_path: &Path,
        live_key_pem_path: &Path,
        cert_pem: &str,
        key_pem: &str,
        backup_dir: impl AsRef<Path>,
    ) -> Result<()> {
        use path_absolutize::Absolutize;

        // Put the new cert in {backup_dir}/%Y%m%d_%H%M%S/cert.pem
        let cert_dir = self.new_cert_dir(backup_dir.as_ref())?;
        let backup_path = cert_dir.absolutize()?;
        let cert_path = backup_path.join("cert.pem");
        let key_path = backup_path.join("key.pem");
        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;
        debug!("stored new cert in {}", cert_dir.display());

        // symlink live_cert_pem_path to the new cert
        ln_force(cert_path, live_cert_pem_path)?;
        ln_force(key_path, live_key_pem_path)?;
        Ok(())
    }

    /// Auto renew given certificate
    pub async fn create_cert_if_needed(
        &self,
        domains: &[String],
        live_cert_pem_path: impl AsRef<Path>,
        live_key_pem_path: impl AsRef<Path>,
        backup_dir: impl AsRef<Path>,
    ) -> Result<bool> {
        if live_cert_pem_path.as_ref().exists() && live_key_pem_path.as_ref().exists() {
            return Ok(false);
        }
        let key_pem = if live_key_pem_path.as_ref().exists() {
            debug!("using existing cert key pair");
            fs::read_to_string(live_key_pem_path.as_ref())?
        } else {
            debug!("generating new cert key pair");
            let key = KeyPair::generate().context("failed to generate key")?;
            key.serialize_pem()
        };
        let cert_pem = self.request_new_certificate(&key_pem, domains).await?;
        self.store_cert(
            live_cert_pem_path.as_ref(),
            live_key_pem_path.as_ref(),
            &cert_pem,
            &key_pem,
            backup_dir.as_ref(),
        )?;
        Ok(true)
    }
}

impl AcmeClient {
    async fn authorize(&self, order: &mut Order, challenges: &mut Vec<Challenge>) -> Result<()> {
        let authorizations = order
            .authorizations()
            .await
            .context("failed to get authorizations")?;
        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => bail!("unsupported authorization status: {:?}", authz.status),
            }

            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .context("no dns01 challenge found")?;

            let Identifier::Dns(identifier) = &authz.identifier;

            let dns_value = order.key_authorization(challenge).dns_value();
            debug!("creating dns record for {}", identifier);
            let acme_domain = format!("_acme-challenge.{identifier}");
            debug!("removing existing dns record for {}", acme_domain);
            self.dns01_client
                .remove_txt_records(&acme_domain)
                .await
                .context("failed to remove existing dns record")?;
            debug!("creating dns record for {}", acme_domain);
            let id = self
                .dns01_client
                .add_txt_record(&acme_domain, &dns_value)
                .await
                .context("failed to create dns record")?;
            challenges.push(Challenge {
                id,
                acme_domain,
                url: challenge.url.clone(),
                dns_value,
            });
        }
        Ok(())
    }

    /// Self check the TXT records for the given challenges.
    async fn check_dns(&self, challenges: &[Challenge]) -> Result<()> {
        let mut delay = Duration::from_millis(250);
        let mut tries = 1u8;

        let mut unsettled_challenges = challenges.to_vec();

        debug!("Unsettled challenges: {unsettled_challenges:#?}");

        'outer: loop {
            use hickory_resolver::AsyncResolver;

            sleep(delay).await;

            let dns_resolver =
                AsyncResolver::tokio_from_system_conf().context("failed to create dns resolver")?;

            while let Some(challenge) = unsettled_challenges.pop() {
                let expected_txt = &challenge.dns_value;
                let settled = match dns_resolver.txt_lookup(&challenge.acme_domain).await {
                    Ok(record) => record.iter().any(|txt| {
                        let actual_txt = txt.to_string();
                        debug!("Expected challenge: {expected_txt}, actual: {actual_txt}");
                        actual_txt == *expected_txt
                    }),
                    Err(err) => {
                        let ResolveErrorKind::NoRecordsFound { .. } = err.kind() else {
                            bail!(
                                "failed to lookup dns record {}: {err}",
                                challenge.acme_domain
                            );
                        };
                        false
                    }
                };
                if !settled {
                    delay = Duration::from_secs(32).min(delay * 2);
                    tries += 1;
                    debug!(
                        tries,
                        domain = &challenge.acme_domain,
                        "challenge not found, waiting for {delay:?}"
                    );
                    unsettled_challenges.push(challenge);
                    continue 'outer;
                }
            }
            break;
        }
        Ok(())
    }

    async fn request_new_certificate_inner(
        &self,
        key: &str,
        domains: &[String],
        challenges: &mut Vec<Challenge>,
    ) -> Result<String> {
        debug!("requesting new certificates for {}", domains.join(", "));
        debug!("creating new order");
        let identifiers = domains
            .iter()
            .map(|name| Identifier::Dns(name.clone()))
            .collect::<Vec<_>>();
        let mut order = self
            .account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .context("failed to cread new order")?;
        let mut challenges_ready = false;
        loop {
            order.refresh().await.context("failed to refresh order")?;
            match order.state().status {
                // Need to accept the challenge
                OrderStatus::Pending => {
                    if challenges_ready {
                        debug!("challenges are ready, waiting for order to be ready");
                        sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    debug!("order is pending, waiting for authorization");
                    self.authorize(&mut order, challenges)
                        .await
                        .context("failed to authorize")?;
                    if challenges.is_empty() {
                        bail!("no challenges found");
                    }
                    self.check_dns(challenges)
                        .await
                        .context("failed to check dns")?;
                    for challenge in &*challenges {
                        debug!("setting challenge ready for {}", challenge.url);
                        order
                            .set_challenge_ready(&challenge.url)
                            .await
                            .context("failed to set challenge ready")?;
                    }
                    challenges_ready = true;
                    continue;
                }
                // To upload CSR
                OrderStatus::Ready => {
                    debug!("order is ready, uploading CSR");
                    let csr = make_csr(key, domains)?;
                    order
                        .finalize(csr.as_ref())
                        .await
                        .context("failed to finalize order")?;
                    continue;
                }
                // Need to wait for the challenge to be accepted
                OrderStatus::Processing => {
                    debug!("order is processing, waiting for the CSR to be accepted");
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                // Certificate is ready
                OrderStatus::Valid => {
                    debug!("order is valid, getting certificate");
                    return extract_certificate(order).await;
                }
                // Something went wrong
                OrderStatus::Invalid => bail!("order is invalid"),
            }
        }
    }

    fn new_cert_dir(&self, backup_dir: &Path) -> Result<PathBuf> {
        let timestamp = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Iso8601::DEFAULT)
            .context("failed to format timestamp")?;
        let backup_path = backup_dir.join(timestamp);
        fs::create_dir_all(&backup_path)?;
        Ok(backup_path)
    }
}

fn make_csr(key: &str, names: &[String]) -> Result<Vec<u8>> {
    let mut params =
        CertificateParams::new(names).context("failed to create certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    let key = KeyPair::from_pem(key).context("failed to parse private key")?;
    let csr = params
        .serialize_request(&key)
        .context("failed to serialize certificate request")?;
    Ok(csr.der().as_ref().to_vec())
}

async fn extract_certificate(mut order: Order) -> Result<String> {
    let mut tries = 0;
    let cert_chain_pem = loop {
        tries += 1;
        if tries > 5 {
            bail!("failed to get certificate");
        }
        match order
            .certificate()
            .await
            .context("failed to get certificate")?
        {
            Some(cert_chain_pem) => break cert_chain_pem,
            None => sleep(Duration::from_secs(1)).await,
        }
    };
    Ok(cert_chain_pem)
}

fn need_renew(cert_pem: &str, expires_in: Duration) -> Result<bool> {
    let pem = read_pem(cert_pem)?;
    let cert = pem.parse_x509().context("Invalid x509 certificate")?;
    let not_after = cert.validity().not_after.to_datetime();
    let now = time::OffsetDateTime::now_utc();
    debug!("will expire in {}", not_after - now);

    Ok(not_after < now + expires_in)
}

pub(crate) fn read_pem(cert_pem: &str) -> Result<Pem> {
    Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()
        .transpose()
        .context("Invalid pem")?
        .context("no certificate in pem")
}

fn extract_subject_alt_names(cert_pem: &str) -> Result<Vec<String>> {
    let pem = read_pem(cert_pem)?;
    let cert = pem.parse_x509().context("Invalid x509 certificate")?;
    let subject_alt_names = cert
        .tbs_certificate
        .subject_alternative_name()
        .context("failed to parse subject alternative name")?
        .context("no subject alternative name found")?;
    let mut domains = Vec::new();
    for name in &subject_alt_names.value.general_names {
        if let GeneralName::DNSName(dns) = name {
            domains.push(dns.to_string());
        } else {
            bail!("unsupported general name: {:?}", name);
        }
    }
    Ok(domains)
}

fn ln_force(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    // Check if the symlink exists without following it
    if dst.as_ref().symlink_metadata().is_ok() {
        fs::remove_file(dst.as_ref())?;
    } else if let Some(dst_parent) = dst.as_ref().parent() {
        fs::create_dir_all(dst_parent)?;
    }
    fs::os::unix::fs::symlink(src.as_ref(), dst.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests;
