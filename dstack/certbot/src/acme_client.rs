// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use fs_err as fs;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount,
    NewOrder, Order, OrderStatus, Problem,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::sleep;
use tracing::{debug, error, info};
use x509_parser::prelude::{GeneralName, Pem};

use super::dns01_client::{Dns01Api, Dns01Client};
use super::http_client::ReqwestHttpClient;

/// A AcmeClient instance.
pub struct AcmeClient {
    account: Account,
    credentials: Credentials,
    dns01_client: Dns01Client,
    max_dns_wait: Duration,
    /// TTL for DNS TXT records used in ACME challenges (in seconds).
    dns_txt_ttl: u32,
}

#[derive(Debug, Clone)]
struct Challenge {
    id: String,
    acme_domain: String,
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

fn caa_tag(content: &str) -> Option<&str> {
    content.split_whitespace().nth(1)
}

impl AcmeClient {
    pub async fn load(
        dns01_client: Dns01Client,
        encoded_credentials: &str,
        max_dns_wait: Duration,
        dns_txt_ttl: u32,
    ) -> Result<Self> {
        let credentials: Credentials = serde_json::from_str(encoded_credentials)?;
        let http_client = Box::new(ReqwestHttpClient::new()?);
        let account = Account::builder_with_http(http_client)
            .from_credentials(credentials.credentials)
            .await?;
        let credentials: Credentials = serde_json::from_str(encoded_credentials)?;
        Ok(Self {
            account,
            dns01_client,
            credentials,
            max_dns_wait,
            dns_txt_ttl,
        })
    }

    /// Create a new account.
    pub async fn new_account(
        acme_url: &str,
        dns01_client: Dns01Client,
        max_dns_wait: Duration,
        dns_txt_ttl: u32,
    ) -> Result<Self> {
        let http_client = Box::new(ReqwestHttpClient::new()?);
        let (account, credentials) = Account::builder_with_http(http_client)
            .create(
                &NewAccount {
                    contact: &[],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                acme_url.to_string(),
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
            max_dns_wait,
            dns_txt_ttl,
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
                if record.r#type == "CAA"
                    && caa_tag(&record.content)
                        .is_some_and(|tag| matches!(tag, "issue" | "issuewild"))
                {
                    debug!(
                        "removing existing issuer CAA record {} {}",
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
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.context("failed to get authorizations")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => bail!("unsupported authorization status: {:?}", authz.status),
            }

            let challenge = authz
                .challenge(ChallengeType::Dns01)
                .context("no dns01 challenge found")?;

            // The bare identifier, without any wildcard prefix: the TXT record for
            // `*.example.com` is published under `_acme-challenge.example.com`.
            let Identifier::Dns(identifier) = challenge.identifier().identifier else {
                bail!("unsupported identifier type in authorization");
            };
            let identifier = identifier.clone();

            let dns_value = challenge.key_authorization().dns_value();
            debug!("creating dns record for {identifier}");
            let acme_domain = format!("_acme-challenge.{identifier}");
            debug!("removing existing TXT record for {acme_domain}");
            self.dns01_client
                .remove_txt_records(&acme_domain)
                .await
                .context("failed to remove existing dns record")?;
            debug!(
                "creating TXT record for {acme_domain} with TTL {}s",
                self.dns_txt_ttl
            );
            let id = self
                .dns01_client
                .add_txt_record(&acme_domain, &dns_value, self.dns_txt_ttl)
                .await
                .context("failed to create dns record")?;
            challenges.push(Challenge {
                id,
                acme_domain,
                dns_value,
            });
        }
        Ok(())
    }

    /// Build a resolver that talks straight to the authoritative nameservers for
    /// the challenge zone.
    ///
    /// The self-check runs moments after the TXT record is created, so the first
    /// lookup can race propagation and come back NXDOMAIN. A recursive resolver
    /// then caches that negative for the zone's SOA minimum -- 1800s is common,
    /// far longer than `max_dns_wait` -- and every retry inside the window is
    /// answered from that cache, so the check can never pass no matter how long
    /// it waits. Reading from the authoritative servers removes the cache from
    /// the path entirely.
    async fn authoritative_resolver(&self, domain: &str) -> Result<TokioResolver> {
        // The NS records and the nameservers' own addresses are stable, so the
        // system resolver -- caching and all -- is the right tool for finding
        // them. Only the challenge record itself must dodge the cache.
        let bootstrap = system_resolver()?;

        // `_acme-challenge.<name>` is almost never a zone cut, and neither is
        // the name below it: for `_acme-challenge.a.example.com` the NS records
        // usually live on `example.com`. Querying the full name returns NODATA,
        // so walk up a label at a time until a name actually carries NS records.
        let mut candidate = domain
            .strip_prefix("_acme-challenge.")
            .unwrap_or(domain)
            .to_string();
        let mut addrs = Vec::new();
        let mut zone = candidate.clone();
        loop {
            if let Ok(ns_lookup) = bootstrap.ns_lookup(&candidate).await {
                for answer in ns_lookup.answers() {
                    let RData::NS(ns) = &answer.data else {
                        continue;
                    };
                    let Ok(ips) = bootstrap.lookup_ip(ns.0.to_utf8()).await else {
                        continue;
                    };
                    addrs.extend(ips.iter().map(|ip| SocketAddr::new(ip, 53)));
                }
                if !addrs.is_empty() {
                    zone = candidate;
                    break;
                }
            }
            match parent_zone(&candidate) {
                Some(parent) => candidate = parent,
                None => break,
            }
        }
        if addrs.is_empty() {
            bail!("no authoritative nameserver found for {domain}");
        }
        addrs.sort();
        addrs.dedup();
        debug!("checking {domain} against authoritative nameservers for {zone}: {addrs:?}");
        resolver_for(&addrs)
    }

    /// Self check the TXT records for the given challenges.
    async fn check_dns(&self, challenges: &[Challenge]) -> Result<()> {
        use tracing::warn;

        let mut delay = Duration::from_millis(250);
        let mut tries = 1u8;

        let mut unsettled_challenges = challenges.to_vec();

        debug!("Unsettled challenges: {unsettled_challenges:#?}");

        // Resolve each challenge's nameservers once. A SAN list can span zones,
        // so this is keyed per challenge rather than one resolver for all of
        // them; and with caching disabled there is nothing to gain by repeating
        // discovery on every retry.
        let mut resolvers = BTreeMap::new();
        for challenge in &unsettled_challenges {
            if resolvers.contains_key(&challenge.acme_domain) {
                continue;
            }
            let resolver = match self.authoritative_resolver(&challenge.acme_domain).await {
                Ok(resolver) => resolver,
                Err(err) => {
                    warn!(
                        "no authoritative nameserver for {} ({err:#}), using the system resolver",
                        challenge.acme_domain
                    );
                    system_resolver()?
                }
            };
            resolvers.insert(challenge.acme_domain.clone(), resolver);
        }

        let start_time = std::time::Instant::now();

        'outer: loop {
            sleep(delay).await;

            let elapsed = start_time.elapsed();
            if elapsed >= self.max_dns_wait {
                warn!(
                    "DNS propagation timeout after {elapsed:?}, max wait time is {max:?}. proceeding anyway as ACME server may have different DNS view",
                    max = self.max_dns_wait
                );
                break;
            }

            while let Some(challenge) = unsettled_challenges.pop() {
                let expected_txt = &challenge.dns_value;
                let dns_resolver = resolvers
                    .get(&challenge.acme_domain)
                    .context("no resolver for challenge domain")?;
                let settled = match dns_resolver.txt_lookup(&challenge.acme_domain).await {
                    Ok(record) => record.answers().iter().any(|answer| {
                        let RData::TXT(txt) = &answer.data else {
                            return false;
                        };
                        let actual_txt = txt.to_string();
                        debug!("Expected challenge: {expected_txt}, actual: {actual_txt}");
                        actual_txt == *expected_txt
                    }),
                    Err(err) if err.is_no_records_found() => false,
                    Err(err) => {
                        // Transport failures land here rather than in the arm
                        // above: `is_no_records_found` covers only
                        // `NoRecordsFound`, so a timeout or `NoConnections`
                        // would otherwise abort issuance outright. The
                        // authoritative servers may simply be unreachable --
                        // egress to :53 is often closed inside a CVM, and a
                        // v6-only NS set fails the same way from a v4-only host.
                        // Drop back to the system resolver for the rest of this
                        // wait: the ACME server has its own DNS view, and the
                        // timeout above already proceeds on expiry.
                        warn!(
                            "authoritative lookup for {} failed ({err:#}), falling back to the system resolver",
                            challenge.acme_domain
                        );
                        resolvers.insert(challenge.acme_domain.clone(), system_resolver()?);
                        unsettled_challenges.push(challenge);
                        continue 'outer;
                    }
                };
                if !settled {
                    delay = Duration::from_secs(32).min(delay * 2);
                    tries += 1;
                    debug!(
                        tries,
                        domain = &challenge.acme_domain,
                        elapsed = ?elapsed,
                        max_wait = ?self.max_dns_wait,
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

    /// Tell the ACME server every pending dns-01 challenge is answerable.
    ///
    /// The TXT records are published first and verified for propagation, so this
    /// is a second pass over the same authorizations: 0.8 dropped
    /// `Order::set_challenge_ready(url)`, and `ChallengeHandle::set_ready()`
    /// borrows the order, so the handle cannot be held across the DNS wait.
    async fn set_challenges_ready(&self, order: &mut Order) -> Result<()> {
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.context("failed to get authorizations")?;
            if authz.status != AuthorizationStatus::Pending {
                continue;
            }
            let mut challenge = authz
                .challenge(ChallengeType::Dns01)
                .context("no dns01 challenge found")?;
            debug!("setting challenge ready");
            challenge
                .set_ready()
                .await
                .context("failed to set challenge ready")?;
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
            .new_order(&NewOrder::new(&identifiers))
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
                    self.set_challenges_ready(&mut order)
                        .await
                        .context("failed to set challenges ready")?;
                    challenges_ready = true;
                    continue;
                }
                // To upload CSR
                OrderStatus::Ready => {
                    debug!("order is ready, uploading CSR");
                    let csr = make_csr(key, domains)?;
                    order
                        .finalize_csr(csr.as_ref())
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
                OrderStatus::Invalid => {
                    let error = find_error(&mut order).await.unwrap_or(Problem {
                        r#type: None,
                        detail: None,
                        status: None,
                        subproblems: Vec::new(),
                    });
                    bail!("order is invalid: {error}");
                }
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

async fn find_error(order: &mut Order) -> Option<Problem> {
    if let Some(error) = order.state().error.as_ref() {
        return Some(error.clone());
    }
    let mut authorizations = order.authorizations();
    while let Some(Ok(authz)) = authorizations.next().await {
        for challenge in &authz.challenges {
            if let Some(error) = &challenge.error {
                return Some(error.clone());
            }
        }
    }
    None
}

/// The resolver from `/etc/resolv.conf`, used to find nameservers and as the
/// fallback when the authoritative ones cannot be reached.
fn system_resolver() -> Result<TokioResolver> {
    TokioResolver::builder_tokio()
        .context("failed to read system dns config")?
        .build()
        .context("failed to build dns resolver")
}

/// The next name up to try when a name carries no NS records.
///
/// Stops at the last two labels. This is a heuristic, not a public-suffix
/// lookup: under a multi-label suffix such as `co.uk` it can stop on the suffix
/// itself and query the registry's nameservers, which answer with a referral
/// rather than the record. That costs one wasted lookup and then falls back,
/// which is why a PSL dependency is not worth carrying here.
fn parent_zone(name: &str) -> Option<String> {
    match name.split_once('.') {
        Some((_, parent)) if parent.contains('.') => Some(parent.to_string()),
        _ => None,
    }
}

/// Build a resolver that queries exactly `servers`.
///
/// Caching is disabled: this resolver exists to observe a record that was just
/// written, so a cached answer of any age is the wrong answer.
fn resolver_for(servers: &[SocketAddr]) -> Result<TokioResolver> {
    let name_servers = servers
        .iter()
        .map(|dns_server| {
            let mut name_server = NameServerConfig::udp_and_tcp(dns_server.ip());
            for connection in &mut name_server.connections {
                connection.port = dns_server.port();
            }
            name_server
        })
        .collect();
    let mut builder = TokioResolver::builder_with_config(
        ResolverConfig::from_parts(None, Vec::new(), name_servers),
        TokioRuntimeProvider::default(),
    );
    let options = builder.options_mut();
    options.cache_size = 0;
    options.negative_min_ttl = Some(Duration::ZERO);
    options.negative_max_ttl = Some(Duration::ZERO);
    builder.build().context("failed to build dns resolver")
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

#[cfg(test)]
mod challenge_parsing_tests {
    use instant_acme::{AuthorizationState, AuthorizationStatus, ChallengeType};

    /// Let's Encrypt offers `dns-persist-01` alongside `dns-01`, and that
    /// challenge object carries no `token`. Deserializing the authorization must
    /// still succeed: `challenges` is one array, so a single unparseable entry
    /// used to take the usable `dns-01` challenge down with it.
    #[test]
    fn an_authorization_survives_a_challenge_type_without_a_token() {
        // Shape taken from a real acme-staging-v02 authorization response.
        let authz = r#"{
            "identifier": { "type": "dns", "value": "example.com" },
            "status": "pending",
            "expires": "2026-09-01T00:00:00Z",
            "challenges": [
                {
                    "type": "dns-persist-01",
                    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1/a",
                    "status": "pending"
                },
                {
                    "type": "dns-01",
                    "url": "https://acme-staging-v02.api.letsencrypt.org/acme/chall/1/b",
                    "status": "pending",
                    "token": "a-real-token"
                }
            ],
            "wildcard": true
        }"#;

        let state: AuthorizationState = serde_json::from_str(authz)
            .expect("authorization with an unknown challenge must parse");
        assert_eq!(state.status, AuthorizationStatus::Pending);
        assert_eq!(state.challenges.len(), 2);

        let dns01 = state
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Dns01)
            .expect("the dns-01 challenge must survive alongside the unknown one");
        assert_eq!(dns01.token, "a-real-token");

        // The tokenless challenge parses with an empty token rather than failing.
        let other = state
            .challenges
            .iter()
            .find(|c| c.r#type != ChallengeType::Dns01)
            .expect("the unknown challenge is kept");
        assert!(other.token.is_empty());

        // A wildcard authorization still reports the bare name, which is what the
        // `_acme-challenge.<name>` TXT record is published under.
        let instant_acme::Identifier::Dns(name) = state.identifier().identifier else {
            panic!("expected a dns identifier");
        };
        assert_eq!(name, "example.com");
    }
}

#[cfg(test)]
mod ns_discovery_tests {
    use super::parent_zone;

    #[test]
    fn the_walk_climbs_to_a_name_that_can_carry_ns_records() {
        // A challenge name is not a zone cut, so the walk has to climb to the
        // name that actually carries the NS records.
        assert_eq!(parent_zone("06rc0.kvin.wang").as_deref(), Some("kvin.wang"));
        assert_eq!(
            parent_zone("a.b.example.com").as_deref(),
            Some("b.example.com")
        );
        // The walk stops at the last two labels. That is a heuristic, not a
        // public-suffix lookup: under a multi-label suffix such as `co.uk` it
        // can stop on the suffix itself. In practice the registrable name
        // carries NS records and the walk breaks a level earlier, and a
        // referral answer just falls back, so this is a stopping rule rather
        // than a correctness guarantee.
        assert_eq!(parent_zone("kvin.wang"), None);
        assert_eq!(parent_zone("wang"), None);
    }
}
