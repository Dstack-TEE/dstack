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
    Account, AccountCredentials, AuthorizationStatus, AuthorizedIdentifier, ChallengeType,
    Identifier, NewAccount, NewOrder, Order, OrderStatus, Problem,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use x509_parser::prelude::{GeneralName, Pem};

use super::dns01_client::{Dns01Api, Dns01Client};
use super::dns_persist::{self, AuthorizationRecord};
use super::http_client::ReqwestHttpClient;

/// The ACME challenge used to prove control of the certificate's domains.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeKind {
    /// RFC 8555 `dns-01`. certbot answers every order by writing a TXT record
    /// through the DNS provider API, so it needs a credential with write access
    /// to the zone.
    #[default]
    #[serde(rename = "dns-01")]
    Dns01,
    /// draft-ietf-acme-dns-persist-01 `dns-persist-01`. Control is proven by a
    /// `_validation-persist` record published once, out of band; certbot needs no
    /// DNS credential and the zone can be hosted anywhere.
    ///
    /// Experimental — see `docs/certbot-dns-persist-01.md`.
    #[serde(rename = "dns-persist-01")]
    DnsPersist01,
}

/// How the client proves control of a domain to the ACME server.
///
/// The two methods differ in who writes DNS. `dns-01` needs certbot to hold a
/// provider credential with write access to the zone for the lifetime of the
/// deployment; `dns-persist-01` moves that to a one-time record the operator
/// publishes by hand, after which certbot only ever reads DNS.
#[derive(Debug)]
pub enum ValidationMethod {
    /// RFC 8555 `dns-01`: certbot publishes a fresh `_acme-challenge` TXT record
    /// through the provider API for every order and removes it afterwards.
    Dns01 {
        /// Provider client with write access to the zone.
        client: Dns01Client,
        /// TTL of the published records, in seconds (1 = auto, min 60 on Cloudflare).
        txt_ttl: u32,
        /// Issuer Domain Name to name in the CAA records certbot publishes.
        issuer_domain_name: String,
    },
    /// draft-ietf-acme-dns-persist-01 `dns-persist-01`: control is proven by a
    /// `_validation-persist` TXT record naming the CA and this ACME account,
    /// published once and left in place. certbot needs no provider credential,
    /// and the zone can be hosted anywhere.
    ///
    /// Experimental: the draft is still changing and Let's Encrypt serves this
    /// challenge on staging only. See `docs/certbot-dns-persist-01.md`.
    DnsPersist01 {
        /// Issuer Domain Name to name in the record and in CAA records. Must be
        /// one of the `issuer-domain-names` the CA sends in the challenge —
        /// `letsencrypt.org` for Let's Encrypt.
        issuer_domain_name: String,
    },
}

impl ValidationMethod {
    /// Which challenge this method answers.
    fn kind(&self) -> ChallengeKind {
        match self {
            Self::Dns01 { .. } => ChallengeKind::Dns01,
            Self::DnsPersist01 { .. } => ChallengeKind::DnsPersist01,
        }
    }

    /// The challenge type to look for in an authorization.
    fn challenge_type(&self) -> ChallengeType {
        match self {
            Self::Dns01 { .. } => ChallengeType::Dns01,
            // instant-acme has no variant for the draft challenge, so it lands in
            // `Unknown`. Matching on the wire string is what selects it.
            Self::DnsPersist01 { .. } => ChallengeType::Unknown(DNS_PERSIST_01.to_string()),
        }
    }

    /// Issuer Domain Name to write into CAA records.
    ///
    /// Both methods read it from configuration, whose default is
    /// `letsencrypt.org` -- the name existing deployments already have published
    /// -- so an untouched configuration writes what it wrote before. A CAA
    /// record naming a CA other than the one at `acme_url` forbids the very
    /// issuance it is published to enable, and that is not a dns-01/
    /// dns-persist-01 distinction.
    fn issuer_domain_name(&self) -> &str {
        match self {
            Self::Dns01 {
                issuer_domain_name, ..
            } => issuer_domain_name,
            Self::DnsPersist01 { issuer_domain_name } => issuer_domain_name,
        }
    }

    /// The provider client, or an error naming why there isn't one.
    fn dns01_client(&self) -> Result<&Dns01Client> {
        match self {
            Self::Dns01 { client, .. } => Ok(client),
            Self::DnsPersist01 { .. } => bail!(
                "dns-persist-01 holds no DNS provider credential, so certbot cannot write \
                 records; publish them out of band (see the `dns-records` command)"
            ),
        }
    }
}

/// Wire name of the draft challenge, as it appears in the authorization.
const DNS_PERSIST_01: &str = "dns-persist-01";

/// A DNS record that has to exist before the CA will issue.
///
/// Rendered as a zone-file line so it can be pasted into any provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredRecord {
    /// FQDN the record lives at.
    pub name: String,
    /// Record type, e.g. `TXT` or `CAA`.
    pub record_type: String,
    /// Record value, including any CAA flags and tag.
    pub content: String,
}

impl fmt::Display for RequiredRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}. IN {} {}", self.name, self.record_type, self.content)
    }
}

/// The CAA `issue`/`issuewild` value that pins issuance to one account.
///
/// `validationmethods` names the challenge actually in use: a record left
/// pinned to `dns-01` after switching to `dns-persist-01` refuses every order,
/// and vice versa.
fn caa_content(challenge: ChallengeKind, issuer_domain_name: &str, account_uri: &str) -> String {
    let method = match challenge {
        ChallengeKind::Dns01 => "dns-01",
        ChallengeKind::DnsPersist01 => DNS_PERSIST_01,
    };
    format!("{issuer_domain_name};validationmethods={method};accounturi={account_uri}")
}

/// Every DNS record that has to exist for the CA to issue for `domains`.
///
/// Under `dns-01` certbot writes these itself and the list is informational.
/// Under `dns-persist-01` it holds no credential and cannot write anything, so
/// this list *is* the one-time setup an operator has to publish by hand.
///
/// Takes the account URI rather than a client so that callers holding only the
/// stored credentials — an admin listing, say — can render the records without
/// a round trip to the CA.
pub fn required_dns_records(
    challenge: ChallengeKind,
    issuer_domain_name: &str,
    account_uri: &str,
    domains: &[String],
) -> Vec<RequiredRecord> {
    let caa_content = caa_content(challenge, issuer_domain_name, account_uri);
    let mut records = Vec::new();
    for base_name in base_names(domains) {
        if challenge == ChallengeKind::DnsPersist01 {
            // One record covers the base name and, with the wildcard policy,
            // `*.<base name>`; only ask for the policy when a wildcard is
            // actually requested, so the record grants no more than needed.
            let record = AuthorizationRecord {
                issuer_domain_name: issuer_domain_name.to_string(),
                account_uri: account_uri.to_string(),
                wildcard: domains
                    .iter()
                    .any(|name| name.strip_prefix("*.") == Some(base_name)),
            };
            records.push(RequiredRecord {
                name: dns_persist::validation_domain(base_name),
                record_type: "TXT".to_string(),
                content: format!("\"{}\"", record.rdata()),
            });
        }
        for tag in ["issue", "issuewild"] {
            records.push(RequiredRecord {
                name: base_name.to_string(),
                record_type: "CAA".to_string(),
                content: format!("0 {tag} \"{caa_content}\""),
            });
        }
    }
    records
}

/// An ACME account, as registered, before any validation method is chosen.
///
/// Returned by [`AcmeClient::register_account`] so a caller can store the
/// credentials and report the URI -- the two things a `dns-persist-01` record
/// and an account-pinned CAA record are written from -- without holding a
/// client it has no use for yet.
pub struct AcmeAccount {
    /// Encoded credentials, in the form [`AcmeClient::load`] takes.
    pub credentials: String,
    /// URI the CA identifies this account by.
    pub account_uri: String,
}

/// The share of `renew_timeout` the pre-order DNS check may spend.
///
/// The rest pays for the order itself: `new_order`, the authorizations, the
/// provider writes under `dns-01`, then finalize and the certificate fetch.
const DNS_WAIT_SHARE_OF_RENEW_TIMEOUT: u32 = 2;

/// The DNS wait to actually use, given what is configured and how long the whole
/// order is allowed to take.
///
/// The wait is advisory by design: certbot polls its own resolver, logs what it
/// could not see, and starts the order regardless, because the CA's DNS view is
/// not this node's. That only holds if the wait ends before the timeout wrapping
/// the order does. It does not by default -- a DNS credential's `max_dns_wait`
/// defaults to 300s and `renew_timeout` defaults to 300s, and the wait is
/// measured from after the order and its authorizations are fetched, so the
/// outer timeout always fires first. The renewal then dies with "certificate
/// request timed out", and the warning naming the record that was missing --
/// the first thing an operator is told to look for -- is never logged.
///
/// Clamping here rather than picking a smaller constant covers both challenges
/// with one rule, and keeps holding when an operator lowers `renew_timeout`
/// from the dashboard, which no constant can.
pub fn advisory_dns_wait(configured: Duration, renew_timeout: Duration) -> Duration {
    configured.min(renew_timeout / DNS_WAIT_SHARE_OF_RENEW_TIMEOUT)
}

/// A AcmeClient instance.
pub struct AcmeClient {
    account: Account,
    credentials: Credentials,
    validation: ValidationMethod,
    max_dns_wait: Duration,
}

/// One pending authorization and the DNS record that answers it.
#[derive(Debug, Clone)]
struct Challenge {
    /// Provider-assigned record id, used by the cleanup pass after the order
    /// settles. `None` when certbot did not create the record and must not
    /// delete it — `dns-persist-01` records belong to the operator.
    id: Option<String>,
    /// FQDN the TXT record lives at.
    acme_domain: String,
    /// What a TXT record there has to say for the CA to accept the challenge.
    expected: Expected,
}

/// The condition a challenge's TXT records have to meet.
#[derive(Debug, Clone)]
enum Expected {
    /// `dns-01`: the key authorization digest, matched verbatim.
    KeyAuthorization(String),
    /// `dns-persist-01`: an issue-value naming our issuer and account.
    Authorization(AuthorizationRecord),
}

impl Expected {
    /// Whether the TXT records currently published at the challenge domain answer
    /// the challenge.
    fn satisfied_by(&self, published: &[String], now: u64) -> bool {
        match self {
            Self::KeyAuthorization(value) => published.iter().any(|txt| txt == value),
            Self::Authorization(record) => record.satisfied_by_any(published, now),
        }
    }
}

impl Challenge {
    /// A line naming what is missing at the challenge domain, phrased so an
    /// operator can act on it: under `dns-persist-01` it is the exact record to
    /// publish, under `dns-01` it is the value certbot just wrote.
    fn unsettled_hint(&self) -> String {
        format!(
            "no TXT record at {} matches the expected value: {}",
            self.acme_domain, self.expected
        )
    }
}

impl fmt::Display for Expected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyAuthorization(value) => f.write_str(value),
            Self::Authorization(record) => write!(f, "{}", record.rdata()),
        }
    }
}

/// Current UNIX time, for comparing against a record's `persistUntil`.
fn now_secs() -> u64 {
    time::OffsetDateTime::now_utc().unix_timestamp().max(0) as u64
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

/// The names CAA and `dns-persist-01` records are published under, deduplicated.
///
/// A wildcard request is authorized from its base name, so `example.com` and
/// `*.example.com` share one set of records.
fn base_names(domains: &[String]) -> BTreeSet<&str> {
    domains
        .iter()
        .map(|name| name.strip_prefix("*.").unwrap_or(name))
        .collect()
}

fn caa_tag(content: &str) -> Option<&str> {
    content.split_whitespace().nth(1)
}

impl AcmeClient {
    pub async fn load(
        validation: ValidationMethod,
        encoded_credentials: &str,
        max_dns_wait: Duration,
    ) -> Result<Self> {
        let credentials: Credentials = serde_json::from_str(encoded_credentials)?;
        let http_client = Box::new(ReqwestHttpClient::new()?);
        let account = Account::builder_with_http(http_client)
            .from_credentials(credentials.credentials)
            .await?;
        let credentials: Credentials = serde_json::from_str(encoded_credentials)?;
        Ok(Self {
            account,
            validation,
            credentials,
            max_dns_wait,
        })
    }

    /// Register a new ACME account, with no validation method attached.
    ///
    /// Registration is a POST to the directory's `newAccount`. It asserts
    /// nothing about any domain and touches no DNS, so it needs neither a
    /// provider credential nor a challenge choice -- and a deployment can
    /// therefore have an account before it has anything to validate. That order
    /// is forced under `dns-persist-01`: the record an operator publishes names
    /// the account, so the account has to exist first.
    pub async fn register_account(acme_url: &str) -> Result<AcmeAccount> {
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
        Ok(AcmeAccount {
            account_uri: credentials.account_id.clone(),
            credentials: serde_json::to_string(&credentials)?,
        })
    }

    /// Create a new account and a client bound to `validation`.
    pub async fn new_account(
        acme_url: &str,
        validation: ValidationMethod,
        max_dns_wait: Duration,
    ) -> Result<Self> {
        let account = Self::register_account(acme_url).await?;
        Self::load(validation, &account.credentials, max_dns_wait)
            .await
            .context("failed to load the account just registered")
    }

    /// Dump the account credentials to a JSON string.
    pub fn dump_credentials(&self) -> Result<String> {
        Ok(serde_json::to_string(&self.credentials)?)
    }

    /// Read the account ID from the encoded credentials.
    pub fn account_id(&self) -> &str {
        &self.credentials.account_id
    }

    /// The CAA `issue`/`issuewild` value that pins issuance to this account.
    fn caa_content(&self) -> String {
        caa_content(
            self.validation.kind(),
            self.validation.issuer_domain_name(),
            self.account_id(),
        )
    }

    /// Every DNS record that has to exist for the CA to issue for `domains`.
    ///
    /// See [`required_dns_records`], which this fills in from the live account.
    pub fn required_dns_records(&self, domains: &[String]) -> Vec<RequiredRecord> {
        required_dns_records(
            self.validation.kind(),
            self.validation.issuer_domain_name(),
            self.account_id(),
            domains,
        )
    }

    pub async fn set_caa_records(&self, domains: &[String]) -> Result<()> {
        let dns01_client = self.validation.dns01_client().context(
            "cannot set CAA records without DNS write access; publish the records \
             printed by `certbot dns-records` instead",
        )?;
        let content = self.caa_content();
        let base_names = base_names(domains);

        for base_name in base_names {
            // 1. Set ";" to guard timing gap between the operations.
            debug!("setting guard CAA records for {base_name}");
            let guard0 = dns01_client
                .add_caa_record(base_name, 0, "issue", ";")
                .await?;
            let guard1 = dns01_client
                .add_caa_record(base_name, 0, "issuewild", ";")
                .await?;
            // 2. Remove the existing constraints
            for record in dns01_client.get_records(base_name).await? {
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
                    dns01_client.remove_record(&record.id).await?;
                }
            }
            // 3. Set the new constraints
            debug!("setting CAA records for {base_name}, 0 issue \"{content}\"");
            dns01_client
                .add_caa_record(base_name, 0, "issue", &content)
                .await?;
            debug!("setting CAA records for {base_name}, 0 issuewild \"{content}\"");
            dns01_client
                .add_caa_record(base_name, 0, "issuewild", &content)
                .await?;
            debug!("removing guard CAA records for {base_name}");
            // 4. Remove the guards
            dns01_client.remove_record(&guard0).await?;
            dns01_client.remove_record(&guard1).await?;
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
        // Only records certbot created are cleaned up. A dns-persist-01 record
        // is the operator's and outlives every order, so it carries no id.
        for id in challenges
            .iter()
            .filter_map(|challenge| challenge.id.as_ref())
        {
            let Ok(dns01_client) = self.validation.dns01_client() else {
                break;
            };
            debug!("removing dns record {id}");
            if let Err(err) = dns01_client.remove_record(id).await {
                error!("failed to remove dns record {id}: {err}");
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

    /// Issue a certificate for `domains` unless the live one is already for
    /// exactly those names.
    ///
    /// Returns whether a certificate was issued.
    pub async fn create_cert_if_needed(
        &self,
        domains: &[String],
        live_cert_pem_path: impl AsRef<Path>,
        live_key_pem_path: impl AsRef<Path>,
        backup_dir: impl AsRef<Path>,
    ) -> Result<bool> {
        if live_cert_pem_path.as_ref().exists() && live_key_pem_path.as_ref().exists() {
            // The live certificate is only "the certificate we were asked for"
            // if it carries the configured names. Treating its mere existence as
            // sufficient pinned the name list at whatever the first issuance
            // used: an operator adding a name to the configuration got no new
            // certificate, and renewal read its names back off the old one, so
            // the edit never took effect at all.
            let reason = match fs::read_to_string(live_cert_pem_path.as_ref()) {
                Ok(live_cert_pem) => reissue_reason(&live_cert_pem, domains),
                // `exists()` has already passed, so this is a permission
                // problem or a file replaced mid-flight rather than a missing
                // certificate. Either way the certificate cannot be checked
                // against the configuration, which is a reissue for the same
                // reason an unparseable one is.
                Err(err) => Some(format!(
                    "cannot read {}: {err:#}",
                    live_cert_pem_path.as_ref().display()
                )),
            };
            match reason {
                None => return Ok(false),
                Some(reason) => info!("reissuing: {reason}"),
            }
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
        let challenge_type = self.validation.challenge_type();
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.context("failed to get authorizations")?;
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => bail!("unsupported authorization status: {:?}", authz.status),
            }

            // Read before taking the challenge handle, which borrows the
            // authorization for the rest of the iteration.
            let wildcard = authz.wildcard;
            let challenge = authz
                .challenge(challenge_type.clone())
                .with_context(|| format!("no {challenge_type:?} challenge found"))?;

            let acme_domain = challenge_domain(self.validation.kind(), challenge.identifier())?;
            let challenge = match &self.validation {
                ValidationMethod::Dns01 {
                    client, txt_ttl, ..
                } => {
                    let dns_value = challenge.key_authorization().dns_value();
                    // Clearing stale records is a per-name preparation step, not a
                    // per-authorization one. An order for `example.com` and
                    // `*.example.com` yields two authorizations that are both answered
                    // under `_acme-challenge.example.com`, each with its own value, and
                    // both values have to be live at validation time. Purging again for
                    // the second authorization would delete the record the first one
                    // just published, so one of the two challenges could never be
                    // answered and the order failed with "Correct value not found for
                    // DNS challenge".
                    if needs_purge(challenges, &acme_domain) {
                        debug!("removing existing TXT records for {acme_domain}");
                        client
                            .remove_txt_records(&acme_domain)
                            .await
                            .context("failed to remove existing dns record")?;
                    }
                    debug!("creating TXT record for {acme_domain} with TTL {txt_ttl}s");
                    let id = client
                        .add_txt_record(&acme_domain, &dns_value, *txt_ttl)
                        .await
                        .context("failed to create dns record")?;
                    Challenge {
                        id: Some(id),
                        acme_domain,
                        expected: Expected::KeyAuthorization(dns_value),
                    }
                }
                // Nothing to publish: the record is already in the zone, or the
                // order is about to fail and say so. There is likewise nothing
                // to purge -- the record is the operator's, and one persistent
                // record answers every authorization under the name.
                ValidationMethod::DnsPersist01 { issuer_domain_name } => Challenge {
                    id: None,
                    acme_domain,
                    expected: Expected::Authorization(AuthorizationRecord {
                        issuer_domain_name: issuer_domain_name.clone(),
                        account_uri: self.account_id().to_string(),
                        wildcard,
                    }),
                },
            };
            challenges.push(challenge);
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
        // The leading label is dropped for any challenge prefix -- `_acme-challenge`
        // for dns-01, `_validation-persist` for dns-persist-01 -- since an
        // underscore label never carries NS records.
        let mut candidate = strip_challenge_label(domain).to_string();
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

    /// Wait until every challenge's records are visible to us.
    ///
    /// Advisory, not a gate: our resolver is not the CA's, and under
    /// `dns-persist-01` our expectation can even be stricter than the CA's --
    /// the `issuer-domain-names` it would accept are not exposed by
    /// instant-acme. A record we never see is reported and the order proceeds,
    /// letting the CA decide.
    async fn check_dns(&self, challenges: &[Challenge]) -> Result<()> {
        let mut delay = Duration::from_millis(250);
        let mut tries = 1u8;

        let mut unsettled_challenges = challenges.to_vec();

        debug!("Unsettled challenges: {unsettled_challenges:#?}");

        // The budget covers discovery as well as the wait. `renew_timeout` is
        // commonly the same value as `max_dns_wait`, so leaving discovery
        // outside it lets the outer timeout kill the renewal mid-wait instead of
        // reaching the graceful "proceed anyway" exit below -- and that exit is
        // what keeps a DNS problem from failing issuance outright.
        let start_time = std::time::Instant::now();

        // Resolve each challenge's nameservers once. A SAN list can span zones,
        // so this is keyed per challenge rather than one resolver for all of
        // them; and with caching disabled there is nothing to gain by repeating
        // discovery on every retry.
        let mut resolvers = BTreeMap::new();
        let mut fell_back = BTreeSet::new();
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

        'outer: loop {
            sleep(delay).await;

            let elapsed = start_time.elapsed();
            if elapsed >= self.max_dns_wait {
                warn!(
                    "DNS propagation timeout after {elapsed:?}, max wait time is {max:?}. proceeding anyway as ACME server may have different DNS view",
                    max = self.max_dns_wait
                );
                for challenge in &unsettled_challenges {
                    warn!("{}", challenge.unsettled_hint());
                }
                break;
            }

            while let Some(challenge) = unsettled_challenges.pop() {
                let dns_resolver = resolvers
                    .get(&challenge.acme_domain)
                    .context("no resolver for challenge domain")?;
                let published = match dns_resolver.txt_lookup(&challenge.acme_domain).await {
                    Ok(records) => records
                        .answers()
                        .iter()
                        .filter_map(|answer| match &answer.data {
                            RData::TXT(txt) => Some(txt.to_string()),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    Err(err) if err.is_no_records_found() => Vec::new(),
                    Err(err) if !fell_back.contains(&challenge.acme_domain) => {
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
                        fell_back.insert(challenge.acme_domain.clone());
                        resolvers.insert(challenge.acme_domain.clone(), system_resolver()?);
                        unsettled_challenges.push(challenge);
                        continue 'outer;
                    }
                    Err(err) => {
                        // Already on the system resolver, so there is nothing
                        // left to fall back to. Treat it as "not settled yet" so
                        // the backoff below applies: re-announcing a fallback
                        // that already happened would both misreport the state
                        // and keep the delay pinned at its initial value.
                        debug!(
                            domain = &challenge.acme_domain,
                            "dns lookup failed: {err:#}"
                        );
                        Vec::new()
                    }
                };
                debug!(
                    "Expected challenge: {}, actual: {published:?}",
                    challenge.expected
                );
                if !challenge.expected.satisfied_by(&published, now_secs()) {
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

    /// Tell the ACME server every pending challenge is answerable.
    ///
    /// The DNS records are published and checked first, so this is a second pass
    /// over the same authorizations: 0.8 dropped `Order::set_challenge_ready(url)`,
    /// and `ChallengeHandle::set_ready()` borrows the order, so the handle cannot
    /// be held across the DNS wait.
    async fn set_challenges_ready(&self, order: &mut Order) -> Result<()> {
        let challenge_type = self.validation.challenge_type();
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.context("failed to get authorizations")?;
            if authz.status != AuthorizationStatus::Pending {
                continue;
            }
            let mut challenge = authz
                .challenge(challenge_type.clone())
                .with_context(|| format!("no {challenge_type:?} challenge found"))?;
            debug!("setting challenge ready for {}", challenge.url);
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
                    let error = find_error(&mut order).await.context(
                        "order is invalid and its authorization error could not be retrieved",
                    )?;
                    match error {
                        Some(error) => bail!("order is invalid: {error}"),
                        None => bail!("order is invalid without error details"),
                    }
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

/// Whether the stale TXT records under `acme_domain` still have to be cleared.
///
/// The purge runs once per challenge name per issuance: the records this run
/// has already published live under the names in `published`, and clearing
/// those would take an answered challenge back down.
fn needs_purge(published: &[Challenge], acme_domain: &str) -> bool {
    !published
        .iter()
        .any(|challenge| challenge.acme_domain == acme_domain)
}

/// The name of the TXT record that answers `challenge`'s validation for `identifier`.
///
/// The record always lives under the bare name: a wildcard authorization for
/// `*.example.com` is answered at `_acme-challenge.example.com`, and at
/// `_validation-persist.example.com` under dns-persist-01. `AuthorizedIdentifier`
/// renders the wildcard prefix in its `Display`, so formatting it directly would publish
/// the record at `_acme-challenge.*.example.com` and fail every wildcard issuance.
fn challenge_domain(
    challenge: ChallengeKind,
    identifier: &AuthorizedIdentifier<'_>,
) -> Result<String> {
    let Identifier::Dns(name) = identifier.identifier else {
        bail!("unsupported identifier type in authorization: {identifier}");
    };
    Ok(match challenge {
        ChallengeKind::Dns01 => format!("_acme-challenge.{name}"),
        ChallengeKind::DnsPersist01 => dns_persist::validation_domain(name),
    })
}

/// Drop a leading underscore label, so the zone walk starts at a real name.
///
/// Challenge records live under a reserved label -- `_acme-challenge` for
/// dns-01, `_validation-persist` for dns-persist-01 -- which never carries NS
/// records, so querying it only costs a round trip.
fn strip_challenge_label(domain: &str) -> &str {
    match domain.starts_with('_') {
        true => domain.split_once('.').map_or(domain, |(_, rest)| rest),
        false => domain,
    }
}

async fn find_error(order: &mut Order) -> Result<Option<Problem>> {
    if let Some(error) = order.state().error.as_ref() {
        return Ok(Some(error.clone()));
    }
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let authz =
            result.context("failed to fetch authorization while looking for the order error")?;
        for challenge in &authz.challenges {
            if let Some(error) = &challenge.error {
                return Ok(Some(error.clone()));
            }
        }
    }
    Ok(None)
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

/// Why the live certificate has to be reissued, or `None` if it is the one the
/// configuration asks for.
///
/// A certificate whose names cannot be read counts as a reissue: it cannot be
/// checked against the configuration, so leaving it in place would keep serving
/// something this process can no longer reason about.
fn reissue_reason(live_cert_pem: &str, domains: &[String]) -> Option<String> {
    match extract_subject_alt_names(live_cert_pem) {
        Ok(names) if names_match(&names, domains) => None,
        Ok(names) => Some(format!(
            "the live certificate covers {}, the configuration asks for {}",
            names.join(", "),
            domains.join(", ")
        )),
        Err(err) => Some(format!("cannot read the live certificate's names: {err:#}")),
    }
}

/// Whether a certificate's DNS names are exactly the configured ones.
///
/// Compared as sets: the order the CA returns names in is its own business, and
/// DNS names are case-insensitive and may carry a trailing root dot. Equality
/// rather than containment, so narrowing the configured list reissues too.
fn names_match(cert_names: &[String], domains: &[String]) -> bool {
    fn normalized(names: &[String]) -> BTreeSet<String> {
        names
            .iter()
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
            .collect()
    }
    normalized(cert_names) == normalized(domains)
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
    fn a_challenge_label_is_dropped_before_the_walk_starts() {
        use super::strip_challenge_label;

        // Both challenge methods put their record under a reserved underscore
        // label, and neither label can carry NS records.
        assert_eq!(
            strip_challenge_label("_acme-challenge.example.com"),
            "example.com"
        );
        assert_eq!(
            strip_challenge_label("_validation-persist.example.com"),
            "example.com"
        );
        assert_eq!(strip_challenge_label("example.com"), "example.com");
    }

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

#[cfg(test)]
mod challenge_domain_tests {
    use super::{challenge_domain, ChallengeKind};
    use instant_acme::Identifier;

    /// A wildcard order authorizes the bare name with `wildcard: true`, and the TXT record
    /// answering it must be published under that bare name. Formatting the identifier
    /// through its `Display` instead would ask for `_acme-challenge.*.example.com`.
    /// dns-persist-01 answers the same authorization under its own label, and the
    /// wildcard prefix must not leak into that name either.
    #[test]
    fn the_challenge_domain_never_carries_a_wildcard_prefix() {
        let dns = Identifier::Dns("example.com".to_string());
        for wildcard in [false, true] {
            assert_eq!(
                challenge_domain(ChallengeKind::Dns01, &dns.authorized(wildcard)).unwrap(),
                "_acme-challenge.example.com",
                "wildcard={wildcard}"
            );
            assert_eq!(
                challenge_domain(ChallengeKind::DnsPersist01, &dns.authorized(wildcard)).unwrap(),
                "_validation-persist.example.com",
                "wildcard={wildcard}"
            );
        }
    }

    /// Both methods are only defined for DNS identifiers; anything else is a bug in the
    /// order we built, so it must be an error rather than a nonsensical record name.
    #[test]
    fn a_non_dns_identifier_is_rejected() {
        let ip = Identifier::Ip("192.0.2.1".parse().unwrap());
        assert!(challenge_domain(ChallengeKind::Dns01, &ip.authorized(false)).is_err());
        assert!(challenge_domain(ChallengeKind::DnsPersist01, &ip.authorized(false)).is_err());
    }
}

#[cfg(test)]
mod required_record_tests {
    use super::*;

    const ACCOUNT: &str = "https://acme-v02.api.letsencrypt.org/acme/acct/1234567890";

    fn records(challenge: ChallengeKind, domains: &[&str]) -> Vec<String> {
        required_dns_records(
            challenge,
            dns_persist::LETS_ENCRYPT_ISSUER_DOMAIN_NAME,
            ACCOUNT,
            &domains.iter().map(|d| d.to_string()).collect::<Vec<_>>(),
        )
        .iter()
        .map(ToString::to_string)
        .collect()
    }

    #[test]
    fn dns01_caa_content_is_byte_identical_to_the_pinned_format() {
        // CAA values published by earlier releases have to keep matching, or
        // issuance stops the moment this string drifts.
        assert_eq!(
            caa_content(
                ChallengeKind::Dns01,
                dns_persist::LETS_ENCRYPT_ISSUER_DOMAIN_NAME,
                ACCOUNT
            ),
            format!("letsencrypt.org;validationmethods=dns-01;accounturi={ACCOUNT}")
        );
    }

    #[test]
    fn caa_content_names_the_challenge_in_use() {
        // A CAA record still pinned to dns-01 refuses every dns-persist-01 order.
        assert!(caa_content(
            ChallengeKind::DnsPersist01,
            dns_persist::LETS_ENCRYPT_ISSUER_DOMAIN_NAME,
            ACCOUNT
        )
        .contains("validationmethods=dns-persist-01"));
    }

    #[test]
    fn dns01_needs_no_validation_record() {
        // certbot writes the `_acme-challenge` record itself, per order.
        assert_eq!(
            records(ChallengeKind::Dns01, &["*.example.com"]),
            vec![
                format!(
                    "example.com. IN CAA 0 issue \"letsencrypt.org;validationmethods=dns-01;accounturi={ACCOUNT}\""
                ),
                format!(
                    "example.com. IN CAA 0 issuewild \"letsencrypt.org;validationmethods=dns-01;accounturi={ACCOUNT}\""
                ),
            ]
        );
    }

    #[test]
    fn dns_persist_asks_for_the_wildcard_policy_only_when_a_wildcard_is_ordered() {
        let plain = records(ChallengeKind::DnsPersist01, &["example.com"]);
        assert_eq!(
            plain[0],
            format!(
                "_validation-persist.example.com. IN TXT \"letsencrypt.org; accounturi={ACCOUNT}\""
            )
        );

        let wildcard = records(ChallengeKind::DnsPersist01, &["*.example.com"]);
        assert_eq!(
            wildcard[0],
            format!(
                "_validation-persist.example.com. IN TXT \"letsencrypt.org; accounturi={ACCOUNT}; policy=wildcard\""
            )
        );
    }

    #[test]
    fn a_name_and_its_wildcard_share_one_validation_record() {
        // Both identifiers authorize from the same base name, so asking the
        // operator for two records would be asking for one too many.
        let records = records(
            ChallengeKind::DnsPersist01,
            &["example.com", "*.example.com"],
        );
        assert_eq!(
            records.iter().filter(|r| r.contains(" TXT ")).count(),
            1,
            "{records:#?}"
        );
        assert!(records[0].contains("policy=wildcard"), "{records:#?}");
    }

    #[test]
    fn each_base_name_gets_its_own_records() {
        let records = records(
            ChallengeKind::DnsPersist01,
            &["*.a.example.com", "*.b.example.com"],
        );
        assert_eq!(records.len(), 6, "{records:#?}");
        assert!(records[0].starts_with("_validation-persist.a.example.com."));
        assert!(records[3].starts_with("_validation-persist.b.example.com."));
    }
}

#[cfg(test)]
mod purge_tests {
    use super::{needs_purge, Challenge, Expected};

    fn challenge(acme_domain: &str, dns_value: &str) -> Challenge {
        Challenge {
            id: Some(format!("rec-{dns_value}")),
            acme_domain: acme_domain.to_string(),
            expected: Expected::KeyAuthorization(dns_value.to_string()),
        }
    }

    /// A base name and its wildcard are two authorizations answered under one
    /// `_acme-challenge.<name>`. The first one clears whatever an aborted run
    /// left behind; the second must publish alongside it instead of wiping it.
    #[test]
    fn a_name_is_cleared_once_per_issuance() {
        let mut published = vec![];
        assert!(needs_purge(&published, "_acme-challenge.example.com"));

        published.push(challenge("_acme-challenge.example.com", "value-for-base"));
        assert!(!needs_purge(&published, "_acme-challenge.example.com"));
    }

    /// A SAN list can span zones, and clearing one challenge name says nothing
    /// about the others.
    #[test]
    fn an_untouched_name_is_still_cleared() {
        let published = vec![challenge("_acme-challenge.example.com", "value-for-base")];
        assert!(needs_purge(&published, "_acme-challenge.example.org"));
    }
}

/// The owned name list the functions under test take, spelled once.
#[cfg(test)]
fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|name| name.to_string()).collect()
}

#[cfg(test)]
mod names_match_tests {
    use super::{names, names_match};

    /// The CA returns the names in whatever order it likes -- the staging CA
    /// puts the wildcard first -- and DNS names are case-insensitive and may
    /// carry the root dot. None of that is a configuration change.
    #[test]
    fn the_same_names_written_differently_are_the_same_names() {
        assert!(names_match(
            &names(&["*.example.com", "Example.com."]),
            &names(&["example.com", "*.example.com"]),
        ));
    }

    /// Adding a name to the configuration is what has to trigger a reissue --
    /// this is the case that silently did nothing before.
    #[test]
    fn an_added_name_does_not_match() {
        assert!(!names_match(
            &names(&["example.com"]),
            &names(&["example.com", "*.example.com"]),
        ));
    }

    /// Dropping a name must reissue as well: a certificate covering more than
    /// the configuration asks for is not the certificate that was asked for.
    #[test]
    fn a_dropped_name_does_not_match() {
        assert!(!names_match(
            &names(&["example.com", "*.example.com"]),
            &names(&["example.com"]),
        ));
    }
}

#[cfg(test)]
mod reissue_reason_tests {
    use super::{names, reissue_reason};
    use rcgen::{CertificateParams, KeyPair};

    /// A certificate carrying exactly `sans`, in the order given -- the CA's own
    /// order is not the configuration's, which is what the decision has to
    /// tolerate.
    fn cert_with_names(sans: &[&str]) -> String {
        let key = KeyPair::generate().expect("failed to generate key");
        CertificateParams::new(names(sans))
            .expect("failed to build certificate params")
            .self_signed(&key)
            .expect("failed to self-sign")
            .pem()
    }

    #[test]
    fn the_configured_certificate_is_kept() {
        let cert = cert_with_names(&["*.example.com", "example.com"]);
        assert_eq!(
            reissue_reason(&cert, &names(&["example.com", "*.example.com"])),
            None
        );
    }

    /// The case that silently did nothing before: a name added to the
    /// configuration has to reach the CA.
    #[test]
    fn a_certificate_missing_a_configured_name_is_reissued() {
        let cert = cert_with_names(&["example.com"]);
        let reason = reissue_reason(&cert, &names(&["example.com", "*.example.com"]))
            .expect("an added name must reissue");
        // Both lists are in the message: the operator has to be able to see
        // what is being replaced and why.
        assert!(reason.contains("covers example.com"), "{reason}");
        assert!(
            reason.contains("asks for example.com, *.example.com"),
            "{reason}"
        );
    }

    /// A certificate whose names cannot be read cannot be checked against the
    /// configuration either, so it is replaced rather than served on.
    #[test]
    fn an_unreadable_certificate_is_reissued() {
        let reason = reissue_reason("not a certificate", &names(&["example.com"]))
            .expect("an unreadable certificate must reissue");
        assert!(reason.contains("cannot read"), "{reason}");
    }
}

#[cfg(test)]
mod dns_wait_tests {
    use super::advisory_dns_wait;
    use std::time::Duration;

    /// The CLI's own defaults are the failing case: a 300s wait inside a 120s
    /// renewal budget never reaches its "proceed anyway" exit, so an unanswered
    /// check ends as a timeout rather than as the warning naming the record.
    #[test]
    fn the_wait_ends_before_the_renewal_budget_does() {
        let wait = advisory_dns_wait(Duration::from_secs(300), Duration::from_secs(120));
        assert!(wait < Duration::from_secs(120), "{wait:?}");
    }

    /// A wait already inside the budget is left where the operator put it.
    #[test]
    fn a_wait_that_already_fits_is_unchanged() {
        assert_eq!(
            advisory_dns_wait(Duration::from_secs(30), Duration::from_secs(600)),
            Duration::from_secs(30)
        );
    }
}
