// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Multi-domain certificate management using WaveKV for synchronization.
//!
//! This module provides distributed certificate management for multiple domains
//! with dynamic DNS credential configuration and attestation storage.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use certbot::{AcmeClient, Dns01Client, ValidationMethod};
use dstack_guest_agent_rpc::v0::RawQuoteArgs;
use ra_tls::attestation::QuoteContentType;
use ra_tls::rcgen::KeyPair;
use tracing::{error, info, warn};

use crate::cert_store::CertResolver;
use crate::kv::{
    AcmeAttestation, CertAttestation, CertCredentials, CertData, DnsCredential, DnsProvider,
    KvStore, PersistentWriteNotifier, ZtDomainConfig,
};
use crate::time::now_secs;

/// Lock timeout for certificate renewal (10 minutes)
const RENEW_LOCK_TIMEOUT_SECS: u64 = 600;

/// Lock timeout for ACME credential rotation (10 minutes)
const ROTATION_LOCK_TIMEOUT_SECS: u64 = 600;

/// Default ACME URL (Let's Encrypt production)
const DEFAULT_ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Multi-domain certificate manager
pub struct DistributedCertBot {
    kv_store: Arc<KvStore>,
    cert_resolver: Arc<CertResolver>,
    write_notifier: Option<Arc<dyn PersistentWriteNotifier>>,
}

impl DistributedCertBot {
    pub fn new(
        kv_store: Arc<KvStore>,
        cert_resolver: Arc<CertResolver>,
        write_notifier: Option<Arc<dyn PersistentWriteNotifier>>,
    ) -> Self {
        Self {
            kv_store,
            cert_resolver,
            write_notifier,
        }
    }

    fn notify_lock_write(&self) {
        if let Some(notifier) = &self.write_notifier {
            notifier.notify_persistent_write();
        }
    }

    /// Acquire the lock that guards the cluster's shared ACME account.
    ///
    /// One lock covers every operation over that account -- rotation, CAA
    /// reconciliation, and first-use registration -- because they all read or
    /// re-pin the same thing, and the record they publish is last-writer-wins
    /// with no compare-and-swap. It lives in WaveKV rather than in this
    /// process, so it orders two nodes as well as two tasks; see
    /// [`KvStore::try_acquire_rotation_lock`] for its best-effort limits.
    ///
    /// The lock is not reentrant, by design: a stale holder must expire rather
    /// than be re-entered. A caller that holds it across a sequence of
    /// per-domain work must therefore make sure nothing inside that sequence
    /// takes it again -- see [`Self::ensure_acme_account`].
    fn acquire_acme_lock(&self, operation: &str) -> Result<crate::kv::CertRenewLock> {
        self.try_acquire_rotation_lock().with_context(|| {
            format!(
                "cannot {operation}: another rotation, CAA reconciliation, or ACME account \
                 registration holds the shared ACME lock; retry after it finishes"
            )
        })
    }

    fn try_acquire_rotation_lock(&self) -> Option<crate::kv::CertRenewLock> {
        let lock = self
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)?;
        self.notify_lock_write();
        Some(lock)
    }

    fn release_rotation_lock(&self, lock: &crate::kv::CertRenewLock) -> Result<()> {
        self.kv_store.release_rotation_lock(lock)?;
        self.notify_lock_write();
        Ok(())
    }

    fn try_acquire_cert_lock(&self, domain: &str) -> bool {
        let acquired = self
            .kv_store
            .try_acquire_cert_lock(domain, RENEW_LOCK_TIMEOUT_SECS);
        if acquired {
            self.notify_lock_write();
        }
        acquired
    }

    fn release_cert_lock(&self, domain: &str) -> Result<()> {
        self.kv_store.release_cert_lock(domain)?;
        self.notify_lock_write();
        Ok(())
    }

    async fn dns_client(&self, domain: &str, dns_cred: &DnsCredential) -> Result<ValidationMethod> {
        let client = match &dns_cred.provider {
            DnsProvider::Cloudflare { api_token, api_url } => {
                Dns01Client::new_cloudflare(domain.to_string(), api_token.clone(), api_url.clone())
                    .await?
            }
        };
        Ok(ValidationMethod::Dns01 {
            client,
            txt_ttl: dns_cred.dns_txt_ttl,
        })
    }

    /// Rotate the shared ACME account without interrupting certificate serving.
    ///
    /// The sequence is: validate every domain's DNS credential, create the
    /// replacement account, publish the new credentials, then re-pin every
    /// domain's CAA record to the new account. Publishing before re-pinning
    /// makes the failure mode convergent: if some domains fail to re-pin, the
    /// cluster is already on the new account and rerunning `SetCaa` finishes
    /// the switch without registering yet another account (Let's Encrypt caps
    /// new registrations per IP).
    ///
    /// Between publishing and re-pinning, a renewal on another node may pick up
    /// the new account while a domain's CAA still pins the old one; that
    /// issuance fails and the periodic renewal task retries. Re-pinning briefly
    /// installs `;` guard CAA records, so a failure can leave a domain blocked
    /// from issuance until a later `SetCaa` run succeeds (the same hazard as
    /// [`Self::set_caa_all`]).
    ///
    /// This RPC re-pins issuance to the new account; it does not deactivate the
    /// old ACME account at the CA.
    ///
    /// Runs under the shared ACME lock, so a concurrent reconciliation or
    /// first-use registration on any node is refused for the duration.
    pub async fn rotate_acme_credentials(&self) -> Result<(String, usize)> {
        let rotation_lock = self.acquire_acme_lock("rotate ACME credentials")?;
        let result = self.do_rotate_acme_credentials().await;
        if let Err(err) = self.release_rotation_lock(&rotation_lock) {
            error!("failed to release ACME rotation lock: {err:?}");
        }
        result
    }

    async fn do_rotate_acme_credentials(&self) -> Result<(String, usize)> {
        let configs = self.kv_store.list_zt_domain_configs();
        let certbot_config = self.config()?;
        let acme_url = if certbot_config.acme_url.is_empty() {
            DEFAULT_ACME_URL
        } else {
            &certbot_config.acme_url
        };

        // Validate every domain's DNS credential up front: constructing a DNS
        // client resolves the zone through an authenticated API call, so a
        // misconfigured domain aborts the rotation here with no side effects
        // and no ACME account consumed.
        let mut prepared = Vec::with_capacity(configs.len());
        for config in &configs {
            let dns_cred = dns_credential_for(&self.kv_store, config)?;
            let dns_client = self
                .dns_client(&config.domain, &dns_cred)
                .await
                .with_context(|| format!("DNS credential check failed for {}", config.domain))?;
            prepared.push((&config.domain, dns_cred, dns_client));
        }
        let total = prepared.len();
        let mut prepared = prepared.into_iter();
        let Some((first_domain, first_cred, first_client)) = prepared.next() else {
            bail!("no ZT-Domain configured for ACME credential rotation");
        };

        let client = AcmeClient::new_account(acme_url, first_client, first_cred.max_dns_wait)
            .await
            .context("failed to create replacement ACME account")?;
        let credentials = client
            .dump_credentials()
            .context("failed to encode replacement ACME credentials")?;
        let account_uri = client.account_id().to_string();

        // Publish immediately. From here the cluster converges on the new
        // account, and recovering from a partial re-pin below never needs to
        // register another account. Readers create an ACME client per
        // operation, so all nodes pick this up after WaveKV propagates it.
        self.kv_store.save_acme_credentials(&CertCredentials {
            acme_credentials: credentials.clone(),
        })?;

        // Re-pin every domain's CAA to the new account, best effort across all
        // domains: one failing domain must not block re-pinning the rest. The
        // first domain reuses the registration client, which is already bound
        // to its DNS client and the new credentials.
        let mut failed = Vec::new();
        let mut record = |domain: &String, result: Result<()>| match result {
            Ok(()) => info!("cert[{domain}]: CAA re-pinned to {account_uri}"),
            Err(err) => {
                error!("cert[{domain}]: failed to re-pin CAA: {err:?}");
                failed.push(domain.clone());
            }
        };
        record(
            first_domain,
            client
                .set_caa_records(std::slice::from_ref(first_domain))
                .await
                .context("failed to update CAA records"),
        );
        for (domain, dns_cred, dns_client) in prepared {
            let result = async {
                let client = AcmeClient::load(dns_client, &credentials, dns_cred.max_dns_wait)
                    .await
                    .context("failed to prepare ACME client")?;
                client
                    .set_caa_records(std::slice::from_ref(domain))
                    .await
                    .context("failed to update CAA records")
            }
            .await;
            record(domain, result);
        }

        // Attest the new account only after CAA re-pinning: attestation does
        // not gate issuance, so its agent round trips must not widen the
        // window where the published account and the CAA records disagree.
        // Run it even when some domains failed so the new account is still
        // recorded.
        if let Err(err) = self.generate_and_save_acme_attestation(&account_uri).await {
            warn!("failed to attest rotated ACME account: {err:?}");
        }

        if !failed.is_empty() {
            bail!(
                "rotated to {account_uri} and published the new credentials, but failed to \
                 re-pin CAA for {}/{total} domains: {}; rerun SetCaa until it succeeds — \
                 retrying the rotation would register yet another account",
                failed.len(),
                failed.join(", ")
            );
        }
        Ok((account_uri, total))
    }

    /// Get the current certbot configuration from KV store.
    ///
    /// Propagates a corrupt record instead of falling back to the defaults:
    /// the default `acme_url` is Let's Encrypt production, so a silent
    /// fallback would move issuance to a different ACME server.
    fn config(&self) -> Result<crate::kv::GlobalCertbotConfig> {
        self.kv_store.get_certbot_config()
    }

    /// The ACME directory this cluster issues from.
    fn acme_url(&self) -> Result<String> {
        let config = self.config()?;
        if config.acme_url.is_empty() {
            return Ok(DEFAULT_ACME_URL.to_string());
        }
        Ok(config.acme_url)
    }

    /// Initialize all ZT-Domain certificates
    pub async fn init_all(&self) -> Result<()> {
        let configs = self.kv_store.list_zt_domain_configs();
        for config in configs {
            if let Err(err) = self.init_domain(&config.domain).await {
                error!("cert[{}]: failed to initialize: {err:?}", config.domain);
            }
        }
        Ok(())
    }

    /// Initialize certificate for a specific domain
    pub async fn init_domain(&self, domain: &str) -> Result<()> {
        // First, try to load from KvStore (synced from other nodes)
        if let Some(cert_data) = self.kv_store.get_cert_data(domain) {
            let now = now_secs();
            if cert_data.not_after > now {
                info!(
                    domain,
                    "loaded from KvStore (issued by node {}, expires in {} days)",
                    cert_data.issued_by,
                    (cert_data.not_after - now) / 86400
                );
                self.cert_resolver.update_cert(domain, &cert_data)?;
                return Ok(());
            }
            info!(domain, "KvStore certificate expired, will request new one");
        }

        // No valid cert, need to request new one
        info!(domain, "no valid certificate found, requesting from ACME");
        self.request_new_cert(domain).await
    }

    /// Set CAA records for every configured ZT domain.
    ///
    /// Runs under the shared ACME lock, so a rotation or another
    /// reconciliation -- on this node or any other -- is refused for the
    /// duration rather than interleaved with it. Reconciling a domain rewrites
    /// its issuer records in place (guard, sweep, write, unguard), and two runs
    /// over the same zone delete each other's records.
    ///
    /// Reconciliation is per-domain best effort: a failing domain is logged and the
    /// remaining domains are still reconciled, so one misconfigured domain cannot
    /// leave the rest unauthorized. Failures are reported together in the returned
    /// error.
    ///
    /// Note that reconciling a domain briefly installs `;` guard CAA records that
    /// forbid issuance for that name. A failure in the middle of the sequence can
    /// leave those guards behind, blocking issuance for the domain until a later run
    /// succeeds. The guard window can also fail an ACME order that is in flight for
    /// the same domain; the periodic renewal task retries, so that is transient.
    pub async fn set_caa_all(&self) -> Result<()> {
        let configs = self.kv_store.list_zt_domain_configs();
        if configs.is_empty() {
            warn!("no ZT-Domain configured, no CAA records to set");
            return Ok(());
        }
        // Before the lock, never under it: registration takes the same lock.
        self.ensure_acme_account(&configs).await?;
        let rotation_lock = self.acquire_acme_lock("reconcile CAA records")?;
        let result = self.do_set_caa_all(configs).await;
        if let Err(err) = self.release_rotation_lock(&rotation_lock) {
            error!("failed to release ACME rotation lock: {err:?}");
        }
        result
    }

    /// Register the cluster's shared ACME account if it does not exist yet.
    ///
    /// Called before taking the ACME lock, by callers that hold it across
    /// per-domain work that would otherwise register lazily from inside the
    /// locked region and be refused by their own lock. The record is read
    /// first, so the steady state -- an account already registered -- costs one
    /// KV read and no provider or CA round trip.
    ///
    /// Any configured domain will do: the account is shared, and registration
    /// only needs one domain's DNS credential to build a client, the same way
    /// rotation uses the first domain's.
    async fn ensure_acme_account(&self, configs: &[ZtDomainConfig]) -> Result<()> {
        let stored = self
            .kv_store
            .get_acme_credentials()
            .context("call RotateAcmeCredentials to replace the stored ACME credentials")?;
        if stored.is_some() {
            return Ok(());
        }
        let Some(config) = configs.first() else {
            return Ok(());
        };
        self.get_or_create_acme_client(&config.domain, config)
            .await
            .context("failed to register the shared ACME account")?;
        Ok(())
    }

    async fn do_set_caa_all(&self, configs: Vec<ZtDomainConfig>) -> Result<()> {
        let total = configs.len();
        let mut failed = Vec::new();
        for config in configs {
            let domain = config.domain.clone();
            match self.set_caa(&domain, &config).await {
                Ok(()) => info!("cert[{domain}]: CAA records reconciled"),
                Err(err) => {
                    error!("cert[{domain}]: failed to set CAA records: {err:?}");
                    failed.push(domain);
                }
            }
        }

        if !failed.is_empty() {
            bail!(
                "failed to set CAA records for {}/{total} domains: {}; \
                 they may retain guard CAA records that block issuance until a rerun succeeds",
                failed.len(),
                failed.join(", ")
            );
        }
        info!("CAA records reconciled for {total} domains");
        Ok(())
    }

    /// Set CAA records for a single ZT domain.
    ///
    /// The domain in the config is the base domain and certificates are issued for
    /// `*.{domain}`, which the CAA lookup covers by climbing to the base domain.
    ///
    /// The written CAA value pins `accounturi` to the global ACME account, which
    /// the caller has already registered; see [`Self::ensure_acme_account`].
    async fn set_caa(&self, domain: &str, config: &ZtDomainConfig) -> Result<()> {
        // Load only. This runs under the ACME lock, which is not reentrant, so
        // registering here would refuse the run that took it -- and the caller
        // has already registered the account before taking it. Nothing under
        // the lock may call [`Self::acquire_acme_lock`], and keeping the
        // registering variant out of this path is what makes that structural
        // rather than a rule to remember.
        let dns_cred = dns_credential_for(&self.kv_store, config)?;
        let acme_url = self.acme_url()?;
        let acme_client = self
            .load_stored_acme_client(domain, &dns_cred, &acme_url)
            .await
            .context("failed to initialize ACME client")?
            .context("no shared ACME account is registered for this cluster")?;
        acme_client
            .set_caa_records(&[domain.to_string()])
            .await
            .context("failed to set CAA records")
    }

    /// Try to renew all ZT-Domain certificates
    pub async fn try_renew_all(&self) -> Result<()> {
        let configs = self.kv_store.list_zt_domain_configs();
        for config in configs {
            if let Err(err) = self.try_renew(&config.domain, false).await {
                error!("cert[{}]: failed to renew: {err:?}", config.domain);
            }
        }
        Ok(())
    }

    /// Try to renew certificate for a specific domain if needed
    #[tracing::instrument(skip(self))]
    pub async fn try_renew(&self, domain: &str, force: bool) -> Result<bool> {
        // Check if config exists
        let config = self
            .kv_store
            .get_zt_domain_config(domain)
            .context("ZT-Domain config not found")?;

        // Check if renewal is needed
        let cert_data = self.kv_store.get_cert_data(domain);
        let needs_renew = if force {
            true
        } else if let Some(ref data) = cert_data {
            let now = now_secs();
            let expires_in = data.not_after.saturating_sub(now);
            expires_in < self.config()?.renew_before_expiration.as_secs()
        } else {
            true
        };

        if !needs_renew {
            info!("does not need renewal");
            return Ok(false);
        }

        // Try to acquire lock
        if !self.try_acquire_cert_lock(domain) {
            info!("another node is renewing, skipping");
            return Ok(false);
        }

        info!("acquired renew lock, starting renewal");

        // Perform renewal or initial issuance
        let result = if cert_data.is_some() {
            self.do_renew(domain, &config).await
        } else {
            // No existing certificate, request new one
            info!("no existing certificate, requesting new one");
            self.do_request_new(domain, &config).await.map(|_| true)
        };

        // Release lock regardless of result
        if let Err(err) = self.release_cert_lock(domain) {
            error!("failed to release lock: {err:?}");
        }

        result
    }

    /// Request new certificate for a domain
    #[tracing::instrument(skip(self))]
    async fn request_new_cert(&self, domain: &str) -> Result<()> {
        let config = self
            .kv_store
            .get_zt_domain_config(domain)
            .context("ZT-Domain config not found")?;

        // Try to acquire lock first
        if !self.try_acquire_cert_lock(domain) {
            // Another node is requesting, wait for it
            info!("another node is requesting, waiting...");
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let Some(cert_data) = self.kv_store.get_cert_data(domain) {
                self.cert_resolver.update_cert(domain, &cert_data)?;
                return Ok(());
            }
            bail!("failed to get certificate from KvStore after waiting");
        }

        let result = self.do_request_new(domain, &config).await;

        if let Err(err) = self.release_cert_lock(domain) {
            error!("failed to release lock: {err:?}");
        }

        result
    }

    async fn do_request_new(&self, domain: &str, config: &ZtDomainConfig) -> Result<()> {
        let acme_client = self.get_or_create_acme_client(domain, config).await?;

        // Generate new key pair (always use new key for security)
        let key = KeyPair::generate().context("failed to generate key")?;
        let key_pem = key.serialize_pem();
        let public_key_der = key.public_key_der();

        // Request wildcard certificate (domain in config is base domain, cert is *.domain)
        let wildcard_domain = format!("*.{}", domain);
        info!(
            "requesting new certificate from ACME for {}...",
            wildcard_domain
        );
        let cert_pem = tokio::time::timeout(
            self.config()?.renew_timeout,
            acme_client.request_new_certificate(&key_pem, &[wildcard_domain]),
        )
        .await
        .context("certificate request timed out")?
        .context("failed to request new certificate")?;

        let not_after = get_cert_expiry(&cert_pem).context("failed to parse certificate expiry")?;

        // Save certificate to KvStore
        self.save_cert_to_kvstore(domain, &cert_pem, &key_pem, not_after)?;
        info!("new certificate obtained from ACME, saved to KvStore");

        // Generate and save attestation
        self.generate_and_save_attestation(domain, &public_key_der)
            .await?;

        // Load into memory cert store
        let cert_data = CertData {
            cert_pem,
            key_pem,
            not_after,
            issued_by: self.kv_store.my_node_id(),
            issued_at: now_secs(),
        };
        self.cert_resolver.update_cert(domain, &cert_data)?;

        info!(
            "new certificate loaded (expires in {} days)",
            (not_after - now_secs()) / 86400
        );
        Ok(())
    }

    async fn do_renew(&self, domain: &str, config: &ZtDomainConfig) -> Result<bool> {
        let acme_client = self.get_or_create_acme_client(domain, config).await?;

        // Generate new key pair (always use new key for each renewal)
        let key = KeyPair::generate().context("failed to generate key")?;
        let key_pem = key.serialize_pem();
        let public_key_der = key.public_key_der();

        // Verify there's a current cert (for audit trail, even though we don't use its key)
        if self.kv_store.get_cert_data(domain).is_none() {
            bail!("no current certificate to renew");
        }

        // Renew with new key (request wildcard certificate)
        let wildcard_domain = format!("*.{}", domain);
        info!(
            "renewing certificate with new key from ACME for {}...",
            wildcard_domain
        );
        let new_cert_pem = tokio::time::timeout(
            self.config()?.renew_timeout,
            // Note: we request a new cert rather than renew, since we have a new key
            acme_client.request_new_certificate(&key_pem, &[wildcard_domain]),
        )
        .await
        .context("certificate renewal timed out")?
        .context("failed to renew certificate")?;

        let not_after =
            get_cert_expiry(&new_cert_pem).context("failed to parse certificate expiry")?;

        // Save to KvStore
        self.save_cert_to_kvstore(domain, &new_cert_pem, &key_pem, not_after)?;
        info!("renewed certificate saved to KvStore");

        // Generate and save attestation
        self.generate_and_save_attestation(domain, &public_key_der)
            .await?;

        // Load into memory cert store
        let cert_data = CertData {
            cert_pem: new_cert_pem,
            key_pem,
            not_after,
            issued_by: self.kv_store.my_node_id(),
            issued_at: now_secs(),
        };
        self.cert_resolver.update_cert(domain, &cert_data)?;

        info!(
            "renewed certificate loaded (expires in {} days)",
            (not_after - now_secs()) / 86400
        );
        Ok(true)
    }

    async fn get_or_create_acme_client(
        &self,
        domain: &str,
        config: &ZtDomainConfig,
    ) -> Result<AcmeClient> {
        // Get DNS credential (from config or default)
        let dns_cred = dns_credential_for(&self.kv_store, config)?;
        let acme_url = self.acme_url()?;

        if let Some(client) = self
            .load_stored_acme_client(domain, &dns_cred, &acme_url)
            .await?
        {
            info!("loaded global ACME account credentials from KvStore");
            return Ok(client);
        }

        // Registering is the one step in this function that cannot be repeated
        // harmlessly. Each run spends a rate-limited registration at the CA, and
        // the credentials record is last-writer-wins with no compare-and-swap,
        // so a concurrent registration's account is simply dropped -- while the
        // attestation written beside it, under its own key with its own
        // last-writer-wins race, may well be the one that survives. Renewal
        // locks are per domain and do not help: a fresh cluster registers from
        // however many domains and nodes start at once. Take the shared ACME
        // lock and look again before spending a registration.
        let rotation_lock = self.acquire_acme_lock("register the shared ACME account")?;
        let client = self
            .register_or_adopt_account(domain, &dns_cred, &acme_url)
            .await;
        if let Err(err) = self.release_rotation_lock(&rotation_lock) {
            error!("failed to release ACME rotation lock: {err:?}");
        }
        client
    }

    /// Build an ACME client from the cluster's stored account credentials, or
    /// `None` if no account has been registered yet.
    ///
    /// A corrupt record is an error, not absence: falling through to account
    /// registration would silently create an account that the account-bound CAA
    /// records refuse, and burn a rate-limited registration. So is a record for
    /// a different ACME directory -- registering a fresh account there would
    /// leave every domain's CAA pinned to the old account and block issuance,
    /// while rotation re-pins CAA along with the switch.
    async fn load_stored_acme_client(
        &self,
        domain: &str,
        dns_cred: &DnsCredential,
        acme_url: &str,
    ) -> Result<Option<AcmeClient>> {
        let Some(creds) = self
            .kv_store
            .get_acme_credentials()
            .context("call RotateAcmeCredentials to replace the stored ACME credentials")?
        else {
            return Ok(None);
        };
        if !acme_url_matches(&creds.acme_credentials, acme_url).context(
            "invalid ACME credentials in KvStore; call RotateAcmeCredentials to replace them",
        )? {
            bail!(
                "stored ACME credentials are for a different ACME directory; \
                 call RotateAcmeCredentials to switch directories"
            );
        }
        let dns01_client = self.dns_client(domain, dns_cred).await?;
        let client = AcmeClient::load(dns01_client, &creds.acme_credentials, dns_cred.max_dns_wait)
            .await
            .context("failed to load ACME client from KvStore credentials")?;
        Ok(Some(client))
    }

    /// Register the cluster's shared ACME account, or adopt the one that
    /// appeared while this call was waiting for the lock.
    ///
    /// Called with the ACME lock held. The re-read is the point: without it
    /// every waiter registers an account of its own the moment it is let
    /// through, which is the race the lock was taken to avoid.
    async fn register_or_adopt_account(
        &self,
        domain: &str,
        dns_cred: &DnsCredential,
        acme_url: &str,
    ) -> Result<AcmeClient> {
        if let Some(client) = self
            .load_stored_acme_client(domain, dns_cred, acme_url)
            .await?
        {
            info!("adopted the ACME account registered while this node waited for the lock");
            return Ok(client);
        }

        info!("creating new global ACME account at {acme_url}");
        let dns01_client = self.dns_client(domain, dns_cred).await?;
        let client = AcmeClient::new_account(acme_url, dns01_client, dns_cred.max_dns_wait)
            .await
            .context("failed to create new ACME account")?;

        let creds_json = client
            .dump_credentials()
            .context("failed to dump ACME credentials")?;

        // Save global ACME credentials to KvStore
        self.kv_store.save_acme_credentials(&CertCredentials {
            acme_credentials: creds_json.clone(),
        })?;

        // Generate and save ACME account attestation
        if let Some(account_uri) = extract_account_uri(&creds_json) {
            self.generate_and_save_acme_attestation(&account_uri)
                .await?;
        }

        Ok(client)
    }

    async fn generate_and_save_acme_attestation(&self, account_uri: &str) -> Result<()> {
        let agent = match crate::dstack_agent() {
            Ok(a) => a,
            Err(err) => {
                warn!("failed to create dstack agent: {err:?}");
                return Ok(());
            }
        };

        let report_data = QuoteContentType::Custom("acme-account")
            .to_report_data(account_uri.as_bytes())
            .to_vec();

        // Get quote. GetQuote is Intel TDX only, so this is best-effort: on other
        // platforms the versioned attestation below is the only evidence available.
        let quote = match agent
            .get_quote(RawQuoteArgs {
                report_data: report_data.clone(),
            })
            .await
        {
            Ok(resp) => serde_json::to_string(&resp).unwrap_or_default(),
            Err(err) => {
                warn!("failed to get TDX quote for ACME account: {err:?}");
                String::new()
            }
        };

        // Get attestation
        let attestation_str = match agent.attest(RawQuoteArgs { report_data }).await {
            Ok(resp) => serde_json::to_string(&resp).unwrap_or_default(),
            Err(err) => {
                warn!("failed to get attestation for ACME account: {err:?}");
                String::new()
            }
        };

        if quote.is_empty() && attestation_str.is_empty() {
            warn!("no attestation evidence for ACME account, skipping save");
            return Ok(());
        }

        let attestation = AcmeAttestation {
            account_uri: account_uri.to_string(),
            quote,
            attestation: attestation_str,
            generated_by: self.kv_store.my_node_id(),
            generated_at: now_secs(),
        };

        self.kv_store.save_acme_attestation(&attestation)?;
        info!("ACME account attestation saved to KvStore");
        Ok(())
    }

    fn save_cert_to_kvstore(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &str,
        not_after: u64,
    ) -> Result<()> {
        let cert_data = CertData {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            not_after,
            issued_by: self.kv_store.my_node_id(),
            issued_at: now_secs(),
        };
        self.kv_store.save_cert_data(domain, &cert_data)
    }

    async fn generate_and_save_attestation(
        &self,
        domain: &str,
        public_key_der: &[u8],
    ) -> Result<()> {
        let agent = match crate::dstack_agent() {
            Ok(a) => a,
            Err(err) => {
                warn!(domain, "failed to create dstack agent: {err:?}");
                return Ok(());
            }
        };

        let report_data = QuoteContentType::Custom("zt-cert")
            .to_report_data(public_key_der)
            .to_vec();

        // Get quote. GetQuote is Intel TDX only, so this is best-effort: on other
        // platforms the versioned attestation below is the only evidence available.
        let quote = match agent
            .get_quote(RawQuoteArgs {
                report_data: report_data.clone(),
            })
            .await
        {
            Ok(resp) => serde_json::to_string(&resp).unwrap_or_default(),
            Err(err) => {
                warn!(domain, "failed to generate TDX quote: {err:?}");
                String::new()
            }
        };

        // Get attestation
        let attestation = match agent.attest(RawQuoteArgs { report_data }).await {
            Ok(resp) => serde_json::to_string(&resp).unwrap_or_default(),
            Err(err) => {
                warn!(domain, "failed to get attestation: {err:?}");
                String::new()
            }
        };

        if quote.is_empty() && attestation.is_empty() {
            warn!(domain, "no attestation evidence for cert, skipping save");
            return Ok(());
        }

        let attestation = CertAttestation {
            public_key: public_key_der.to_vec(),
            quote,
            attestation,
            generated_by: self.kv_store.my_node_id(),
            generated_at: now_secs(),
        };

        self.kv_store.save_cert_attestation(domain, &attestation)?;
        info!(domain, "attestation saved to KvStore");
        Ok(())
    }
}

fn dns_credential_for(kv_store: &KvStore, config: &ZtDomainConfig) -> Result<DnsCredential> {
    if let Some(ref cred_id) = config.dns_cred_id {
        kv_store
            .get_dns_credential(cred_id)?
            .context("specified DNS credential not found")
    } else {
        kv_store
            .get_default_dns_credential()?
            .context("no default DNS credential configured")
    }
}

fn get_cert_expiry(cert_pem: &str) -> Option<u64> {
    use x509_parser::prelude::*;
    let pem = Pem::iter_from_buffer(cert_pem.as_bytes()).next()?.ok()?;
    let cert = pem.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp() as u64)
}

fn acme_url_matches(credentials_json: &str, expected_url: &str) -> Result<bool> {
    #[derive(serde::Deserialize)]
    struct Creds {
        acme_url: String,
    }
    let credentials = serde_json::from_str::<Creds>(credentials_json)
        .context("failed to decode ACME credentials")?;
    Ok(credentials.acme_url == expected_url)
}

/// Extract account_id (URI) from ACME credentials JSON
pub(crate) fn extract_account_uri(credentials_json: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Creds {
        #[serde(default)]
        account_id: String,
    }
    serde_json::from_str::<Creds>(credentials_json)
        .ok()
        .filter(|c| !c.account_id.is_empty())
        .map(|c| c.account_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct CountingNotifier(AtomicUsize);

    impl PersistentWriteNotifier for CountingNotifier {
        fn notify_persistent_write(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn test_certbot(data_dir: &std::path::Path) -> DistributedCertBot {
        let kv_store =
            Arc::new(KvStore::new(1, vec![], data_dir, None).expect("failed to create kv store"));
        DistributedCertBot::new(kv_store, Arc::new(CertResolver::new()), None)
    }

    /// A DNS credential pointing at a closed port: any provider API call fails
    /// fast, so a test that reaches one fails instead of hanging on the network.
    fn unreachable_dns_credential() -> DnsCredential {
        DnsCredential {
            id: "cred-1".to_string(),
            name: "unreachable".to_string(),
            provider: DnsProvider::Cloudflare {
                api_token: "token".to_string(),
                api_url: Some("http://127.0.0.1:1/client/v4".to_string()),
            },
            max_dns_wait: Duration::from_secs(1),
            dns_txt_ttl: 60,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn test_zt_domain_config() -> ZtDomainConfig {
        ZtDomainConfig {
            domain: "app.example.com".to_string(),
            dns_cred_id: Some("cred-1".to_string()),
            port: 443,
            node: None,
            priority: 0,
        }
    }

    /// A certbot with one ZT domain whose DNS provider is unreachable.
    fn certbot_with_domain(data_dir: &std::path::Path) -> DistributedCertBot {
        let certbot = test_certbot(data_dir);
        certbot
            .kv_store
            .save_dns_credential(&unreachable_dns_credential())
            .expect("failed to store dns credential");
        certbot
            .kv_store
            .save_zt_domain_config(&test_zt_domain_config())
            .expect("failed to store zt domain config");
        certbot
    }

    fn save_credentials_for(certbot: &DistributedCertBot, acme_url: &str) {
        certbot
            .kv_store
            .save_acme_credentials(&CertCredentials {
                acme_credentials: format!(r#"{{"acme_url":"{acme_url}"}}"#),
            })
            .expect("failed to store acme credentials");
    }

    #[test]
    fn lock_writes_wake_the_persistent_push_path() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let kv_store = Arc::new(
            KvStore::new(1, vec![], data_dir.path(), None).expect("failed to create kv store"),
        );
        let notifier = Arc::new(CountingNotifier::default());
        let certbot = DistributedCertBot::new(
            kv_store,
            Arc::new(CertResolver::new()),
            Some(notifier.clone()),
        );

        let rotation = certbot
            .try_acquire_rotation_lock()
            .expect("rotation lock should be free");
        assert_eq!(notifier.0.load(Ordering::Relaxed), 1);
        certbot
            .release_rotation_lock(&rotation)
            .expect("rotation lock release should succeed");
        assert_eq!(notifier.0.load(Ordering::Relaxed), 2);

        assert!(certbot.try_acquire_cert_lock("example.com"));
        assert_eq!(notifier.0.load(Ordering::Relaxed), 3);
        assert!(!certbot.try_acquire_cert_lock("example.com"));
        assert_eq!(
            notifier.0.load(Ordering::Relaxed),
            3,
            "a rejected acquisition did not write and must not wake push"
        );
        certbot
            .release_cert_lock("example.com")
            .expect("renewal lock release should succeed");
        assert_eq!(notifier.0.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn set_caa_all_succeeds_without_configured_domains() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = test_certbot(data_dir.path());
        // No ZT-Domain configured: nothing to reconcile and no DNS provider is contacted.
        certbot
            .set_caa_all()
            .await
            .expect("set_caa_all should succeed without domains");
    }

    /// CAA reconciliation rewrites a zone's issuer records in place -- guard,
    /// sweep, write, unguard -- so two runs over the same zone can delete each
    /// other's records and leave the guards behind, which blocks issuance until
    /// a later run succeeds. The lock that orders them is the shared ACME one,
    /// so it orders another node's rotation against this run too.
    #[tokio::test]
    async fn set_caa_all_rejects_concurrent_runs() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = certbot_with_domain(data_dir.path());
        // An account already exists, so this run has nothing to register and
        // reaches the lock it takes for the reconciliation itself.
        save_credentials_for(&certbot, DEFAULT_ACME_URL);
        assert!(certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .is_some());

        let err = certbot
            .set_caa_all()
            .await
            .expect_err("a concurrent run should be rejected");
        assert!(
            err.to_string().contains("cannot reconcile CAA records"),
            "unexpected error: {err}"
        );
    }

    /// Registration takes the same lock this run holds for the reconciliation,
    /// and the lock is not reentrant. Registering up front is what keeps a
    /// fresh cluster's first `SetCaa` from refusing -- or deadlocking on -- its
    /// own lock.
    #[tokio::test]
    async fn set_caa_all_registers_the_account_before_taking_the_lock() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = certbot_with_domain(data_dir.path());

        let err = tokio::time::timeout(Duration::from_secs(30), certbot.set_caa_all())
            .await
            .expect("set_caa_all must not block on its own lock")
            .expect_err("the unreachable DNS provider should fail the run");
        assert!(
            err.to_string()
                .contains("failed to register the shared ACME account"),
            "unexpected error: {err:?}"
        );
        // A failed run leaves the lock free for the next attempt.
        assert!(certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .is_some());
    }

    /// First-use registration must wait on the same lock rotation takes, or a
    /// fresh cluster registers one account per node that happens to start a
    /// renewal -- and the credentials record, being last-writer-wins, keeps
    /// exactly one of them.
    ///
    /// Reaching the lock at all is the assertion: the DNS provider client is
    /// built only after the lock is granted, so an unreachable provider (as
    /// configured here) cannot be what this run fails on.
    #[tokio::test]
    async fn first_use_registration_waits_for_the_rotation_lock() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = certbot_with_domain(data_dir.path());
        let config = test_zt_domain_config();

        // Another node is mid-registration or mid-rotation.
        assert!(certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .is_some());

        let err = match certbot
            .get_or_create_acme_client(&config.domain, &config)
            .await
        {
            Ok(_) => panic!("registration must not proceed while the lock is held"),
            Err(err) => err,
        };
        assert!(
            err.to_string()
                .contains("cannot register the shared ACME account"),
            "unexpected error: {err}"
        );
    }

    /// Nothing inside the locked region may take the lock again. With an
    /// account already registered, a run reaches the DNS provider -- it fails
    /// there, on the reconciliation itself, and never on its own lock.
    #[tokio::test]
    async fn set_caa_all_does_not_take_its_own_lock_again() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = certbot_with_domain(data_dir.path());
        save_credentials_for(&certbot, DEFAULT_ACME_URL);

        let err = tokio::time::timeout(Duration::from_secs(30), certbot.set_caa_all())
            .await
            .expect("set_caa_all must not block on its own lock")
            .expect_err("the unreachable DNS provider should fail the run");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("failed to set CAA records for 1/1 domains"),
            "unexpected error: {msg}"
        );
        assert!(
            !msg.contains("shared ACME lock"),
            "the run refused its own lock: {msg}"
        );
        assert!(certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .is_some());
    }

    /// Whoever the lock lets through next must look at the record again. Its
    /// contents decide the outcome -- adopt, or refuse a directory switch --
    /// and reaching either one proves no second registration was spent.
    #[tokio::test]
    async fn registration_rereads_the_record_under_the_lock() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = certbot_with_domain(data_dir.path());
        // The account that appeared while this call waited is registered at a
        // different ACME directory than the one this run is configured for.
        save_credentials_for(&certbot, "https://acme.test/directory");

        let err = match certbot
            .register_or_adopt_account(
                "app.example.com",
                &unreachable_dns_credential(),
                DEFAULT_ACME_URL,
            )
            .await
        {
            Ok(_) => panic!("a directory switch must not be made by registering"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("different ACME directory"),
            "unexpected error: {err:?}"
        );
    }

    /// Two rotations on this node are ordered by the same lock that orders two
    /// nodes: the lock lives in the KV store, so a second in-process run sees
    /// the first one's record.
    #[tokio::test]
    async fn rotate_acme_credentials_rejects_concurrent_runs() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = test_certbot(data_dir.path());
        let _held = certbot
            .try_acquire_rotation_lock()
            .expect("lock should be free");
        let err = certbot
            .rotate_acme_credentials()
            .await
            .expect_err("a concurrent run should be rejected");
        assert!(
            err.to_string().contains("cannot rotate ACME credentials"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rotate_acme_credentials_rejects_when_another_node_holds_the_lock() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = test_certbot(data_dir.path());
        assert!(certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .is_some());
        let err = certbot
            .rotate_acme_credentials()
            .await
            .expect_err("rotation should be rejected while the KV lock is held");
        assert!(
            err.to_string().contains("cannot rotate ACME credentials"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn rotate_acme_credentials_requires_a_configured_domain() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = test_certbot(data_dir.path());
        let err = certbot
            .rotate_acme_credentials()
            .await
            .expect_err("rotation without domains should fail");
        assert!(
            err.to_string().contains("no ZT-Domain configured"),
            "unexpected error: {err}"
        );
        // The failed rotation must release the KV lock so a later run can proceed.
        assert!(certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .is_some());
    }

    #[tokio::test]
    async fn stale_rotation_holder_does_not_release_a_newer_lock() {
        let data_dir = tempfile::tempdir().expect("failed to create temp dir");
        let certbot = test_certbot(data_dir.path());
        let current = certbot
            .kv_store
            .try_acquire_rotation_lock(ROTATION_LOCK_TIMEOUT_SECS)
            .expect("lock should be free");
        // Simulate a holder that exceeded the timeout and was superseded.
        let stale = crate::kv::CertRenewLock {
            started_at: current.started_at.saturating_sub(100),
            started_by: 99,
        };
        certbot
            .kv_store
            .release_rotation_lock(&stale)
            .expect("stale release should be a no-op, not an error");
        assert!(
            certbot.kv_store.get_rotation_lock().is_some(),
            "the newer holder's lock must remain in place"
        );
        certbot
            .kv_store
            .release_rotation_lock(&current)
            .expect("owner release should succeed");
        assert!(certbot.kv_store.get_rotation_lock().is_none());
    }

    #[test]
    fn corrupt_acme_credentials_fail_closed() {
        assert!(acme_url_matches("not-json", "https://acme.test/directory").is_err());
        assert!(acme_url_matches("{}", "https://acme.test/directory").is_err());
    }

    #[test]
    fn valid_acme_credentials_distinguish_directory() {
        let credentials = r#"{"acme_url":"https://acme.test/directory"}"#;
        assert!(acme_url_matches(credentials, "https://acme.test/directory")
            .expect("valid credentials rejected"));
        assert!(
            !acme_url_matches(credentials, "https://other.test/directory")
                .expect("valid credentials rejected")
        );
    }
}
