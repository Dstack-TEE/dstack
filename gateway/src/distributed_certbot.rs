// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Multi-domain certificate management using WaveKV for synchronization.
//!
//! This module provides distributed certificate management for multiple domains
//! with dynamic DNS credential configuration and attestation storage.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use certbot::{AcmeClient, Dns01Client};
use ra_tls::rcgen::KeyPair;
use tracing::{error, info, warn};

use crate::cert_store::CertResolver;
use crate::kv::{
    AcmeAttestation, CertAttestation, CertCredentials, CertData, DnsProvider, KvStore,
    ZtDomainConfig,
};

/// Lock timeout for certificate renewal (10 minutes)
const RENEW_LOCK_TIMEOUT_SECS: u64 = 600;

/// Default ACME URL (Let's Encrypt production)
const DEFAULT_ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";

/// Multi-domain certificate manager
pub struct DistributedCertBot {
    kv_store: Arc<KvStore>,
    cert_resolver: Arc<CertResolver>,
}

impl DistributedCertBot {
    pub fn new(kv_store: Arc<KvStore>, cert_resolver: Arc<CertResolver>) -> Self {
        Self {
            kv_store,
            cert_resolver,
        }
    }

    /// Get the current certbot configuration from KV store
    fn config(&self) -> crate::kv::GlobalCertbotConfig {
        self.kv_store.get_certbot_config()
    }

    /// Initialize all ZT-Domain certificates
    pub async fn init_all(&self) -> Result<()> {
        let configs = self.kv_store.list_zt_domain_configs();
        for config in configs {
            if let Err(e) = self.init_domain(&config.domain).await {
                error!("cert[{}]: failed to initialize: {}", config.domain, e);
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

    /// Try to renew all ZT-Domain certificates
    pub async fn try_renew_all(&self) -> Result<()> {
        let configs = self.kv_store.list_zt_domain_configs();
        for config in configs {
            if let Err(e) = self.try_renew(&config.domain, false).await {
                error!("cert[{}]: failed to renew: {}", config.domain, e);
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
            expires_in < self.config().renew_before_expiration.as_secs()
        } else {
            true
        };

        if !needs_renew {
            info!("does not need renewal");
            return Ok(false);
        }

        // Try to acquire lock
        if !self
            .kv_store
            .try_acquire_cert_lock(domain, RENEW_LOCK_TIMEOUT_SECS)
        {
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
        if let Err(e) = self.kv_store.release_cert_lock(domain) {
            error!("failed to release lock: {e}");
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
        if !self
            .kv_store
            .try_acquire_cert_lock(domain, RENEW_LOCK_TIMEOUT_SECS)
        {
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

        if let Err(e) = self.kv_store.release_cert_lock(domain) {
            error!("failed to release lock: {e}");
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
            self.config().renew_timeout,
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
            self.config().renew_timeout,
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
        let dns_cred = if let Some(ref cred_id) = config.dns_cred_id {
            self.kv_store
                .get_dns_credential(cred_id)
                .context("specified DNS credential not found")?
        } else {
            self.kv_store
                .get_default_dns_credential()
                .context("no default DNS credential configured")?
        };

        // Create DNS client based on provider
        let dns01_client = match &dns_cred.provider {
            DnsProvider::Cloudflare { api_token, api_url } => {
                Dns01Client::new_cloudflare(domain.to_string(), api_token.clone(), api_url.clone())
                    .await?
            }
        };

        // Use ACME URL from certbot config, fall back to default if not set
        let config = self.config();
        let acme_url = if config.acme_url.is_empty() {
            DEFAULT_ACME_URL
        } else {
            &config.acme_url
        };

        // Try to load global ACME credentials from KvStore
        if let Some(creds) = self.kv_store.get_acme_credentials() {
            if acme_url_matches(&creds.acme_credentials, acme_url) {
                info!("loaded global ACME account credentials from KvStore");
                return AcmeClient::load(
                    dns01_client,
                    &creds.acme_credentials,
                    dns_cred.max_dns_wait,
                    dns_cred.dns_txt_ttl,
                )
                .await
                .context("failed to load ACME client from KvStore credentials");
            }
            warn!("ACME URL mismatch in KvStore credentials, will create new account");
        }

        // Create new global ACME account
        info!("creating new global ACME account at {acme_url}");
        let client = AcmeClient::new_account(
            acme_url,
            dns01_client,
            dns_cred.max_dns_wait,
            dns_cred.dns_txt_ttl,
        )
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
        // Generate TDX quote for the account URI
        let todo = "Use dstack agent";
        let quote = match generate_tdx_quote(account_uri.as_bytes()).await {
            Ok(q) => q,
            Err(e) => {
                warn!("failed to generate TDX quote for ACME account: {e}");
                // Don't fail if attestation fails (might be running in non-TDX environment)
                return Ok(());
            }
        };

        let attestation = AcmeAttestation {
            account_uri: account_uri.to_string(),
            quote,
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
        // Generate TDX quote for the public key
        let todo = "Use dstack agent";
        let quote = match generate_tdx_quote(public_key_der).await {
            Ok(q) => q,
            Err(e) => {
                warn!(domain, "failed to generate TDX quote: {e}");
                // Don't fail the certificate process if attestation fails
                // (might be running in non-TDX environment)
                return Ok(());
            }
        };

        let attestation = CertAttestation {
            public_key: public_key_der.to_vec(),
            quote,
            generated_by: self.kv_store.my_node_id(),
            generated_at: now_secs(),
        };

        self.kv_store.save_cert_attestation(domain, &attestation)?;
        info!(domain, "attestation saved to KvStore");
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn get_cert_expiry(cert_pem: &str) -> Option<u64> {
    use x509_parser::prelude::*;
    let pem = Pem::iter_from_buffer(cert_pem.as_bytes()).next()?.ok()?;
    let cert = pem.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp() as u64)
}

fn acme_url_matches(credentials_json: &str, expected_url: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Creds {
        #[serde(default)]
        acme_url: String,
    }
    serde_json::from_str::<Creds>(credentials_json)
        .map(|c| c.acme_url == expected_url)
        .unwrap_or(false)
}

/// Extract account_id (URI) from ACME credentials JSON
fn extract_account_uri(credentials_json: &str) -> Option<String> {
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

/// Generate TDX quote for the given data (certificate public key)
async fn generate_tdx_quote(data: &[u8]) -> Result<String> {
    use sha2::{Digest, Sha256};

    // Hash the public key to fit in report data (64 bytes max)
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();

    // Prepare report data (64 bytes, padded with zeros)
    let mut report_data = [0u8; 64];
    report_data[..32].copy_from_slice(&hash);

    // Try to get quote from TDX
    let (_, quote) =
        tdx_attest::get_quote(&report_data, None).context("failed to get TDX quote")?;

    // Return as hex-encoded string
    Ok(hex::encode(&quote))
}
