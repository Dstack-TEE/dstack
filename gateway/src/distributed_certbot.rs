// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Distributed certificate management using WaveKV for synchronization.
//!
//! This module wraps the certbot library to provide distributed certificate
//! management across multiple gateway nodes sharing the same domain.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use certbot::{AcmeClient, Dns01Client, WorkDir};
use fs_err as fs;
use ra_tls::rcgen::KeyPair;
use tracing::{error, info, warn};

use crate::config::CertbotConfig;
use crate::kv::{CertCredentials, CertData, KvStore};

/// Lock timeout for certificate renewal (10 minutes)
const RENEW_LOCK_TIMEOUT_SECS: u64 = 600;

/// Distributed certificate manager
pub struct DistributedCertBot {
    config: CertbotConfig,
    kv_store: Arc<KvStore>,
    workdir: WorkDir,
}

impl DistributedCertBot {
    pub fn new(config: CertbotConfig, kv_store: Arc<KvStore>) -> Self {
        let workdir = WorkDir::new(&config.workdir);
        Self {
            config,
            kv_store,
            workdir,
        }
    }

    pub fn domain(&self) -> &str {
        &self.config.domain
    }

    pub fn renew_interval(&self) -> Duration {
        self.config.renew_interval
    }

    /// Set CAA records for the domain
    pub async fn set_caa(&self) -> Result<()> {
        let acme_client = self.get_or_create_acme_client().await?;
        acme_client
            .set_caa_records(&[self.config.domain.clone()])
            .await
    }

    /// Initialize certificates - load from KvStore or create new
    pub async fn init(&self) -> Result<()> {
        // First, try to load from KvStore (synced from other nodes)
        if let Some(cert_data) = self.kv_store.get_cert_data(&self.config.domain) {
            let now = now_secs();
            if cert_data.not_after > now {
                info!(
                    "cert[{}]: loaded from KvStore (issued by node {}, expires in {} days)",
                    self.config.domain,
                    cert_data.issued_by,
                    (cert_data.not_after - now) / 86400
                );
                self.save_cert_to_disk(&cert_data.cert_pem, &cert_data.key_pem)?;
                return Ok(());
            }
            info!(
                "cert[{}]: KvStore certificate expired, will request new one",
                self.config.domain
            );
        }

        // Check if local cert exists and is valid
        if self.workdir.cert_path().exists() && self.workdir.key_path().exists() {
            let cert_pem = fs::read_to_string(self.workdir.cert_path())?;
            let key_pem = fs::read_to_string(self.workdir.key_path())?;
            if let Some(not_after) = get_cert_expiry(&cert_pem) {
                let now = now_secs();
                if not_after > now {
                    info!(
                        "cert[{}]: loaded from local file, expires in {} days",
                        self.config.domain,
                        (not_after - now) / 86400
                    );
                    // Sync to KvStore for other nodes
                    self.save_cert_to_kvstore(&cert_pem, &key_pem, not_after)?;
                    info!(
                        "cert[{}]: saved to KvStore for other nodes",
                        self.config.domain
                    );
                    return Ok(());
                }
            }
        }

        // No valid cert anywhere, need to request new one
        info!(
            "cert[{}]: no valid certificate found, requesting from ACME",
            self.config.domain
        );
        self.request_new_cert().await
    }

    /// Try to renew certificate if needed
    pub async fn try_renew(&self, force: bool) -> Result<bool> {
        let domain = &self.config.domain;

        // Check if renewal is needed
        let cert_data = self.kv_store.get_cert_data(domain);
        let needs_renew = if force {
            true
        } else if let Some(ref data) = cert_data {
            let now = now_secs();
            let expires_in = data.not_after.saturating_sub(now);
            let renew_before = self.config.renew_before_expiration.as_secs();
            expires_in < renew_before
        } else {
            true
        };

        if !needs_renew {
            info!("certificate for {} does not need renewal", domain);
            return Ok(false);
        }

        // Try to acquire lock
        if !self
            .kv_store
            .try_acquire_cert_renew_lock(domain, RENEW_LOCK_TIMEOUT_SECS)
        {
            info!(
                "another node is renewing certificate for {}, skipping",
                domain
            );
            return Ok(false);
        }

        info!("acquired renew lock for {}, starting renewal", domain);

        // Perform renewal
        let result = self.do_renew().await;

        // Release lock regardless of result
        if let Err(e) = self.kv_store.release_cert_renew_lock(domain) {
            error!("failed to release cert renew lock: {}", e);
        }

        result
    }

    /// Reload certificate from KvStore (called when watcher triggers)
    pub fn reload_from_kvstore(&self) -> Result<bool> {
        let Some(cert_data) = self.kv_store.get_cert_data(&self.config.domain) else {
            return Ok(false);
        };

        // Check if this is newer than what we have
        if self.workdir.cert_path().exists() {
            let local_cert = fs::read_to_string(self.workdir.cert_path())?;
            if let Some(local_expiry) = get_cert_expiry(&local_cert) {
                if local_expiry >= cert_data.not_after {
                    return Ok(false);
                }
            }
        }

        info!(
            "cert[{}]: reloading from KvStore (sync triggered, issued by node {})",
            self.config.domain, cert_data.issued_by
        );
        self.save_cert_to_disk(&cert_data.cert_pem, &cert_data.key_pem)?;
        Ok(true)
    }

    async fn request_new_cert(&self) -> Result<()> {
        let domain = &self.config.domain;

        // Try to acquire lock first
        if !self
            .kv_store
            .try_acquire_cert_renew_lock(domain, RENEW_LOCK_TIMEOUT_SECS)
        {
            // Another node is requesting, wait for it
            info!(
                "another node is requesting certificate for {}, waiting...",
                domain
            );
            // Wait and then try to load from KvStore
            tokio::time::sleep(Duration::from_secs(30)).await;
            if let Some(cert_data) = self.kv_store.get_cert_data(domain) {
                self.save_cert_to_disk(&cert_data.cert_pem, &cert_data.key_pem)?;
                return Ok(());
            }
            anyhow::bail!("failed to get certificate from KvStore after waiting");
        }

        let result = self.do_request_new().await;

        if let Err(e) = self.kv_store.release_cert_renew_lock(domain) {
            error!("failed to release cert renew lock: {}", e);
        }

        result
    }

    async fn do_request_new(&self) -> Result<()> {
        let acme_client = self.get_or_create_acme_client().await?;
        let domain = &self.config.domain;
        let timeout = self.config.renew_timeout;

        // Generate new key pair
        let key = KeyPair::generate().context("failed to generate key")?;
        let key_pem = key.serialize_pem();

        // Request certificate with timeout
        info!("cert[{}]: requesting new certificate from ACME...", domain);
        let cert_pem = tokio::time::timeout(
            timeout,
            acme_client.request_new_certificate(&key_pem, &[domain.clone()]),
        )
        .await
        .context("certificate request timed out")?
        .context("failed to request new certificate")?;

        let not_after = get_cert_expiry(&cert_pem).context("failed to parse certificate expiry")?;

        // Save to KvStore first (so other nodes can see it)
        self.save_cert_to_kvstore(&cert_pem, &key_pem, not_after)?;
        info!(
            "cert[{}]: new certificate obtained from ACME, saved to KvStore",
            domain
        );

        // Then save to disk
        self.save_cert_to_disk(&cert_pem, &key_pem)?;

        info!(
            "cert[{}]: new certificate saved to disk (expires in {} days)",
            domain,
            (not_after - now_secs()) / 86400
        );
        Ok(())
    }

    async fn do_renew(&self) -> Result<bool> {
        let acme_client = self.get_or_create_acme_client().await?;
        let domain = &self.config.domain;
        let timeout = self.config.renew_timeout;

        // Load current cert and key
        let cert_pem = fs::read_to_string(self.workdir.cert_path())
            .context("failed to read current certificate")?;
        let key_pem =
            fs::read_to_string(self.workdir.key_path()).context("failed to read current key")?;

        // Renew with timeout
        info!("cert[{}]: renewing certificate from ACME...", domain);
        let new_cert_pem =
            tokio::time::timeout(timeout, acme_client.renew_cert(&cert_pem, &key_pem))
                .await
                .context("certificate renewal timed out")?
                .context("failed to renew certificate")?;

        let not_after =
            get_cert_expiry(&new_cert_pem).context("failed to parse certificate expiry")?;

        // Save to KvStore first
        self.save_cert_to_kvstore(&new_cert_pem, &key_pem, not_after)?;
        info!("cert[{}]: renewed certificate saved to KvStore", domain);

        // Then save to disk
        self.save_cert_to_disk(&new_cert_pem, &key_pem)?;

        info!(
            "cert[{}]: renewed certificate saved to disk (expires in {} days)",
            domain,
            (not_after - now_secs()) / 86400
        );
        Ok(true)
    }

    async fn get_or_create_acme_client(&self) -> Result<AcmeClient> {
        let dns01_client = Dns01Client::new_cloudflare(
            self.config.cf_zone_id.clone(),
            self.config.cf_api_token.clone(),
        );

        // Try to load credentials from KvStore
        if let Some(creds) = self.kv_store.get_cert_credentials(&self.config.domain) {
            if acme_url_matches(&creds.acme_credentials, &self.config.acme_url) {
                info!(
                    "acme[{}]: loaded account credentials from KvStore",
                    self.config.domain
                );
                return AcmeClient::load(dns01_client, &creds.acme_credentials)
                    .await
                    .context("failed to load ACME client from KvStore credentials");
            }
            warn!(
                "acme[{}]: URL mismatch in KvStore credentials, will try local file",
                self.config.domain
            );
        }

        // Try to load from local file
        let credentials_path = self.workdir.account_credentials_path();
        if credentials_path.exists() {
            let creds_json = fs::read_to_string(&credentials_path)?;
            if acme_url_matches(&creds_json, &self.config.acme_url) {
                info!(
                    "acme[{}]: loaded account credentials from local file",
                    self.config.domain
                );
                // Save to KvStore for other nodes
                self.kv_store.save_cert_credentials(
                    &self.config.domain,
                    &CertCredentials {
                        acme_credentials: creds_json.clone(),
                    },
                )?;
                return AcmeClient::load(dns01_client, &creds_json)
                    .await
                    .context("failed to load ACME client from local credentials");
            }
        }

        // Create new account
        info!(
            "acme[{}]: creating new account at {}",
            self.config.domain, self.config.acme_url
        );
        let client = AcmeClient::new_account(&self.config.acme_url, dns01_client)
            .await
            .context("failed to create new ACME account")?;

        let creds_json = client
            .dump_credentials()
            .context("failed to dump ACME credentials")?;

        // Set CAA records if configured
        if self.config.auto_set_caa {
            client
                .set_caa_records(&[self.config.domain.clone()])
                .await?;
        }

        // Save to KvStore
        self.kv_store.save_cert_credentials(
            &self.config.domain,
            &CertCredentials {
                acme_credentials: creds_json.clone(),
            },
        )?;

        // Save to local file
        if let Some(parent) = credentials_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&credentials_path, &creds_json)?;

        Ok(client)
    }

    fn save_cert_to_kvstore(&self, cert_pem: &str, key_pem: &str, not_after: u64) -> Result<()> {
        let cert_data = CertData {
            cert_pem: cert_pem.to_string(),
            key_pem: key_pem.to_string(),
            not_after,
            issued_by: self.kv_store.my_node_id(),
            issued_at: now_secs(),
        };
        self.kv_store
            .save_cert_data(&self.config.domain, &cert_data)
    }

    fn save_cert_to_disk(&self, cert_pem: &str, key_pem: &str) -> Result<()> {
        let cert_path = self.workdir.cert_path();
        let key_path = self.workdir.key_path();

        // Create parent directories
        if let Some(parent) = cert_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Also save to backup dir with timestamp
        let backup_dir = self.workdir.backup_dir();
        fs::create_dir_all(&backup_dir)?;
        let timestamp = now_secs();
        let backup_subdir = backup_dir.join(format!("{}", timestamp));
        fs::create_dir_all(&backup_subdir)?;
        fs::write(backup_subdir.join("cert.pem"), cert_pem)?;
        fs::write(backup_subdir.join("key.pem"), key_pem)?;

        // Write main cert files
        fs::write(&cert_path, cert_pem)?;
        fs::write(&key_path, key_pem)?;

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
