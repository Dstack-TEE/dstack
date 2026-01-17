// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! In-memory certificate store with SNI-based certificate resolution.
//!
//! This module provides a thread-safe certificate store that supports:
//! - Multiple certificates for different domains
//! - Wildcard certificate matching
//! - Dynamic certificate updates from KvStore
//! - SNI-based certificate selection for TLS connections

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info};

use crate::kv::CertData;

/// In-memory certificate store supporting SNI-based resolution.
///
/// Certificates are stored in two maps:
/// - `exact_certs`: For exact domain matches (e.g., "example.com")
/// - `wildcard_certs`: For wildcard matches (e.g., "*.example.com" matches "foo.example.com")
pub struct CertStore {
    /// Exact domain -> CertifiedKey
    exact_certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Parent domain -> CertifiedKey (for wildcard certs)
    /// e.g., "example.com" -> cert for "*.example.com"
    wildcard_certs: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    /// Domain -> CertData (for metadata like expiry)
    cert_data: RwLock<HashMap<String, CertData>>,
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact_domains: Vec<_> = self
            .exact_certs
            .read()
            .map(|g| g.keys().cloned().collect())
            .unwrap_or_default();
        let wildcard_domains: Vec<_> = self
            .wildcard_certs
            .read()
            .map(|g| g.keys().map(|k| format!("*.{}", k)).collect())
            .unwrap_or_default();

        f.debug_struct("CertStore")
            .field("exact_domains", &exact_domains)
            .field("wildcard_domains", &wildcard_domains)
            .finish()
    }
}

impl CertStore {
    /// Create a new empty certificate store
    pub fn new() -> Self {
        Self {
            exact_certs: RwLock::new(HashMap::new()),
            wildcard_certs: RwLock::new(HashMap::new()),
            cert_data: RwLock::new(HashMap::new()),
        }
    }

    /// Load a certificate from CertData
    pub fn load_cert(&self, domain: &str, data: &CertData) -> Result<()> {
        let certified_key = parse_certified_key(&data.cert_pem, &data.key_pem)
            .with_context(|| format!("failed to parse certificate for {}", domain))?;

        let certified_key = Arc::new(certified_key);

        // Determine if this is a wildcard cert
        if let Some(parent_domain) = domain.strip_prefix("*.") {
            // Wildcard certificate
            let mut wildcards = self.wildcard_certs.write().unwrap();
            wildcards.insert(parent_domain.to_string(), certified_key);
            info!(
                "cert_store: loaded wildcard certificate for *.{} (expires: {})",
                parent_domain,
                format_expiry(data.not_after)
            );
        } else {
            // Exact domain certificate
            let mut exacts = self.exact_certs.write().unwrap();
            exacts.insert(domain.to_string(), certified_key);
            info!(
                "cert_store: loaded certificate for {} (expires: {})",
                domain,
                format_expiry(data.not_after)
            );
        }

        // Store metadata
        {
            let mut metadata = self.cert_data.write().unwrap();
            metadata.insert(domain.to_string(), data.clone());
        }

        Ok(())
    }

    /// Remove a certificate for a domain
    pub fn remove_cert(&self, domain: &str) {
        if let Some(parent_domain) = domain.strip_prefix("*.") {
            let mut wildcards = self.wildcard_certs.write().unwrap();
            wildcards.remove(parent_domain);
        } else {
            let mut exacts = self.exact_certs.write().unwrap();
            exacts.remove(domain);
        }

        let mut metadata = self.cert_data.write().unwrap();
        metadata.remove(domain);

        info!("cert_store: removed certificate for {}", domain);
    }

    /// Get certificate data for a domain
    pub fn get_cert_data(&self, domain: &str) -> Option<CertData> {
        let metadata = self.cert_data.read().unwrap();
        metadata.get(domain).cloned()
    }

    /// List all loaded domains
    pub fn list_domains(&self) -> Vec<String> {
        let metadata = self.cert_data.read().unwrap();
        metadata.keys().cloned().collect()
    }

    /// Check if a certificate exists for a domain
    pub fn has_cert(&self, domain: &str) -> bool {
        let metadata = self.cert_data.read().unwrap();
        metadata.contains_key(domain)
    }

    /// Resolve certificate for a given SNI hostname
    fn resolve_cert(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        // 1. Try exact match first
        {
            let exacts = self.exact_certs.read().unwrap();
            if let Some(cert) = exacts.get(sni) {
                debug!("cert_store: exact match for {}", sni);
                return Some(cert.clone());
            }
        }

        // 2. Try wildcard match
        // For "foo.bar.example.com", try "bar.example.com", then "example.com"
        let mut hostname = sni;
        while let Some(pos) = hostname.find('.') {
            let parent = &hostname[pos + 1..];
            {
                let wildcards = self.wildcard_certs.read().unwrap();
                if let Some(cert) = wildcards.get(parent) {
                    debug!("cert_store: wildcard match *.{} for {}", parent, sni);
                    return Some(cert.clone());
                }
            }
            hostname = parent;
        }

        debug!("cert_store: no certificate found for {}", sni);
        None
    }
}

impl Default for CertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for CertStore {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        self.resolve_cert(sni)
    }
}

/// Parse certificate and private key PEM strings into a CertifiedKey
fn parse_certified_key(cert_pem: &str, key_pem: &str) -> Result<CertifiedKey> {
    let certs = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate chain")?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in PEM");
    }

    let key =
        PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).context("failed to parse private key")?;

    let signing_key = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("failed to create signing key: {:?}", e))?;

    Ok(CertifiedKey::new(certs, signing_key))
}

/// Format expiry timestamp as human-readable string
fn format_expiry(not_after: u64) -> String {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    let expiry = UNIX_EPOCH + Duration::from_secs(not_after);
    let now = SystemTime::now();

    match expiry.duration_since(now) {
        Ok(remaining) => {
            let days = remaining.as_secs() / 86400;
            format!("{} days remaining", days)
        }
        Err(_) => "expired".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cert_data() -> CertData {
        // Generate a self-signed test certificate using rcgen
        use ra_tls::rcgen::{self, CertificateParams, KeyPair};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let mut params = CertificateParams::new(vec!["test.example.com".to_string()])
            .expect("failed to create cert params");
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let cert = params
            .self_signed(&key_pair)
            .expect("failed to generate self-signed cert");

        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + Duration::from_secs(365 * 24 * 3600).as_secs();

        CertData {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            not_after,
            issued_by: 1,
            issued_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    #[test]
    fn test_cert_store_basic() {
        let store = CertStore::new();
        assert!(store.list_domains().is_empty());
    }

    #[test]
    fn test_cert_store_load_and_resolve() {
        let store = CertStore::new();
        let data = make_test_cert_data();

        // Load certificate
        store
            .load_cert("test.example.com", &data)
            .expect("failed to load cert");

        // Check it's loaded
        assert!(store.has_cert("test.example.com"));
        assert_eq!(store.list_domains().len(), 1);

        // Resolve exact match
        assert!(store.resolve_cert("test.example.com").is_some());

        // Should not resolve unknown domain
        assert!(store.resolve_cert("unknown.example.com").is_none());
    }

    #[test]
    fn test_cert_store_wildcard() {
        let store = CertStore::new();

        // Generate wildcard cert
        use ra_tls::rcgen::{self, CertificateParams, KeyPair};
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        let key_pair = KeyPair::generate().expect("failed to generate key pair");
        let mut params = CertificateParams::new(vec!["*.example.com".to_string()])
            .expect("failed to create cert params");
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let cert = params
            .self_signed(&key_pair)
            .expect("failed to generate self-signed cert");

        let not_after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            + Duration::from_secs(365 * 24 * 3600).as_secs();

        let data = CertData {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            not_after,
            issued_by: 1,
            issued_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        store
            .load_cert("*.example.com", &data)
            .expect("failed to load wildcard cert");

        // Should resolve any subdomain
        assert!(store.resolve_cert("foo.example.com").is_some());
        assert!(store.resolve_cert("bar.example.com").is_some());

        // Note: wildcard certs also match nested subdomains in our implementation
        // This is intentional for ease of use with wildcard domains
        assert!(store.resolve_cert("sub.foo.example.com").is_some());

        // Should not resolve different domain
        assert!(store.resolve_cert("example.org").is_none());
    }
}
