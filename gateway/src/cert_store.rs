// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! In-memory certificate store with SNI-based certificate resolution.
//!
//! This module provides a lock-free certificate store that supports:
//! - Multiple certificates for different domains
//! - Wildcard certificate matching
//! - Dynamic certificate updates via atomic replacement
//! - SNI-based certificate selection for TLS connections
//!
//! Architecture: `CertStore` is immutable after construction for lock-free reads.
//! Updates are done by building a new `CertStore` and atomically swapping the `Arc<CertStore>`
//! in the outer `RwLock<Arc<CertStore>>`.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result};
use arc_swap::{ArcSwap, Guard};
use or_panic::ResultOrPanic;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info};

use crate::kv::CertData;

/// Immutable, lock-free certificate store.
///
/// This struct is designed for maximum read performance - no locks required for lookups.
/// Updates are done by creating a new instance and atomically swapping via outer RwLock<Arc<CertStore>>.
pub struct CertStore {
    /// Exact domain -> CertifiedKey
    exact_certs: HashMap<String, Arc<CertifiedKey>>,
    /// Parent domain -> CertifiedKey (for wildcard certs)
    /// e.g., "example.com" -> cert for "*.example.com"
    wildcard_certs: HashMap<String, Arc<CertifiedKey>>,
    /// Domain -> CertData (for metadata like expiry)
    cert_data: HashMap<String, CertData>,
}

impl CertStore {
    /// Create a new empty certificate store
    pub fn new() -> Self {
        Self {
            exact_certs: HashMap::new(),
            wildcard_certs: HashMap::new(),
            cert_data: HashMap::new(),
        }
    }

    /// Resolve certificate for a given SNI hostname (lock-free)
    fn resolve_cert(&self, sni: &str) -> Option<Arc<CertifiedKey>> {
        // 1. Try exact match first
        if let Some(cert) = self.exact_certs.get(sni) {
            debug!("exact match for {sni}");
            return Some(cert.clone());
        }

        // 2. Try wildcard match (only one level deep per TLS spec)
        // For "foo.bar.example.com", only try "bar.example.com"
        if let Some((_, parent)) = sni.split_once('.') {
            if let Some(cert) = self.wildcard_certs.get(parent) {
                debug!("wildcard match *.{parent} for {sni}");
                return Some(cert.clone());
            }
        }

        debug!("no certificate found for {sni}");
        None
    }

    /// Check if a certificate exists for a domain
    pub fn has_cert(&self, domain: &str) -> bool {
        self.cert_data.contains_key(domain)
    }

    /// Get certificate data for a domain
    pub fn get_cert_data(&self, domain: &str) -> Option<&CertData> {
        self.cert_data.get(domain)
    }

    /// List all loaded domains
    pub fn list_domains(&self) -> Vec<String> {
        self.cert_data.keys().cloned().collect()
    }

    /// Check if a certificate can be resolved for a given SNI hostname
    pub fn has_cert_for_sni(&self, sni: &str) -> bool {
        self.resolve_cert(sni).is_some()
    }

    /// Check if a wildcard certificate exists for a domain
    pub fn contains_wildcard(&self, base_domain: &str) -> bool {
        self.wildcard_certs.contains_key(base_domain)
    }
}

impl fmt::Debug for CertStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let exact_domains: Vec<_> = self.exact_certs.keys().cloned().collect();
        let wildcard_domains: Vec<_> = self
            .wildcard_certs
            .keys()
            .map(|k| format!("*.{}", k))
            .collect();

        f.debug_struct("CertStore")
            .field("exact_domains", &exact_domains)
            .field("wildcard_domains", &wildcard_domains)
            .finish()
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

/// Certificate resolver that wraps `ArcSwap<CertStore>` for lock-free reads.
///
/// This allows TLS acceptors to be created once and certificates to be updated
/// without recreating the acceptor. The read path (TLS handshake) is completely
/// lock-free via `ArcSwap`. Write operations are serialized via a `Mutex` to
/// prevent lost updates during concurrent certificate changes.
pub struct CertResolver {
    store: ArcSwap<CertStore>,
    /// Mutex to serialize write operations (reads are still lock-free)
    write_lock: std::sync::Mutex<()>,
}

impl CertResolver {
    /// Create a new resolver with an empty CertStore
    pub fn new() -> Self {
        Self {
            store: ArcSwap::from_pointee(CertStore::new()),
            write_lock: std::sync::Mutex::new(()),
        }
    }

    /// Get the current CertStore (lock-free)
    pub fn get(&self) -> Guard<Arc<CertStore>> {
        self.store.load()
    }

    /// Replace the CertStore atomically (lock-free)
    pub fn set(&self, new_store: Arc<CertStore>) {
        self.store.store(new_store);
    }

    /// List all domains
    pub fn list_domains(&self) -> Vec<String> {
        self.get().list_domains()
    }

    /// Check if a certificate exists for a domain
    pub fn has_cert(&self, domain: &str) -> bool {
        self.get().has_cert(domain)
    }

    /// Update a single certificate (creates new store with updated cert)
    ///
    /// This is an incremental update that preserves all existing certificates.
    /// Write operations are serialized to prevent lost updates.
    pub fn update_cert(&self, domain: &str, data: &CertData) -> Result<()> {
        let _guard = self
            .write_lock
            .lock()
            .or_panic("failed to acquire write lock");

        let old_store = self.get();

        // Build new store with all existing certs plus the new/updated one
        let mut builder = CertStoreBuilder::new();

        // Copy existing certs (except the one we're replacing)
        for existing_domain in old_store.list_domains() {
            if existing_domain != domain {
                if let Some(existing_data) = old_store.get_cert_data(&existing_domain) {
                    builder.add_cert(&existing_domain, existing_data)?;
                }
            }
        }

        // Add the new/updated cert
        builder.add_cert(domain, data)?;

        // Atomically swap
        self.set(Arc::new(builder.build()));
        Ok(())
    }
}

impl Default for CertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

impl ResolvesServerCert for CertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        // Lock-free load via ArcSwap
        let store = self.store.load();
        let sni = client_hello.server_name()?;
        store.resolve_cert(sni)
    }
}

/// Builder for constructing a new CertStore.
///
/// Use this to build a complete certificate store, then call `build()` to get the immutable CertStore.
pub struct CertStoreBuilder {
    exact_certs: HashMap<String, Arc<CertifiedKey>>,
    wildcard_certs: HashMap<String, Arc<CertifiedKey>>,
    cert_data: HashMap<String, CertData>,
}

impl CertStoreBuilder {
    /// Create a new empty builder
    pub fn new() -> Self {
        Self {
            exact_certs: HashMap::new(),
            wildcard_certs: HashMap::new(),
            cert_data: HashMap::new(),
        }
    }

    /// Add a certificate to the builder
    ///
    /// The domain is the base domain (e.g., "example.com").
    /// All gateway certificates are wildcard certs for "*.{domain}".
    pub fn add_cert(&mut self, domain: &str, data: &CertData) -> Result<()> {
        let certified_key = parse_certified_key(&data.cert_pem, &data.key_pem)
            .with_context(|| format!("failed to parse certificate for {}", domain))?;

        let certified_key = Arc::new(certified_key);

        // Gateway certificates are always wildcard certs
        // domain is the base domain (e.g., "example.com"), cert is for "*.example.com"
        self.wildcard_certs
            .insert(domain.to_string(), certified_key);
        info!(
            "cert_store: prepared wildcard certificate for *.{} (expires: {})",
            domain,
            format_expiry(data.not_after)
        );

        // Store metadata
        self.cert_data.insert(domain.to_string(), data.clone());

        Ok(())
    }

    /// Build the immutable CertStore
    pub fn build(self) -> CertStore {
        CertStore {
            exact_certs: self.exact_certs,
            wildcard_certs: self.wildcard_certs,
            cert_data: self.cert_data,
        }
    }
}

impl Default for CertStoreBuilder {
    fn default() -> Self {
        Self::new()
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
    fn test_cert_store_builder() {
        let data = make_test_cert_data();

        // Use builder - domain is base domain (e.g., "example.com")
        // All gateway certs are wildcard certs
        let mut builder = CertStoreBuilder::new();
        builder
            .add_cert("example.com", &data)
            .expect("failed to add cert");

        let store = builder.build();

        // Check it's loaded (stored by base domain)
        assert!(store.has_cert("example.com"));
        assert_eq!(store.list_domains().len(), 1);

        // Should resolve any subdomain via wildcard matching
        assert!(store.has_cert_for_sni("test.example.com"));
        assert!(store.has_cert_for_sni("foo.example.com"));

        // Should not resolve exact base domain (wildcard doesn't match base)
        assert!(!store.has_cert_for_sni("example.com"));

        // Should not resolve different domain
        assert!(!store.has_cert_for_sni("example.org"));
    }

    #[test]
    fn test_cert_store_wildcard() {
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

        let mut builder = CertStoreBuilder::new();
        // Now we use base domain format (without *. prefix)
        builder
            .add_cert("example.com", &data)
            .expect("failed to add wildcard cert");

        let store = builder.build();

        // Should resolve any subdomain
        assert!(store.has_cert_for_sni("foo.example.com"));
        assert!(store.has_cert_for_sni("bar.example.com"));

        // Note: wildcard certs also match nested subdomains in our implementation
        // This is intentional for ease of use with wildcard domains
        assert!(store.has_cert_for_sni("sub.foo.example.com"));

        // Should not resolve different domain
        assert!(!store.has_cert_for_sni("example.org"));
    }
}
