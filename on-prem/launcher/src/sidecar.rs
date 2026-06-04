use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Serialize)]
struct AcquireLeaseRequest {
    app_id: String,
    instance_id: String,
    compose_hash: String,
    image_digest: String,
}

/// One image-decryption private key in the leased keyring. `kid` labels it;
/// all leased `priv_pem`s are handed to skopeo, and ocicrypt (native JWE)
/// decrypts with whichever one is the image's recipient.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyEntry {
    pub kid: String,
    pub priv_pem: String, // PEM EC P-256 (PKCS#8)
}

#[derive(Debug, Deserialize)]
pub struct AcquireLeaseResponse {
    pub lease: String,
    pub keyset: Vec<KeyEntry>,
}

#[derive(Debug, Serialize)]
struct RenewLeaseRequest {
    slot_id: String,
    instance_id: String,
}

#[derive(Debug, Deserialize)]
pub struct VersionResponse {
    pub current_image_digest: String,
    pub bundle_seq: u64,
}

pub struct SidecarClient {
    client: reqwest::Client,
    base_url: String,
}

impl SidecarClient {
    pub fn new(
        base_url: String,
        ca_cert_pem: &str,
        client_cert_pem: &str,
        client_key_pem: &str,
    ) -> Result<Self> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use rustls_pemfile::{certs, pkcs8_private_keys, rsa_private_keys};

        let ca_cert_bytes = ca_cert_pem.as_bytes();
        let mut ca_cursor = std::io::Cursor::new(ca_cert_bytes);
        let ca_certs: Vec<CertificateDer<'static>> = certs(&mut ca_cursor)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse ca cert")?;

        let mut root_store = rustls::RootCertStore::empty();
        for cert in ca_certs {
            root_store
                .add(cert)
                .context("failed to add ca cert to root store")?;
        }

        let client_cert_bytes = client_cert_pem.as_bytes();
        let mut cert_cursor = std::io::Cursor::new(client_cert_bytes);
        let client_certs: Vec<CertificateDer<'static>> = certs(&mut cert_cursor)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed to parse client cert")?;

        let client_key_bytes = client_key_pem.as_bytes();
        let mut key_cursor = std::io::Cursor::new(client_key_bytes);

        let private_key: PrivateKeyDer<'static> = {
            let pkcs8_keys: Vec<_> = pkcs8_private_keys(&mut key_cursor)
                .collect::<std::result::Result<Vec<_>, _>>()
                .unwrap_or_default();
            if !pkcs8_keys.is_empty() {
                PrivateKeyDer::Pkcs8(pkcs8_keys.into_iter().next().unwrap())
            } else {
                let mut key_cursor2 = std::io::Cursor::new(client_key_pem.as_bytes());
                let rsa_keys: Vec<_> = rsa_private_keys(&mut key_cursor2)
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .context("failed to parse private key")?;
                PrivateKeyDer::Pkcs1(rsa_keys.into_iter().next().context("no private key found")?)
            }
        };

        // FAIL-CLOSED: always verify the key-broker's server cert against the KMS
        // CA (root_store, from GetMeta). No insecure bypass.
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, private_key)
            .context("failed to build tls config with client cert")?;

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls_config)
            .build()
            .context("failed to build reqwest client")?;

        Ok(Self { client, base_url })
    }

    pub fn new_insecure(base_url: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context("failed to build insecure client")?;
        Ok(Self { client, base_url })
    }

    pub async fn acquire_lease(
        &self,
        app_id: &str,
        instance_id: &str,
        compose_hash: &str,
        image_digest: &str,
    ) -> Result<AcquireLeaseResponse> {
        let url = format!("{}/lease/acquire", self.base_url.trim_end_matches('/'));
        let body = AcquireLeaseRequest {
            app_id: app_id.to_string(),
            instance_id: instance_id.to_string(),
            compose_hash: compose_hash.to_string(),
            image_digest: image_digest.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("failed to post to {url}"))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("lease/acquire failed with status {status}: {text}");
        }

        response
            .json::<AcquireLeaseResponse>()
            .await
            .context("failed to decode acquire lease response")
    }

    pub async fn renew_lease(&self, slot_id: &str, instance_id: &str) -> Result<()> {
        let url = format!("{}/lease/renew", self.base_url.trim_end_matches('/'));
        let body = RenewLeaseRequest {
            slot_id: slot_id.to_string(),
            instance_id: instance_id.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("failed to post to {url}"))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("lease/renew failed with status {status}: {text}");
        }

        Ok(())
    }

    pub async fn get_version(&self, app_id: &str) -> Result<VersionResponse> {
        let url = format!("{}/version", self.base_url.trim_end_matches('/'));
        let response = self
            .client
            .get(&url)
            .query(&[("app_id", app_id)])
            .send()
            .await
            .with_context(|| format!("failed to get {url}"))?;

        let status = response.status();
        if !status.is_success() {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("GET /version failed with status {status}: {text}");
        }

        response
            .json::<VersionResponse>()
            .await
            .context("failed to decode version response")
    }
}

pub type SharedSidecarClient = Arc<SidecarClient>;
