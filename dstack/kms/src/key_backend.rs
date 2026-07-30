// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Root-key operation boundary.
//!
//! The public KMS service must only depend on this interface. The local
//! implementation preserves the legacy behavior; the MPC implementation can
//! replace it without making root key material available to request handlers.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use cggmp21::key_share::AnyKeyShare as _;
use k256::ecdsa::SigningKey;
use ra_tls::{
    cert::{CaCert, CertRequest},
    kdf,
};

use crate::{
    cggmp_engine::{load_share, CggmpCurve, K256KeyShare, P256KeyShare},
    crypto::{derive_k256_key, sign_message, sign_message_with_timestamp},
};

pub(crate) struct DerivedAppKeys {
    pub disk_key: [u8; 32],
    pub env_key: [u8; 32],
    pub k256_key: Vec<u8>,
    pub k256_signature: Vec<u8>,
}

#[async_trait]
pub(crate) trait KeyBackend: Send + Sync {
    async fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys>;
    async fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]>;
    async fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    async fn sign_k256_timestamped(
        &self,
        prefix: &[u8],
        app_id: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Result<Vec<u8>>;
    fn k256_public_key(&self) -> Vec<u8>;
    fn p256_public_key(&self) -> Vec<u8>;
    fn root_ca_cert(&self) -> &str;
    async fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert>;
    /// Legacy KMS-to-KMS migration. MPC backends must reject this operation.
    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)>;
}

pub(crate) struct LocalKeyBackend {
    root_ca: CaCert,
    k256_key: SigningKey,
}

impl LocalKeyBackend {
    pub(crate) fn from_pem_and_bytes(
        root_ca_cert: String,
        root_ca_key: String,
        k256_key: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            root_ca: CaCert::new(root_ca_cert, root_ca_key).context("invalid root CA")?,
            k256_key: SigningKey::from_slice(k256_key).context("invalid K-256 root key")?,
        })
    }
}

#[async_trait]
impl KeyBackend for LocalKeyBackend {
    async fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys> {
        let disk_key = kdf::derive_dh_secret(
            &self.root_ca.key,
            &[app_id, instance_id, b"app-disk-crypt-key"],
        )?;
        let env_key = self.derive_env_key(app_id).await?;
        let (k256_key, k256_signature) = derive_k256_key(&self.k256_key, app_id)?;
        Ok(DerivedAppKeys {
            disk_key,
            env_key,
            k256_key: k256_key.to_bytes().to_vec(),
            k256_signature,
        })
    }

    async fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]> {
        kdf::derive_dh_secret(&self.root_ca.key, &[app_id, b"env-encrypt-key"])
    }

    async fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        sign_message(&self.k256_key, prefix, app_id, message)
    }

    async fn sign_k256_timestamped(
        &self,
        prefix: &[u8],
        app_id: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        sign_message_with_timestamp(&self.k256_key, prefix, app_id, timestamp, message)
    }

    fn k256_public_key(&self) -> Vec<u8> {
        self.k256_key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn p256_public_key(&self) -> Vec<u8> {
        self.root_ca.key.public_key_raw().to_vec()
    }

    fn root_ca_cert(&self) -> &str {
        &self.root_ca.pem_cert
    }

    async fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert> {
        let app_key = kdf::derive_p256_key_pair(&self.root_ca.key, &[app_id, b"app-ca"])?;
        let request = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        let certificate = self
            .root_ca
            .sign(request)
            .context("failed to sign app CA")?;
        Ok(CaCert::from_parts(app_key, certificate))
    }

    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)> {
        Ok((
            self.root_ca.key.serialize_pem(),
            self.k256_key.to_bytes().to_vec(),
        ))
    }
}

/// MPC backend containing only validated threshold shares. No complete root
/// private key is loaded or reconstructed by this backend.
pub(crate) struct MpcKeyBackend {
    root_ca_cert: String,
    p256_share: P256KeyShare,
    k256_share: K256KeyShare,
}

impl MpcKeyBackend {
    pub(crate) fn load(
        root_ca_cert: String,
        cluster_id: &str,
        epoch: u64,
        node_id: &str,
        p256_share_file: &std::path::Path,
        k256_share_file: &std::path::Path,
    ) -> Result<Self> {
        Ok(Self {
            root_ca_cert,
            p256_share: load_share(
                p256_share_file,
                cluster_id,
                epoch,
                node_id,
                CggmpCurve::P256,
            )?,
            k256_share: load_share(
                k256_share_file,
                cluster_id,
                epoch,
                node_id,
                CggmpCurve::K256,
            )?,
        })
    }
}

#[async_trait]
impl KeyBackend for MpcKeyBackend {
    async fn derive_app_keys(&self, _app_id: &[u8], _instance_id: &[u8]) -> Result<DerivedAppKeys> {
        bail!("MPC derivation protocol is unavailable")
    }

    async fn derive_env_key(&self, _app_id: &[u8]) -> Result<[u8; 32]> {
        bail!("MPC derivation protocol is unavailable")
    }

    async fn sign_k256(&self, _prefix: &[u8], _app_id: &[u8], _message: &[u8]) -> Result<Vec<u8>> {
        bail!("MPC signing protocol is unavailable")
    }

    async fn sign_k256_timestamped(
        &self,
        _prefix: &[u8],
        _app_id: &[u8],
        _timestamp: u64,
        _message: &[u8],
    ) -> Result<Vec<u8>> {
        bail!("MPC signing protocol is unavailable")
    }

    fn k256_public_key(&self) -> Vec<u8> {
        self.k256_share
            .shared_public_key()
            .to_bytes(true)
            .as_bytes()
            .to_vec()
    }

    fn p256_public_key(&self) -> Vec<u8> {
        self.p256_share
            .shared_public_key()
            .to_bytes(false)
            .as_bytes()
            .to_vec()
    }

    fn root_ca_cert(&self) -> &str {
        &self.root_ca_cert
    }

    async fn derive_app_ca(&self, _app_id: &[u8]) -> Result<CaCert> {
        bail!("legacy app CA derivation is unavailable in MPC mode")
    }

    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)> {
        bail!("MPC root shares cannot be exported as root keys")
    }
}
