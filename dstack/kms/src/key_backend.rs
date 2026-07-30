// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Root-key operation boundary.
//!
//! The public KMS service must only depend on this interface. The local
//! implementation preserves the legacy behavior; the MPC implementation can
//! replace it without making root key material available to request handlers.

use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;
use ra_tls::{kdf, rcgen::KeyPair};

use crate::crypto::{derive_k256_key, sign_message, sign_message_with_timestamp};

pub(crate) struct DerivedAppKeys {
    pub disk_key: [u8; 32],
    pub env_key: [u8; 32],
    pub k256_key: Vec<u8>,
    pub k256_signature: Vec<u8>,
}

pub(crate) trait KeyBackend: Send + Sync {
    fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys>;
    fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]>;
    fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    fn sign_k256_timestamped(
        &self,
        prefix: &[u8],
        app_id: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Result<Vec<u8>>;
    fn k256_public_key(&self) -> Vec<u8>;
}

pub(crate) struct LocalKeyBackend {
    root_ca_key: KeyPair,
    k256_key: SigningKey,
}

impl LocalKeyBackend {
    pub(crate) fn from_pem_and_bytes(root_ca_key: &str, k256_key: &[u8]) -> Result<Self> {
        Ok(Self {
            root_ca_key: KeyPair::from_pem(root_ca_key).context("invalid root CA key")?,
            k256_key: SigningKey::from_slice(k256_key).context("invalid K-256 root key")?,
        })
    }
}

impl KeyBackend for LocalKeyBackend {
    fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys> {
        let disk_key = kdf::derive_dh_secret(
            &self.root_ca_key,
            &[app_id, instance_id, b"app-disk-crypt-key"],
        )?;
        let env_key = self.derive_env_key(app_id)?;
        let (k256_key, k256_signature) = derive_k256_key(&self.k256_key, app_id)?;
        Ok(DerivedAppKeys {
            disk_key,
            env_key,
            k256_key: k256_key.to_bytes().to_vec(),
            k256_signature,
        })
    }

    fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]> {
        kdf::derive_dh_secret(&self.root_ca_key, &[app_id, b"env-encrypt-key"])
    }

    fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        sign_message(&self.k256_key, prefix, app_id, message)
    }

    fn sign_k256_timestamped(
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
}
