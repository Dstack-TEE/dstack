// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use or_panic::ResultOrPanic;
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use sha2::Sha256;
use sha3::{Digest, Keccak256};
use std::{error::Error, fmt};

use crate::KeyProviderKind;

const MR_CONFIG_V3_DOCUMENT_HASH_DOMAIN: &[u8] = b"dstack-mr-config-v3:";

pub enum MrConfig<'a> {
    V1 {
        compose_hash: &'a [u8; 32],
    },
    V2 {
        compose_hash: &'a [u8; 32],
        app_id: &'a [u8; 20],
        key_provider: KeyProviderKind,
        key_provider_id: &'a [u8],
    },
}

fn key_provider_kind_byte(key_provider: KeyProviderKind) -> u8 {
    match key_provider {
        KeyProviderKind::None => 0,
        KeyProviderKind::Local => 1,
        KeyProviderKind::Kms => 2,
        KeyProviderKind::Tpm => 3,
    }
}

impl MrConfig<'_> {
    pub fn to_mr_config_id(&self) -> [u8; 48] {
        match self {
            MrConfig::V1 { compose_hash } => {
                let mut config_id = [0u8; 48];
                config_id[0] = 1;
                config_id[1..33].copy_from_slice(*compose_hash);
                config_id
            }
            MrConfig::V2 {
                compose_hash,
                app_id,
                key_provider,
                key_provider_id,
            } => {
                let mut hasher = Keccak256::new();
                hasher.update(compose_hash);
                hasher.update(app_id);
                hasher.update([key_provider_kind_byte(*key_provider)]);
                hasher.update(key_provider_id);
                let digest = hasher.finalize();
                let mut config_id = [0u8; 48];
                config_id[0] = 2;
                config_id[1..33].copy_from_slice(digest.as_slice());
                config_id
            }
        }
    }
}

fn mr_config_v3_version() -> u8 {
    3
}

/// Platform-independent app/config binding document.
///
/// Hosts generate the document in JCS form, while verifiers hash the supplied
/// document bytes directly because the platform carrier binds the exact
/// document string.
#[derive(Debug)]
pub enum MrConfigDocumentError {
    Json(serde_json::Error),
}

impl fmt::Display for MrConfigDocumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "failed to parse mr_config document: {err}"),
        }
    }
}

impl Error for MrConfigDocumentError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Json(err) => Some(err),
        }
    }
}

impl From<serde_json::Error> for MrConfigDocumentError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MrConfigV3 {
    #[serde(default = "mr_config_v3_version")]
    pub version: u8,
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub compose_hash: Vec<u8>,
    pub key_provider: KeyProviderKind,
    #[serde(default, with = "hex_bytes")]
    pub key_provider_id: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub instance_id: Vec<u8>,
}

impl MrConfigV3 {
    pub fn new(
        app_id: Vec<u8>,
        compose_hash: Vec<u8>,
        key_provider: KeyProviderKind,
        key_provider_id: Vec<u8>,
        instance_id: Vec<u8>,
    ) -> Self {
        Self {
            version: mr_config_v3_version(),
            app_id,
            compose_hash,
            key_provider,
            key_provider_id,
            instance_id,
        }
    }

    pub fn to_snp_host_data(&self) -> [u8; 32] {
        Self::snp_host_data_from_document(&self.to_canonical_json())
    }

    pub fn to_tdx_mr_config_id(&self) -> [u8; 48] {
        Self::tdx_mr_config_id_from_document(&self.to_canonical_json())
    }

    pub fn to_canonical_json(&self) -> String {
        // JCS serialization of this owned struct cannot fail; panic loudly if
        // that invariant is ever broken.
        serde_jcs::to_string(self).or_panic("MrConfigV3 JCS serialization")
    }

    pub fn from_document(document: &str) -> Result<Self, MrConfigDocumentError> {
        Ok(serde_json::from_str(document)?)
    }

    pub fn snp_host_data_from_document(document: &str) -> [u8; 32] {
        Self::hash_document(document)
    }

    pub fn tdx_mr_config_id_from_document(document: &str) -> [u8; 48] {
        let digest = Self::hash_document(document);
        let mut config_id = [0u8; 48];
        config_id[0] = 3;
        config_id[1..33].copy_from_slice(&digest);
        config_id
    }

    fn hash_document(document: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(MR_CONFIG_V3_DOCUMENT_HASH_DOMAIN);
        hasher.update([0]);
        hasher.update(document.as_bytes());
        hasher.finalize().into()
    }

    pub fn key_provider_name(&self) -> &'static str {
        match self.key_provider {
            KeyProviderKind::None => "none",
            KeyProviderKind::Local => "local-sgx",
            KeyProviderKind::Kms => "kms",
            KeyProviderKind::Tpm => "tpm",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mr_config_v3_hash_changes_with_app_identity() {
        let config = MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            KeyProviderKind::Kms,
            vec![0x33; 32],
            vec![0x44; 20],
        );
        let mut changed = config.clone();
        changed.app_id[0] ^= 0xff;

        assert_ne!(config.to_snp_host_data(), changed.to_snp_host_data());
        assert_eq!(config.to_snp_host_data().len(), 32);
        assert_ne!(config.to_tdx_mr_config_id(), changed.to_tdx_mr_config_id());
        assert_eq!(config.to_tdx_mr_config_id()[0], 3);
    }

    #[test]
    fn mr_config_v3_generates_jcs_but_hashes_document_bytes() -> Result<(), Box<dyn Error>> {
        let config = MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            KeyProviderKind::Kms,
            vec![0x33; 32],
            vec![0x44; 20],
        );
        let document = config.to_canonical_json();

        assert_eq!(
            document,
            concat!(
                "{\"app_id\":\"1111111111111111111111111111111111111111\",",
                "\"compose_hash\":\"2222222222222222222222222222222222222222222222222222222222222222\",",
                "\"instance_id\":\"4444444444444444444444444444444444444444\",",
                "\"key_provider\":\"kms\",",
                "\"key_provider_id\":\"3333333333333333333333333333333333333333333333333333333333333333\",",
                "\"version\":3}"
            )
        );
        assert_eq!(MrConfigV3::from_document(&document)?, config);

        let pretty = serde_json::to_string_pretty(&config)?;
        assert_eq!(MrConfigV3::from_document(&pretty)?, config);
        assert_ne!(
            MrConfigV3::snp_host_data_from_document(&document),
            MrConfigV3::snp_host_data_from_document(&pretty)
        );
        Ok(())
    }
}
