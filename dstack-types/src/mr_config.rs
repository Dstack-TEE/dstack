// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use sha3::{Digest, Keccak256};

use crate::KeyProviderKind;

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
                let kp_kind = match key_provider {
                    KeyProviderKind::None => 0_u8,
                    KeyProviderKind::Local => 1,
                    KeyProviderKind::Kms => 2,
                };
                let mut hasher = Keccak256::new();
                hasher.update(compose_hash);
                hasher.update(app_id);
                hasher.update([kp_kind]);
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
