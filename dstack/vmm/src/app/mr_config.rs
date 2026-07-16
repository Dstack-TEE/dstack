// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Application identity and VM measurement-configuration derivation.

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use dstack_types::mr_config::{MrConfig, MrConfigV3};
use dstack_types::AppCompose;
use fs_err as fs;
use sha2::{Digest, Sha256};

use super::VmWorkDir;

/// Derives a deterministic, locally administered unicast MAC address from a VM ID.
///
/// `prefix` may contain zero to three fixed bytes. Remaining bytes are filled
/// from SHA-256 of `vm_id`.
pub(super) fn mac_address_for_vm(vm_id: &str, prefix: &[u8]) -> String {
    let hash = Sha256::digest(vm_id.as_bytes());
    let prefix_len = prefix.len().min(3);
    let mut bytes = [0_u8; 6];
    bytes[..prefix_len].copy_from_slice(&prefix[..prefix_len]);
    for index in prefix_len..bytes.len() {
        bytes[index] = hash[index - prefix_len];
    }
    bytes[0] = (bytes[0] & 0xfe) | 0x02;
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

pub(super) fn tdx_mr_config_id(workdir: &VmWorkDir, app_compose: &AppCompose) -> Result<String> {
    if let Some(document) = workdir
        .sys_config()
        .context("failed to read sys config for tdx mrconfigid")?
        .mr_config
    {
        MrConfigV3::from_document(&document).context("invalid mr_config document")?;
        return Ok(BASE64_STANDARD.encode(MrConfigV3::tdx_mr_config_id_from_document(&document)));
    }

    let compose_hash = workdir
        .app_compose_hash()
        .context("failed to get compose hash")?;
    let mr_config = if app_compose.key_provider_id.is_empty() {
        MrConfig::V1 {
            compose_hash: &compose_hash,
        }
    } else {
        let instance_info = workdir
            .instance_info()
            .context("failed to get instance info")?;
        let app_id = if instance_info.app_id.is_empty() {
            &compose_hash[..20]
        } else {
            &instance_info.app_id
        };
        MrConfig::V2 {
            compose_hash: &compose_hash,
            app_id: &app_id.try_into().context("invalid app ID")?,
            key_provider: app_compose.key_provider(),
            key_provider_id: &app_compose.key_provider_id,
        }
    };
    Ok(BASE64_STANDARD.encode(mr_config.to_mr_config_id()))
}

pub(super) fn snp_host_data(workdir: &VmWorkDir) -> Result<String> {
    let document = workdir
        .sys_config()
        .context("failed to read sys config for amd sev-snp host-data")?
        .mr_config
        .context("mr_config is required for amd sev-snp host-data")?;
    MrConfigV3::from_document(&document).context("invalid mr_config document")?;
    Ok(BASE64_STANDARD.encode(MrConfigV3::snp_host_data_from_document(&document)))
}

impl VmWorkDir {
    pub fn prepare_mr_config_v3(&self, app_compose: &AppCompose) -> Result<String> {
        let compose_hash = self
            .app_compose_hash()
            .context("failed to get compose hash")?;
        let mut instance_info = self
            .instance_info_or_default()
            .context("failed to get instance info")?;
        let app_id = if instance_info.app_id.is_empty() {
            compose_hash[..20].to_vec()
        } else {
            instance_info.app_id.clone()
        };
        if app_id.len() != 20 {
            bail!(
                "invalid app ID length: expected 20 bytes, got {}",
                app_id.len()
            );
        }

        let disk_reusable = !app_compose.key_provider().is_none();
        if !disk_reusable || instance_info.instance_id_seed.is_empty() {
            instance_info.instance_id_seed = {
                let mut seed = vec![0_u8; 20];
                getrandom::fill(&mut seed).context("failed to generate instance ID seed")?;
                seed
            };
        }

        let instance_id = if app_compose.no_instance_id {
            Vec::new()
        } else {
            let mut id_path = instance_info.instance_id_seed.clone();
            id_path.extend_from_slice(&app_id);
            Sha256::digest(id_path)[..20].to_vec()
        };
        instance_info.app_id = app_id.clone();
        instance_info.instance_id = instance_id.clone();
        fs::write(
            self.instance_info_path(),
            serde_json::to_string(&instance_info).context("failed to serialize instance info")?,
        )
        .context("failed to write instance info")?;

        Ok(MrConfigV3::new(
            app_id,
            compose_hash.to_vec(),
            app_compose.key_provider(),
            app_compose.key_provider_id.clone(),
            instance_id,
        )
        .to_canonical_json())
    }
}

#[cfg(test)]
mod tests {
    use super::mac_address_for_vm;

    #[test]
    fn mac_address_is_deterministic_and_locally_administered() {
        let mac = mac_address_for_vm("vm-1", &[0xaa, 0xbb, 0xcc]);
        assert_eq!(&mac[..8], "aa:bb:cc");
        assert_eq!(mac, mac_address_for_vm("vm-1", &[0xaa, 0xbb, 0xcc]));
        let first = u8::from_str_radix(&mac[..2], 16).unwrap();
        assert_eq!(first & 0x03, 0x02);
    }
}
