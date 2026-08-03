// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Application identity and VM measurement-configuration derivation.

use anyhow::{bail, Context, Result};
use base64::prelude::*;
use dstack_types::mr_config::{MrConfig, MrConfigV3};
use dstack_types::{gpu_policy_hash, AppCompose};
use fs_err as fs;
use sha2::{Digest, Sha256};

use super::{GpuConfig, Manifest, VmWorkDir};
use crate::config::{CvmConfig, CvmPlatform};

fn bind_init_script_hashes(mut mr_config: MrConfigV3, app_compose: &AppCompose) -> MrConfigV3 {
    if app_compose.manifest_version_u32().unwrap_or_default() >= 3 {
        let hashes = app_compose
            .init_script
            .iter()
            .map(|script| Sha256::digest(script.as_bytes()).to_vec())
            .collect();
        mr_config = mr_config.with_init_script_hashes(hashes);
    }
    mr_config
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum MrConfigVersion {
    V1,
    V3,
}

pub(super) fn mr_config_version(
    manifest: &Manifest,
    platform: CvmPlatform,
    use_mrconfigid: bool,
    has_key_provider_id: bool,
) -> Result<Option<MrConfigVersion>> {
    if manifest.simulated_tee == Some(dstack_types::TeeVariant::DstackAmdSevSnp) {
        return Ok(Some(MrConfigVersion::V3));
    }
    if manifest.no_tee {
        return Ok(None);
    }
    match platform {
        CvmPlatform::AmdSevSnp => Ok(Some(MrConfigVersion::V3)),
        CvmPlatform::Tdx if has_key_provider_id && !use_mrconfigid => {
            bail!("key provider ID requires MrConfigV3, but use_mrconfigid is disabled")
        }
        CvmPlatform::Tdx if !use_mrconfigid => Ok(None),
        CvmPlatform::Tdx if has_key_provider_id => Ok(Some(MrConfigVersion::V3)),
        CvmPlatform::Tdx => Ok(Some(MrConfigVersion::V1)),
    }
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
    pub(crate) fn prepare_mr_config(
        &self,
        manifest: &Manifest,
        config: &CvmConfig,
        app_compose: &AppCompose,
    ) -> Result<Option<String>> {
        let version = mr_config_version(
            manifest,
            config.resolved_platform(),
            config.use_mrconfigid,
            !app_compose.key_provider_id.is_empty(),
        )?;
        match version {
            Some(MrConfigVersion::V3) => self
                .prepare_mr_config_v3(
                    app_compose,
                    manifest.gpus.as_ref().is_some_and(GpuConfig::has_gpus),
                )
                .map(Some),
            Some(MrConfigVersion::V1) | None => Ok(None),
        }
    }

    fn prepare_mr_config_v3(&self, app_compose: &AppCompose, has_gpus: bool) -> Result<String> {
        let compose_hash = self
            .app_compose_hash()
            .context("failed to get compose hash")?;
        let gpu_policy_hash = if has_gpus {
            let compose_json = fs::read(self.app_compose_path())
                .context("failed to read app compose for GPU policy hash")?;
            Some(
                gpu_policy_hash(&compose_json)
                    .context("failed to hash raw GPU policy")?
                    .to_vec(),
            )
        } else {
            None
        };
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

        // Manifest v3 is the fail-closed capability signal: older guests
        // reject its string version instead of seeing an unknown MrConfigV3
        // field generated by a newer VMM.
        let mr_config = MrConfigV3::new(
            app_id,
            compose_hash.to_vec(),
            gpu_policy_hash,
            app_compose.key_provider(),
            app_compose.key_provider_id.clone(),
            instance_id,
        );
        Ok(bind_init_script_hashes(mr_config, app_compose).to_canonical_json())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dstack_types::KeyProviderKind;

    fn app_compose(manifest_version: serde_json::Value) -> AppCompose {
        serde_json::from_value(serde_json::json!({
            "manifest_version": manifest_version,
            "name": "test",
            "runner": "docker-compose"
        }))
        .unwrap()
    }

    fn base_mr_config() -> MrConfigV3 {
        MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            None,
            KeyProviderKind::None,
            Vec::new(),
            vec![0x33; 20],
        )
    }

    #[test]
    fn manifest_v2_omits_init_script_hashes() {
        let document =
            bind_init_script_hashes(base_mr_config(), &app_compose(serde_json::json!(2)))
                .to_canonical_json();
        let document: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert!(document.get("init_script_hashes").is_none());
    }

    #[test]
    fn manifest_v3_includes_empty_init_script_hashes() {
        let document =
            bind_init_script_hashes(base_mr_config(), &app_compose(serde_json::json!("3")))
                .to_canonical_json();
        let document: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(document["init_script_hashes"], serde_json::json!([]));
    }
}
