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

use super::VmWorkDir;

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
    pub fn prepare_mr_config_v3(&self, app_compose: &AppCompose, has_gpus: bool) -> Result<String> {
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

        Ok(MrConfigV3::new(
            app_id,
            compose_hash.to_vec(),
            gpu_policy_hash,
            app_compose.key_provider(),
            app_compose.key_provider_id.clone(),
            instance_id,
        )
        .to_canonical_json())
    }
}


#[cfg(test)]
mod tests {
    use super::{snp_host_data, tdx_mr_config_id};
    use crate::app::VmWorkDir;
    use base64::prelude::*;
    use dstack_types::{
        mr_config::MrConfigV3, shared_filenames::SYS_CONFIG, AppCompose, KeyProviderKind,
    };
    use fs_err as fs;
    use tempfile::TempDir;

    fn compose(no_instance_id: bool, gpu_policy: Option<&str>) -> (String, AppCompose) {
        let requirements = gpu_policy
            .map(|policy| format!(r#","requirements":{{"gpu_policy":{policy}}}"#))
            .unwrap_or_default();
        let raw = format!(
            r#"{{"manifest_version":"3","name":"case","runner":"docker-compose","gateway_enabled":false,"key_provider":"none","no_instance_id":{no_instance_id}{requirements}}}"#
        );
        let parsed = serde_json::from_str(&raw).unwrap();
        (raw, parsed)
    }

    fn workdir(raw_compose: &str) -> (TempDir, VmWorkDir) {
        let temp = TempDir::new().unwrap();
        let workdir = VmWorkDir::new(temp.path().join("vm"));
        fs::create_dir_all(workdir.shared_dir()).unwrap();
        fs::write(workdir.app_compose_path(), raw_compose).unwrap();
        (temp, workdir)
    }

    fn write_document(workdir: &VmWorkDir, document: Option<&str>) {
        let value = serde_json::json!({
            "docker_registry": null,
            "host_api_url": null,
            "mr_config": document,
            "vm_config": "{}"
        });
        fs::write(
            workdir.shared_dir().join(SYS_CONFIG),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    fn document(app_byte: u8) -> String {
        MrConfigV3::new(
            vec![app_byte; 20],
            vec![2; 32],
            None,
            KeyProviderKind::None,
            vec![],
            vec![3; 20],
        )
        .to_canonical_json()
    }

    #[test]
    fn platform_carriers_match_v3_document_and_bind_mutations() {
        let (raw, app) = compose(true, None);
        let (_temp, workdir) = workdir(&raw);
        let first = document(1);
        write_document(&workdir, Some(&first));
        let tdx_first = tdx_mr_config_id(&workdir, &app).unwrap();
        let snp_first = snp_host_data(&workdir).unwrap();
        assert_eq!(
            tdx_first,
            BASE64_STANDARD.encode(MrConfigV3::tdx_mr_config_id_from_document(&first))
        );
        assert_eq!(
            snp_first,
            BASE64_STANDARD.encode(MrConfigV3::snp_host_data_from_document(&first))
        );

        let second = document(9);
        write_document(&workdir, Some(&second));
        assert_ne!(tdx_mr_config_id(&workdir, &app).unwrap(), tdx_first);
        assert_ne!(snp_host_data(&workdir).unwrap(), snp_first);
    }

    #[test]
    fn malformed_and_missing_documents_fail_closed() {
        let (raw, app) = compose(true, None);
        let (_temp, workdir) = workdir(&raw);
        write_document(&workdir, Some("{invalid"));
        assert!(tdx_mr_config_id(&workdir, &app).is_err());
        assert!(snp_host_data(&workdir).is_err());
        write_document(&workdir, None);
        assert!(snp_host_data(&workdir).is_err());
    }

    #[test]
    fn prepared_document_is_deterministic_and_binds_compose() {
        let (raw, app) = compose(true, None);
        let (_temp, workdir) = workdir(&raw);
        let first = workdir.prepare_mr_config_v3(&app, false).unwrap();
        let repeated = workdir.prepare_mr_config_v3(&app, false).unwrap();
        assert_eq!(first, repeated);
        let parsed = MrConfigV3::from_document(&first).unwrap();
        assert!(parsed.instance_id.is_empty());

        let (changed_raw, changed_app) = compose(true, Some(r#"{"allow_debug":true}"#));
        fs::write(workdir.app_compose_path(), changed_raw).unwrap();
        assert_ne!(
            workdir.prepare_mr_config_v3(&changed_app, false).unwrap(),
            first
        );
    }

    #[test]
    fn gpu_policy_changes_are_measured() {
        let (raw, app) = compose(true, Some("{}"));
        let (_temp, workdir) = workdir(&raw);
        let baseline = workdir.prepare_mr_config_v3(&app, true).unwrap();
        let (changed_raw, changed_app) = compose(true, Some(r#"{"allow_debug":true}"#));
        fs::write(workdir.app_compose_path(), changed_raw).unwrap();
        let changed = workdir.prepare_mr_config_v3(&changed_app, true).unwrap();
        assert_ne!(baseline, changed);
        assert_ne!(
            MrConfigV3::from_document(&baseline).unwrap().gpu_policy_hash,
            MrConfigV3::from_document(&changed).unwrap().gpu_policy_hash
        );
    }
}
