// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM working directory layout and persisted state.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dstack_types::{
    shared_filenames::{APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, SYS_CONFIG, USER_CONFIG},
    AppCompose, SysConfig,
};
use fs_err as fs;
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

use crate::{app::Manifest, config::Networking};

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct InstanceInfo {
    #[serde(default, with = "hex_bytes")]
    pub instance_id_seed: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub instance_id: Vec<u8>,
    #[serde(default, with = "hex_bytes")]
    pub app_id: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct State {
    started: bool,
}

/// Partition the VM owns in the fabric manager NVLink partition table.
///
/// Written only while `[cvm.gpu.nvswitch] managed` is set, and kept in its own
/// file so the deploy-time `started` flag and this fabric bookkeeping never have
/// to be read or rewritten for each other's sake.
#[derive(Deserialize, Serialize)]
struct NvswitchPartition {
    partition_id: u32,
}

pub struct VmWorkDir {
    workdir: PathBuf,
}

impl Deref for VmWorkDir {
    type Target = PathBuf;
    fn deref(&self) -> &Self::Target {
        &self.workdir
    }
}

impl AsRef<Path> for &VmWorkDir {
    fn as_ref(&self) -> &Path {
        self.workdir.as_ref()
    }
}

impl VmWorkDir {
    pub fn new(workdir: impl AsRef<Path>) -> Self {
        Self {
            workdir: workdir.as_ref().to_path_buf(),
        }
    }

    pub fn manifest_path(&self) -> PathBuf {
        self.workdir.join("vm-manifest.json")
    }

    pub fn state_path(&self) -> PathBuf {
        self.workdir.join("vm-state.json")
    }

    pub fn manifest(&self) -> Result<Manifest> {
        let manifest_path = self.manifest_path();
        let raw = fs::read_to_string(manifest_path).context("failed to read manifest")?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).context("failed to parse manifest json")?;
        Manifest::from_json(value).context("failed to deserialize manifest")
    }

    pub fn put_manifest(&self, manifest: &Manifest) -> Result<()> {
        fs::create_dir_all(&self.workdir).context("failed to create workdir")?;
        let manifest_path = self.manifest_path();
        let mut value = serde_json::to_value(manifest)?;
        if let Some(networking) = manifest.networks.first() {
            value["networking"] = serde_json::to_value(networking)?;
        }
        fs::write(manifest_path, serde_json::to_string(&value)?).context("failed to write manifest")
    }

    pub fn started(&self) -> Result<bool> {
        let state_path = self.state_path();
        if !state_path.exists() {
            return Ok(false);
        }
        let state: State =
            serde_json::from_str(&fs::read_to_string(state_path).context("failed to read state")?)
                .context("failed to parse state")?;
        Ok(state.started)
    }

    pub fn set_started(&self, started: bool) -> Result<()> {
        let state_path = self.state_path();
        fs::write(state_path, serde_json::to_string(&State { started })?)
            .context("failed to write state")
    }

    pub fn nvswitch_partition_path(&self) -> PathBuf {
        self.workdir.join("nvswitch-partition.json")
    }

    /// The partition id assigned on an earlier start, if the VM has one.
    ///
    /// An unreadable file is an error rather than "no id": silently treating it
    /// as a fresh VM would hand a running VM a different partition id, which is
    /// exactly what this file exists to prevent.
    pub fn nvswitch_partition_id(&self) -> Result<Option<u32>> {
        let path = self.nvswitch_partition_path();
        if !path.exists() {
            return Ok(None);
        }
        let partition: NvswitchPartition = serde_json::from_str(
            &fs::read_to_string(path).context("failed to read the partition")?,
        )
        .context("failed to parse the partition")?;
        Ok(Some(partition.partition_id))
    }

    pub fn set_nvswitch_partition_id(&self, partition_id: u32) -> Result<()> {
        let serialized = serde_json::to_vec(&NvswitchPartition { partition_id })?;
        safe_write::safe_write(self.nvswitch_partition_path(), serialized)
            .context("failed to write the partition")
    }

    pub fn shared_dir(&self) -> PathBuf {
        self.workdir.join("shared")
    }

    pub fn swtpm_state_dir(&self) -> PathBuf {
        self.workdir.join("swtpm")
    }

    pub fn swtpm_socket(&self) -> PathBuf {
        self.swtpm_state_dir().join("swtpm.sock")
    }

    pub fn launch_spec_path(&self) -> PathBuf {
        self.workdir.join("launch.json")
    }

    pub fn app_compose_path(&self) -> PathBuf {
        self.shared_dir().join(APP_COMPOSE)
    }

    pub fn app_compose_hash(&self) -> Result<[u8; 32]> {
        use sha2::Digest;
        let compose_path = self.app_compose_path();
        let compose = fs::read(compose_path).context("failed to read compose")?;
        Ok(sha2::Sha256::new_with_prefix(&compose).finalize().into())
    }

    pub fn user_config_path(&self) -> PathBuf {
        self.shared_dir().join(USER_CONFIG)
    }

    pub fn encrypted_env_path(&self) -> PathBuf {
        self.shared_dir().join(ENCRYPTED_ENV)
    }

    pub fn instance_info_path(&self) -> PathBuf {
        self.shared_dir().join(INSTANCE_INFO)
    }

    pub fn runtime_networks_path(&self) -> PathBuf {
        self.workdir.join("runtime-networks.json")
    }

    pub fn runtime_networks(&self) -> Vec<Networking> {
        fs::read_to_string(self.runtime_networks_path())
            .ok()
            .and_then(|contents| serde_json::from_str(&contents).ok())
            .unwrap_or_default()
    }

    pub fn set_runtime_networks(&self, networks: &[Networking]) -> Result<()> {
        // A macvtap device path is valid only while its host interface exists.
        // Keep it in memory for launch preparation, but never persist it across
        // VMM restarts where the same /dev/tapN may identify another device.
        let mut persistent_networks = networks.to_vec();
        for network in &mut persistent_networks {
            network.device.clear();
        }
        let serialized = serde_json::to_vec(&persistent_networks)?;
        safe_write::safe_write(self.runtime_networks_path(), serialized)
            .context("failed to write runtime networks")
    }

    pub fn clear_runtime_networks(&self) -> Result<()> {
        let path = self.runtime_networks_path();
        if path.exists() {
            fs::remove_file(path).context("failed to clear runtime networks")?;
        }
        Ok(())
    }

    pub fn serial_file(&self) -> PathBuf {
        self.workdir.join("serial.log")
    }

    pub fn serial_pty(&self) -> PathBuf {
        self.workdir.join("serial.pty")
    }

    pub fn stdout_file(&self) -> PathBuf {
        self.workdir.join("stdout.log")
    }

    pub fn stderr_file(&self) -> PathBuf {
        self.workdir.join("stderr.log")
    }

    pub fn pid_file(&self) -> PathBuf {
        self.workdir.join("qemu.pid")
    }

    pub fn hda_path(&self) -> PathBuf {
        self.workdir.join("hda.img")
    }

    pub fn shared_disk_path(&self) -> PathBuf {
        self.workdir.join("shared.img")
    }

    pub fn qmp_socket(&self) -> PathBuf {
        self.workdir.join("qmp.sock")
    }

    pub fn removing_marker(&self) -> PathBuf {
        self.workdir.join(".removing")
    }

    pub fn is_removing(&self) -> bool {
        self.removing_marker().exists()
    }

    pub fn set_removing(&self) -> Result<()> {
        fs::write(self.removing_marker(), "").context("failed to write .removing marker")
    }

    pub fn path(&self) -> &Path {
        &self.workdir
    }

    pub fn instance_info(&self) -> Result<InstanceInfo> {
        let info_file = self.instance_info_path();
        let info: InstanceInfo = serde_json::from_slice(&fs::read(&info_file)?)?;
        Ok(info)
    }

    pub fn instance_info_or_default(&self) -> Result<InstanceInfo> {
        match self.instance_info() {
            Ok(info) => Ok(info),
            Err(err) => match err.downcast_ref::<std::io::Error>() {
                Some(io_err) if io_err.kind() == std::io::ErrorKind::NotFound => {
                    Ok(InstanceInfo::default())
                }
                _ => Err(err),
            },
        }
    }

    pub fn sys_config(&self) -> Result<SysConfig> {
        let sys_config_file = self.shared_dir().join(SYS_CONFIG);
        let sys_config: SysConfig = serde_json::from_slice(&fs::read(sys_config_file)?)?;
        Ok(sys_config)
    }

    pub fn app_compose(&self) -> Result<AppCompose> {
        let compose_file = self.app_compose_path();
        let compose: AppCompose = serde_json::from_str(&fs::read_to_string(compose_file)?)?;
        Ok(compose)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        os::unix::fs::symlink,
        time::{SystemTime, UNIX_EPOCH},
    };

    use anyhow::Result;
    use fs_err as fs;

    use super::VmWorkDir;
    use crate::config::Networking;

    #[test]
    fn runtime_networks_snapshot_replaces_target_instead_of_following_it() -> Result<()> {
        let temp = std::env::temp_dir().join(format!(
            "dstack-vmm-runtime-networks-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir_all(&temp)?;
        let external = temp.join("external.json");
        fs::write(&external, "sentinel")?;
        let workdir = VmWorkDir::new(temp.join("vm"));
        fs::create_dir_all(workdir.path())?;
        symlink(&external, workdir.runtime_networks_path())?;

        workdir.set_runtime_networks(&[])?;

        assert_eq!(fs::read_to_string(&external)?, "sentinel");
        assert_eq!(fs::read_to_string(workdir.runtime_networks_path())?, "[]");
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn runtime_networks_snapshot_omits_ephemeral_device_paths() -> Result<()> {
        let temp = std::env::temp_dir().join(format!(
            "dstack-vmm-runtime-networks-device-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let workdir = VmWorkDir::new(temp.join("vm"));
        fs::create_dir_all(workdir.path())?;
        let network: Networking = serde_json::from_value(serde_json::json!({
            "mode": "macvtap",
            "parent": "br0",
            "macvtap_mode": "private",
            "device": "/dev/tap42"
        }))?;

        workdir.set_runtime_networks(&[network])?;

        let persisted = workdir.runtime_networks();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].parent, "br0");
        assert!(persisted[0].device.is_empty());
        assert!(!fs::read_to_string(workdir.runtime_networks_path())?.contains("/dev/tap42"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }
}
