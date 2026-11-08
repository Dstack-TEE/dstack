// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM working directory layout and persisted state.

use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use dstack_types::{
    shared_filenames::{
        APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, SEALED_ENV, SYS_CONFIG, USER_CONFIG,
    },
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

    pub(crate) fn validate_env_update(encrypted: &[u8], sealed: &[u8]) -> Result<()> {
        if !encrypted.is_empty() && !sealed.is_empty() {
            anyhow::bail!("encrypted_env and sealed_env are mutually exclusive");
        }
        Ok(())
    }

    /// Empty inputs preserve existing environment files, including invalid sealed files.
    pub(crate) fn uses_sealed_env(&self, encrypted: &[u8], sealed: &[u8]) -> Result<bool> {
        Self::validate_env_update(encrypted, sealed)?;
        if !sealed.is_empty() {
            return Ok(true);
        }
        if !encrypted.is_empty() {
            return Ok(false);
        }
        match fs::symlink_metadata(self.sealed_env_path()) {
            Ok(_) => Ok(true),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err).context("failed to inspect sealed environment"),
        }
    }

    /// Caller serializes updates to an existing VM with its launch lock.
    pub(crate) fn write_env(&self, encrypted: &[u8], sealed: &[u8]) -> Result<()> {
        Self::validate_env_update(encrypted, sealed)?;
        let (path, other, data) = if !sealed.is_empty() {
            (self.sealed_env_path(), self.encrypted_env_path(), sealed)
        } else if !encrypted.is_empty() {
            (self.encrypted_env_path(), self.sealed_env_path(), encrypted)
        } else {
            return Ok(());
        };
        safe_write::safe_write(path, data).context("failed to write env")?;
        match fs::remove_file(other) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).context("failed to remove superseded env"),
        }
    }

    pub fn encrypted_env_path(&self) -> PathBuf {
        self.shared_dir().join(ENCRYPTED_ENV)
    }

    pub fn sealed_env_path(&self) -> PathBuf {
        self.shared_dir().join(SEALED_ENV)
    }

    pub fn instance_info_path(&self) -> PathBuf {
        self.shared_dir().join(INSTANCE_INFO)
    }

    pub fn runtime_networks_path(&self) -> PathBuf {
        self.workdir.join("runtime-networks.json")
    }

    /// The only record that netd may hold host interfaces for this VM.
    ///
    /// Written durably before asking netd to create anything, and removed only
    /// after a successful whole-VM sweep, so it is present whenever netd holds
    /// something. The reverse need not hold: host interfaces do not survive a
    /// reboot while this file does, and a marker with nothing behind it costs
    /// one sweep.
    pub fn mark_network_cleanup_pending(&self) -> Result<()> {
        safe_write::safe_write(self.workdir.join(".netd-pending"), b"")
            .context("failed to persist pending network cleanup")
    }

    pub fn network_cleanup_pending(&self) -> bool {
        self.workdir.join(".netd-pending").exists()
    }

    pub fn clear_network_cleanup_pending(&self) -> Result<()> {
        match fs::remove_file(self.workdir.join(".netd-pending")) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).context("failed to clear pending network cleanup"),
        }
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
        // Durable: this is what makes a removal resume after a crash.
        safe_write::safe_write(self.removing_marker(), b"")
            .context("failed to write .removing marker")
    }

    /// Deletes the directory, `.removing` last.
    ///
    /// A deletion interrupted part-way leaves the marker behind, so the next
    /// VMM start finishes the removal instead of loading what is left as a VM.
    pub fn remove_all(&self) -> Result<()> {
        let marker = self.removing_marker();
        let entries = match fs::read_dir(&self.workdir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path == marker {
                continue;
            }
            if path.symlink_metadata()?.is_dir() {
                fs::remove_dir_all(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        match fs::remove_file(&marker) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if let Err(error) = fs::remove_dir(&self.workdir) {
            // Something wrote into the directory while it was being emptied.
            // Put the marker back, so what is left is still a removal to the
            // next reload rather than a VM that fails to load.
            if self.workdir.exists() {
                let _ = self.set_removing();
            }
            return Err(error.into());
        }
        Ok(())
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
        assert_eq!(persisted[0].nic.parent, "br0");
        assert!(persisted[0].device.is_empty());
        assert!(!fs::read_to_string(workdir.runtime_networks_path())?.contains("/dev/tap42"));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    /// `.removing` goes last, so an interrupted deletion is still a removal.
    #[test]
    fn remove_all_deletes_everything_and_tolerates_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let workdir = VmWorkDir::new(dir.path().join("vm"));
        std::fs::create_dir_all(workdir.path().join("shared")).unwrap();
        std::fs::write(workdir.path().join("shared/file"), b"x").unwrap();
        workdir.mark_network_cleanup_pending().unwrap();
        workdir.set_removing().unwrap();
        workdir.remove_all().unwrap();
        assert!(!workdir.path().exists());
        workdir.remove_all().unwrap();
    }
}

#[cfg(test)]
mod env_tests {
    use super::*;

    #[test]
    fn env_updates_replace_the_other_format_and_reject_ambiguity() {
        let dir = tempfile::tempdir().unwrap();
        let workdir = VmWorkDir::new(dir.path());
        fs::create_dir_all(workdir.shared_dir()).unwrap();
        workdir.write_env(b"legacy", &[]).unwrap();
        workdir.write_env(&[], b"sealed").unwrap();
        assert!(!workdir.encrypted_env_path().exists());
        assert_eq!(fs::read(workdir.sealed_env_path()).unwrap(), b"sealed");
        assert!(workdir.write_env(b"ambiguous", b"ambiguous").is_err());
        assert_eq!(fs::read(workdir.sealed_env_path()).unwrap(), b"sealed");
        workdir.write_env(&[], &[]).unwrap();
        assert_eq!(fs::read(workdir.sealed_env_path()).unwrap(), b"sealed");
        workdir.write_env(b"owner", &[]).unwrap();
        assert!(!workdir.sealed_env_path().exists());
        assert_eq!(fs::read(workdir.encrypted_env_path()).unwrap(), b"owner");
    }

    #[test]
    #[ignore = "finding CR3: expected to fail until CR3 is fixed"]
    fn finding_cr3_interrupted_legacy_replacement_keeps_the_owner_env_selected() {
        let dir = tempfile::tempdir().unwrap();
        let workdir = VmWorkDir::new(dir.path());
        fs::create_dir_all(workdir.shared_dir()).unwrap();
        workdir.write_env(&[], b"replaced sealed env").unwrap();
        // `write_env(b"owner legacy env", &[])` interrupted after publishing
        // the new file and before removing the one it supersedes.
        safe_write::safe_write(workdir.encrypted_env_path(), b"owner legacy env").unwrap();
        // With no new upload, the env the VM boots with is the stored one,
        // selected the way the guest selects it.
        assert!(!workdir.uses_sealed_env(&[], &[]).unwrap());
    }

    #[test]
    fn env_write_failure_preserves_original_and_cleanup_errors_propagate() {
        let dir = tempfile::tempdir().unwrap();
        let workdir = VmWorkDir::new(dir.path());
        fs::create_dir_all(workdir.shared_dir()).unwrap();
        workdir.write_env(b"original", &[]).unwrap();
        fs::create_dir(workdir.sealed_env_path()).unwrap();
        assert!(workdir.write_env(&[], b"replacement").is_err());
        assert_eq!(fs::read(workdir.encrypted_env_path()).unwrap(), b"original");
        assert!(workdir.write_env(b"updated", &[]).is_err());
        assert_eq!(fs::read(workdir.encrypted_env_path()).unwrap(), b"updated");
    }
}
