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

use crate::app::Manifest;

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
        let manifest = fs::read_to_string(manifest_path).context("failed to read manifest")?;
        let manifest: Manifest =
            serde_json::from_str(&manifest).context("failed to parse manifest")?;
        Ok(manifest)
    }

    pub fn put_manifest(&self, manifest: &Manifest) -> Result<()> {
        fs::create_dir_all(&self.workdir).context("failed to create workdir")?;
        let manifest_path = self.manifest_path();
        fs::write(manifest_path, serde_json::to_string(manifest)?)
            .context("failed to write manifest")
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

    pub fn guest_ip_path(&self) -> PathBuf {
        self.workdir.join("guest-ip")
    }

    pub fn guest_ip(&self) -> Option<String> {
        fs::read_to_string(self.guest_ip_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    pub fn set_guest_ip(&self, ip: &str) -> Result<()> {
        fs::write(self.guest_ip_path(), ip).context("failed to write guest IP")
    }

    pub fn serial_file(&self) -> PathBuf {
        self.workdir.join("serial.log")
    }

    pub fn serial_history_file(&self) -> PathBuf {
        self.workdir.join("serial.history.log")
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
