// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::{Config, Networking, ProcessAnnotation, Protocol};
use dstack_port_forward::{ForwardRule, ForwardService, Protocol as FwdProtocol};

use anyhow::{bail, Context, Result};
use bon::Builder;
use dstack_kms_rpc::kms_client::KmsClient;
use dstack_types::mr_config::MrConfigV3;
use dstack_types::shared_filenames::{
    APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, SYS_CONFIG, USER_CONFIG,
};
use dstack_vmm_rpc::{
    self as pb, GpuInfo, ReloadVmsResponse, StatusRequest, StatusResponse, VmConfiguration,
};
use fs_err as fs;
use guest_api::client::DefaultClient as GuestClient;
use id_pool::IdPool;
use or_panic::ResultOrPanic;
use ra_rpc::client::RaClient;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;
use supervisor_client::SupervisorClient;
use tracing::{debug, error, info, warn};

pub use image::{Image, ImageInfo};
pub use qemu::{VmConfig, VmWorkDir};

mod id_pool;
mod image;
mod qemu;
pub(crate) mod registry;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PortMapping {
    pub address: IpAddr,
    pub protocol: Protocol,
    pub from: u16,
    pub to: u16,
}

#[derive(Deserialize, Serialize, Clone, Builder, Debug)]
pub struct Manifest {
    pub id: String,
    pub name: String,
    pub app_id: String,
    pub vcpu: u32,
    pub memory: u32,
    pub disk_size: u32,
    pub image: String,
    pub port_map: Vec<PortMapping>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub pin_numa: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus: Option<GpuConfig>,
    #[serde(default)]
    pub kms_urls: Vec<String>,
    #[serde(default)]
    pub gateway_urls: Vec<String>,
    #[serde(default)]
    pub no_tee: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<Networking>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AttachMode {
    All,
    #[default]
    Listed,
}

impl std::fmt::Display for AttachMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttachMode::All => write!(f, "all"),
            AttachMode::Listed => write!(f, "listed"),
        }
    }
}

impl AttachMode {
    pub fn is_all(&self) -> bool {
        matches!(self, AttachMode::All)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GpuConfig {
    pub attach_mode: AttachMode,
    #[serde(default)]
    pub gpus: Vec<GpuSpec>,
    #[serde(default)]
    pub bridges: Vec<GpuSpec>,
}

impl GpuConfig {
    pub fn is_empty(&self) -> bool {
        if self.attach_mode.is_all() {
            return false;
        }
        self.gpus.is_empty() && self.bridges.is_empty()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GpuSpec {
    #[serde(default)]
    pub slot: String,
}

#[derive(Clone, Debug)]
pub(crate) enum PullStatus {
    Pulling,
    Failed(String),
}

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub supervisor: SupervisorClient,
    state: Arc<Mutex<AppState>>,
    forward_service: Arc<tokio::sync::Mutex<ForwardService>>,
    /// Pull status for registry images: tag → status.
    pub(crate) pull_status: Arc<Mutex<std::collections::HashMap<String, PullStatus>>>,
}

impl App {
    pub(crate) fn lock(&self) -> MutexGuard<'_, AppState> {
        self.state.lock().or_panic("mutex poisoned")
    }

    pub(crate) fn vm_dir(&self) -> PathBuf {
        self.config.run_path.clone()
    }

    pub(crate) fn work_dir(&self, id: &str) -> VmWorkDir {
        VmWorkDir::new(self.config.run_path.join(id))
    }

    pub fn new(config: Config, supervisor: SupervisorClient) -> Self {
        let cid_start = config.cvm.cid_start;
        let cid_end = cid_start.saturating_add(config.cvm.cid_pool_size);
        let cid_pool = IdPool::new(cid_start, cid_end);
        Self {
            supervisor: supervisor.clone(),
            state: Arc::new(Mutex::new(AppState {
                cid_pool,
                vms: HashMap::new(),
                active_forwards: HashMap::new(),
            })),
            config: Arc::new(config),
            forward_service: Arc::new(tokio::sync::Mutex::new(ForwardService::new())),
            pull_status: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub async fn load_vm(
        &self,
        work_dir: impl AsRef<Path>,
        cids_assigned: &HashMap<String, u32>,
        auto_start: bool,
    ) -> Result<()> {
        let vm_work_dir = VmWorkDir::new(work_dir.as_ref());
        let manifest = vm_work_dir.manifest().context("Failed to read manifest")?;
        if manifest.image.len() > 64
            || manifest.image.contains("..")
            || !manifest
                .image
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            bail!("Invalid image name");
        }
        let image_path = self.config.image.path.join(&manifest.image);
        let image = Image::load(&image_path).context("Failed to load image")?;
        let vm_id = manifest.id.clone();
        let app_compose = vm_work_dir
            .app_compose()
            .context("Failed to read compose file")?;
        {
            let mut states = self.lock();
            let cid = states
                .get(&vm_id)
                .map(|vm| vm.config.cid)
                .or_else(|| cids_assigned.get(&vm_id).cloned())
                .or_else(|| states.cid_pool.allocate())
                .context("CID pool exhausted")?;
            let vm_config = VmConfig {
                manifest,
                image,
                cid,
                workdir: vm_work_dir.path().to_path_buf(),
                gateway_enabled: app_compose.gateway_enabled(),
            };
            match states.get_mut(&vm_id) {
                Some(vm) => {
                    vm.config = vm_config.into();
                }
                None => {
                    states.add(VmState::new(vm_config));
                }
            }
        };
        if auto_start && vm_work_dir.started().unwrap_or_default() {
            self.start_vm(&vm_id).await?;
        }
        Ok(())
    }

    pub async fn start_vm(&self, id: &str) -> Result<()> {
        {
            let state = self.lock();
            if let Some(vm) = state.get(id) {
                if vm.state.removing {
                    bail!("VM is being removed");
                }
            }
        }
        self.sync_dynamic_config(id)?;
        let is_running = self
            .supervisor
            .info(id)
            .await?
            .is_some_and(|info| info.state.status.is_running());
        self.set_started(id, true)?;
        let vm_config = {
            let mut state = self.lock();
            let vm_state = state.get_mut(id).context("VM not found")?;
            // Older images does not support for progress reporting
            if vm_state.config.image.info.shared_ro {
                vm_state.state.start(is_running);
            } else {
                vm_state.state.reset_na();
            }
            vm_state.config.clone()
        };
        if !is_running {
            let work_dir = self.work_dir(id);
            for path in [work_dir.serial_pty(), work_dir.qmp_socket()] {
                if path.symlink_metadata().is_ok() {
                    fs::remove_file(path)?;
                }
            }
            // Append current serial.log to serial.history.log before QEMU truncates it.
            rotate_serial_log(&work_dir, self.config.cvm.serial_history_max_bytes);
            // Add boot separator to stdout/stderr (they are opened in append mode).
            append_boot_separator(&work_dir.stdout_file());
            append_boot_separator(&work_dir.stderr_file());

            let devices = self.try_allocate_gpus(&vm_config.manifest)?;
            let processes = vm_config.config_qemu(&work_dir, &self.config.cvm, &devices)?;
            for process in processes {
                self.supervisor
                    .deploy(&process)
                    .await
                    .with_context(|| format!("Failed to start process {}", process.id))?;
            }

            let mut state = self.lock();
            let vm_state = state.get_mut(id).context("VM not found")?;
            vm_state.state.devices = devices;
        }
        Ok(())
    }

    fn set_started(&self, id: &str, started: bool) -> Result<()> {
        let work_dir = self.work_dir(id);
        work_dir
            .set_started(started)
            .context("Failed to set started")
    }

    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        self.set_started(id, false)?;
        self.cleanup_port_forward(id).await;
        self.supervisor.stop(id).await?;
        Ok(())
    }

    pub async fn remove_vm(&self, id: &str) -> Result<()> {
        {
            let mut state = self.lock();
            let vm = state.get_mut(id).context("VM not found")?;
            if vm.state.removing {
                // Already being removed — idempotent
                return Ok(());
            }
            vm.state.removing = true;
        }

        // Persist the removing marker so crash recovery can resume
        let work_dir = self.work_dir(id);
        if let Err(err) = work_dir.set_removing() {
            warn!("failed to write .removing marker for {id}: {err:?}");
        }

        // Clean up port forwarding immediately
        self.cleanup_port_forward(id).await;

        // User-initiated removal always deletes the workdir
        let app = self.clone();
        let id = id.to_string();
        tokio::spawn(async move {
            if let Err(err) = app.finish_remove_vm(&id, true).await {
                error!("Background cleanup failed for {id}: {err:?}");
            }
        });

        Ok(())
    }

    /// Background cleanup: stop supervisor process, wait for it to exit,
    /// remove from supervisor, optionally delete workdir, and free CID.
    ///
    /// `delete_workdir`: true for user-initiated removal, false for orphan cleanup.
    async fn finish_remove_vm(&self, id: &str, delete_workdir: bool) -> Result<()> {
        // Stop the supervisor process (idempotent if already stopped)
        if let Err(err) = self.supervisor.stop(id).await {
            debug!("supervisor.stop({id}) during removal: {err:?}");
        }

        // Poll until the process is no longer running, then remove it.
        // Some VMs take a long time to stop (e.g. 2+ hours), so we wait indefinitely.
        let mut poll_count: u64 = 0;
        loop {
            match self.supervisor.info(id).await {
                Ok(Some(info)) if info.state.status.is_running() => {
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    poll_count += 1;
                    if poll_count.is_multiple_of(30) {
                        info!(
                            "VM {id} still running after {}m during removal, waiting...",
                            poll_count * 2 / 60
                        );
                    }
                }
                Ok(Some(_)) => {
                    // Not running — remove from supervisor
                    if let Err(err) = self.supervisor.remove(id).await {
                        warn!("supervisor.remove({id}) failed: {err:?}");
                    }
                    break;
                }
                Ok(None) => {
                    // Already gone from supervisor
                    break;
                }
                Err(err) => {
                    warn!("supervisor.info({id}) failed during removal: {err:?}");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        }

        // Only delete the workdir for user-initiated removal or if .removing marker exists.
        // Orphaned supervisor processes without the marker keep their data intact.
        let vm_path = self.work_dir(id);
        if delete_workdir || vm_path.is_removing() {
            if vm_path.path().exists() {
                if let Err(err) = fs::remove_dir_all(&vm_path) {
                    error!("failed to remove VM directory for {id}: {err:?}");
                }
            }
        } else if vm_path.path().exists() {
            info!(
                "VM {id} workdir preserved (orphan cleanup): {}",
                vm_path.path().display()
            );
        }

        // Free CID and remove from memory (last step)
        {
            let mut state = self.lock();
            if let Some(vm_state) = state.remove(id) {
                state.cid_pool.free(vm_state.config.cid);
            }
        }

        info!("VM {id} removed successfully");
        Ok(())
    }

    /// Spawn a background task to clean up a VM (stop + remove from supervisor).
    /// Workdir deletion is based on the `.removing` marker (only present for user-initiated removal).
    /// Returns false if a cleanup task is already running for this VM.
    fn spawn_finish_remove(&self, id: &str) -> bool {
        {
            let mut state = self.lock();
            if let Some(vm) = state.get_mut(id) {
                if vm.state.removing {
                    // Already being cleaned up — skip
                    return false;
                }
                vm.state.removing = true;
            }
            // If VM is not in memory (e.g. orphaned supervisor process), no entry to guard
            // but we still need to clean up the supervisor process.
        }
        let app = self.clone();
        let id = id.to_string();
        tokio::spawn(async move {
            // Don't pass delete_workdir=true; rely on .removing marker check inside
            if let Err(err) = app.finish_remove_vm(&id, false).await {
                error!("Background cleanup failed for {id}: {err:?}");
            }
        });
        true
    }

    /// Handle a DHCP lease notification: look up VM by MAC address, persist
    /// the guest IP, and reconfigure port forwarding.
    pub async fn report_dhcp_lease(&self, mac: &str, ip: &str) {
        use crate::app::qemu::mac_address_for_vm;

        let vm_id = {
            let mut state = self.lock();
            let prefix = self.config.cvm.networking.mac_prefix_bytes();
            let found = state
                .vms
                .iter_mut()
                .find(|(id, _)| mac_address_for_vm(id, &prefix) == mac);
            let Some((id, vm)) = found else {
                debug!(mac, ip, "DHCP lease for unknown MAC, ignoring");
                return;
            };
            let vm_id = id.clone();
            let workdir = VmWorkDir::new(vm.config.workdir.clone());
            if let Err(e) = workdir.set_guest_ip(ip) {
                error!(mac, ip, "failed to persist guest IP: {e}");
            }
            vm.state.guest_ip = ip.to_string();
            info!(mac, ip, id = %vm_id, "DHCP lease updated");
            vm_id
        };
        self.reconfigure_port_forward(&vm_id).await;
    }

    /// Reconfigure port forwarding for a bridge-mode VM.
    ///
    /// Computes desired rules from the VM's port_map and guest_ip, then diffs
    /// against currently active rules. Only changed rules are added/removed so
    /// existing connections on unchanged rules are not interrupted.
    pub async fn reconfigure_port_forward(&self, id: &str) {
        let info = {
            let state = self.lock();
            let Some(vm) = state.get(id) else {
                return;
            };
            let networking = vm
                .config
                .manifest
                .networking
                .as_ref()
                .unwrap_or(&self.config.cvm.networking);
            if !networking.is_bridge() || !networking.forward_service_enabled {
                return;
            }
            let guest_ip = vm.state.guest_ip.clone();
            let port_map = vm.config.manifest.port_map.clone();
            (guest_ip, port_map)
        };

        let (guest_ip_str, port_map) = info;
        if guest_ip_str.is_empty() {
            return;
        }
        let Ok(guest_ip) = guest_ip_str.parse::<IpAddr>() else {
            warn!(id, ip = %guest_ip_str, "invalid guest IP, skipping port forward");
            return;
        };

        let new_rules: Vec<ForwardRule> = port_map
            .iter()
            .map(|pm| ForwardRule {
                protocol: match pm.protocol {
                    Protocol::Tcp => FwdProtocol::Tcp,
                    Protocol::Udp => FwdProtocol::Udp,
                },
                listen_addr: pm.address,
                listen_port: pm.from,
                target_ip: guest_ip,
                target_port: pm.to,
            })
            .collect();

        let old_rules = self
            .lock()
            .active_forwards
            .get(id)
            .cloned()
            .unwrap_or_default();

        let old_set: HashSet<_> = old_rules.iter().collect();
        let new_set: HashSet<_> = new_rules.iter().collect();

        let mut fwd = self.forward_service.lock().await;

        // Remove rules no longer needed
        for rule in old_rules.iter().filter(|r| !new_set.contains(r)) {
            if let Err(e) = fwd.remove_rule(rule).await {
                warn!(id, ?rule, "failed to remove forwarding rule: {e}");
            }
        }

        // Add new rules
        for rule in new_rules.iter().filter(|r| !old_set.contains(r)) {
            if let Err(e) = fwd.add_rule(rule.clone()) {
                warn!(id, ?rule, "failed to add forwarding rule: {e}");
            }
        }

        drop(fwd);
        self.lock()
            .active_forwards
            .insert(id.to_string(), new_rules);
        info!(id, "port forwarding reconfigured");
    }

    /// Remove all port forwarding rules for a VM.
    pub async fn cleanup_port_forward(&self, id: &str) {
        let old_rules = self.lock().active_forwards.remove(id).unwrap_or_default();
        if old_rules.is_empty() {
            return;
        }
        let mut fwd = self.forward_service.lock().await;
        for rule in &old_rules {
            if let Err(e) = fwd.remove_rule(rule).await {
                warn!(id, ?rule, "failed to remove forwarding rule: {e}");
            }
        }
        info!(id, count = old_rules.len(), "port forwarding cleaned up");
    }

    pub async fn reload_vms(&self) -> Result<()> {
        let vm_path = self.vm_dir();
        let running_vms = self.supervisor.list().await.context("Failed to list VMs")?;
        let running_vms: Vec<(ProcessAnnotation, _)> = running_vms
            .into_iter()
            .map(|p| (serde_json::from_str(&p.config.note).unwrap_or_default(), p))
            .collect();
        let occupied_cids = running_vms
            .iter()
            .filter(|(note, _)| note.is_cvm())
            .flat_map(|(_, p)| p.config.cid.map(|cid| (p.config.id.clone(), cid)))
            .collect::<HashMap<_, _>>();
        {
            let mut state = self.lock();
            for cid in occupied_cids.values() {
                state.cid_pool.occupy(*cid)?;
            }
        }

        // Track VMs with .removing marker — load them but resume cleanup
        let mut removing_ids = Vec::new();

        if vm_path.exists() {
            for entry in fs::read_dir(&vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_path = entry.path();
                if vm_path.is_dir() {
                    let workdir = VmWorkDir::new(&vm_path);
                    let is_removing = workdir.is_removing();
                    // Load all VMs into memory (including removing ones, so they show in UI)
                    if let Err(err) = self.load_vm(&vm_path, &occupied_cids, !is_removing).await {
                        error!("Failed to load VM: {err:?}");
                    }
                    if is_removing {
                        if let Some(id) = vm_path.file_name().and_then(|n| n.to_str()) {
                            info!("Found VM {id} with .removing marker, resuming cleanup");
                            removing_ids.push(id.to_string());
                        }
                    }
                }
            }
        }

        // Resume cleanup for VMs with .removing marker
        for id in removing_ids {
            self.spawn_finish_remove(&id);
        }

        // Clean up orphaned supervisor processes (in supervisor but not loaded as VMs)
        let loaded_vm_ids: HashSet<String> = self.lock().vms.keys().cloned().collect();
        for (_, process) in &running_vms {
            if !loaded_vm_ids.contains(&process.config.id) {
                info!(
                    "Cleaning up orphaned supervisor process: {}",
                    process.config.id
                );
                self.spawn_finish_remove(&process.config.id);
            }
        }

        // Restore port forwarding for running bridge-mode VMs with persisted guest IPs
        let vm_ids: Vec<String> = self.lock().vms.keys().cloned().collect();
        for id in vm_ids {
            let workdir = self.work_dir(&id);
            if let Some(ip) = workdir.guest_ip() {
                {
                    let mut state = self.lock();
                    if let Some(vm) = state.get_mut(&id) {
                        vm.state.guest_ip = ip;
                    }
                }
                self.reconfigure_port_forward(&id).await;
            }
        }

        Ok(())
    }

    /// Reload VMs directory and sync with memory state while preserving statistics
    pub async fn reload_vms_sync(&self) -> Result<ReloadVmsResponse> {
        let vm_path = self.vm_dir();
        let mut loaded = 0u32;
        let mut updated = 0u32;
        let mut removed = 0u32;

        // Get running VMs to preserve CIDs and process info
        let running_vms = self.supervisor.list().await.context("Failed to list VMs")?;
        let running_vms_map: HashMap<String, _> = running_vms
            .into_iter()
            .map(|p| (p.config.id.clone(), p))
            .collect();
        let occupied_cids = running_vms_map
            .iter()
            .filter(|(_, p)| {
                serde_json::from_str::<ProcessAnnotation>(&p.config.note)
                    .unwrap_or_default()
                    .is_cvm()
            })
            .flat_map(|(id, p)| p.config.cid.map(|cid| (id.clone(), cid)))
            .collect::<HashMap<_, _>>();

        // Update CID pool with running VMs
        {
            let mut state = self.lock();
            // First clear the pool and re-occupy running VM CIDs
            state.cid_pool.clear();
            for cid in occupied_cids.values() {
                state.cid_pool.occupy(*cid)?;
            }
        }

        // Get VM IDs from filesystem
        let mut fs_vm_ids = HashSet::new();
        if vm_path.exists() {
            for entry in fs::read_dir(&vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_dir_path = entry.path();
                if vm_dir_path.is_dir() {
                    // Try to get VM ID from directory name or manifest
                    if let Some(vm_id) = vm_dir_path.file_name().and_then(|n| n.to_str()) {
                        fs_vm_ids.insert(vm_id.to_string());
                    }
                }
            }
        }

        // Get VM IDs currently in memory and their CIDs
        let (memory_vm_ids, existing_cids): (HashSet<String>, HashSet<u32>) = {
            let state = self.lock();
            (
                state.vms.keys().cloned().collect(),
                state.vms.values().map(|vm| vm.config.cid).collect(),
            )
        };

        // Remove VMs that no longer exist in filesystem
        let to_remove: Vec<String> = memory_vm_ids.difference(&fs_vm_ids).cloned().collect();
        for vm_id in &to_remove {
            if self.spawn_finish_remove(vm_id) {
                removed += 1;
                info!("VM {vm_id} scheduled for removal (directory no longer exists)");
            }
        }

        // Load or update VMs from filesystem
        let mut removing_ids = Vec::new();
        if vm_path.exists() {
            for entry in fs::read_dir(vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_path = entry.path();
                if vm_path.is_dir() {
                    let workdir = VmWorkDir::new(&vm_path);
                    let is_removing = workdir.is_removing();
                    // Load all VMs (including removing ones, so they show in UI)
                    match self
                        .load_or_update_vm(&vm_path, &occupied_cids, !is_removing)
                        .await
                    {
                        Ok(is_new) => {
                            if is_new {
                                loaded += 1;
                            } else {
                                updated += 1;
                            }
                        }
                        Err(err) => {
                            error!("Failed to load or update VM: {err:?}");
                        }
                    }
                    if is_removing {
                        if let Some(id) = vm_path.file_name().and_then(|n| n.to_str()) {
                            removing_ids.push(id.to_string());
                        }
                    }
                }
            }
        }
        for id in &removing_ids {
            if self.spawn_finish_remove(id) {
                info!("Resuming cleanup for VM {id} (.removing marker)");
            }
        }

        // Clean up any orphaned CIDs that aren't being used
        {
            let mut state = self.lock();
            let used_cids: HashSet<u32> = state.vms.values().map(|vm| vm.config.cid).collect();
            let orphaned_cids: Vec<u32> = existing_cids.difference(&used_cids).cloned().collect();
            for cid in orphaned_cids {
                state.cid_pool.free(cid);
                info!("Released orphaned CID {cid}");
            }
        }

        Ok(ReloadVmsResponse {
            loaded,
            updated,
            removed,
        })
    }

    /// Load or update a VM, preserving existing statistics
    async fn load_or_update_vm(
        &self,
        work_dir: impl AsRef<Path>,
        cids_assigned: &HashMap<String, u32>,
        auto_start: bool,
    ) -> Result<bool> {
        let vm_work_dir = VmWorkDir::new(work_dir.as_ref());
        let manifest = vm_work_dir.manifest().context("Failed to read manifest")?;
        if manifest.image.len() > 64
            || manifest.image.contains("..")
            || !manifest
                .image
                .chars()
                .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            bail!("Invalid image name");
        }
        let image_path = self.config.image.path.join(&manifest.image);
        let image = Image::load(&image_path).context("Failed to load image")?;
        let vm_id = manifest.id.clone();
        let already_running = cids_assigned.contains_key(&vm_id);
        let app_compose = vm_work_dir
            .app_compose()
            .context("Failed to read compose file")?;

        let mut is_new = false;
        {
            let mut states = self.lock();

            // For existing VMs, keep their current CID
            // For new VMs, try to use assigned CID or allocate a new one
            let cid = if let Some(existing_vm) = states.get(&vm_id) {
                // Keep existing CID
                existing_vm.config.cid
            } else if let Some(assigned_cid) = cids_assigned.get(&vm_id) {
                // Use assigned CID from running processes
                *assigned_cid
            } else {
                // Allocate new CID only for truly new VMs
                states.cid_pool.allocate().context("CID pool exhausted")?
            };

            let vm_config = VmConfig {
                manifest,
                image,
                cid,
                workdir: vm_work_dir.path().to_path_buf(),
                gateway_enabled: app_compose.gateway_enabled(),
            };

            match states.get_mut(&vm_id) {
                Some(vm) => {
                    // Update existing VM but preserve statistics and CID
                    let old_state = vm.state.clone();
                    vm.config = vm_config.into();
                    vm.state = old_state; // Preserve the existing state with statistics
                }
                None => {
                    // This is a new VM, need to occupy its CID if it wasn't allocated
                    if !cids_assigned.contains_key(&vm_id) {
                        states.cid_pool.occupy(cid)?;
                    }
                    states.add(VmState::new(vm_config));
                    is_new = true;
                }
            }
        };

        if auto_start && vm_work_dir.started().unwrap_or_default() {
            if already_running {
                info!("Skipping, {vm_id} is already running");
            } else {
                self.start_vm(&vm_id).await?;
            }
        }

        Ok(is_new)
    }

    pub async fn list_vms(&self, request: StatusRequest) -> Result<StatusResponse> {
        let vms = self
            .supervisor
            .list()
            .await
            .context("Failed to list VMs")?
            .into_iter()
            .map(|p| (p.config.id.clone(), p))
            .collect::<HashMap<_, _>>();

        let mut infos = self
            .lock()
            .iter_vms()
            .filter(|vm| {
                if !request.ids.is_empty() && !request.ids.contains(&vm.config.manifest.id) {
                    return false;
                }
                if request.keyword.is_empty() {
                    true
                } else {
                    vm.config.manifest.name.contains(&request.keyword)
                        || vm.config.manifest.id.contains(&request.keyword)
                        || vm.config.manifest.app_id.contains(&request.keyword)
                        || vm.config.manifest.image.contains(&request.keyword)
                }
            })
            .cloned()
            .collect::<Vec<_>>();
        infos.sort_by(|a, b| {
            a.config
                .manifest
                .created_at_ms
                .cmp(&b.config.manifest.created_at_ms)
        });

        let total = infos.len() as u32;
        let vms = paginate(infos, request.page, request.page_size)
            .map(|vm| {
                vm.merged_info(
                    vms.get(&vm.config.manifest.id),
                    &self.work_dir(&vm.config.manifest.id),
                )
            })
            .map(|info| info.to_pb(&self.config.gateway, request.brief))
            .collect::<Vec<_>>();
        Ok(StatusResponse {
            vms,
            port_mapping_enabled: self.config.cvm.port_mapping.enabled,
            total,
        })
    }

    pub fn list_images(&self) -> Result<Vec<(String, ImageInfo)>> {
        let image_path = self.config.image.path.clone();
        let images = fs::read_dir(image_path).context("Failed to read image directory")?;
        Ok(images
            .flat_map(|entry| {
                let path = entry.ok()?.path();
                let img = Image::load(&path).ok()?;
                Some((path.file_name()?.to_string_lossy().to_string(), img.info))
            })
            .collect())
    }

    pub async fn vm_info(&self, id: &str) -> Result<Option<pb::VmInfo>> {
        let proc_state = self.supervisor.info(id).await?;
        let state = self.lock();
        let Some(vm_state) = state.get(id) else {
            return Ok(None);
        };
        let info = vm_state
            .merged_info(proc_state.as_ref(), &self.work_dir(id))
            .to_pb(&self.config.gateway, false);
        Ok(Some(info))
    }

    pub(crate) fn vm_event_report(&self, cid: u32, event: &str, body: String) -> Result<()> {
        info!(cid, event, "VM event");
        if body.len() > 1024 * 4 {
            error!("Event body too large, skipping");
            return Ok(());
        }
        let mut state = self.lock();
        let Some(vm) = state.vms.values_mut().find(|vm| vm.config.cid == cid) else {
            bail!("VM not found");
        };
        vm.state.events.push_back(pb::GuestEvent {
            event: event.into(),
            body: body.clone(),
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        });
        while vm.state.events.len() > self.config.event_buffer_size {
            vm.state.events.pop_front();
        }
        match event {
            "boot.progress" => {
                vm.state.boot_progress = body;
            }
            "boot.error" => {
                vm.state.boot_error = body;
            }
            "shutdown.progress" => {
                if body == "powering off" {
                    self.set_started(&vm.config.manifest.id, false)?;
                }
                vm.state.shutdown_progress = body;
            }
            "instance.info" => {
                let workdir = VmWorkDir::new(vm.config.workdir.clone());
                let instancd_info_path = workdir.instance_info_path();
                safe_write::safe_write(&instancd_info_path, &body)?;
            }
            _ => {
                error!("Guest reported unknown event: {event}");
            }
        }
        Ok(())
    }

    pub(crate) fn compose_file_path(&self, id: &str) -> PathBuf {
        self.shared_dir(id).join(APP_COMPOSE)
    }

    pub(crate) fn encrypted_env_path(&self, id: &str) -> PathBuf {
        self.shared_dir(id).join(ENCRYPTED_ENV)
    }

    pub(crate) fn user_config_path(&self, id: &str) -> PathBuf {
        self.shared_dir(id).join(USER_CONFIG)
    }

    pub(crate) fn shared_dir(&self, id: &str) -> PathBuf {
        self.config.run_path.join(id).join("shared")
    }

    pub(crate) fn prepare_work_dir(
        &self,
        id: &str,
        req: &VmConfiguration,
        app_id: &str,
    ) -> Result<VmWorkDir> {
        let work_dir = self.work_dir(id);
        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(shared_dir.join(APP_COMPOSE), &req.compose_file)
            .context("Failed to write compose file")?;
        if !req.encrypted_env.is_empty() {
            fs::write(shared_dir.join(ENCRYPTED_ENV), &req.encrypted_env)
                .context("Failed to write encrypted env")?;
        }
        if !req.user_config.is_empty() {
            fs::write(shared_dir.join(USER_CONFIG), &req.user_config)
                .context("Failed to write user config")?;
        }
        if !app_id.is_empty() {
            let instance_info = json!({
                "app_id": app_id,
            });
            fs::write(
                shared_dir.join(INSTANCE_INFO),
                serde_json::to_string(&instance_info)?,
            )
            .context("Failed to write vm config")?;
        }
        Ok(work_dir)
    }

    pub(crate) fn sync_dynamic_config(&self, id: &str) -> Result<()> {
        let work_dir = self.work_dir(id);
        let shared_dir = self.shared_dir(id);
        let manifest = work_dir.manifest().context("Failed to read manifest")?;
        let cfg = &self.config;
        let compose_hash = sha256_file(shared_dir.join(APP_COMPOSE))?;
        let platform = cfg.cvm.platform.resolve();
        let app_compose = work_dir
            .app_compose()
            .context("Failed to get app compose")?;
        let use_mr_config_v3 = !manifest.no_tee
            && (platform == crate::config::TeePlatform::AmdSevSnp
                || (platform == crate::config::TeePlatform::Tdx
                    && cfg.cvm.use_mrconfigid
                    && !app_compose.key_provider_id.is_empty()));
        let mr_config = if use_mr_config_v3 {
            Some(
                work_dir
                    .prepare_mr_config_v3(&app_compose)
                    .context("Failed to prepare mr_config")?,
            )
        } else {
            None
        };
        let sys_config_str =
            make_sys_config(cfg, &manifest, &hex::encode(compose_hash), mr_config)?;
        fs::write(shared_dir.join(SYS_CONFIG), sys_config_str)
            .context("Failed to write vm config")?;
        Ok(())
    }

    pub(crate) fn kms_client(&self) -> Result<KmsClient<RaClient>> {
        if self.config.kms_url.is_empty() {
            bail!("KMS is not configured");
        }
        let url = format!("{}/prpc", self.config.kms_url);
        let prpc_client = RaClient::new(url, true)?;
        Ok(KmsClient::new(prpc_client))
    }

    pub(crate) fn guest_agent_client(&self, id: &str) -> Result<GuestClient> {
        let cid = self.lock().get(id).context("vm not found")?.config.cid;
        Ok(guest_api::client::new_client(format!(
            "vsock://{cid}:8000/api"
        )))
    }

    fn try_allocate_gpus(&self, manifest: &Manifest) -> Result<GpuConfig> {
        if !self.config.cvm.gpu.enabled {
            return Ok(GpuConfig::default());
        }
        Ok(manifest.gpus.clone().unwrap_or_default())
    }

    pub(crate) async fn list_gpus(&self) -> Result<Vec<GpuInfo>> {
        if !self.config.cvm.gpu.enabled {
            return Ok(Vec::new());
        }
        let gpus = self
            .config
            .cvm
            .gpu
            .list_devices()?
            .iter()
            .map(|dev| GpuInfo {
                slot: dev.slot.clone(),
                product_id: dev.full_product_id().clone(),
                description: dev.description.clone(),
                is_free: !dev.in_use(),
            })
            .collect();
        Ok(gpus)
    }

    pub(crate) async fn try_restart_exited_vms(&self) -> Result<()> {
        let running_vms = self
            .supervisor
            .list()
            .await
            .context("Failed to list VMs")?
            .iter()
            .filter(|v| v.state.status.is_running())
            .map(|v| v.config.id.clone())
            .collect::<BTreeSet<_>>();
        let exited_vms = self
            .lock()
            .iter_vms()
            .filter(|vm| {
                if vm.state.removing {
                    return false;
                }
                let workdir = self.work_dir(&vm.config.manifest.id);
                let started = workdir.started().unwrap_or(false);
                started && !running_vms.contains(&vm.config.manifest.id)
            })
            .map(|vm| vm.config.manifest.id.clone())
            .collect::<Vec<_>>();
        for id in exited_vms {
            info!("Restarting VM {id}");
            self.start_vm(&id).await?;
        }
        Ok(())
    }
}

/// Append a boot separator line with timestamp to an append-mode log file.
fn append_boot_separator(path: &std::path::Path) {
    use std::io::Write;
    if !path.exists() {
        return;
    }
    let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) else {
        return;
    };
    let timestamp = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    let _ = writeln!(file, "\n===== boot @ {timestamp} =====\n");
}

/// Append current serial.log into serial.history.log with a boot separator,
/// then truncate history if it exceeds `max_bytes`.
fn rotate_serial_log(work_dir: &VmWorkDir, max_bytes: u64) {
    use std::io::Write;

    let serial = work_dir.serial_file();
    if !serial.exists() {
        return;
    }
    let Ok(content) = fs::read(&serial) else {
        return;
    };
    if content.is_empty() {
        return;
    }
    let history = work_dir.serial_history_file();
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&history)
    else {
        return;
    };
    let timestamp = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    let _ = writeln!(file, "\n===== boot @ {timestamp} =====\n");
    let _ = file.write_all(&content);
    drop(file);

    // Truncate from the front if history exceeds max_bytes.
    if let Ok(meta) = fs::metadata(&history) {
        if meta.len() > max_bytes {
            if let Ok(data) = fs::read(&history) {
                let skip = data.len() - max_bytes as usize;
                // Find the next newline after skip point to avoid cutting mid-line.
                let start = data[skip..]
                    .iter()
                    .position(|&b| b == b'\n')
                    .map(|p| skip + p + 1)
                    .unwrap_or(skip);
                let _ = fs::write(&history, &data[start..]);
            }
        }
    }
}

pub(crate) fn make_sys_config(
    cfg: &Config,
    manifest: &Manifest,
    compose_hash: &str,
    mr_config: Option<String>,
) -> Result<String> {
    let image_path = cfg.image.path.join(&manifest.image);
    let image = Image::load(image_path).context("Failed to load image info")?;
    let img_ver = image.info.version_tuple().unwrap_or((0, 0, 0));
    let kms_urls = if manifest.kms_urls.is_empty() {
        cfg.cvm.kms_urls.clone()
    } else {
        manifest.kms_urls.clone()
    };
    let gateway_urls = if manifest.gateway_urls.is_empty() {
        cfg.cvm.gateway_urls.clone()
    } else {
        manifest.gateway_urls.clone()
    };
    if img_ver < (0, 5, 0) {
        bail!("Unsupported image version: {img_ver:?}");
    }

    let mut sys_config = json!({
        "kms_urls": kms_urls,
        "gateway_urls": gateway_urls,
        "pccs_url": cfg.cvm.pccs_url,
        "docker_registry": cfg.cvm.docker_registry,
        "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
        "vm_config": serde_json::to_string(&make_vm_config(cfg, manifest, &image, compose_hash, mr_config.clone())?)?,
    });
    if let Some(mr_config) = mr_config {
        MrConfigV3::from_document(&mr_config).context("Invalid mr_config document")?;
        sys_config["mr_config"] = serde_json::to_value(mr_config)?;
    } else if let Some(mr_config) = mr_config_from_vm_config(&sys_config)? {
        sys_config["mr_config"] = serde_json::to_value(mr_config)?;
    }
    let sys_config_str =
        serde_json::to_string(&sys_config).context("Failed to serialize vm config")?;
    Ok(sys_config_str)
}

fn mr_config_from_vm_config(sys_config: &serde_json::Value) -> Result<Option<String>> {
    let Some(vm_config) = sys_config.get("vm_config").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let vm_config: serde_json::Value = serde_json::from_str(vm_config)?;
    let Some(mr_config) = vm_config.get("mr_config") else {
        return Ok(None);
    };
    let mr_config = mr_config
        .as_str()
        .context("mr_config must be a JSON string")?;
    MrConfigV3::from_document(mr_config).context("Invalid mr_config document")?;
    Ok(Some(mr_config.to_string()))
}

fn file_sha256_hex(path: &Path) -> Result<String> {
    Ok(hex::encode(sha256_file(path)?))
}

fn amd_sev_snp_ovmf_measurement_info(image: &Image) -> Result<dstack_mr::sev::OvmfMeasurementInfo> {
    // Measure the same firmware the guest launches with: the SEV firmware
    // (bios-sev) when present, falling back to the generic bios. The OVMF
    // parsing/GCTX logic is shared with `dstack-mr sev-os-image-hash`.
    let bios = image
        .firmware(true)
        .map(|p| p.as_path())
        .ok_or_else(|| anyhow::anyhow!("bios/OVMF is required for amd sev-snp measurement"))?;
    dstack_mr::sev::ovmf_measurement_info(bios).with_context(|| {
        format!(
            "failed to extract amd sev-snp OVMF measurement metadata from {}",
            bios.display()
        )
    })
}

fn image_rootfs_hash(image: &Image) -> Result<&str> {
    if let Some(rootfs_hash) = image.info.rootfs_hash.as_deref() {
        return Ok(rootfs_hash);
    }
    let cmdline = image.info.cmdline.as_deref().unwrap_or_default();
    cmdline
        .split_whitespace()
        .find_map(|param| param.strip_prefix("dstack.rootfs_hash="))
        .ok_or_else(|| anyhow::anyhow!("rootfs_hash is required for amd sev-snp"))
}

fn amd_sev_snp_measurement_base_cmdline(base_cmdline: Option<&str>) -> Option<String> {
    base_cmdline.map(|cmdline| cmdline.trim().to_string())
}

fn sha256_file(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let data = fs::read(path).context("Failed to read file for sha256")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    Ok(out)
}

fn make_vm_config(
    cfg: &Config,
    manifest: &Manifest,
    image: &Image,
    _compose_hash: &str,
    mr_config: Option<String>,
) -> Result<serde_json::Value> {
    let is_amd_sev_snp =
        cfg.cvm.platform.resolve() == crate::config::TeePlatform::AmdSevSnp && !manifest.no_tee;
    // AMD SEV-SNP binds the OS image through the launch-measurement-derived
    // os_image_hash, computed at image build time by `dstack-mr sev-os-image-hash`
    // and shipped as `digest.sev.txt` (the same value KMS/verifier derive from a
    // verified launch measurement). The VMM reads it from the image rather than
    // recomputing it; TDX still uses the generic content digest.
    let os_image_hash = if is_amd_sev_snp {
        let digest = image.sev_digest.as_deref().context(
            "amd sev-snp image is missing digest.sev.txt; \
             rebuild the image so `dstack-mr sev-os-image-hash` emits it",
        )?;
        hex::decode(digest).context("digest.sev.txt is not valid hex")?
    } else {
        image
            .digest
            .as_ref()
            .and_then(|d| hex::decode(d).ok())
            .unwrap_or_default()
    };
    let gpus = manifest.gpus.clone().unwrap_or_default();
    let mut config = serde_json::to_value(dstack_types::VmConfig {
        os_image_hash,
        cpu_count: manifest.vcpu,
        memory_size: manifest.memory as u64 * 1024 * 1024,
        qemu_single_pass_add_pages: cfg.cvm.qemu_single_pass_add_pages,
        pic: cfg.cvm.qemu_pic,
        qemu_version: cfg.cvm.qemu_version.clone(),
        pci_hole64_size: cfg.cvm.qemu_pci_hole64_size,
        hugepages: manifest.hugepages,
        num_gpus: gpus.gpus.len() as u32,
        num_nvswitches: gpus.bridges.len() as u32,
        host_share_mode: cfg.cvm.host_share_mode.clone(),
        hotplug_off: cfg.cvm.qemu_hotplug_off,
        image: Some(manifest.image.clone()),
        ovmf_variant: image.info.ovmf_variant,
    })?;
    // For backward compatibility
    config["spec_version"] = serde_json::Value::from(1);
    if is_amd_sev_snp {
        let rootfs_hash = image_rootfs_hash(image)?;
        if let Some(mr_config) = mr_config {
            MrConfigV3::from_document(&mr_config).context("Invalid mr_config document")?;
            config["mr_config"] = serde_json::Value::String(mr_config);
        }
        let ovmf = amd_sev_snp_ovmf_measurement_info(image)?;
        let measurement = json!({
            "rootfs_hash": rootfs_hash,
            "base_cmdline": amd_sev_snp_measurement_base_cmdline(image.info.cmdline.as_deref()),
            "ovmf_hash": ovmf.ovmf_hash,
            "kernel_hash": file_sha256_hex(&image.kernel)?,
            "initrd_hash": file_sha256_hex(&image.initrd)?,
            "sev_hashes_table_gpa": ovmf.sev_hashes_table_gpa,
            "sev_es_reset_eip": ovmf.sev_es_reset_eip,
            "vcpus": manifest.vcpu,
            "vcpu_type": "EPYC-v4",
            "guest_features": 1,
            "ovmf_sections": ovmf.sections,
        });
        config["sev_snp_measurement"] = serde_json::Value::String(
            serde_json::to_string(&measurement)
                .context("Failed to serialize amd sev-snp measurement input")?,
        );
    }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_config_figment, TeePlatform};
    use rocket::figment::Figment;
    use std::time::UNIX_EPOCH;

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn write_u16_le_at(buf: &mut [u8], off: usize, value: u16) {
        buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32_le_at(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn ovmf_footer_entry(data: &[u8], guid: &[u8; 16]) -> Vec<u8> {
        let mut entry = data.to_vec();
        entry.extend_from_slice(&((data.len() + 18) as u16).to_le_bytes());
        entry.extend_from_slice(guid);
        entry
    }

    fn synthetic_snp_ovmf() -> Vec<u8> {
        const GUID_FOOTER_TABLE: [u8; 16] = [
            0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a,
            0x08, 0x2d,
        ];
        const GUID_SEV_HASH_TABLE_RV: [u8; 16] = [
            0x1f, 0x37, 0x55, 0x72, 0x3b, 0x3a, 0x04, 0x4b, 0x92, 0x7b, 0x1d, 0xa6, 0xef, 0xa8,
            0xd4, 0x54,
        ];
        const GUID_SEV_ES_RESET_BLK: [u8; 16] = [
            0xde, 0x71, 0xf7, 0x00, 0x7e, 0x1a, 0xcb, 0x4f, 0x89, 0x0e, 0x68, 0xc7, 0x7e, 0x2f,
            0xb4, 0x4e,
        ];
        const GUID_SEV_META_DATA: [u8; 16] = [
            0x66, 0x65, 0x88, 0xdc, 0x4a, 0x98, 0x98, 0x47, 0xa7, 0x5e, 0x55, 0x85, 0xa7, 0xbf,
            0x67, 0xcc,
        ];

        let mut ovmf = vec![0u8; 4096];
        let meta_start = 512usize;
        ovmf[meta_start..meta_start + 4].copy_from_slice(b"ASEV");
        write_u32_le_at(&mut ovmf, meta_start + 8, 1);
        write_u32_le_at(&mut ovmf, meta_start + 12, 4);
        let sections = [
            (0x1000u32, 0x1000u32, 1u32),
            (0x2000u32, 0x1000u32, 2u32),
            (0x3000u32, 0x1000u32, 3u32),
            (0x4000u32, 0x1000u32, 0x10u32),
        ];
        for (i, (gpa, size, section_type)) in sections.into_iter().enumerate() {
            let off = meta_start + 16 + i * 12;
            write_u32_le_at(&mut ovmf, off, gpa);
            write_u32_le_at(&mut ovmf, off + 4, size);
            write_u32_le_at(&mut ovmf, off + 8, section_type);
        }

        let mut table = Vec::new();
        table.extend(ovmf_footer_entry(
            &0x4000u32.to_le_bytes(),
            &GUID_SEV_HASH_TABLE_RV,
        ));
        table.extend(ovmf_footer_entry(
            &0xffff_fff0u32.to_le_bytes(),
            &GUID_SEV_ES_RESET_BLK,
        ));
        table.extend(ovmf_footer_entry(
            &((ovmf.len() - meta_start) as u32).to_le_bytes(),
            &GUID_SEV_META_DATA,
        ));

        let footer_off = ovmf.len() - 32 - 18;
        let table_start = footer_off - table.len();
        ovmf[table_start..footer_off].copy_from_slice(&table);
        write_u16_le_at(&mut ovmf, footer_off, (table.len() + 18) as u16);
        ovmf[footer_off + 2..footer_off + 18].copy_from_slice(&GUID_FOOTER_TABLE);
        ovmf
    }

    #[test]
    fn amd_sev_snp_measurement_base_cmdline_trims_image_cmdline() {
        assert_eq!(
            amd_sev_snp_measurement_base_cmdline(Some(" console=ttyS0 loglevel=7 ")),
            Some("console=ttyS0 loglevel=7".to_string())
        );
    }

    #[test]
    fn amd_sev_snp_sys_config_includes_measurement_input_and_mr_config() -> Result<()> {
        let temp = std::env::temp_dir().join(format!(
            "dstack-vmm-snp-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let temp = temp.as_path();
        let image_root = temp.join("images");
        let image_dir = image_root.join("dstack-test");
        fs::create_dir_all(&image_dir)?;
        fs::write(image_dir.join("kernel"), b"snp-test-kernel")?;
        fs::write(image_dir.join("initrd"), b"snp-test-initrd")?;
        fs::write(image_dir.join("rootfs"), b"snp-test-rootfs")?;
        fs::write(image_dir.join("ovmf.fd"), synthetic_snp_ovmf())?;
        fs::write(
            image_dir.join("metadata.json"),
            serde_json::json!({
                "cmdline": format!("console=ttyS0 dstack.rootfs_hash={}", hex_of(0x33, 32)),
                "kernel": "kernel",
                "initrd": "initrd",
                "rootfs": "rootfs",
                "bios": "ovmf.fd",
                "version": "0.5.11"
            })
            .to_string(),
        )?;

        let mut config: Config = Figment::from(load_config_figment(None)).extract()?;
        config.image.path = image_root;
        config.cvm.platform = TeePlatform::AmdSevSnp;
        let compose_hash = hex_of(0x22, 32);
        let manifest = Manifest {
            id: "snp-test".to_string(),
            name: "snp-test".to_string(),
            app_id: hex_of(0x11, 20),
            vcpu: 2,
            memory: 1024,
            disk_size: 1024,
            image: "dstack-test".to_string(),
            port_map: vec![],
            created_at_ms: 0,
            hugepages: false,
            pin_numa: false,
            gpus: None,
            kms_urls: vec![],
            gateway_urls: vec![],
            no_tee: false,
            networking: None,
        };

        let mr_config = MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            dstack_types::KeyProviderKind::None,
            vec![],
            vec![0x44; 20],
        )
        .to_canonical_json();

        // digest.sev.txt is produced at build time by the `dstack-mr
        // sev-os-image-hash` command; the VMM reads it instead of recomputing.
        // Emit it here so the deploy path (make_vm_config) can read it back.
        let build_hash = dstack_mr::sev::sev_os_image_hash_for_image_dir(&image_dir)?;
        fs::write(image_dir.join("digest.sev.txt"), hex::encode(build_hash))?;

        let sys_config_document =
            make_sys_config(&config, &manifest, &compose_hash, Some(mr_config))?;
        let sys_config: serde_json::Value = serde_json::from_str(&sys_config_document)?;
        let vm_config: serde_json::Value = serde_json::from_str(
            sys_config["vm_config"]
                .as_str()
                .context("vm_config must be a string")?,
        )?;
        let measurement_document = vm_config["sev_snp_measurement"]
            .as_str()
            .context("sev_snp_measurement must be a string")?;
        let measurement: serde_json::Value = serde_json::from_str(measurement_document)?;
        let mr_config_document = sys_config["mr_config"]
            .as_str()
            .context("mr_config must be a string")?;
        let parsed_mr_config = MrConfigV3::from_document(mr_config_document)?;

        assert_eq!(parsed_mr_config.app_id, vec![0x11; 20]);
        assert_eq!(parsed_mr_config.compose_hash, vec![0x22; 32]);
        assert_eq!(vm_config["mr_config"], sys_config["mr_config"]);
        // The deploy path must surface the os_image_hash straight from
        // digest.sev.txt (not recompute it).
        assert_eq!(
            vm_config["os_image_hash"]
                .as_str()
                .context("os_image_hash must be a string")?,
            hex::encode(build_hash),
            "vm_config os_image_hash must come from digest.sev.txt"
        );
        assert!(measurement.get("app_id").is_none());
        assert!(measurement.get("compose_hash").is_none());
        assert_eq!(measurement["rootfs_hash"], hex_of(0x33, 32));
        assert_eq!(
            measurement["base_cmdline"],
            format!("console=ttyS0 dstack.rootfs_hash={}", hex_of(0x33, 32))
        );
        assert_eq!(
            measurement["kernel_hash"],
            hex::encode(Sha256::digest(b"snp-test-kernel"))
        );
        assert_eq!(
            measurement["initrd_hash"],
            hex::encode(Sha256::digest(b"snp-test-initrd"))
        );
        assert_eq!(measurement["vcpus"], 2);
        assert_eq!(measurement["vcpu_type"], "EPYC-v4");
        assert_eq!(measurement["guest_features"], 1);
        assert_eq!(
            measurement["ovmf_hash"]
                .as_str()
                .context("ovmf_hash must be a string")?
                .len(),
            96
        );
        assert_eq!(measurement["sev_hashes_table_gpa"], 0x4000);
        assert_eq!(measurement["sev_es_reset_eip"], 0xffff_fff0u32);
        assert_eq!(
            measurement["ovmf_sections"]
                .as_array()
                .context("ovmf_sections must be an array")?
                .len(),
            4
        );

        // The build-time os_image_hash (dstack-mr sev-os-image-hash ->
        // digest.sev.txt) must equal the os_image_hash a verifier derives from
        // the launch measurement document, i.e. the image-invariant projection.
        let as_str = |v: &serde_json::Value| v.as_str().unwrap().to_string();
        let projected = dstack_types::SevOsImageMeasurement {
            rootfs_hash: as_str(&measurement["rootfs_hash"]),
            base_cmdline: measurement["base_cmdline"].as_str().map(str::to_string),
            ovmf_hash: as_str(&measurement["ovmf_hash"]),
            kernel_hash: as_str(&measurement["kernel_hash"]),
            initrd_hash: as_str(&measurement["initrd_hash"]),
            sev_hashes_table_gpa: measurement["sev_hashes_table_gpa"].as_u64().unwrap(),
            sev_es_reset_eip: measurement["sev_es_reset_eip"].as_u64().unwrap() as u32,
            ovmf_sections: measurement["ovmf_sections"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| dstack_types::OvmfSection {
                    gpa: s["gpa"].as_u64().unwrap(),
                    size: s["size"].as_u64().unwrap(),
                    section_type: s["section_type"].as_u64().unwrap() as u32,
                })
                .collect(),
        };
        assert_eq!(
            build_hash,
            projected.os_image_hash(),
            "digest.sev.txt must match the os_image_hash derived from the launch measurement"
        );
        Ok(())
    }
}

fn paginate<T>(items: Vec<T>, page: u32, page_size: u32) -> impl Iterator<Item = T> {
    let skip;
    let take;
    if page == 0 || page_size == 0 {
        skip = 0;
        take = items.len();
    } else {
        let page = page - 1;
        let start = page * page_size;
        skip = start as usize;
        take = page_size as usize;
    }
    items.into_iter().skip(skip).take(take)
}

#[derive(Clone)]
pub struct VmState {
    pub(crate) config: Arc<VmConfig>,
    state: VmStateMut,
}

#[derive(Debug, Clone, Default)]
struct VmStateMut {
    boot_progress: String,
    boot_error: String,
    shutdown_progress: String,
    guest_ip: String,
    devices: GpuConfig,
    events: VecDeque<pb::GuestEvent>,
    /// True when the VM is being removed (cleanup in progress).
    removing: bool,
}

impl VmStateMut {
    pub fn start(&mut self, already_running: bool) {
        self.boot_progress = if already_running {
            "running".to_string()
        } else {
            "booting".to_string()
        };
        self.boot_error.clear();
        self.shutdown_progress.clear();
    }

    pub fn reset_na(&mut self) {
        self.boot_progress = "N/A".to_string();
        self.shutdown_progress = "N/A".to_string();
        self.boot_error.clear();
    }
}

impl VmState {
    pub fn new(config: VmConfig) -> Self {
        Self {
            config: Arc::new(config),
            state: VmStateMut::default(),
        }
    }
}

pub(crate) struct AppState {
    cid_pool: IdPool<u32>,
    vms: HashMap<String, VmState>,
    /// Tracks active port forwarding rules per VM ID (bridge mode only).
    active_forwards: HashMap<String, Vec<ForwardRule>>,
}

impl AppState {
    pub fn add(&mut self, vm: VmState) {
        self.vms.insert(vm.config.manifest.id.clone(), vm);
    }

    pub fn get(&self, id: &str) -> Option<&VmState> {
        self.vms.get(id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut VmState> {
        self.vms.get_mut(id)
    }

    pub fn remove(&mut self, id: &str) -> Option<VmState> {
        self.vms.remove(id)
    }

    pub fn iter_vms(&self) -> impl Iterator<Item = &VmState> {
        self.vms.values()
    }
}
