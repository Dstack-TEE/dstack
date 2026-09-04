// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::{
    config::{
        Config, NetdInterface, Networking, NetworkingMode, NicNetworking, ProcessAnnotation,
        Protocol,
    },
    logrotate,
    netd::{
        self, InterfaceIdentity, PrepareBridgeRequest, PrepareMacvtapRequest,
        Request as NetdRequest,
    },
};

use anyhow::{bail, Context, Result};
use bon::Builder;
use dstack_kms_rpc::kms_client::KmsClient;
use dstack_types::mr_config::MrConfigV3;
use dstack_types::shared_filenames::{
    APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, SYS_CONFIG, TEE_SIMULATOR_CONFIG, USER_CONFIG,
};
use dstack_types::version::Version;
use dstack_vmm_rpc::{
    self as pb, GpuInfo, ReloadVmsResponse, StatusRequest, StatusResponse, VmConfiguration,
};
use fs_err as fs;
use guest_api::client::DefaultClient as GuestClient;
use id_pool::IdPool;
use nix::unistd::Uid;
use or_panic::ResultOrPanic;
use ra_rpc::client::RaClient;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use supervisor_client::SupervisorClient;
use tracing::{debug, error, info, warn};

pub use image::{Image, ImageInfo};
pub(crate) use network::{
    filters_bridge_traffic, ingress_for, mode_carries_ingress, needs_netd_interface, netd_teardown,
    resolve_networking, resolved_networks, settle_vhost, stranded_ingress,
    validate_resolved_network, validate_resolved_networks,
};
pub use qemu::VmConfig;
// Exported so the RPC layer can assert that everything it reports is
// something it also accepts.
#[cfg(test)]
pub(crate) use vm_info::networking_to_proto;
pub use workdir::VmWorkDir;

mod host_share;
mod id_pool;
mod image;
mod mr_config;
pub(crate) mod network;
mod qemu;
pub(crate) mod registry;
mod vm_info;
mod workdir;

fn signal_pidfd(pid: u32, signal: libc::c_int) -> std::io::Result<()> {
    // SAFETY: pidfd syscalls receive scalar arguments and a null siginfo pointer.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd,
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    // SAFETY: fd was returned by pidfd_open and is owned by this function.
    unsafe { libc::close(fd as libc::c_int) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PortMapping {
    pub address: IpAddr,
    pub protocol: Protocol,
    pub from: u16,
    pub to: u16,
    /// Which NIC carries this mapping. `None` resolves by the node's rule; see
    /// [`crate::app::network::ingress_nic`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nic_index: Option<usize>,
}

/// An extra disk attached to the VM (e.g. a pre-baked verity volume). `source`
/// is an absolute host path already resolved and validated by the VMM against
/// `cvm.volumes_dir`.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VmVolume {
    pub source: String,
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
    pub simulated_tee: Option<dstack_types::TeeVariant>,
    /// Deployment-time decision to attach QEMU swtpm.
    #[serde(default)]
    pub swtpm: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub networks: Vec<NicNetworking>,
    #[serde(default)]
    pub volumes: Vec<VmVolume>,
}

impl Manifest {
    pub fn from_json(value: serde_json::Value) -> serde_json::Result<Self> {
        let mut map = value;
        if let Some(obj) = map.as_object_mut() {
            if !obj.contains_key("networks")
                || obj["networks"].as_array().is_some_and(|a| a.is_empty())
            {
                if let Some(legacy) = obj.remove("networking") {
                    obj.insert("networks".into(), serde_json::Value::Array(vec![legacy]));
                }
            }
        }
        serde_json::from_value(map)
    }
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
    pub fn has_gpus(&self) -> bool {
        !self.gpus.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        if self.attach_mode.is_all() {
            return false;
        }
        self.gpus.is_empty() && self.bridges.is_empty()
    }
}

/// Round up a value to the nearest multiple of another value.
/// If the value is already a multiple, it remains unchanged.
pub(crate) fn round_up(value: u32, multiple: u32) -> u32 {
    if multiple <= 1 {
        return value;
    }

    let remainder = value % multiple;
    if remainder == 0 {
        return value;
    }

    value + (multiple - remainder)
}

/// Get the NUMA node associated with a PCI device.
pub(crate) fn pci_numa_node(device: &str) -> Result<String> {
    // Ensure the device string only contains valid hexadecimal characters and colons.
    if !device
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
    {
        bail!("Invalid device string");
    }

    let numa_node_path = format!("/sys/bus/pci/devices/0000:{device}/numa_node");
    let numa_node = fs::read_to_string(&numa_node_path)
        .with_context(|| format!("Failed to read NUMA node from {numa_node_path}"))?
        .trim()
        .to_string();

    // If the NUMA node is -1, default to 0.
    if numa_node == "-1" {
        return Ok("0".to_string());
    }

    Ok(numa_node)
}

/// NUMA nodes used by the QEMU hugepage layout.
///
/// This mirrors the launch path: only GPU devices determine the split, while
/// bridges/NVSwitches are attached after the NUMA topology is constructed.  If
/// no GPU is attached, QEMU still creates a single node (node 0).
pub(crate) fn hugepage_numa_nodes(gpus: &GpuConfig) -> Result<HashMap<String, u32>> {
    let mut numa_nodes = HashMap::new();

    for device in &gpus.gpus {
        let node = pci_numa_node(&device.slot)?;
        *numa_nodes.entry(node).or_insert(0) += 1;
    }

    if numa_nodes.is_empty() {
        numa_nodes.insert("0".to_string(), 0);
    }

    Ok(numa_nodes)
}

/// Effective vCPU count used for both QEMU `-smp` and SNP launch measurement.
///
/// QEMU launches at least one vCPU and, with hugepage NUMA layout enabled,
/// rounds the vCPU count up so it can be split evenly across NUMA nodes.  The
/// SEV-SNP launch measurement includes one measured VMSA page per vCPU, so the
/// measurement input must use this same effective count rather than the raw
/// manifest value.
pub(crate) fn effective_vcpu_count(
    requested_vcpu: u32,
    hugepage_numa_node_count: Option<u32>,
) -> u32 {
    let vcpus = requested_vcpu.max(1);
    match hugepage_numa_node_count {
        Some(numa_nodes) => round_up(vcpus, numa_nodes.max(1)),
        None => vcpus,
    }
}

pub(crate) fn effective_vcpu_count_for_manifest(
    manifest: &Manifest,
    gpus: &GpuConfig,
) -> Result<u32> {
    let numa_node_count = if manifest.hugepages {
        Some(hugepage_numa_nodes(gpus)?.len() as u32)
    } else {
        None
    };
    Ok(effective_vcpu_count(manifest.vcpu, numa_node_count))
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
    /// Pull status for registry images: tag → status.
    pub(crate) pull_status: Arc<Mutex<std::collections::HashMap<String, PullStatus>>>,
    /// One lock per VM, held across a launch or a teardown. See
    /// [`App::launch_lock`].
    launch_locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// What this node's netd last said it can do, and when. See
    /// [`App::netd_capabilities`].
    netd_probe: Arc<Mutex<Option<(std::time::Instant, netd::Reachability)>>>,
}

/// How long a netd capability answer is reused. Short, because netd is
/// upgraded and restarted under a running VMM, and a VMM that cached "this one
/// cannot sweep" across the upgrade that gave it the ability would keep
/// falling back for as long as it stayed up.
const NETD_PROBE_TTL: Duration = Duration::from_secs(30);

/// How far past a VM's recorded NIC count a teardown reaches when netd is too
/// old to sweep by identity.
///
/// The record is what a legacy netd leaves us: it cannot derive the space
/// itself, and asking it for all 256 possible indices would be 256 round trips
/// on every stop. Eight covers a lost NIC or two on any topology anyone
/// deploys, each miss is one cheap no-op, and what it does not reach is
/// collected the next time the node runs a netd that can sweep.
const LEGACY_TEARDOWN_SPAN: usize = 8;

const GUEST_AGENT_RPC_TIMEOUT: Duration = Duration::from_secs(30);

impl App {
    pub(crate) fn lock(&self) -> MutexGuard<'_, AppState> {
        self.state.lock().or_panic("mutex poisoned")
    }

    pub(crate) fn vm_dir(&self) -> PathBuf {
        self.config.run_path.clone()
    }

    pub(crate) fn work_dir(&self, id: &str) -> Result<VmWorkDir> {
        validate_vm_id(id)?;
        Ok(VmWorkDir::new(self.config.run_path.join(id)))
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
            })),
            config: Arc::new(config),
            pull_status: Arc::new(Mutex::new(std::collections::HashMap::new())),
            launch_locks: Arc::new(Mutex::new(HashMap::new())),
            netd_probe: Arc::new(Mutex::new(None)),
        }
    }

    /// Serializes everything that creates or deletes one VM's host interfaces.
    ///
    /// A launch reads whether QEMU is already up and then spends many awaits --
    /// a GPU reset, a whole netd conversation, building the QEMU arguments --
    /// before it launches anything. Nothing used to cover that window. Two
    /// `StartVm` calls, or one racing the auto-restart timer, could both read
    /// "not running", and the loser's sweep would delete the TAPs the winner's
    /// QEMU was already holding open: a live VM silently loses its networking,
    /// and the loser's error path then clears the winner's record of it. The
    /// authoritative rejection lives in the supervisor, which is reached long
    /// after the damage is done.
    ///
    /// A tokio mutex, because it is held across awaits. Per VM, because a slow
    /// start must not stall unrelated ones. Taken by stop and by removal as
    /// well as by start: those delete the same interfaces from the other side.
    pub(crate) async fn launch_lock(&self, id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.launch_lock_handle(id).lock_owned().await
    }

    /// The launch lock, if nothing else holds it.
    ///
    /// For a caller with something better to do than wait. A held lock means a
    /// launch, a stop or a removal of this VM is in flight, and every one of
    /// those manages that VM's interfaces itself -- so waiting would be waiting
    /// for the very thing that makes the work unnecessary. A removal holds it
    /// for as long as the VM takes to exit, which its own comment puts at hours.
    pub(crate) fn try_launch_lock(&self, id: &str) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        self.launch_lock_handle(id).try_lock_owned().ok()
    }

    fn launch_lock_handle(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.launch_locks.lock().or_panic("mutex poisoned");
        // A VM that is neither starting nor stopping leaves the map holding
        // the only reference, so the map stays the size of what is in flight
        // rather than of every VM this process has ever touched.
        locks.retain(|_, lock| Arc::strong_count(lock) > 1);
        locks.entry(id.to_string()).or_default().clone()
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
        let mut runtime_networks = vm_work_dir.runtime_networks();
        if runtime_networks.is_empty() && cids_assigned.contains_key(&vm_id) {
            runtime_networks = self.inferred_runtime_networks(&manifest);
            if let Err(err) = vm_work_dir.set_runtime_networks(&runtime_networks) {
                warn!(id = %vm_id, "failed to persist inferred runtime networks: {err}");
            }
        }
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
                    vm.state.runtime_networks = runtime_networks;
                }
                None => {
                    let mut vm_state = VmState::new(vm_config);
                    vm_state.state.runtime_networks = runtime_networks;
                    states.add(vm_state);
                }
            }
        };
        if auto_start && vm_work_dir.started().unwrap_or_default() {
            self.start_vm(&vm_id).await?;
        }
        Ok(())
    }

    /// Refuses an operation on a VM that is being removed.
    ///
    /// Cheap, and taken before the launch lock as well as under it. Removal
    /// holds that lock until the VM has exited -- hours, by its own estimate --
    /// so anything that only asked afterwards would wait the removal out in
    /// order to be told no.
    pub(crate) fn refuse_if_removing(&self, id: &str) -> Result<()> {
        let state = self.lock();
        if state.get(id).is_some_and(|vm| vm.state.removing) {
            bail!("VM is being removed");
        }
        Ok(())
    }

    pub async fn start_vm(&self, id: &str) -> Result<()> {
        self.start_vm_with_restart_policy(id, true).await
    }

    async fn start_vm_with_restart_policy(
        &self,
        id: &str,
        reset_restart_policy: bool,
    ) -> Result<()> {
        if reset_restart_policy {
            if let Some(vm) = self.lock().get_mut(id) {
                vm.state.auto_restart.reset();
            }
        }
        // Before the lock as well as after it. Removal holds the lock until the
        // VM has exited, so a launch that only asked afterwards would wait that
        // out -- hours, by removal's own estimate -- to be told no. Asking
        // first is not sufficient on its own, because the marker can be set
        // while this waits; asking again under the lock is what makes it
        // authoritative.
        self.refuse_if_removing(id)?;
        // Everything below reads whether this VM is running and acts on the
        // answer for as long as the launch takes. See [`App::launch_lock`].
        let _launch = self.launch_lock(id).await;
        self.refuse_if_removing(id)?;
        // A restart decided before a stop must not outlive it. The decision
        // read `started` from disk; `stop_vm` writes it false under this lock,
        // so re-reading it here is what makes the stop stick. An explicit start
        // sets the flag itself and has nothing to re-read.
        if !reset_restart_policy && !self.work_dir(id)?.started().unwrap_or(false) {
            debug!(id, "skipping automatic restart: the VM was stopped");
            return Ok(());
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
            let work_dir = self.work_dir(id)?;
            for path in [work_dir.serial_pty(), work_dir.qmp_socket()] {
                if path.symlink_metadata().is_ok() {
                    fs::remove_file(path)?;
                }
            }
            // Archive the previous boot into segments, which also clears the
            // live logs for this boot. QEMU runs with logappend=on and no
            // longer truncates serial.log on open, so a boot is simply another
            // rotation trigger and boot boundaries land on segment boundaries.
            for path in rotatable_logs(&work_dir, true) {
                rotate_log(&path, self.config.cvm.log.max_backups);
                // The logs are opened in append mode, so this marks the start
                // of the new boot rather than replacing anything.
                append_boot_separator(&path);
            }

            let mut runtime_networks = self.runtime_networks(&vm_config.manifest);
            let devices = self.try_allocate_gpus(&vm_config.manifest)?;
            let gpu_host_config = self.config.cvm.gpu.clone();
            let devices_to_sanitize = devices.clone();
            tokio::task::spawn_blocking(move || {
                crate::gpu_reset::sanitize_on_attach(&gpu_host_config, &devices_to_sanitize)
            })
            .await
            .context("GPU sanitization task failed")??;
            if let Err(error) = self
                .prepare_filtered_networks(&vm_config, &mut runtime_networks)
                .await
            {
                let _ = work_dir.clear_runtime_networks();
                return Err(error);
            }
            let processes = match vm_config.config_qemu(
                &work_dir,
                &self.config.cvm,
                &devices,
                &runtime_networks,
            ) {
                Ok(processes) => processes,
                Err(error) => {
                    self.release_vm_interfaces(&vm_config.manifest.id, &runtime_networks)
                        .await;
                    return Err(error);
                }
            };
            if let Err(error) = work_dir.set_runtime_networks(&runtime_networks) {
                self.release_vm_interfaces(&vm_config.manifest.id, &runtime_networks)
                    .await;
                return Err(error);
            }
            {
                let mut state = self.lock();
                let vm_state = state.get_mut(id).context("VM not found")?;
                vm_state.state.runtime_networks = runtime_networks.clone();
            }
            for process in processes {
                if let Err(err) = self.supervisor.deploy(&process).await {
                    self.release_vm_interfaces(&vm_config.manifest.id, &runtime_networks)
                        .await;
                    if let Err(clear_err) = work_dir.clear_runtime_networks() {
                        warn!(
                            id,
                            "failed to clear runtime networks after start failure: {clear_err}"
                        );
                    }
                    if let Some(vm_state) = self.lock().get_mut(id) {
                        vm_state.state.runtime_networks.clear();
                    }
                    return Err(err)
                        .with_context(|| format!("failed to start process {}", process.id));
                }
            }

            let mut state = self.lock();
            let vm_state = state.get_mut(id).context("VM not found")?;
            vm_state.state.devices = devices;
        }
        Ok(())
    }

    fn set_started(&self, id: &str, started: bool) -> Result<()> {
        let work_dir = self.work_dir(id)?;
        work_dir
            .set_started(started)
            .context("Failed to set started")
    }

    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        // Removal stops the VM itself and holds the launch lock while it does,
        // so this would otherwise wait hours to do again what is already being
        // done.
        self.refuse_if_removing(id)?;
        if let Some(vm) = self.lock().get_mut(id) {
            vm.state.auto_restart.reset();
        }
        // Teardown deletes the same interfaces a launch creates, and derives
        // their names rather than reading a record, so it must not overlap one.
        let _launch = self.launch_lock(id).await;
        self.set_started(id, false)?;
        self.stop_vm_process(id).await?;
        let networks = self.work_dir(id)?.runtime_networks();
        // Not fallible: a VM that has been asked to stop is stopped whether or
        // not netd could be reached. What is left behind is reclaimed by this
        // VM's next launch, which releases before it prepares, or by its
        // removal. Not by reconciliation -- a stopped VM is still one this
        // instance claims, so a VM that is never started or removed again keeps
        // its interfaces. See [`App::release_vm_interfaces`].
        self.release_vm_interfaces(id, &networks).await;
        Ok(())
    }

    async fn prepare_filtered_networks(
        &self,
        vm: &VmConfig,
        networks: &mut [Networking],
    ) -> Result<()> {
        // Before the early return, because a mapping with nowhere to go is a
        // property of the resolved topology and not of whether netd is in it.
        // Deployment refuses every way of asking for one, so reaching this
        // means an edit removed the NIC out from under a mapping that named it.
        for mapping in stranded_ingress(&vm.manifest.port_map, networks) {
            warn!(
                vm_id = %vm.manifest.id,
                "port mapping {} {}:{} names NIC {:?}, which this VM no longer has a backend \
                 for; it will not be published",
                mapping.protocol.as_str(),
                mapping.address,
                mapping.from,
                mapping.nic_index,
            );
        }
        // Whatever an earlier boot left behind: a crash between creating an
        // interface and recording it, a NIC this VM no longer has, or a whole
        // backend it no longer uses. Prepare replaces the names it is about to
        // use, but only those, so an index nothing will claim again is only
        // reachable from here.
        //
        // Before the early return, and not inside it. A VM that has moved from
        // a bridge to user-mode networking needs this release precisely because
        // it no longer wants an interface, and gating it on wanting one is how
        // the interfaces it left behind would become unreachable to every
        // later launch.
        self.release_vm_interfaces(&vm.manifest.id, networks).await;
        if !networks.iter().any(needs_netd_interface) {
            return Ok(());
        }
        // Resolved before the loop borrows `networks` mutably, and once rather
        // than per NIC, so both the request and the warning below read the same
        // answer.
        let ingress: Vec<Vec<netd::IngressRequest>> = (0..networks.len())
            .map(|nic_index| ingress_for(&vm.manifest.port_map, networks, nic_index))
            .collect();
        let qemu_uid = Uid::effective().as_raw();
        // Only ever read back out of a log line: netd is told where the VM
        // lives so an operator holding an opaque TAP name can reach the VM
        // without going through the VMM first.
        let workdir = self
            .work_dir(&vm.manifest.id)
            .map(|dir| dir.path().display().to_string())
            .unwrap_or_default();
        // `port_map` is implemented as QEMU `hostfwd=` entries on a user-mode
        // netdev, so a bridge NIC drops every one of them. The VMM cannot
        // forward them itself -- it runs without CAP_NET_ADMIN by design -- so
        // it states the requirement and lets the node's netd answer it.
        let mut prepared = Vec::new();
        for (nic_index, network) in networks.iter_mut().enumerate() {
            if !needs_netd_interface(network) {
                continue;
            }
            let identity = InterfaceIdentity {
                instance_id: self.config.cvm.instance_id.clone(),
                vm_id: vm.manifest.id.clone(),
                nic_index,
            };
            let mac = network::mac_address_for_vm_index(
                &vm.manifest.id,
                &network.mac_prefix_bytes(),
                nic_index,
            );
            let queues = network.queue_pairs();
            let filtered = filters_bridge_traffic(network, &self.config.cvm);
            let request = match network.nic.mode {
                NetworkingMode::Bridge => NetdRequest::PrepareBridge(PrepareBridgeRequest {
                    identity: identity.clone(),
                    bridge: network.nic.bridge.clone(),
                    mac,
                    qemu_uid,
                    // Which filter, and with what parameters, is netd's to
                    // decide from its own configuration. An unfiltered TAP is
                    // only asked for by multiqueue, where the node may not run
                    // libvirt at all.
                    filtered,
                    queues,
                    workdir: workdir.clone(),
                    // Only the mappings that resolve to this NIC. One mapping
                    // lands on exactly one, and a user-mode NIC's are emitted
                    // as QEMU `hostfwd=` instead, so no host port is claimed
                    // twice.
                    ingress: ingress[nic_index].clone(),
                }),
                NetworkingMode::Macvtap => NetdRequest::PrepareMacvtap(PrepareMacvtapRequest {
                    identity: identity.clone(),
                    parent: network.nic.parent.clone(),
                    mac,
                    qemu_uid,
                    mode: network.macvtap_mode.clone(),
                    queues,
                    workdir: workdir.clone(),
                }),
                NetworkingMode::User | NetworkingMode::Custom => continue,
            };
            let response = match netd::request(&self.config.netd.socket, &request).await {
                Ok(response) => response,
                Err(error) => {
                    // The client may have timed out while netd was still
                    // finishing this Prepare. Remove the in-flight identity
                    // first: the operation lock makes netd run that removal
                    // after the Prepare it is undoing, whatever order the two
                    // connections arrived in.
                    if let Err(cleanup_error) = netd::request(
                        &self.config.netd.socket,
                        &NetdRequest::Remove {
                            identity: identity.clone(),
                            filtered,
                        },
                    )
                    .await
                    {
                        warn!(%cleanup_error, "failed to roll back in-flight filtered network");
                    }
                    self.roll_back_prepared_networks(prepared).await;
                    // netd's own message is about a socket or a TAP, so
                    // neither the NIC that asked nor what a node has to install
                    // to satisfy it appears anywhere in the failure.
                    let unreachable = netd::is_unreachable(&error);
                    let mode = network.nic.mode.as_str();
                    let error = Err(error).context("failed to prepare netd-managed networking");
                    return if unreachable {
                        error.with_context(|| {
                            format!(
                                "interface {nic_index} is {mode}, whose host interface only netd \
                                 can build; run dstack-vmm netd on this host"
                            )
                        })
                    } else if queues > 1 {
                        error.with_context(|| {
                            format!("interface {nic_index} asked for {queues} queue pairs")
                        })
                    } else {
                        error.with_context(|| format!("interface {nic_index} is {mode}"))
                    };
                }
            };
            prepared.push((identity.clone(), filtered));
            // netd built this one. Record it now, before anything else can
            // fail, so teardown never has to re-derive it from a node
            // configuration the operator may since have changed.
            network.netd_interface = if filtered {
                NetdInterface::Filtered
            } else {
                NetdInterface::Unfiltered
            };
            // Everything below runs after netd already built a host interface,
            // so a failure has to unwind the same way a failed Prepare does.
            let accepted = (|| {
                if network.nic.mode == NetworkingMode::Macvtap {
                    network.device = response
                        .device
                        .clone()
                        .context("netd response omitted macvtap device")?;
                }
                // QEMU refuses a TAP whose IFF_MULTI_QUEUE state disagrees with
                // its own `queues=`, and reports it from inside the per-VM
                // launcher. netd echoes what it built, so a netd too old to
                // understand the request fails here, where the reason is
                // legible.
                if queues > 1 && response.queues != Some(queues) {
                    bail!(
                        "netd prepared interface {nic_index} with {} queue pairs instead of \
                         {queues}; its version may predate multiqueue support",
                        response.queues.map_or_else(
                            || "an unreported number of".to_string(),
                            |q| q.to_string()
                        )
                    );
                }
                Ok(())
            })();
            // Ports asked for and not answered for used to vanish in silence:
            // no warning, and `GetInfo` still listing them as though they
            // worked.
            let asked = &ingress[nic_index];
            match &response.ingress {
                // A netd that forwards says what it built, so saying nothing is
                // how one that does not reports it. A warning rather than a
                // refusal: a VM deployed before this has been running with its
                // ports dropped, and failing its launch now would turn a silent
                // misconfiguration into an outage on upgrade.
                None if !asked.is_empty() => warn!(
                    vm_id = %vm.manifest.id,
                    ports = asked.len(),
                    "netd on this node does not forward host ports, so this VM's port mappings \
                     on interface {nic_index} are not published"
                ),
                // It answered, so hold it to the answer. A netd may refuse one
                // port out of a set -- a node policy over which ports may be
                // handed out is its own to state -- and the mapping that lost
                // is the one worth naming.
                Some(bound) => {
                    // What was answered, not what was asked. `GetInfo` reports
                    // the difference rather than the request.
                    network.ingress = bound.clone();
                    for request in asked {
                        if !bound.iter().any(|binding| {
                            binding.answers(
                                &request.protocol,
                                &request.host_address,
                                request.host_port,
                                request.guest_port,
                            )
                        }) {
                            warn!(
                                vm_id = %vm.manifest.id,
                                "netd did not publish {} {}:{} on interface {nic_index}",
                                request.protocol,
                                request.host_address,
                                request.host_port,
                            );
                        }
                    }
                }
                None => {}
            }
            if let Err(error) = accepted {
                self.roll_back_prepared_networks(prepared).await;
                return Err(error);
            }
        }
        Ok(())
    }

    /// The NICs a VM has now, or would get if it were started.
    ///
    /// While QEMU is up this is what the launch actually built. Once it is
    /// down the snapshot describes a boot that is over: the node configuration
    /// and the VM's own manifest can both have changed since, so reporting it
    /// would answer a question about the past with the grammar of the present.
    /// Predict instead, the same way the next launch will.
    fn effective_networks(&self, info: &vm_info::VmInfo) -> Vec<Networking> {
        if info.running && !info.runtime_networks.is_empty() {
            return info.runtime_networks.clone();
        }
        self.merge_networks(&info.manifest)
    }

    /// Launch-time view of a VM's NICs: node defaults merged in and the
    /// vCPU-scaled queue count made concrete.
    pub(crate) fn runtime_networks(&self, manifest: &Manifest) -> Vec<Networking> {
        self.merge_networks(manifest)
    }

    /// A running VM whose snapshot is missing, because a VMM that predates the
    /// snapshot -- or predates it recording what netd built -- started it.
    ///
    /// Guessing is all that is left, so guess the way that VMM would have, and
    /// then write the guess down. Leaving the marker unset would make every
    /// later teardown re-derive it from node configuration that may by then
    /// have moved, which is the failure this snapshot exists to prevent.
    ///
    /// The way *that* VMM would have, not this one: a build old enough to leave
    /// no snapshot had no vhost and no multiqueue at all, so whatever this
    /// node's defaults say now, the QEMU process actually running was given one
    /// queue pair and no vhost. Asking `runtime_networks` would apply today's
    /// defaults to a launch that predates them, and the guess is persisted, so
    /// it would keep describing that VM wrongly for the life of its boot.
    fn inferred_runtime_networks(&self, manifest: &Manifest) -> Vec<Networking> {
        let mut networks = self.merge_networks(manifest);
        for network in &mut networks {
            network.nic.vhost = Some(false);
            network.nic.queues = Some(1);
        }
        for network in &mut networks {
            network.netd_interface = match netd_teardown(network, &self.config.cvm) {
                Some(true) => NetdInterface::Filtered,
                Some(false) => NetdInterface::Unfiltered,
                None => NetdInterface::None,
            };
        }
        networks
    }

    /// The merge itself: node defaults applied, then the data plane settled so
    /// that every later stage reads one answer instead of recomputing it.
    fn merge_networks(&self, manifest: &Manifest) -> Vec<Networking> {
        let mut resolved = resolved_networks(manifest, &self.config.cvm);
        settle_vhost(&mut resolved);
        resolved
    }

    /// Removes interfaces netd already built for a launch that then failed.
    async fn roll_back_prepared_networks(&self, prepared: Vec<(InterfaceIdentity, bool)>) {
        for (identity, filtered) in prepared.into_iter().rev() {
            if let Err(cleanup_error) = netd::request(
                &self.config.netd.socket,
                &NetdRequest::Remove { identity, filtered },
            )
            .await
            {
                warn!(%cleanup_error, "failed to roll back prepared network interface");
            }
        }
    }

    /// What this node's netd can do, cached for [`NETD_PROBE_TTL`].
    ///
    /// Asked rather than inferred, and asked once per window rather than per
    /// VM: it is a round trip, and the paths that want it are the ones already
    /// making one.
    /// An unreachable answer is not cached -- a failed connect costs nothing,
    /// and holding on to it would keep a VMM blind to the netd an operator
    /// just started.
    pub(crate) async fn netd_capabilities(&self) -> netd::Reachability {
        if let Some((_, reachability)) = self
            .netd_probe
            .lock()
            .or_panic("mutex poisoned")
            .as_ref()
            .filter(|(asked, _)| asked.elapsed() < NETD_PROBE_TTL)
        {
            return reachability.clone();
        }
        let reachability = netd::probe(&self.config.netd.socket).await;
        // Only a real answer is cached. "Unreachable" and "too old to answer"
        // are both produced by transient failures too, and holding either for
        // half a minute turns one blip into a deployment refused for a reason
        // that is not true -- `refuse_unpublishable_ports` reads this. A netd
        // that genuinely predates `hello` is re-asked on a path that was
        // already making a round trip.
        if matches!(reachability, netd::Reachability::Capable(_)) {
            *self.netd_probe.lock().or_panic("mutex poisoned") =
                Some((std::time::Instant::now(), reachability.clone()));
        }
        reachability
    }

    /// Every VM whose interfaces this instance may still be using.
    ///
    /// Wider than the VMs it managed to load. A VM whose manifest is corrupt
    /// or whose image is missing fails to load and is only logged; `reload_vms`
    /// then stops any supervisor process it still has, but that runs in the
    /// background, and a collection deciding on the loaded set alone races it
    /// -- over a file the VMM could not parse. A directory is enough of a
    /// claim, and what has been removed for real leaves none behind.
    /// `None` when the answer cannot be established, which is not the same as
    /// nobody claiming anything: an unreadable VM directory read as empty
    /// would offer every interface on the host up for collection.
    fn claimable_vm_ids(&self) -> Option<Vec<String>> {
        let mut ids: HashSet<String> = self.lock().vms.keys().cloned().collect();
        match fs::read_dir(self.vm_dir()) {
            Ok(entries) => {
                for entry in entries {
                    // Every error here is answered the same way the `read_dir`
                    // error below is, and for the same reason: an entry that
                    // cannot be read is a VM that might exist, and dropping it
                    // silently is how a collection deletes a running VM's
                    // networking over an unreadable directory entry.
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            warn!("failed to read a VM directory entry: {error}; not collecting");
                            return None;
                        }
                    };
                    match entry.file_type() {
                        Ok(file_type) if !file_type.is_dir() => continue,
                        Ok(_) => {}
                        Err(error) => {
                            warn!(
                                name = ?entry.file_name(),
                                "failed to stat a VM directory entry: {error}; not collecting"
                            );
                            return None;
                        }
                    }
                    match entry.file_name().into_string() {
                        Ok(id) => {
                            ids.insert(id);
                        }
                        // A VM ID is ASCII, so a name that is not UTF-8 is not
                        // a VM directory -- but it is also not something to
                        // decide a deletion around.
                        Err(name) => {
                            warn!(?name, "unreadable VM directory name; not collecting");
                            return None;
                        }
                    }
                }
            }
            // "Never ran" and "the volume is not mounted yet" produce the same
            // error, and only one of them means there are no VMs. A VMM that
            // has never run has nothing to collect either way, so declining
            // costs nothing and the other reading costs every interface this
            // instance owns.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                debug!("no VM directory yet; not collecting interfaces");
                return None;
            }
            Err(error) => {
                warn!("failed to read the VM directory: {error}; not collecting interfaces");
                return None;
            }
        }
        Some(ids.into_iter().collect())
    }

    /// Deletes every host interface netd holds for a VM this instance no
    /// longer has.
    ///
    /// Per-VM release reaches only what its caller can still name. This reaches
    /// what nothing names any more, which is where a leak actually ends up: a
    /// VM removed while the VMM was down, a workdir deleted by hand, a teardown
    /// that raced a netd outage and was never retried because the VM it
    /// belonged to no longer exists to retry it.
    ///
    /// The decision is made here and not in netd, and that is the whole design.
    /// A collection decided in netd is decided against a set of live VMs that
    /// was true when the caller sent it: netd runs the request when it wins the
    /// operation lock, which may be long after, and a VM created in between is
    /// absent from the set and present on the host. netd cannot close that --
    /// the lock that would close it is the VMM's per-VM launch lock, and netd
    /// has no way to take it. Here, each VM is decided under exactly that lock
    /// and re-checked while holding it, so a launch and a collection of the
    /// same VM cannot both believe they are alone.
    ///
    /// What is claimed is every VM this instance has, running or not. Not the
    /// running set: a VMM restarts under VMs that keep running, and collecting
    /// by what is running would delete their interfaces out from under them.
    pub(crate) async fn reconcile_netd_interfaces(&self) {
        let Some(claimed) = self.claimable_vm_ids() else {
            return;
        };
        let interfaces = match netd::list(&self.config.netd.socket, "").await {
            Ok(interfaces) => interfaces,
            Err(error) if netd::is_unreachable(&error) => {
                debug!("no netd to reconcile interfaces with");
                return;
            }
            Err(error) => {
                // It answered, so ask whether the answer means it cannot do
                // this at all -- the same reading a release gets.
                if self.netd_capabilities().await.supports("list") {
                    warn!("failed to list netd-managed interfaces: {error:#}");
                } else {
                    warn!(
                        "netd on this node cannot say what it holds, so interfaces belonging to a \
                         VM removed while this VMM was down stay until the node runs a newer netd"
                    );
                }
                return;
            }
        };
        let mut unattributed = 0;
        let mut dead = BTreeSet::new();
        for record in &interfaces {
            match (&record.instance_id, &record.vm_id) {
                // Another instance's. Never ours to collect: on a host where
                // two VMMs share one netd, this is the other one's running VM,
                // and the ownership record is the only thing that says so.
                (Some(instance_id), _) if instance_id != &self.config.cvm.instance_id => {}
                (Some(_), Some(vm_id)) if !claimed.contains(vm_id) => {
                    dead.insert(vm_id.clone());
                }
                (Some(_), _) => {}
                // Built before netd recorded ownership, or by another netd.
                // Nothing here can attribute it, so nothing here can decide
                // about it: `dstack-vmm netd remove-interface` is where an
                // operator who can decide says so.
                _ => unattributed += 1,
            }
        }
        if unattributed > 0 {
            // Why there are any is the difference between "these are from
            // before the upgrade and will sort themselves out" and "this netd
            // never records ownership, so they never will".
            let records_ownership = self.netd_capabilities().await.records_ownership();
            info!(
                unattributed,
                records_ownership,
                "host interfaces carry no ownership record, so no VMM can tell whose they are \
                 and none will collect them; `dstack-vmm netd list` shows them and \
                 `netd remove-interface` removes one"
            );
        }
        for vm_id in dead {
            // The lock a launch of this VM holds from before it asks netd for
            // an interface until after it has recorded one -- and that a
            // removal holds until the VM has exited, which can be hours. Taking
            // it without waiting is both safe and necessary: whoever holds it
            // is already dealing with this VM's interfaces, and waiting would
            // stall the collection of every other VM behind one that is busy.
            let Some(_launch) = self.try_launch_lock(&vm_id) else {
                debug!(vm_id = %vm_id, "not collecting: this VM is busy");
                continue;
            };
            // Re-read under it. Between the listing and this line the VM may
            // have been created and started: its directory exists now, and its
            // interfaces are the ones a launch just built.
            if self.claims_vm(&vm_id) {
                continue;
            }
            info!(vm_id = %vm_id, "collecting host interfaces no VM of this instance claims");
            self.release_vm_interfaces(&vm_id, &[]).await;
        }
    }

    /// Whether this instance has a VM by this ID at all, loaded or merely
    /// present on disk. See [`App::claimable_vm_ids`].
    fn claims_vm(&self, vm_id: &str) -> bool {
        if self.lock().vms.contains_key(vm_id) {
            return true;
        }
        // `validate_vm_id` keeps an ID from naming anything outside the VM
        // directory, so this cannot be pointed at another path.
        self.work_dir(vm_id)
            .is_ok_and(|work_dir| work_dir.path().is_dir())
    }

    /// Releases every host interface netd holds for this VM.
    ///
    /// Unconditional and non-fatal, which is one decision made twice. The
    /// release path must not be gated on a predicate that can change under it:
    /// `needs_netd_interface` reads the VM's *current* backend, and a VM whose
    /// NIC was a bridge when its TAP was built and is a user-mode NIC now would
    /// skip the release for interfaces that exist. And a VM must be able to
    /// stop when the daemon holding its interfaces cannot be reached, or a
    /// netd outage becomes a fleet that cannot be stopped.
    ///
    /// Nothing is lost by not failing: the next launch releases before it
    /// prepares, and startup reconciliation collects what no launch will ever
    /// reach. `recorded` is not the source of truth -- it is what a netd too
    /// old to sweep by identity has to be told instead.
    pub(crate) async fn release_vm_interfaces(&self, vm_id: &str, recorded: &[Networking]) {
        // Ask for the release, rather than asking whether it can be asked for.
        // A probe first would put a second round trip in front of every stop
        // and -- worse -- would make a *busy* netd look like an absent one and
        // skip the release entirely. The operation itself cannot be misread
        // that way: it succeeds, or it says netd is not there, or netd answers
        // with a refusal, and only the last of those has a fallback.
        match netd::remove_all(
            &self.config.netd.socket,
            &self.config.cvm.instance_id,
            vm_id,
        )
        .await
        {
            Ok(sweep) => {
                if sweep.removed > 0 {
                    info!(
                        vm_id,
                        removed = sweep.removed,
                        "released netd-managed interfaces"
                    );
                }
                // A sweep that ran out of time is not a sweep that found
                // nothing left. Saying so is the difference between a host an
                // operator can reason about and one where "released 3
                // interfaces" hid the fourth.
                if sweep.incomplete {
                    warn!(
                        vm_id,
                        "netd stopped releasing this VM's interfaces on its deadline; the rest \
                         are released by its next launch or its removal"
                    );
                }
            }
            Err(error) if netd::is_unreachable(&error) => {
                debug!(vm_id, %error, "no netd to release interfaces from")
            }
            Err(error) => {
                // It answered, so it is up. Now the question is worth a round
                // trip: an operation a netd does not have looks exactly like
                // one that failed, and only one of those has a fallback. A netd
                // that has this operation and failed at it is a failure to
                // report, not a reason to send it eight more requests.
                if self.netd_capabilities().await.supports("remove_all") {
                    warn!(
                        vm_id,
                        "failed to release netd-managed interfaces: {error:#}"
                    );
                } else {
                    self.release_recorded_interfaces(vm_id, recorded).await;
                }
            }
        }
    }

    /// The teardown a netd that cannot sweep by identity gets.
    ///
    /// One `Remove` per index, over the record plus a margin for what the
    /// record has lost. See [`LEGACY_TEARDOWN_SPAN`].
    async fn release_recorded_interfaces(&self, vm_id: &str, recorded: &[Networking]) {
        warn!(
            vm_id,
            "netd on this node cannot release a VM's interfaces by identity; falling back to \
             the recorded ones. Interfaces it has no record of are left behind until this node \
             runs a netd that can sweep"
        );
        for nic_index in (0..recorded.len().max(LEGACY_TEARDOWN_SPAN)).rev() {
            // Beyond the record there is nothing to say whether the interface
            // carried a binding, and an unfiltered removal still clears one it
            // finds. Inside it, say what was built.
            let filtered = recorded
                .get(nic_index)
                .and_then(|network| netd_teardown(network, &self.config.cvm))
                .unwrap_or(false);
            let identity = InterfaceIdentity {
                instance_id: self.config.cvm.instance_id.clone(),
                vm_id: vm_id.to_string(),
                nic_index,
            };
            if let Err(error) = netd::request(
                &self.config.netd.socket,
                &NetdRequest::Remove { identity, filtered },
            )
            .await
            {
                if netd::is_unreachable(&error) {
                    return;
                }
                warn!(vm_id, nic_index, "failed to release interface: {error:#}");
            }
        }
    }

    pub(crate) async fn stop_vm_process(&self, id: &str) -> Result<()> {
        let Some(info) = self.supervisor.info(id).await? else {
            return Ok(());
        };
        // Non-TPM VMs run QEMU directly and keep the existing Supervisor stop
        // path. Only the TPM launcher's hidden subcommand implements graceful
        // child-process shutdown.
        if info.config.args.first().map(String::as_str) != Some("vm-launcher") {
            return self.supervisor.stop(id).await;
        }
        if info.state.status.is_running() {
            let pid = info.state.pid.context("running VM launcher has no PID")?;
            if let Err(error) = signal_pidfd(pid, libc::SIGTERM) {
                warn!(id, %pid, %error, "failed to signal VM launcher gracefully; forcing shutdown");
                return self.supervisor.stop(id).await;
            }
            for _ in 0..150 {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                let running = self
                    .supervisor
                    .info(id)
                    .await?
                    .is_some_and(|info| info.state.status.is_running());
                if !running {
                    // Synchronize Supervisor's `started` flag after the launcher
                    // completed its graceful child cleanup.
                    return self.supervisor.stop(id).await;
                }
            }
            warn!(id, "VM launcher did not stop gracefully; forcing shutdown");
        }
        self.supervisor.stop(id).await
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
        let work_dir = self.work_dir(id)?;
        if let Err(err) = work_dir.set_removing() {
            warn!("failed to write .removing marker for {id}: {err:?}");
        }

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
        // Held across the stop, the wait and the release, not just the release.
        // `removing` turns launches away, but a launch that passed that check
        // before the marker was set is already inside the lock: it has not
        // deployed yet, so the wait below sees nothing running and returns at
        // once, and the release then deletes the interfaces of the QEMU that
        // launch went on to start. Taking the lock first means the launch
        // finishes before removal decides anything, and removal then stops what
        // it actually started.
        let _launch = self.launch_lock(id).await;
        // Stop the supervisor process (idempotent if already stopped)
        if let Err(err) = self.stop_vm_process(id).await {
            debug!("graceful VM stop during removal failed: {err:?}");
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

        let runtime_networks = self.work_dir(id)?.runtime_networks();
        self.release_vm_interfaces(id, &runtime_networks).await;

        // Only delete the workdir for user-initiated removal or if .removing marker exists.
        // Orphaned supervisor processes without the marker keep their data intact.
        let vm_path = self.work_dir(id)?;
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
            for (vm_id, cid) in occupied_cids.iter() {
                // These CIDs come from processes that are already running, not
                // from the pool, so a CID left over from an earlier cid_start /
                // cid_pool_size must not stop the VMM from starting.
                if let Err(err) = state.cid_pool.occupy(*cid) {
                    warn!(id = %vm_id, "not tracking cid {cid} in the pool: {err}");
                }
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

        // Rebuild the CID pool from every CID that is still spoken for
        {
            let mut state = self.lock();
            let reserved = cids_to_reserve(
                &occupied_cids,
                state.vms.iter().map(|(id, vm)| (id.clone(), vm.config.cid)),
            );
            state.cid_pool.clear();
            for (cid, vm_id) in reserved {
                // Same as in reload_vms(): an out-of-range CID from an earlier
                // configuration is reported, not fatal.
                if let Err(err) = state.cid_pool.occupy(cid) {
                    warn!(id = %vm_id, "not tracking cid {cid} in the pool: {err}");
                }
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
        let mut runtime_networks = vm_work_dir.runtime_networks();
        if runtime_networks.is_empty() && already_running {
            runtime_networks = self.inferred_runtime_networks(&manifest);
            if let Err(err) = vm_work_dir.set_runtime_networks(&runtime_networks) {
                warn!(id = %vm_id, "failed to persist inferred runtime networks: {err}");
            }
        }
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
                    let mut old_state = vm.state.clone();
                    if old_state.runtime_networks.is_empty() {
                        old_state.runtime_networks = runtime_networks;
                    }
                    vm.config = vm_config.into();
                    vm.state = old_state; // Preserve the existing state with statistics
                }
                None => {
                    // Assigned CIDs were occupied above, while allocate() reserves a new CID.
                    let mut vm_state = VmState::new(vm_config);
                    vm_state.state.runtime_networks = runtime_networks;
                    states.add(vm_state);
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
                let work_dir = self.work_dir(&vm.config.manifest.id)?;
                let info = vm.merged_info(vms.get(&vm.config.manifest.id), &work_dir);
                let networks = self.effective_networks(&info);
                Ok(info.to_pb(&self.config.gateway, request.brief, &networks))
            })
            .collect::<Result<Vec<_>>>()?;
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
        // Snapshot under the lock, then release it: describing the VM can
        // probe netd, and that is a blocking connect the global state lock has
        // no business being held across.
        let info = {
            let state = self.lock();
            let Some(vm_state) = state.get(id) else {
                return Ok(None);
            };
            vm_state.merged_info(proc_state.as_ref(), &self.work_dir(id)?)
        };
        let networks = self.effective_networks(&info);
        Ok(Some(info.to_pb(&self.config.gateway, false, &networks)))
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

    pub(crate) fn compose_file_path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.shared_dir(id)?.join(APP_COMPOSE))
    }

    pub(crate) fn encrypted_env_path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.shared_dir(id)?.join(ENCRYPTED_ENV))
    }

    pub(crate) fn user_config_path(&self, id: &str) -> Result<PathBuf> {
        Ok(self.shared_dir(id)?.join(USER_CONFIG))
    }

    pub(crate) fn shared_dir(&self, id: &str) -> Result<PathBuf> {
        validate_vm_id(id)?;
        Ok(self.config.run_path.join(id).join("shared"))
    }

    pub(crate) fn prepare_work_dir(
        &self,
        id: &str,
        req: &VmConfiguration,
        app_id: &str,
    ) -> Result<VmWorkDir> {
        let work_dir = self.work_dir(id)?;
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
        let work_dir = self.work_dir(id)?;
        let shared_dir = self.shared_dir(id)?;
        let manifest = work_dir.manifest().context("Failed to read manifest")?;
        let cfg = &self.config;
        let compose_hash = sha256_file(shared_dir.join(APP_COMPOSE))?;
        let app_compose = work_dir
            .app_compose()
            .context("Failed to get app compose")?;
        let mr_config = work_dir
            .prepare_mr_config(&manifest, &cfg.cvm, &app_compose)
            .context("Failed to prepare mr_config")?;
        let sys_config_str = make_sys_config(
            cfg,
            &manifest,
            &hex::encode(compose_hash),
            mr_config,
            app_compose.requirements.as_ref(),
        )?;
        fs::write(shared_dir.join(SYS_CONFIG), &sys_config_str)
            .context("Failed to write vm config")?;
        let simulator_config = simulator_config_for_manifest(&self.config.cvm, &manifest)?;
        sync_tee_simulator_config(&shared_dir, simulator_config.as_ref(), &sys_config_str)?;
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
        Ok(guest_api::client::new_client_with_timeout(
            format!("vsock://{cid}:8000/api"),
            GUEST_AGENT_RPC_TIMEOUT,
        ))
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

    /// Rotate any live log that has grown past the configured cap.
    pub(crate) async fn rotate_oversized_logs(&self) -> Result<()> {
        let max_bytes = self.config.cvm.log.max_bytes;
        if max_bytes == 0 {
            return Ok(());
        }
        let max_backups = self.config.cvm.log.max_backups;
        let running = self
            .supervisor
            .list()
            .await
            .context("failed to list VMs")?
            .into_iter()
            .filter(|process| process.state.status.is_running());
        for process in running {
            let Ok(work_dir) = self.work_dir(&process.config.id) else {
                continue;
            };
            let serial = serial_log_is_rotatable(&process.config.note);
            for path in rotatable_logs(&work_dir, serial) {
                if let Some(rotated) = logrotate::rotate_if_oversized(&path, max_bytes, max_backups)
                {
                    logrotate::append_rotation_note(&path, &rotated);
                    info!(
                        id = process.config.id,
                        log = %path.display(),
                        bytes = rotated.bytes,
                        "rotated oversized log"
                    );
                }
            }
        }
        Ok(())
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
        let now = std::time::Instant::now();
        let mut restart_vms = Vec::new();
        {
            let mut state = self.lock();
            for vm in state.vms.values_mut() {
                let id = &vm.config.manifest.id;
                if vm.state.removing {
                    vm.state.auto_restart.reset();
                    continue;
                }
                if running_vms.contains(id) {
                    if vm
                        .state
                        .auto_restart
                        .observe_running(now, self.config.cvm.auto_restart.reset_window)
                    {
                        info!(
                            id,
                            "automatic restart retry budget reset after healthy window"
                        );
                    }
                    continue;
                }
                let Ok(workdir) = self.work_dir(id) else {
                    warn!(id, "skipping restart: invalid VM id");
                    vm.state.auto_restart.reset();
                    continue;
                };
                let started = workdir.started().unwrap_or(false);
                if !started {
                    vm.state.auto_restart.reset();
                    continue;
                }
                match vm
                    .state
                    .auto_restart
                    .observe_exited(now, &self.config.cvm.auto_restart)
                {
                    AutoRestartDecision::Scheduled { delay_secs } => {
                        info!(id, delay_secs, "automatic restart scheduled");
                    }
                    AutoRestartDecision::Restart {
                        attempt,
                        next_delay_secs,
                    } => {
                        info!(id, attempt, next_delay_secs, "automatic restart attempt");
                        restart_vms.push(id.clone());
                    }
                    AutoRestartDecision::Exhausted { attempts } => {
                        warn!(id, attempts, "automatic restart retry limit exhausted");
                        vm.state.events.push_back(pb::GuestEvent {
                            event: "vmm.auto_restart.exhausted".into(),
                            body: format!(
                                "Automatic restart stopped after {attempts} failed attempts"
                            ),
                            timestamp: SystemTime::now()
                                .duration_since(SystemTime::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as u64,
                        });
                        while vm.state.events.len() > self.config.event_buffer_size {
                            vm.state.events.pop_front();
                        }
                    }
                    AutoRestartDecision::Wait => {}
                }
            }
        }
        for id in restart_vms {
            // A manual stop may have landed after the restart decision was made.
            let Ok(workdir) = self.work_dir(&id) else {
                warn!(id, "skipping restart: invalid VM id");
                continue;
            };
            if !workdir.started().unwrap_or(false) {
                continue;
            }
            if let Err(error) = self.start_vm_with_restart_policy(&id, false).await {
                warn!(id, %error, "automatic restart attempt failed");
            }
        }
        Ok(())
    }
}

/// Leading bytes of the separator written by [`append_boot_separator`].
///
/// Written to stdout, stderr and the serial log at each boot so a log read in
/// isolation still shows where a boot began.
const BOOT_SEPARATOR_PREFIX: &str = "\n===== boot @ ";

/// Append a boot separator line with timestamp to an append-mode log file.
fn append_boot_separator(path: &std::path::Path) {
    use std::io::Write;
    if !path.exists() {
        return;
    }
    let Ok(mut file) = fs::OpenOptions::new().append(true).open(path) else {
        return;
    };
    let timestamp = humantime::format_rfc3339_seconds(std::time::SystemTime::now());
    let _ = writeln!(file, "{BOOT_SEPARATOR_PREFIX}{timestamp} =====\n");
}

/// Logs a CVM writes into its work directory, subject to retention.
///
/// stdout and stderr are written by the supervisor, which always opens them
/// with `append(true)` and reopens them when they change, so they satisfy
/// [`crate::logrotate`]'s contract no matter which VMM launched the VM.
/// serial.log is written by QEMU, whose fd only appends when *we* passed
/// `logappend=on`, so it is included only when `serial` says so.
fn rotatable_logs(work_dir: &VmWorkDir, serial: bool) -> Vec<PathBuf> {
    let mut paths = vec![work_dir.stdout_file(), work_dir.stderr_file()];
    if serial {
        paths.push(work_dir.serial_file());
    }
    paths
}

/// Rotate a log and record where its output went.
///
/// The rotation itself is generic (see [`crate::logrotate`]); the note is here
/// because the VMM log API serves only the live file.
fn rotate_log(path: &Path, max_backups: usize) {
    if let Some(rotated) = logrotate::rotate(path, max_backups) {
        logrotate::append_rotation_note(path, &rotated);
    }
}

/// Whether a supervised process's serial log may be rotated in place.
///
/// Rotation truncates the log while QEMU holds it open, which only works when
/// QEMU opened it with `logappend=on`. Anything we cannot positively confirm —
/// an annotation from an older VMM, an unparseable note — answers `false`.
fn serial_log_is_rotatable(note: &str) -> bool {
    serde_json::from_str::<ProcessAnnotation>(note)
        .unwrap_or_default()
        .serial_logappend
}

pub(crate) fn simulator_config_for_manifest(
    cvm: &crate::config::CvmConfig,
    manifest: &Manifest,
) -> Result<Option<dstack_types::TeeSimulatorConfig>> {
    let Some(platform) = manifest.simulated_tee else {
        return Ok(None);
    };
    let mut config = cvm
        .tee_simulator
        .clone()
        .context("tee simulator credentials are not configured on this VMM")?;
    config.platform = platform;
    Ok(Some(config))
}

pub(crate) fn sync_tee_simulator_config(
    shared_dir: &Path,
    simulator_config: Option<&dstack_types::TeeSimulatorConfig>,
    sys_config: &str,
) -> Result<()> {
    let path = shared_dir.join(TEE_SIMULATOR_CONFIG);
    let Some(simulator_config) = simulator_config else {
        if path.exists() {
            fs::remove_file(&path).context("failed to remove stale TEE simulator config")?;
        }
        return Ok(());
    };

    let sys_config: dstack_types::SysConfig = serde_json::from_str(sys_config)?;
    let mut simulator_config = simulator_config.clone();
    simulator_config.mr_config = sys_config.mr_config;
    let vm_config_value: serde_json::Value = serde_json::from_str(&sys_config.vm_config)?;
    simulator_config.aws_pcr_replay = vm_config_value
        .get("aws_pcr_replay")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("invalid aws_pcr_replay in vm_config")?;
    simulator_config.gcp_tpm_replay = vm_config_value
        .get("gcp_tpm_replay")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .context("invalid gcp_tpm_replay in vm_config")?;
    simulator_config.vm_config = Some(sys_config.vm_config);
    fs::write(path, serde_json::to_vec(&simulator_config)?)
        .context("failed to write TEE simulator config")
}

pub(crate) fn make_sys_config(
    cfg: &Config,
    manifest: &Manifest,
    compose_hash: &str,
    mr_config: Option<String>,
    requirements: Option<&dstack_types::Requirements>,
) -> Result<String> {
    let image_path = cfg.image.path.join(&manifest.image);
    let image = Image::load(image_path).context("Failed to load image info")?;
    let img_ver = image
        .info
        .version()
        .with_context(|| format!("Unparseable image version: {:?}", image.info.version))?;
    let mut kms_urls = if manifest.kms_urls.is_empty() {
        cfg.cvm.kms_urls.clone()
    } else {
        manifest.kms_urls.clone()
    };
    if cfg.cvm.shuffle_kms_urls {
        kms_urls.shuffle(&mut rand::thread_rng());
    }
    let mut gateway_urls = if manifest.gateway_urls.is_empty() {
        cfg.cvm.gateway_urls.clone()
    } else {
        manifest.gateway_urls.clone()
    };
    let mut gateway_clusters = cfg.cvm.gateway_clusters.clone();
    if cfg.cvm.shuffle_gateway_urls {
        // Give each CVM an independent starting gateway. The guest preserves
        // these orders when it has no previously successful gateway to prefer.
        let mut rng = rand::thread_rng();
        gateway_urls.shuffle(&mut rng);
        for cluster in &mut gateway_clusters {
            cluster.urls.shuffle(&mut rng);
        }
    }
    if img_ver < Version::new(0, 5, 0) {
        bail!("Unsupported image version: {img_ver}");
    }

    let vm_config = make_vm_config(
        cfg,
        manifest,
        &image,
        compose_hash,
        mr_config.clone(),
        requirements,
    )?;
    let mut sys_config = json!({
        "kms_urls": kms_urls,
        "gateway_urls": gateway_urls,
        "gateway_clusters": gateway_clusters,
        "pccs_url": cfg.cvm.pccs_url,
        "collateral_urls": { "pccs": cfg.cvm.pccs_url },
        "nvidia_attestation_proxy_url": cfg.cvm.nvidia_attestation_proxy_url,
        "docker_registry": cfg.cvm.docker_registry,
        "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
        "vm_config": serde_json::to_string(&vm_config)?,
    });
    // No attestation trust anchor is ever written here. Simulated deployments
    // receive only the development seed through `.tee-simulator.json`; the
    // in-guest simulator derives the matching roots itself and publishes them
    // to the guest verifier. A host cannot be allowed to choose the root that
    // authenticates the guest's key provider.
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

fn sha256_file(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let data = fs::read(path).context("Failed to read file for sha256")?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(data));
    Ok(out)
}

fn image_supports_tdx_lite(image: &Image) -> bool {
    image
        .digest
        .as_deref()
        .is_some_and(|d| !d.trim().is_empty())
        && image.tdx_measurement.is_some()
}

fn tdx_attestation_variant_from_requirements(
    requirements: Option<&dstack_types::Requirements>,
) -> Option<dstack_types::TdxAttestationVariant> {
    requirements
        .and_then(|requirements| requirements.tdx_measure_acpi_tables)
        .map(|measure_acpi_tables| {
            if measure_acpi_tables {
                dstack_types::TdxAttestationVariant::Legacy
            } else {
                dstack_types::TdxAttestationVariant::Lite
            }
        })
}

fn make_vm_config(
    cfg: &Config,
    manifest: &Manifest,
    image: &Image,
    _compose_hash: &str,
    mr_config: Option<String>,
    requirements: Option<&dstack_types::Requirements>,
) -> Result<serde_json::Value> {
    let platform = cfg.cvm.resolved_platform();
    let is_amd_sev_snp = platform == crate::config::CvmPlatform::AmdSevSnp && !manifest.no_tee;
    let is_tdx = platform == crate::config::CvmPlatform::Tdx && !manifest.no_tee;
    let is_gcp_tdx = manifest.simulated_tee == Some(dstack_types::TeeVariant::DstackGcpTdx);
    let is_aws_nitro_tpm =
        manifest.simulated_tee == Some(dstack_types::TeeVariant::DstackAwsNitroTpm);
    let tdx_attestation_variant = if is_tdx {
        tdx_attestation_variant_from_requirements(requirements).unwrap_or_else(|| {
            cfg.cvm
                .tdx_attestation_variant
                .resolve(manifest.memory, image_supports_tdx_lite(image))
        })
    } else {
        dstack_types::TdxAttestationVariant::Legacy
    };
    // All dstack OS-image verification modes use the same public image
    // identity: digest.txt = sha256(sha256sum.txt). Lite TDX/SNP carry extra
    // split CBOR measurement material, but that material is committed by
    // sha256sum.txt instead of defining a second image hash.
    let os_image_hash = image
        .digest
        .as_ref()
        .and_then(|d| hex::decode(d).ok())
        .unwrap_or_default();
    // Attach the lite measurement material whenever the image provides it,
    // regardless of the resolved attestation variant, so the config shape stays
    // uniform across images. It does not widen how the boot is verified:
    // verifiers select the path from `tdx_attestation_variant` alone, and a
    // legacy-resolved boot is verified through the image download even with the
    // document attached. `tdx_attestation_variant` keeps its original meaning of
    // "the scheme the VMM/KMS resolved for this boot".
    let tdx_measurement = if is_tdx {
        if tdx_attestation_variant.is_lite() {
            Some(image.tdx_measurement.clone().context(
                "tdx lite attestation requested but image is missing \
                 measurement.tdx.cbor/sha256sum.txt measurement material",
            )?)
        } else {
            image.tdx_measurement.clone()
        }
    } else {
        None
    };
    let gpus = if cfg.cvm.gpu.enabled {
        manifest.gpus.clone().unwrap_or_default()
    } else {
        GpuConfig::default()
    };
    let effective_vcpus = effective_vcpu_count_for_manifest(manifest, &gpus)?;
    // Each resolved network interface becomes one virtio-net-pci device in the
    // QEMU command (see `VmConfig::config_qemu`), which changes the guest's
    // ACPI/DSDT layout and therefore RTMR0. Measure the interface count so the
    // verifier reconstructs the exact device layout.
    let num_nics = resolved_networks(manifest, &cfg.cvm).len() as u32;
    let num_verity_volumes = manifest.volumes.len() as u32;
    let swtpm = manifest.swtpm;
    let gcp_measurement = if is_gcp_tdx {
        Some(
            image
                .gcp_measurement
                .clone()
                .context("GCP TDX image is missing measurement.gcp.cbor measurement material")?,
        )
    } else {
        None
    };
    let aws_measurement =
        if is_aws_nitro_tpm {
            Some(image.aws_measurement.clone().context(
                "AWS NitroTPM image is missing measurement.aws.cbor measurement material",
            )?)
        } else {
            None
        };
    let mut config = serde_json::to_value(dstack_types::VmConfig {
        os_image_hash,
        cpu_count: effective_vcpus,
        memory_size: manifest.memory as u64 * 1024 * 1024,
        qemu_single_pass_add_pages: cfg.cvm.qemu_single_pass_add_pages,
        pic: cfg.cvm.qemu_pic,
        qemu_version: cfg.cvm.qemu_version.clone(),
        pci_hole64_size: cfg.cvm.qemu_pci_hole64_size,
        hugepages: manifest.hugepages,
        num_gpus: gpus.gpus.len() as u32,
        num_nvswitches: gpus.bridges.len() as u32,
        num_nics,
        num_verity_volumes,
        swtpm,
        host_share_mode: cfg.cvm.host_share_mode.clone(),
        hotplug_off: cfg.cvm.qemu_hotplug_off,
        image: Some(manifest.image.clone()),
        ovmf_variant: image.info.ovmf_variant,
        tdx_attestation_variant,
        tdx_measurement,
        gcp_measurement,
        aws_measurement,
    })?;
    // For backward compatibility
    config["spec_version"] = serde_json::Value::from(1);
    if is_aws_nitro_tpm {
        let replay = image
            .aws_pcr_replay
            .as_ref()
            .context("AWS NitroTPM simulation requires measurement.aws.replay.json")?;
        let replay_measurement = dstack_types::AwsOsImageMeasurement::from_boot_pcrs(
            &replay.pcr4,
            &replay.pcr7,
            &replay.pcr12,
        )
        .map_err(anyhow::Error::msg)?;
        let image_measurement = image
            .aws_measurement
            .as_ref()
            .context("AWS NitroTPM image is missing measurement.aws.cbor")?
            .decode_measurement()
            .map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            replay_measurement == image_measurement,
            "measurement.aws.replay.json does not match measurement.aws.cbor"
        );
        config["aws_pcr_replay"] = serde_json::to_value(replay)?;
    }
    if is_gcp_tdx {
        config["gcp_tpm_replay"] = serde_json::to_value(
            image
                .gcp_tpm_replay
                .as_ref()
                .context("GCP TDX simulation requires measurement.gcp.eventlog.bin")?,
        )?;
    }
    if is_amd_sev_snp {
        if let Some(mr_config) = mr_config {
            MrConfigV3::from_document(&mr_config).context("Invalid mr_config document")?;
            config["mr_config"] = serde_json::Value::String(mr_config);
        }
        let image_measurement = image.sev_measurement.as_ref().context(
            "amd sev-snp image is missing measurement.snp.cbor/sha256sum.txt measurement material",
        )?;
        let measurement = dstack_mr::sev::SnpMeasurementDocument {
            checksum_file: image_measurement.checksum_file.clone(),
            measurement: image_measurement.measurement.clone(),
            vcpus: effective_vcpus,
            vcpu_type: Some("EPYC-v4".to_string()),
            guest_features: 1,
        };
        config["sev_snp_measurement"] = serde_json::Value::String(
            serde_json::to_string(&measurement)
                .context("Failed to serialize amd sev-snp measurement input")?,
        );
    }
    Ok(config)
}

pub(crate) fn needs_swtpm(
    key_provider: dstack_types::KeyProviderKind,
    simulated_tee: Option<dstack_types::TeeVariant>,
) -> bool {
    matches!(key_provider, dstack_types::KeyProviderKind::Tpm)
        && !simulated_tee.is_some_and(mock_attestation::platform_provides_tpm)
}

#[cfg(test)]
mod tests {
    use super::mr_config::{mr_config_version, MrConfigVersion};
    use super::*;

    fn test_app() -> App {
        use rocket::figment::providers::Format as _;
        let config: Config = rocket::figment::Figment::from(
            rocket::figment::providers::Toml::string(crate::config::DEFAULT_CONFIG),
        )
        .extract()
        .unwrap();
        App::new(config, SupervisorClient::new("http://127.0.0.1:0"))
    }

    fn test_config(netd_socket: &Path, run_path: &Path) -> Config {
        use rocket::figment::providers::Format as _;
        let mut config: Config = rocket::figment::Figment::from(
            rocket::figment::providers::Toml::string(crate::config::DEFAULT_CONFIG),
        )
        .extract()
        .unwrap();
        config.netd.socket = netd_socket.to_path_buf();
        config.cvm.instance_id = "test-instance".to_string();
        config.run_path = run_path.to_path_buf();
        config
    }

    fn app_talking_to(netd_socket: &Path) -> App {
        let run_path = netd_socket.parent().unwrap_or(Path::new("/nonexistent"));
        App::new(
            test_config(netd_socket, run_path),
            SupervisorClient::new("http://127.0.0.1:0"),
        )
    }

    /// A VM whose manifest is corrupt or whose image is missing fails to load
    /// and is only logged -- but its QEMU may well still be running. Collecting
    /// by what loaded would delete a running VM's networking over a file the
    /// VMM could not parse.
    #[test]
    fn a_vm_that_failed_to_load_still_claims_its_interfaces() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("vm-that-did-not-load")).unwrap();
        std::fs::write(dir.path().join("not-a-vm"), "").unwrap();
        let app = App::new(
            test_config(Path::new("/nonexistent/netd.sock"), dir.path()),
            SupervisorClient::new("http://127.0.0.1:0"),
        );
        assert_eq!(
            app.claimable_vm_ids(),
            Some(vec!["vm-that-did-not-load".to_string()])
        );

        // Unreadable is not "nobody claims anything", which would offer every
        // interface on the host up for collection.
        let app = App::new(
            test_config(
                Path::new("/nonexistent/netd.sock"),
                Path::new("/proc/self/environ"),
            ),
            SupervisorClient::new("http://127.0.0.1:0"),
        );
        assert_eq!(app.claimable_vm_ids(), None);

        // "Never ran" and "the volume is not mounted yet" produce the same
        // error and only one of them means there are no VMs. A VMM that has
        // never run has nothing to collect either way, so declining costs
        // nothing and the other reading costs every interface it owns.
        let app = app_talking_to(Path::new("/nonexistent/netd.sock"));
        assert_eq!(app.claimable_vm_ids(), None);
    }

    /// A netd outage must not become a fleet that cannot be stopped.
    #[tokio::test]
    async fn a_stop_survives_a_netd_that_is_not_there() {
        let app = app_talking_to(Path::new("/nonexistent/dstack-netd.sock"));
        // Returns rather than propagating: there is no error type here on
        // purpose, because there is no caller that should act on one.
        app.release_vm_interfaces("vm-1", &[]).await;
    }

    /// The regression this pair exists to prevent: `remove_all` is an
    /// operation, and an operation a netd does not have answers with an error
    /// that looks exactly like the sweep having failed. Reading that as failure
    /// used to fail the stop *and* leave every interface behind -- strictly
    /// worse than the per-NIC removal it replaced.
    #[tokio::test]
    async fn a_netd_too_old_to_sweep_gets_the_teardown_it_understands() {
        let netd = netd::testing::FakeNetd::spawn(netd::testing::Behavior::Legacy);
        let app = app_talking_to(netd.socket());
        app.release_vm_interfaces("vm-1", &[]).await;

        let operations = netd.operations();
        assert_eq!(
            operations[0], "remove_all",
            "the release is asked for, not asked about"
        );
        assert_eq!(
            operations[1], "hello",
            "only a refusal is worth a question, and then it is asked rather than inferred"
        );
        assert_eq!(
            operations.iter().filter(|op| *op == "remove").count(),
            LEGACY_TEARDOWN_SPAN,
            "the record is not the only thing reached, even on a netd that cannot sweep"
        );
    }

    /// A probe in front of every stop is a second round trip on the hot path,
    /// and one whose failure mode is silence: a netd too slow to answer it
    /// reads as an absent one, and an absent netd's release is skipped. The
    /// operation itself cannot be misread that way.
    #[tokio::test]
    async fn a_netd_that_sweeps_is_asked_to_without_a_question_first() {
        let netd = netd::testing::FakeNetd::spawn(netd::testing::Behavior::capable(&[
            "hello",
            "remove",
            "remove_all",
        ]));
        let app = app_talking_to(netd.socket());
        app.release_vm_interfaces("vm-1", &[]).await;

        assert_eq!(netd.operations(), vec!["remove_all"]);
        let sweep = &netd.seen()[0];
        assert_eq!(sweep["vm_id"], "vm-1");
        assert_eq!(sweep["instance_id"], "test-instance");
        // A sweep names no NIC: reaching the indices the caller can no longer
        // name is the entire point.
        assert!(sweep.get("nic_index").is_none());
    }

    /// A real answer is reused; anything else is asked again.
    ///
    /// "Unreachable" and "too old to answer" are both produced by transient
    /// failures too, and holding either for half a minute turns one blip into
    /// a deployment refused for a reason that is not true.
    #[tokio::test]
    async fn only_a_real_capability_answer_is_reused() {
        let netd = netd::testing::FakeNetd::spawn(netd::testing::Behavior::capable(&["hello"]));
        let app = app_talking_to(netd.socket());
        app.netd_capabilities().await;
        app.netd_capabilities().await;
        assert_eq!(netd.operations(), vec!["hello"], "asked once, read twice");

        let legacy = netd::testing::FakeNetd::spawn(netd::testing::Behavior::Legacy);
        let app = app_talking_to(legacy.socket());
        app.netd_capabilities().await;
        app.netd_capabilities().await;
        assert_eq!(
            legacy.operations().len(),
            2,
            "an answer that may have been a blip is not held onto"
        );
    }

    fn held(tap: &str, instance: Option<&str>, vm: Option<&str>) -> serde_json::Value {
        serde_json::json!({
            "tap": tap,
            "kind": "tap",
            "instance_id": instance,
            "vm_id": vm,
            "nic_index": 0,
            "bound": false,
        })
    }

    /// The decision a collection is made of. It lives here, and not in netd,
    /// because it is only safe under a lock netd cannot take -- see
    /// [`App::reconcile_netd_interfaces`].
    #[tokio::test]
    async fn a_collection_takes_only_what_this_instance_no_longer_claims() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("live-vm")).unwrap();
        let netd = netd::testing::FakeNetd::spawn_holding(
            netd::testing::Behavior::capable(&["hello", "list", "remove_all"]),
            vec![
                held("dt000000000001", Some("test-instance"), Some("live-vm")),
                held("dt000000000002", Some("test-instance"), Some("dead-vm")),
                // Another VMM instance on the same host. The ownership record
                // is the only thing that can tell this from ours, which is why
                // there is one: without it a collection would delete another
                // instance's running VM's networking.
                held("dt000000000003", Some("someone-else"), Some("dead-vm")),
                // Built before ownership was recorded, or by another netd.
                // Nothing here can attribute it, so nothing here decides.
                held("dt000000000004", None, None),
            ],
        );
        let app = App::new(
            test_config(netd.socket(), dir.path()),
            SupervisorClient::new("http://127.0.0.1:0"),
        );
        app.reconcile_netd_interfaces().await;

        let swept: Vec<serde_json::Value> = netd
            .seen()
            .into_iter()
            .filter(|request| request["operation"] == "remove_all")
            .collect();
        assert_eq!(swept.len(), 1, "one VM collected, and only one");
        assert_eq!(swept[0]["vm_id"], "dead-vm");
        assert_eq!(swept[0]["instance_id"], "test-instance");
    }

    /// A netd that cannot say what it holds must not read as one holding
    /// nothing.
    #[tokio::test]
    async fn a_netd_that_cannot_enumerate_collects_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let netd = netd::testing::FakeNetd::spawn(netd::testing::Behavior::capable(&[
            "hello",
            "remove_all",
        ]));
        let app = App::new(
            test_config(netd.socket(), dir.path()),
            SupervisorClient::new("http://127.0.0.1:0"),
        );
        app.reconcile_netd_interfaces().await;
        assert!(
            !netd
                .operations()
                .iter()
                .any(|operation| operation == "remove_all"),
            "nothing is collected on the strength of an answer netd could not give"
        );
    }

    /// A VM directory that cannot be read is not an absent VM. Reading it as
    /// one offers every interface this instance owns up for collection.
    #[tokio::test]
    async fn an_unreadable_vm_directory_collects_nothing() {
        let netd = netd::testing::FakeNetd::spawn_holding(
            netd::testing::Behavior::capable(&["hello", "list", "remove_all"]),
            vec![held(
                "dt000000000001",
                Some("test-instance"),
                Some("running-vm"),
            )],
        );
        for run_path in [
            Path::new("/proc/self/environ"),
            Path::new("/nonexistent/vms"),
        ] {
            let app = App::new(
                test_config(netd.socket(), run_path),
                SupervisorClient::new("http://127.0.0.1:0"),
            );
            app.reconcile_netd_interfaces().await;
        }
        assert!(
            netd.operations().is_empty(),
            "an answer that could not be established is not an answer"
        );
    }

    /// A removal holds the launch lock until the VM has exited, which its own
    /// comment puts at hours. Nothing that has something better to do than
    /// wait may queue behind it.
    #[tokio::test]
    async fn work_that_can_wait_does_not_queue_behind_a_removal() {
        let app = test_app();
        let removal = app.launch_lock("vm-1").await;

        // The collection skips a busy VM rather than stalling every other VM
        // behind it: whoever holds the lock is already dealing with this one.
        assert!(app.try_launch_lock("vm-1").is_none());
        assert!(app.try_launch_lock("vm-2").is_some());

        drop(removal);
        assert!(app.try_launch_lock("vm-1").is_some());
    }

    /// A restart decided before a stop must not outlive it. The restart task
    /// reads the started flag off disk and only then queues a launch, which
    /// waits for the lock the stop is holding; without a re-read under that
    /// lock the launch resurrects a VM the operator was told was stopped.
    #[tokio::test]
    async fn an_automatic_restart_does_not_outlive_the_stop_it_raced() {
        let dir = tempfile::tempdir().unwrap();
        let app = App::new(
            test_config(Path::new("/nonexistent/netd.sock"), dir.path()),
            SupervisorClient::new("http://127.0.0.1:0"),
        );
        let work_dir = app.work_dir("vm-1").unwrap();
        std::fs::create_dir_all(work_dir.path()).unwrap();

        work_dir.set_started(false).unwrap();
        app.start_vm_with_restart_policy("vm-1", false)
            .await
            .expect("an automatic restart of a stopped VM does nothing");

        // The flag is the whole difference: with it set, the same call goes on
        // to do the work, and fails here for want of a VM to launch.
        work_dir.set_started(true).unwrap();
        assert!(app
            .start_vm_with_restart_policy("vm-1", false)
            .await
            .is_err());

        // An explicit start sets the flag itself and has nothing to re-read,
        // so it is never turned away by one.
        work_dir.set_started(false).unwrap();
        assert!(app.start_vm("vm-1").await.is_err());
    }

    /// The window a launch spends between reading "not running" and actually
    /// starting QEMU is long -- a GPU reset, a netd conversation -- and the
    /// sweep inside it deletes interfaces by deriving their names. Two entrants
    /// in that window meant the loser deleting the winner's live TAPs.
    #[tokio::test]
    async fn one_vm_launches_at_a_time_and_the_lock_map_stays_small() {
        let app = test_app();
        let held = app.launch_lock("vm-1").await;

        // A different VM is never blocked by it: a slow start must not stall
        // every other launch on the node.
        let other = tokio::time::timeout(Duration::from_millis(50), app.launch_lock("vm-2")).await;
        assert!(other.is_ok(), "an unrelated VM must not wait");

        // The same VM is.
        let same = tokio::time::timeout(Duration::from_millis(50), app.launch_lock("vm-1")).await;
        assert!(same.is_err(), "a second entrant must wait for the first");

        drop(held);
        drop(other);
        tokio::time::timeout(Duration::from_millis(50), app.launch_lock("vm-1"))
            .await
            .expect("the lock is released");

        // Nothing is in flight now, so the map holds nothing either.
        assert!(app.launch_locks.lock().unwrap().len() <= 1);
        let _ = app.launch_lock("vm-3").await;
        assert!(app.launch_locks.lock().unwrap().len() <= 2);
    }

    #[test]
    fn accepts_server_generated_ids() {
        validate_vm_id(&uuid::Uuid::new_v4().to_string()).unwrap();
        validate_vm_id("3f2504e0-4f89-41d3-9a0c-0305e82c3301").unwrap();
        validate_vm_id("vm_1-A").unwrap();
    }

    #[test]
    fn rejects_ids_that_would_escape_run_path() {
        for id in [
            "",
            "..",
            "../../etc",
            "/etc/passwd",
            "a/b",
            "a\\b",
            "vm id",
            ".",
            "\0",
            "café",
        ] {
            assert!(validate_vm_id(id).is_err(), "should reject {id:?}");
        }
        assert!(validate_vm_id(&"a".repeat(65)).is_err());
    }

    use crate::config::{
        load_config_figment, CvmPlatform, NetworkingMode, TdxAttestationVariantConfig,
    };
    use dstack_types::{
        TdxImageMeasurement, TdxMrtdCandidates, TdxOsImageMeasurement,
        TdxOsImageMeasurementDocument, TdxTdvfMeasurement,
    };
    use rocket::figment::Figment;
    use std::time::UNIX_EPOCH;

    fn reserve(running: &[(&str, u32)], in_memory: &[(&str, u32)]) -> Vec<(u32, String)> {
        let running: HashMap<String, u32> = running
            .iter()
            .map(|(id, cid)| (id.to_string(), *cid))
            .collect();
        cids_to_reserve(
            &running,
            in_memory.iter().map(|(id, cid)| (id.to_string(), *cid)),
        )
        .into_iter()
        .collect()
    }

    #[test]
    fn stopped_vms_keep_their_cid_reserved_across_a_reload() {
        // "running" comes from the supervisor, so a stopped VM appears only in
        // memory. Reserving just the running set would free 1001 and let the
        // next allocate() hand it to a new VM.
        let reserved = reserve(
            &[("running-vm", 1000)],
            &[("running-vm", 1000), ("stopped-vm", 1001)],
        );
        assert_eq!(
            reserved,
            vec![
                (1000, "running-vm".to_string()),
                (1001, "stopped-vm".to_string()),
            ]
        );
    }

    #[test]
    fn a_vm_both_running_and_in_memory_is_reserved_once() {
        let reserved = reserve(&[("vm-a", 1000)], &[("vm-a", 1000)]);
        assert_eq!(reserved, vec![(1000, "vm-a".to_string())]);
    }

    #[test]
    fn running_state_wins_when_memory_disagrees_about_the_owner() {
        // The supervisor knows who actually holds the CID right now.
        let reserved = reserve(&[("live-owner", 1000)], &[("stale-owner", 1000)]);
        assert_eq!(reserved, vec![(1000, "live-owner".to_string())]);
    }

    #[test]
    fn nothing_is_reserved_when_no_vm_holds_a_cid() {
        assert!(reserve(&[], &[]).is_empty());
    }

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }
    fn restart_config() -> crate::config::AutoRestartConfig {
        crate::config::AutoRestartConfig {
            enabled: true,
            interval: 1,
            max_retries: 3,
            initial_backoff: 2,
            max_backoff: 5,
            reset_window: 10,
        }
    }

    #[test]
    fn serial_log_is_rotatable_only_when_the_annotation_confirms_it() {
        // A VM launched by the current binary.
        let current = serde_json::to_string(&ProcessAnnotation {
            kind: "cvm".into(),
            live_for: None,
            serial_logappend: true,
        })
        .unwrap();
        assert!(serial_log_is_rotatable(&current));

        // A VM inherited from a VMM that predates the option: its QEMU holds
        // the log without O_APPEND, so truncating it would punch a sparse hole
        // and the file would spring straight back over the cap.
        assert!(!serial_log_is_rotatable(r#"{"kind":"cvm"}"#));
        assert!(!serial_log_is_rotatable(
            r#"{"kind":"cvm","live_for":null}"#
        ));

        // Anything we cannot read must answer conservatively.
        assert!(!serial_log_is_rotatable(""));
        assert!(!serial_log_is_rotatable("not json"));
        assert!(!serial_log_is_rotatable(r#"{"serial_logappend":"yes"}"#));
    }

    #[test]
    fn cvm_annotation_marks_the_serial_log_rotatable() {
        // The flag must survive the round trip the supervisor performs, and
        // must not disturb how existing consumers classify the process.
        let note = serde_json::to_string(&ProcessAnnotation {
            kind: "cvm".into(),
            live_for: None,
            serial_logappend: true,
        })
        .unwrap();
        let parsed: ProcessAnnotation = serde_json::from_str(&note).unwrap();
        assert!(parsed.serial_logappend);
        assert!(parsed.is_cvm());
    }

    #[test]
    fn rotatable_logs_always_include_supervisor_written_logs() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let workdir = VmWorkDir::new(temp.path());

        // A VM inherited from an older VMM: QEMU holds serial.log without
        // O_APPEND, so rotating it would punch a sparse hole. stdout and stderr
        // are the supervisor's, always opened with append(true), so they stay
        // eligible and keep their cap across a VMM upgrade.
        let inherited = rotatable_logs(&workdir, false);
        assert_eq!(
            inherited,
            vec![workdir.stdout_file(), workdir.stderr_file()]
        );

        let launched = rotatable_logs(&workdir, true);
        assert_eq!(
            launched,
            vec![
                workdir.stdout_file(),
                workdir.stderr_file(),
                workdir.serial_file()
            ]
        );
        Ok(())
    }

    #[test]
    fn log_retention_defaults() -> Result<()> {
        // These come from the shipped vmm.toml, not from serde defaults, so
        // this also pins that the values there parse into what they read as.
        let config = test_tdx_config()?;
        assert_eq!(config.cvm.log.max_bytes, 4 * 1024 * 1024);
        assert_eq!(config.cvm.log.max_backups, 3);
        assert_eq!(config.cvm.log.check_interval_secs, 5);
        Ok(())
    }

    #[test]
    fn auto_restart_policy_backs_off_caps_and_exhausts_once() {
        let config = restart_config();
        let start = std::time::Instant::now();
        let mut state = AutoRestartState::default();
        assert_eq!(
            state.observe_exited(start, &config),
            AutoRestartDecision::Scheduled { delay_secs: 2 }
        );
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(1), &config),
            AutoRestartDecision::Wait
        );
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(2), &config),
            AutoRestartDecision::Restart {
                attempt: 1,
                next_delay_secs: 4
            }
        );
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(6), &config),
            AutoRestartDecision::Restart {
                attempt: 2,
                next_delay_secs: 5
            }
        );
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(11), &config),
            AutoRestartDecision::Restart {
                attempt: 3,
                next_delay_secs: 5
            }
        );
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(12), &config),
            AutoRestartDecision::Exhausted { attempts: 3 }
        );
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(20), &config),
            AutoRestartDecision::Wait
        );
    }

    #[test]
    fn auto_restart_policy_resets_only_after_healthy_window() {
        let config = restart_config();
        let start = std::time::Instant::now();
        let mut state = AutoRestartState::default();
        state.observe_exited(start, &config);
        state.observe_exited(start + std::time::Duration::from_secs(2), &config);
        assert!(!state.observe_running(start + std::time::Duration::from_secs(3), 10));
        assert!(!state.observe_running(start + std::time::Duration::from_secs(12), 10));
        assert!(state.observe_running(start + std::time::Duration::from_secs(13), 10));
        assert_eq!(state.attempts, 0);
        assert_eq!(
            state.observe_exited(start + std::time::Duration::from_secs(14), &config),
            AutoRestartDecision::Scheduled { delay_secs: 2 }
        );
    }

    #[test]
    fn simulator_config_is_written_separately_with_measurement_inputs() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let config = dstack_types::TeeSimulatorConfig {
            platform: dstack_types::TeeVariant::DstackAmdSevSnp,
            mock_attestation_seed: Some("11".repeat(32)),
            collateral_base_url: Some("http://127.0.0.1:18088".into()),
            ..Default::default()
        };
        let mr_config = r#"{"version":3}"#;
        let vm_config = format!(
            r#"{{"image":"dev","aws_pcr_replay":{{"version":1,"events":[],"pcr4":"{zero}","pcr7":"{zero}","pcr12":"{zero}"}},"gcp_tpm_replay":{{"event_log":"AQID"}}}}"#,
            zero = "00".repeat(48)
        );
        let sys_config = serde_json::json!({
            "kms_urls": [],
            "gateway_urls": [],
            "vm_config": vm_config,
            "mr_config": mr_config,
        })
        .to_string();

        sync_tee_simulator_config(dir.path(), Some(&config), &sys_config)?;

        let written: dstack_types::TeeSimulatorConfig =
            serde_json::from_slice(&fs::read(dir.path().join(TEE_SIMULATOR_CONFIG))?)?;
        assert_eq!(written.platform, config.platform);
        assert_eq!(written.mock_attestation_seed, config.mock_attestation_seed);
        assert_eq!(written.collateral_base_url, config.collateral_base_url);
        assert_eq!(written.mr_config.as_deref(), Some(mr_config));
        assert_eq!(written.vm_config.as_deref(), Some(vm_config.as_str()));
        assert_eq!(
            written.aws_pcr_replay.as_ref().map(|replay| replay.version),
            Some(1)
        );
        assert_eq!(
            written
                .gcp_tpm_replay
                .as_ref()
                .map(|replay| replay.event_log.as_slice()),
            Some([1, 2, 3].as_slice())
        );

        sync_tee_simulator_config(dir.path(), None, &sys_config)?;
        assert!(!dir.path().join(TEE_SIMULATOR_CONFIG).exists());
        Ok(())
    }

    #[test]
    fn instance_platform_overrides_node_simulator_template() -> Result<()> {
        let mut config = test_tdx_config()?;
        config.cvm.tee_simulator = Some(dstack_types::TeeSimulatorConfig {
            platform: dstack_types::TeeVariant::DstackTdx,
            mock_attestation_seed: Some("11".repeat(32)),
            ..Default::default()
        });
        let mut manifest = test_manifest(2048);
        assert!(simulator_config_for_manifest(&config.cvm, &manifest)?.is_none());
        manifest.simulated_tee = Some(dstack_types::TeeVariant::DstackNitroEnclave);

        let resolved = simulator_config_for_manifest(&config.cvm, &manifest)?
            .context("simulator config should be enabled")?;

        assert_eq!(
            resolved.platform,
            dstack_types::TeeVariant::DstackNitroEnclave
        );
        Ok(())
    }

    #[test]
    fn gpu_config_has_gpus_only_when_resolved_gpu_list_is_non_empty() {
        assert!(!GpuConfig::default().has_gpus());
        assert!(!GpuConfig {
            attach_mode: AttachMode::All,
            ..Default::default()
        }
        .has_gpus());
        assert!(!GpuConfig {
            bridges: vec![GpuSpec {
                slot: "0000:01:00.0".into(),
            }],
            ..Default::default()
        }
        .has_gpus());
        assert!(GpuConfig {
            gpus: vec![GpuSpec {
                slot: "0000:02:00.0".into(),
            }],
            ..Default::default()
        }
        .has_gpus());
    }

    #[test]
    fn put_manifest_keeps_legacy_networking_for_rollback() -> Result<()> {
        let temp = std::env::temp_dir().join(format!(
            "dstack-vmm-manifest-test-{}",
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        let workdir = VmWorkDir::new(&temp);
        let mut manifest = test_manifest(1024);
        manifest.networks = vec![NicNetworking {
            mode: NetworkingMode::Bridge,
            bridge: "dstack-br0".to_string(),
            ..NicNetworking::default()
        }];

        workdir.put_manifest(&manifest)?;
        let raw = fs::read_to_string(workdir.manifest_path())?;
        let value: serde_json::Value = serde_json::from_str(&raw)?;
        assert_eq!(value["networks"].as_array().map(Vec::len), Some(1));
        assert_eq!(value["networking"]["mode"], "bridge");
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn manifest_deserializes_legacy_singular_networking_as_networks() {
        let manifest: Manifest = Manifest::from_json(serde_json::json!({
            "id": "vm-1",
            "name": "vm-1",
            "app_id": "app-1",
            "vcpu": 1,
            "memory": 1024,
            "disk_size": 10,
            "image": "dstack-test",
            "port_map": [],
            "created_at_ms": 0,
            "networking": { "mode": "bridge", "bridge": "dstack-br0" }
        }))
        .unwrap();

        assert_eq!(manifest.networks.len(), 1);
        assert_eq!(manifest.networks[0].mode, NetworkingMode::Bridge);
        assert_eq!(manifest.networks[0].bridge, "dstack-br0");
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

    fn test_manifest(memory: u32) -> Manifest {
        Manifest {
            id: "tdx-test".to_string(),
            name: "tdx-test".to_string(),
            app_id: hex_of(0x11, 20),
            vcpu: 2,
            memory,
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
            simulated_tee: None,
            swtpm: false,
            networks: vec![],
            volumes: vec![],
        }
    }

    #[test]
    fn selects_mr_config_version_for_each_tee_mode() -> Result<()> {
        let manifest = test_manifest(2048);
        assert_eq!(
            mr_config_version(&manifest, CvmPlatform::AmdSevSnp, false, false)?,
            Some(MrConfigVersion::V3)
        );
        assert_eq!(
            mr_config_version(&manifest, CvmPlatform::Tdx, false, false)?,
            None
        );
        assert_eq!(
            mr_config_version(&manifest, CvmPlatform::Tdx, true, false)?,
            Some(MrConfigVersion::V1)
        );
        assert_eq!(
            mr_config_version(&manifest, CvmPlatform::Tdx, true, true)?,
            Some(MrConfigVersion::V3)
        );
        assert_eq!(
            mr_config_version(&manifest, CvmPlatform::Tdx, false, true)
                .err()
                .map(|error| error.to_string()),
            Some("key provider ID requires MrConfigV3, but use_mrconfigid is disabled".to_string())
        );

        let mut no_tee = manifest.clone();
        no_tee.no_tee = true;
        assert_eq!(
            mr_config_version(&no_tee, CvmPlatform::AmdSevSnp, true, true)?,
            None
        );

        no_tee.simulated_tee = Some(dstack_types::TeeVariant::DstackAmdSevSnp);
        assert_eq!(
            mr_config_version(&no_tee, CvmPlatform::Tdx, false, false)?,
            Some(MrConfigVersion::V3)
        );
        Ok(())
    }

    fn dummy_tdx_measurement_document() -> TdxOsImageMeasurementDocument {
        let measurement = TdxOsImageMeasurement {
            image: TdxImageMeasurement {
                kernel_cmdline_sha384: vec![0x10; 48],
                kernel_authenticode: vec![0x20; 48],
                initrd_sha384: vec![0x30; 48],
            },
            tdvf: TdxTdvfMeasurement {
                ovmf_variant: Default::default(),
                mrtd: TdxMrtdCandidates {
                    single_pass: vec![0x40; 48],
                    two_pass: vec![0x50; 48],
                },
                td_hob_witness: vec![0x60; 16],
            },
        };
        let measurement = measurement.to_cbor_vec();
        let sha256sum = format!(
            "{}  {}\n",
            hex::encode(Sha256::digest(&measurement)),
            dstack_types::TDX_MEASUREMENT_FILENAME
        )
        .into_bytes();
        TdxOsImageMeasurementDocument::new(sha256sum, measurement)
    }

    fn test_tdx_image(supports_lite: bool) -> Image {
        let tdx_measurement = supports_lite.then(dummy_tdx_measurement_document);
        Image {
            info: ImageInfo {
                cmdline: None,
                kernel: "kernel".to_string(),
                initrd: "initrd".to_string(),
                hda: None,
                rootfs: None,
                bios: None,
                bios_sev: None,
                rootfs_hash: None,
                shared_ro: false,
                version: "0.6.0".to_string(),
                is_dev: false,
                ovmf_variant: None,
            },
            initrd: PathBuf::from("initrd"),
            kernel: PathBuf::from("kernel"),
            hda: None,
            rootfs: None,
            bios: None,
            bios_sev: None,
            digest: Some(hex_of(0xaa, 32)),
            tdx_measurement,
            sev_measurement: None,
            gcp_measurement: None,
            aws_measurement: None,
            aws_pcr_replay: None,
            gcp_tpm_replay: None,
        }
    }

    fn test_tdx_config() -> Result<Config> {
        let mut config: Config = Figment::from(load_config_figment(None)).extract()?;
        config.cvm.platform = Some(CvmPlatform::Tdx);
        config.cvm.tdx_attestation_variant = TdxAttestationVariantConfig::Auto;
        Ok(config)
    }

    #[test]
    fn effective_vcpu_count_clamps_zero_to_one() {
        assert_eq!(effective_vcpu_count(0, None), 1);
        assert_eq!(effective_vcpu_count(0, Some(1)), 1);
    }

    #[test]
    fn effective_vcpu_count_rounds_for_hugepage_numa_split() {
        assert_eq!(effective_vcpu_count(3, Some(2)), 4);
        assert_eq!(effective_vcpu_count(4, Some(2)), 4);
        assert_eq!(effective_vcpu_count(3, Some(0)), 3);
        assert_eq!(effective_vcpu_count(3, None), 3);
    }

    #[test]
    fn vm_measurement_config_ignores_networking_changes() -> Result<()> {
        let config = test_tdx_config()?;
        let mut bridge_manifest = test_manifest(2048);
        bridge_manifest.networks = vec![NicNetworking {
            mode: NetworkingMode::Bridge,
            bridge: "dstack-br0".to_string(),
            ..NicNetworking::default()
        }];
        let user_manifest = test_manifest(2048);
        let image = test_tdx_image(true);
        let compose_hash = hex_of(0x22, 32);

        let bridge_config =
            make_vm_config(&config, &bridge_manifest, &image, &compose_hash, None, None)?;
        let user_config =
            make_vm_config(&config, &user_manifest, &image, &compose_hash, None, None)?;

        assert_eq!(bridge_config, user_config);
        Ok(())
    }

    #[test]
    fn vm_measurement_config_includes_verity_volume_count() -> Result<()> {
        let config = test_tdx_config()?;
        let mut manifest = test_manifest(2048);
        manifest.volumes = vec![
            VmVolume {
                source: "/volumes/a.img".into(),
            },
            VmVolume {
                source: "/volumes/b.img".into(),
            },
        ];
        let vm_config = make_vm_config(
            &config,
            &manifest,
            &test_tdx_image(true),
            &hex_of(0x22, 32),
            None,
            None,
        )?;

        assert_eq!(vm_config["num_verity_volumes"], 2);
        Ok(())
    }

    #[test]
    fn vm_measurement_config_includes_swtpm() -> Result<()> {
        let config = test_tdx_config()?;
        let mut manifest = test_manifest(2048);
        manifest.swtpm = true;

        let vm_config = make_vm_config(
            &config,
            &manifest,
            &test_tdx_image(true),
            &hex_of(0x22, 32),
            None,
            None,
        )?;

        assert_eq!(vm_config["swtpm"], true);
        Ok(())
    }

    #[test]
    fn tdx_auto_variant_uses_legacy_for_low_non_2g_memory() -> Result<()> {
        let config = test_tdx_config()?;
        let manifest = test_manifest(1024);
        let image = test_tdx_image(true);
        let vm_config = make_vm_config(&config, &manifest, &image, &hex_of(0x22, 32), None, None)?;

        assert!(vm_config.get("tdx_attestation_variant").is_none());
        // tdx_measurement is attached whenever the image supports it, even
        // when the resolved variant is legacy, so a verifier can still
        // choose lite verification for this boot.
        assert!(vm_config.get("tdx_measurement").is_some());
        assert_eq!(
            vm_config["os_image_hash"]
                .as_str()
                .context("os_image_hash must be a string")?,
            hex_of(0xaa, 32)
        );
        Ok(())
    }

    #[test]
    fn tdx_auto_variant_uses_lite_for_2g_supported_image() -> Result<()> {
        let config = test_tdx_config()?;
        let manifest = test_manifest(2048);
        let image = test_tdx_image(true);
        let vm_config = make_vm_config(&config, &manifest, &image, &hex_of(0x22, 32), None, None)?;

        assert_eq!(vm_config["tdx_attestation_variant"], "lite");
        assert!(vm_config.get("tdx_measurement").is_some());
        assert_eq!(
            vm_config["os_image_hash"]
                .as_str()
                .context("os_image_hash must be a string")?,
            hex_of(0xaa, 32)
        );
        Ok(())
    }

    #[test]
    fn tdx_auto_variant_falls_back_to_legacy_when_image_lacks_lite_support() -> Result<()> {
        let config = test_tdx_config()?;
        let manifest = test_manifest(3072);
        let image = test_tdx_image(false);
        let vm_config = make_vm_config(&config, &manifest, &image, &hex_of(0x22, 32), None, None)?;

        assert!(vm_config.get("tdx_attestation_variant").is_none());
        assert!(vm_config.get("tdx_measurement").is_none());
        assert_eq!(
            vm_config["os_image_hash"]
                .as_str()
                .context("os_image_hash must be a string")?,
            hex_of(0xaa, 32)
        );
        Ok(())
    }

    #[test]
    fn tdx_requirements_measure_acpi_tables_overrides_lite_to_legacy() -> Result<()> {
        let mut config = test_tdx_config()?;
        config.cvm.tdx_attestation_variant = TdxAttestationVariantConfig::Lite;
        let manifest = test_manifest(2048);
        let image = test_tdx_image(true);
        let requirements = dstack_types::Requirements {
            tdx_measure_acpi_tables: Some(true),
            ..Default::default()
        };
        let vm_config = make_vm_config(
            &config,
            &manifest,
            &image,
            &hex_of(0x22, 32),
            None,
            Some(&requirements),
        )?;

        assert!(vm_config.get("tdx_attestation_variant").is_none());
        // Still attached even though the requirement forced this boot to
        // legacy: a verifier can independently choose lite for it.
        assert!(vm_config.get("tdx_measurement").is_some());
        Ok(())
    }

    #[test]
    fn tdx_requirements_skip_acpi_tables_overrides_legacy_to_lite() -> Result<()> {
        let mut config = test_tdx_config()?;
        config.cvm.tdx_attestation_variant = TdxAttestationVariantConfig::Legacy;
        let manifest = test_manifest(2048);
        let image = test_tdx_image(true);
        let requirements = dstack_types::Requirements {
            tdx_measure_acpi_tables: Some(false),
            ..Default::default()
        };
        let vm_config = make_vm_config(
            &config,
            &manifest,
            &image,
            &hex_of(0x22, 32),
            None,
            Some(&requirements),
        )?;

        assert_eq!(vm_config["tdx_attestation_variant"], "lite");
        assert!(vm_config.get("tdx_measurement").is_some());
        Ok(())
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
        config.cvm.platform = Some(CvmPlatform::AmdSevSnp);
        config.cvm.nvidia_attestation_proxy_url = Some("http://10.0.2.2:8090".to_string());
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
            simulated_tee: None,
            swtpm: false,
            networks: vec![],
            volumes: vec![],
        };

        let mr_config = MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            None,
            dstack_types::KeyProviderKind::None,
            vec![],
            vec![0x44; 20],
        )
        .to_canonical_json();

        // The image build emits split SNP measurement CBOR, includes it in
        // sha256sum.txt, and keeps digest.txt as sha256(sha256sum.txt).
        let snp_cbor = dstack_mr::sev::sev_os_image_measurement_cbor_for_image_dir(&image_dir)?;
        fs::write(
            image_dir.join(dstack_types::SNP_MEASUREMENT_FILENAME),
            &snp_cbor,
        )?;
        let mut sha256sum = String::new();
        for name in [
            "ovmf.fd",
            "kernel",
            "initrd",
            "metadata.json",
            dstack_types::SNP_MEASUREMENT_FILENAME,
        ] {
            sha256sum.push_str(&format!(
                "{}  {}\n",
                hex::encode(Sha256::digest(fs::read(image_dir.join(name))?)),
                name
            ));
        }
        fs::write(image_dir.join("sha256sum.txt"), &sha256sum)?;
        let build_hash = Sha256::digest(sha256sum.as_bytes()).to_vec();
        fs::write(image_dir.join("digest.txt"), hex::encode(&build_hash))?;

        let sys_config_document =
            make_sys_config(&config, &manifest, &compose_hash, Some(mr_config), None)?;
        let sys_config: serde_json::Value = serde_json::from_str(&sys_config_document)?;
        assert!(sys_config.get("tee_simulator").is_none());
        // A host must never nominate the trust anchor that authenticates its
        // guest's key provider, in any deployment mode. Simulated guests derive
        // their own roots from the seed in `.tee-simulator.json` instead.
        for key in sys_config
            .as_object()
            .context("sys-config must be an object")?
            .keys()
        {
            assert!(
                !key.contains("root_ca") && !key.contains("trust_anchor"),
                "sys-config must not carry an attestation trust anchor: {key}"
            );
        }
        assert_eq!(sys_config["pccs_url"], config.cvm.pccs_url);
        assert_eq!(sys_config["collateral_urls"]["pccs"], config.cvm.pccs_url);
        let vm_config: serde_json::Value = serde_json::from_str(
            sys_config["vm_config"]
                .as_str()
                .context("vm_config must be a string")?,
        )?;
        let measurement_document = vm_config["sev_snp_measurement"]
            .as_str()
            .context("sev_snp_measurement must be a string")?;
        let measurement: dstack_mr::sev::SnpMeasurementDocument =
            serde_json::from_str(measurement_document)?;
        let image_measurement =
            dstack_types::SevOsImageMeasurement::from_cbor_slice(&measurement.measurement)
                .map_err(anyhow::Error::msg)?;
        let mr_config_document = sys_config["mr_config"]
            .as_str()
            .context("mr_config must be a string")?;
        let parsed_mr_config = MrConfigV3::from_document(mr_config_document)?;

        assert_eq!(
            sys_config["nvidia_attestation_proxy_url"],
            "http://10.0.2.2:8090"
        );
        assert_eq!(parsed_mr_config.app_id, Some(vec![0x11; 20]));
        assert_eq!(parsed_mr_config.compose_hash, vec![0x22; 32]);
        assert_eq!(parsed_mr_config.gpu_policy_hash, None);
        assert_eq!(vm_config["mr_config"], sys_config["mr_config"]);
        assert_eq!(
            vm_config["os_image_hash"]
                .as_str()
                .context("os_image_hash must be a string")?,
            hex::encode(&build_hash),
            "vm_config os_image_hash must come from digest.txt"
        );
        assert_eq!(
            image_measurement.base_cmdline,
            format!("console=ttyS0 dstack.rootfs_hash={}", hex_of(0x33, 32))
        );
        assert_eq!(
            image_measurement.kernel_hash,
            Sha256::digest(b"snp-test-kernel").to_vec()
        );
        assert_eq!(
            image_measurement.initrd_hash,
            Sha256::digest(b"snp-test-initrd").to_vec()
        );
        assert_eq!(measurement.vcpus, 2);
        assert_eq!(measurement.vcpu_type.as_deref(), Some("EPYC-v4"));
        assert_eq!(measurement.guest_features, 1);
        assert_eq!(
            image_measurement.ovmf_hash.len(),
            48,
            "ovmf_hash must be 48 bytes"
        );
        assert_eq!(image_measurement.sev_hashes_table_gpa, 0x4000);
        assert_eq!(image_measurement.sev_es_reset_eip, 0xffff_fff0u32);
        assert_eq!(image_measurement.ovmf_sections.len(), 4);
        dstack_types::SevOsImageMeasurementDocument::new(
            measurement.checksum_file,
            measurement.measurement,
        )
        .verify(&build_hash)
        .map_err(anyhow::Error::msg)?;
        Ok(())
    }
}

/// CIDs that must survive a pool rebuild, mapped to the VM that owns each one.
///
/// Running processes are the authoritative source for CIDs currently on the
/// wire, but they are not the whole picture: a stopped VM still records its CID
/// in `vm.config.cid` and keeps it on restart, so it has to stay reserved too.
/// Reserving only the running set would let `allocate()` hand the same CID to a
/// new VM, and the two would collide the moment the stopped one starts.
///
/// Keyed by CID so a VM that is both running and in memory is reserved once.
fn cids_to_reserve(
    running: &HashMap<String, u32>,
    in_memory: impl Iterator<Item = (String, u32)>,
) -> BTreeMap<u32, String> {
    let mut reserved: BTreeMap<u32, String> = in_memory.map(|(id, cid)| (cid, id)).collect();
    reserved.extend(running.iter().map(|(id, cid)| (*cid, id.clone())));
    reserved
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

/// Per-process retry bookkeeping; intentionally reset whenever the VMM restarts.
#[derive(Debug, Clone, Default)]
struct AutoRestartState {
    attempts: u32,
    next_retry: Option<std::time::Instant>,
    healthy_since: Option<std::time::Instant>,
    exhausted_reported: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AutoRestartDecision {
    Wait,
    Scheduled { delay_secs: u64 },
    Restart { attempt: u32, next_delay_secs: u64 },
    Exhausted { attempts: u32 },
}

impl AutoRestartState {
    fn reset(&mut self) {
        *self = Self::default();
    }

    fn observe_running(&mut self, now: std::time::Instant, reset_window: u64) -> bool {
        let healthy_since = self.healthy_since.get_or_insert(now);
        if self.attempts > 0
            && now.duration_since(*healthy_since) >= std::time::Duration::from_secs(reset_window)
        {
            self.reset();
            return true;
        }
        false
    }

    fn observe_exited(
        &mut self,
        now: std::time::Instant,
        config: &crate::config::AutoRestartConfig,
    ) -> AutoRestartDecision {
        self.healthy_since = None;
        if self.attempts >= config.max_retries {
            if self.exhausted_reported {
                return AutoRestartDecision::Wait;
            }
            self.exhausted_reported = true;
            return AutoRestartDecision::Exhausted {
                attempts: self.attempts,
            };
        }
        let Some(next_retry) = self.next_retry else {
            self.next_retry = Some(now + std::time::Duration::from_secs(config.initial_backoff));
            return AutoRestartDecision::Scheduled {
                delay_secs: config.initial_backoff,
            };
        };
        if now < next_retry {
            return AutoRestartDecision::Wait;
        }
        self.attempts += 1;
        let shift = self.attempts.min(63);
        let delay_secs = config
            .initial_backoff
            .saturating_mul(1u64 << shift)
            .min(config.max_backoff);
        self.next_retry = Some(now + std::time::Duration::from_secs(delay_secs));
        AutoRestartDecision::Restart {
            attempt: self.attempts,
            next_delay_secs: delay_secs,
        }
    }
}

#[derive(Debug, Clone, Default)]
struct VmStateMut {
    boot_progress: String,
    boot_error: String,
    shutdown_progress: String,
    runtime_networks: Vec<Networking>,
    devices: GpuConfig,
    events: VecDeque<pb::GuestEvent>,
    auto_restart: AutoRestartState,
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

/// Reject VM ids that would escape `run_path` once joined into a filesystem
/// path. Ids are server-generated UUIDs, so hex digits plus `-` covers every
/// legitimate value; `Path::join` replaces the base outright on an absolute
/// path, and `..` walks out of it, so neither may reach the join.
pub(crate) fn validate_vm_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 64
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("invalid VM id");
    }
    Ok(())
}
