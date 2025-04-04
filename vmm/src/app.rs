use crate::config::{Config, ProcessNote, Protocol};

use anyhow::{bail, Context, Result};
use bon::Builder;
use dstack_kms_rpc::kms_client::KmsClient;
use dstack_types::shared_filenames::{
    compat_v3, APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, SYS_CONFIG, USER_CONFIG,
};
use dstack_vmm_rpc::{self as pb, GpuInfo, StatusRequest, StatusResponse, VmConfiguration};
use fs_err as fs;
use guest_api::client::DefaultClient as GuestClient;
use id_pool::IdPool;
use ra_rpc::client::RaClient;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use supervisor_client::SupervisorClient;
use tracing::{error, info};

pub use image::{Image, ImageInfo};
pub use qemu::{VmConfig, VmWorkDir};

mod id_pool;
mod image;
mod qemu;

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
    #[serde(default)]
    pub gpus: Vec<GpuSpec>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GpuSpec {
    #[serde(default)]
    pub product_id: String,
    #[serde(default)]
    pub slot: String,
}

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub supervisor: SupervisorClient,
    state: Arc<Mutex<AppState>>,
}

impl App {
    fn lock(&self) -> MutexGuard<AppState> {
        self.state.lock().unwrap()
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
        let devices = if !config.cvm.gpu.enabled {
            Vec::new()
        } else {
            match config.cvm.gpu.list_devices() {
                Ok(devices) => devices,
                Err(e) => {
                    error!("Failed to list GPU devices: {e:?}");
                    Vec::new()
                }
            }
        };
        let gpu_pool = devices
            .into_iter()
            .map(|d| DeviceState {
                allocated: false,
                pci_in_use: d.in_use(),
                product_id: d.full_product_id(),
                description: d.description,
                slot: d.slot,
            })
            .collect();

        Self {
            supervisor: supervisor.clone(),
            state: Arc::new(Mutex::new(AppState {
                cid_pool,
                gpu_pool,
                vms: HashMap::new(),
            })),
            config: Arc::new(config),
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
        let image_path = self.config.image_path.join(&manifest.image);
        let image = Image::load(&image_path).context("Failed to load image")?;
        let vm_id = manifest.id.clone();
        {
            let mut teapot = self.lock();
            let cid = teapot
                .get(&vm_id)
                .map(|vm| vm.config.cid)
                .or_else(|| cids_assigned.get(&vm_id).cloned())
                .or_else(|| teapot.cid_pool.allocate())
                .context("CID pool exhausted")?;
            let vm_config = VmConfig {
                manifest,
                image,
                cid,
                networking: self.config.networking.clone(),
                workdir: vm_work_dir.path().to_path_buf(),
            };
            if vm_config.manifest.disk_size > self.config.cvm.max_disk_size {
                bail!(
                    "disk size too large, max size is {}",
                    self.config.cvm.max_disk_size
                );
            }
            teapot.add(VmState::new(vm_config));
        };
        if auto_start && vm_work_dir.started().unwrap_or_default() {
            self.start_vm(&vm_id).await?;
        }
        Ok(())
    }

    pub async fn start_vm(&self, id: &str) -> Result<()> {
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

            self.refresh_gpu_state().await?;
            let devices = self.try_allocate_gpus(&vm_config.manifest)?;
            let process_config = vm_config.config_qemu(&work_dir, &self.config.cvm, &devices)?;
            self.supervisor
                .deploy(process_config)
                .await
                .with_context(|| format!("Failed to start VM {id}"))?;

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

    pub fn release_devices(&self, id: &str) -> Result<()> {
        let mut state = self.lock();
        let vm_state = state.get_mut(id).context("VM not found")?;
        vm_state.state.devices.clear();
        Ok(())
    }

    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        self.set_started(id, false)?;
        self.supervisor.stop(id).await?;
        self.release_devices(id)?;
        Ok(())
    }

    pub async fn remove_vm(&self, id: &str) -> Result<()> {
        let info = self.supervisor.info(id).await?;
        let is_running = info.as_ref().is_some_and(|i| i.state.status.is_running());
        if is_running {
            bail!("VM is running, stop it first");
        }

        if let Some(info) = info {
            if !info.state.status.is_stopped() {
                self.supervisor.stop(id).await?;
            }
            self.supervisor.remove(id).await?;
        }

        {
            let mut state = self.lock();
            if let Some(vm_state) = state.remove(id) {
                state.cid_pool.free(vm_state.config.cid);
            }
        }

        let vm_path = self.work_dir(id);
        fs::remove_dir_all(&vm_path).context("Failed to remove VM directory")?;
        Ok(())
    }

    pub async fn reload_vms(&self) -> Result<()> {
        let vm_path = self.vm_dir();
        let running_vms = self.supervisor.list().await.context("Failed to list VMs")?;
        let occupied_devices: HashMap<String, Vec<String>> = running_vms
            .iter()
            .filter(|p| p.state.status.is_running())
            .map(|p| {
                let note: ProcessNote = serde_json::from_str(&p.config.note).unwrap_or_default();
                (p.config.id.clone(), note.devices.clone())
            })
            .collect();
        let occupied_cids = running_vms
            .iter()
            .flat_map(|p| p.config.cid.map(|cid| (p.config.id.clone(), cid)))
            .collect::<HashMap<_, _>>();
        {
            let mut state = self.lock();
            for cid in occupied_cids.values() {
                state.cid_pool.occupy(*cid)?;
            }
            for slot in occupied_devices.values().flat_map(|od| od.iter()) {
                let Some(gpu) = state.gpu_pool.iter_mut().find(|gpu| gpu.slot == *slot) else {
                    continue;
                };
                info!("Occupied GPU: {slot}");
                gpu.allocated = true;
            }
        }
        if vm_path.exists() {
            for entry in fs::read_dir(vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_path = entry.path();
                if vm_path.is_dir() {
                    if let Err(err) = self.load_vm(vm_path, &occupied_cids, true).await {
                        error!("Failed to load VM: {err:?}");
                    }
                }
            }
        }
        {
            let mut state = self.lock();
            for vm in state.vms.values_mut() {
                if let Some(od) = occupied_devices.get(&vm.config.manifest.id) {
                    vm.state.devices = od.to_vec();
                }
            }
        }
        Ok(())
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
            .map(|info| info.to_pb(&self.config.gateway))
            .collect::<Vec<_>>();
        Ok(StatusResponse {
            vms,
            port_mapping_enabled: self.config.cvm.port_mapping.enabled,
            total,
        })
    }

    pub fn list_images(&self) -> Result<Vec<(String, ImageInfo)>> {
        let image_path = self.config.image_path.clone();
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
            .to_pb(&self.config.gateway);
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
            let instance_info = serde_json::json!({
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
        let image_path = cfg.image_path.join(&manifest.image);
        let image_info = ImageInfo::load(image_path.join("metadata.json"))
            .context("Failed to load image info")?;
        let rootfs_hash = image_info
            .rootfs_hash
            .as_ref()
            .context("Rootfs hash not found in image info")?;
        let img_ver = image_info.version_tuple().unwrap_or((0, 0, 0));
        let sys_config = if img_ver >= (0, 4, 2) {
            serde_json::json!({
                "kms_urls": cfg.cvm.kms_urls,
                "gateway_urls": cfg.cvm.gateway_urls,
                "pccs_url": cfg.cvm.pccs_url,
                "docker_registry": cfg.cvm.docker_registry,
                "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
            })
        } else if img_ver >= (0, 4, 0) {
            serde_json::json!({
                "rootfs_hash": rootfs_hash,
                "kms_urls": cfg.cvm.kms_urls,
                "tproxy_urls": cfg.cvm.gateway_urls,
                "pccs_url": cfg.cvm.pccs_url,
                "docker_registry": cfg.cvm.docker_registry,
                "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
            })
        } else {
            serde_json::json!({
                "rootfs_hash": rootfs_hash,
                "kms_url": cfg.cvm.kms_urls.first(),
                "tproxy_url": cfg.cvm.gateway_urls.first(),
                "pccs_url": cfg.cvm.pccs_url,
                "docker_registry": cfg.cvm.docker_registry,
                "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
            })
        };
        let sys_config_str =
            serde_json::to_string(&sys_config).context("Failed to serialize vm config")?;
        let config_file = if img_ver >= (0, 4, 0) {
            SYS_CONFIG
        } else {
            compat_v3::SYS_CONFIG
        };
        fs::write(shared_dir.join(config_file), sys_config_str)
            .context("Failed to write vm config")?;
        if img_ver < (0, 4, 0) {
            // Sync .encrypted-env to encrypted-env
            let compat_encrypted_env_path = shared_dir.join(compat_v3::ENCRYPTED_ENV);
            let encrypted_env_path = shared_dir.join(ENCRYPTED_ENV);
            if compat_encrypted_env_path.exists() {
                fs::remove_file(&compat_encrypted_env_path)?;
            }
            if encrypted_env_path.exists() {
                fs::copy(&encrypted_env_path, &compat_encrypted_env_path)?;
            }

            // Sync certs
            let certs_dir = shared_dir.join("certs");
            fs::create_dir_all(&certs_dir).context("Failed to create certs directory")?;
            if cfg.cvm.ca_cert.is_empty()
                || cfg.cvm.tmp_ca_cert.is_empty()
                || cfg.cvm.tmp_ca_key.is_empty()
            {
                bail!("Certificates are required for older images");
            }
            fs::copy(&cfg.cvm.ca_cert, certs_dir.join("ca.cert"))
                .context("Failed to copy ca cert")?;
            fs::copy(&cfg.cvm.tmp_ca_cert, certs_dir.join("tmp-ca.cert"))
                .context("Failed to copy tmp ca cert")?;
            fs::copy(&cfg.cvm.tmp_ca_key, certs_dir.join("tmp-ca.key"))
                .context("Failed to copy tmp ca key")?;
        }
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

    async fn refresh_gpu_state(&self) -> Result<()> {
        if !self.config.cvm.gpu.enabled {
            return Ok(());
        }

        let pci_devices = self.config.cvm.gpu.list_devices()?;
        let used_slots = pci_devices
            .iter()
            .filter(|dev| dev.in_use())
            .map(|dev| dev.slot.clone())
            .collect::<HashSet<_>>();
        let mut state = self.lock();
        state.gpu_pool.iter_mut().for_each(|gpu| {
            gpu.pci_in_use = false;
            gpu.allocated = false;
        });
        for device in pci_devices {
            let Some(gpu) = state
                .gpu_pool
                .iter_mut()
                .find(|gpu| gpu.slot == device.slot)
            else {
                continue;
            };
            gpu.pci_in_use = device.in_use();
        }
        let mut allocated_devices = HashSet::new();
        for vm in state.vms.values() {
            if vm.config.manifest.gpus.is_empty() {
                continue;
            }
            allocated_devices.extend(
                vm.state
                    .devices
                    .iter()
                    .filter(|slot| used_slots.contains(*slot))
                    .cloned(),
            );
        }
        for gpu in state.gpu_pool.iter_mut() {
            if allocated_devices.contains(&gpu.slot) {
                gpu.allocated = true;
            }
        }
        Ok(())
    }

    fn try_allocate_gpus(&self, manifest: &Manifest) -> Result<Vec<String>> {
        if !self.config.cvm.gpu.enabled {
            return Ok(Vec::new());
        }
        let mut state = self.lock();
        let mut cloned_pool = state.gpu_pool.clone();
        let mut allocated_devices = Vec::new();

        for spec in &manifest.gpus {
            // If specific product_id or slot is requested, try to match it
            let gpu_index = if !spec.product_id.is_empty() || !spec.slot.is_empty() {
                cloned_pool.iter().position(|gpu| {
                    gpu.is_free()
                        && (spec.product_id.is_empty() || gpu.product_id == spec.product_id)
                        && (spec.slot.is_empty() || gpu.slot == spec.slot)
                })
            } else {
                // If no specific GPU is requested, allocate any available one
                cloned_pool.iter().position(|gpu| gpu.is_free())
            };

            match gpu_index {
                Some(index) => {
                    cloned_pool[index].allocated = true;
                    allocated_devices.push(cloned_pool[index].slot.clone());
                }
                None => bail!("No available GPU found"),
            }
        }
        state.gpu_pool = cloned_pool;

        Ok(allocated_devices)
    }

    pub(crate) async fn list_gpus(&self) -> Result<Vec<GpuInfo>> {
        if !self.config.cvm.gpu.enabled {
            return Ok(Vec::new());
        }
        self.refresh_gpu_state().await?;
        let state = self.lock();
        Ok(state
            .gpu_pool
            .iter()
            .map(|gpu| GpuInfo {
                slot: gpu.slot.clone(),
                product_id: gpu.product_id.clone(),
                description: gpu.description.clone(),
                is_free: gpu.is_free(),
            })
            .collect())
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
    devices: Vec<String>,
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

#[derive(Clone, Debug)]
pub(crate) struct DeviceState {
    /// Product ID of the device
    product_id: String,
    /// Description of the device
    description: String,
    /// Slot of the device
    slot: String,
    /// In use detected by lspci
    pci_in_use: bool,
    /// Allocated to a VM by dstack-vmm
    allocated: bool,
}

impl DeviceState {
    fn is_free(&self) -> bool {
        !self.pci_in_use && !self.allocated
    }
}

pub(crate) struct AppState {
    cid_pool: IdPool<u32>,
    gpu_pool: Vec<DeviceState>,
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
