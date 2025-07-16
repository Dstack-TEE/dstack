use crate::config::{Config, Protocol};

use anyhow::{bail, Context, Result};
use bon::Builder;
use dstack_kms_rpc::kms_client::KmsClient;
use dstack_types::shared_filenames::{
    compat_v3, APP_COMPOSE, ENCRYPTED_ENV, INSTANCE_INFO, SYS_CONFIG, USER_CONFIG,
};
use dstack_vmm_rpc::{
    self as pb, BackupInfo, GpuInfo, StatusRequest, StatusResponse, VmConfiguration,
};
use fs_err as fs;
use guest_api::client::DefaultClient as GuestClient;
use id_pool::IdPool;
use ra_rpc::client::RaClient;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard};
use supervisor_client::SupervisorClient;
use tracing::{error, info, warn};

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gpus: Option<GpuConfig>,
    #[serde(default)]
    pub kms_urls: Vec<String>,
    #[serde(default)]
    pub gateway_urls: Vec<String>,
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

    fn backups_dir(&self, id: &str) -> PathBuf {
        self.config.cvm.backup.path.join(id).join("backups")
    }

    fn backup_dir(&self, id: &str, backup_id: &str) -> PathBuf {
        self.backups_dir(id).join(backup_id)
    }

    fn backup_file(&self, id: &str, backup_id: &str, snapshot_id: &str) -> PathBuf {
        self.backup_dir(id, backup_id).join(snapshot_id)
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
                networking: self.config.networking.clone(),
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

    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        self.set_started(id, false)?;
        self.supervisor.stop(id).await?;
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
        let occupied_cids = running_vms
            .iter()
            .flat_map(|p| p.config.cid.map(|cid| (p.config.id.clone(), cid)))
            .collect::<HashMap<_, _>>();
        {
            let mut state = self.lock();
            for cid in occupied_cids.values() {
                state.cid_pool.occupy(*cid)?;
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
            .map(|info| info.to_pb(&self.config.gateway, request.brief))
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
        let image_path = cfg.image_path.join(&manifest.image);
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
        let sys_config = if img_ver >= (0, 5, 0) {
            let os_image_hash = hex::decode(image.digest.unwrap_or_default())
                .context("Failed to decode image digest")?;
            let gpus = manifest.gpus.unwrap_or_default();
            let vm_config = serde_json::to_string(&dstack_types::VmConfig {
                spec_version: 1,
                os_image_hash,
                cpu_count: manifest.vcpu.try_into().context("Too many vCPUs")?,
                memory_size: manifest.memory as u64 * 1024 * 1024,
                qemu_single_pass_add_pages: cfg.cvm.qemu_single_pass_add_pages,
                pic: cfg.cvm.qemu_pic,
                pci_hole64_size: cfg.cvm.qemu_pci_hole64_size,
                hugepages: manifest.hugepages,
                num_gpus: gpus.gpus.len() as u32,
                num_nvswitches: gpus.bridges.len() as u32,
                hotplug_off: cfg.cvm.qemu_hotplug_off,
            })?;
            json!({
                "kms_urls": kms_urls,
                "gateway_urls": gateway_urls,
                "pccs_url": cfg.cvm.pccs_url,
                "docker_registry": cfg.cvm.docker_registry,
                "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
                "vm_config": vm_config,
            })
        } else if img_ver >= (0, 4, 2) {
            json!({
                "kms_urls": kms_urls,
                "gateway_urls": gateway_urls,
                "pccs_url": cfg.cvm.pccs_url,
                "docker_registry": cfg.cvm.docker_registry,
                "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
            })
        } else if img_ver >= (0, 4, 0) {
            let rootfs_hash = image
                .info
                .rootfs_hash
                .as_ref()
                .context("Rootfs hash not found in image info")?;
            json!({
                "rootfs_hash": rootfs_hash,
                "kms_urls": kms_urls,
                "tproxy_urls": gateway_urls,
                "pccs_url": cfg.cvm.pccs_url,
                "docker_registry": cfg.cvm.docker_registry,
                "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
            })
        } else {
            let rootfs_hash = image
                .info
                .rootfs_hash
                .as_ref()
                .context("Rootfs hash not found in image info")?;
            json!({
                "rootfs_hash": rootfs_hash,
                "kms_url": kms_urls.first(),
                "tproxy_url": gateway_urls.first(),
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

    pub(crate) async fn backup_disk(&self, id: &str, level: &str) -> Result<()> {
        if !self.config.cvm.backup.enabled {
            bail!("Backup is not enabled");
        }
        let work_dir = self.work_dir(id);
        let backup_dir = self.backups_dir(id);

        // Determine backup level based on the backup_type
        let backup_level = match level {
            "full" => "full",
            "incremental" => "inc",
            _ => bail!("Invalid backup level: {level}"),
        };

        let qmp_socket = work_dir.qmp_socket();
        let _lock = BackupLock::try_lock(work_dir.backup_lock_file())
            .context("Failed to lock for backup")?;

        let id = id.to_string();
        tokio::task::spawn_blocking(move || {
            let latest_dir = backup_dir.join("latest");
            if backup_level == "full" {
                // clear the bitmaps
                let output = Command::new("qmpbackup")
                    .arg("--socket")
                    .arg(&qmp_socket)
                    .arg("cleanup")
                    .arg("--remove-bitmap")
                    .output()
                    .context("Failed to clear bitmaps")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    warn!("Failed to clear bitmaps for {id}: {stderr}");
                }
                // Switch to new dir and symbol link the latest to it
                let timestamp = chrono::Utc::now().format("%Y%m%dZ%H%M%S").to_string();
                let new_dir = backup_dir.join(&timestamp);
                fs::create_dir_all(&new_dir).context("Failed to create backup directory")?;
                if fs::symlink_metadata(&latest_dir).is_ok() {
                    fs::remove_file(&latest_dir)
                        .context("Failed to remove latest directory link")?;
                }
                fs::os::unix::fs::symlink(&timestamp, &latest_dir)
                    .context("Failed to create latest directory link")?;
            }
            let output = Command::new("qmpbackup")
                .arg("--socket")
                .arg(&qmp_socket)
                .arg("backup")
                .arg("-i")
                .arg("hd1")
                .arg("--no-subdir")
                .arg("-t")
                .arg(&latest_dir)
                .arg("-l")
                .arg(backup_level)
                .output()
                .context("Failed to execute qmpbackup command")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to backup disk for {id}: {stderr}");
            }
            Ok(())
        })
        .await
        .context("Failed to execute backup task")?
    }

    pub(crate) async fn list_backups(&self, id: &str) -> Result<Vec<BackupInfo>> {
        let backup_dir = self.backups_dir(id);

        // Create backup directory if it doesn't exist
        if !backup_dir.exists() {
            return Ok(Vec::new());
        }

        // List backup groups in the directory
        let mut backups = Vec::new();

        // Read directory entries in a blocking task
        let backup_dir_clone = backup_dir.clone();
        let backup_entries =
            std::fs::read_dir(backup_dir_clone).context("Failed to read backup directory")?;

        fn filename(path: &Path) -> Option<String> {
            path.file_name()
                .and_then(|n| n.to_str().map(|s| s.to_string()))
        }

        // Process each entry
        for backup_entry in backup_entries {
            let backup_path = match backup_entry {
                Ok(entry) => entry.path(),
                Err(e) => {
                    warn!("Failed to read directory entry: {e:?}");
                    continue;
                }
            };
            if !backup_path.is_dir() {
                continue;
            }
            if backup_path.ends_with("latest") {
                continue;
            }
            let backup_id = filename(&backup_path).context("Failed to get group name")?;
            let snaps = match std::fs::read_dir(backup_path) {
                Ok(entries) => entries,
                Err(e) => {
                    warn!("Failed to read directory entry: {e:?}");
                    continue;
                }
            };
            for snap in snaps {
                let snap_path = match snap {
                    Ok(entry) => entry.path(),
                    Err(e) => {
                        warn!("Failed to read directory entry: {e:?}");
                        continue;
                    }
                };
                if !snap_path.is_file() {
                    continue;
                }
                // Get file name
                let snap_filename = filename(&snap_path).context("Failed to get file name")?;

                if !snap_filename.ends_with(".img") {
                    continue;
                }
                let parts = snap_filename
                    .split('.')
                    .next()
                    .context("Failed to split filename")?
                    .split('-')
                    .collect::<Vec<_>>();
                let [level, timestamp, _] = parts[..] else {
                    warn!("Invalid backup filename: {snap_filename}");
                    continue;
                };
                let size = snap_path
                    .metadata()
                    .context("Failed to get file metadata")?
                    .len();
                backups.push(BackupInfo {
                    backup_id: backup_id.clone(),
                    snapshot_id: snap_filename.clone(),
                    timestamp: timestamp.to_string(),
                    level: level.to_string(),
                    size,
                });
            }
        }
        Ok(backups)
    }

    pub(crate) async fn delete_backup(&self, vm_id: &str, backup_id: &str) -> Result<()> {
        if !self.config.cvm.backup.enabled {
            bail!("Backup is not enabled");
        }
        let backup_dir = self.backup_dir(vm_id, backup_id);
        if !backup_dir.exists() {
            bail!("Backup does not exist");
        }
        if !backup_dir.is_dir() {
            bail!("Backup is not a directory");
        }
        fs::remove_dir_all(&backup_dir).context("Failed to remove backup directory")?;
        Ok(())
    }

    pub(crate) async fn restore_backup(
        &self,
        vm_id: &str,
        backup_id: &str,
        snapshot_id: &str,
    ) -> Result<()> {
        if !self.config.cvm.backup.enabled {
            bail!("Backup is not enabled");
        }
        // First, ensure the vm is stopped
        let info = self.vm_info(vm_id).await?.context("VM not found")?;
        if info.status != "stopped" {
            bail!("VM is not stopped: status={}", info.status);
        }

        let backup_file = self.backup_file(vm_id, backup_id, snapshot_id);
        if !backup_file.exists() {
            bail!("Backup file not found");
        }
        let vm_work_dir = self.work_dir(vm_id);
        let hda_img = vm_work_dir.hda_path();
        if snapshot_id.starts_with("FULL") {
            // Just copy the file
            tokio::fs::copy(&backup_file, &hda_img).await?;
        } else {
            let backup_dir = self.backup_dir(vm_id, backup_id);
            let snapshot_id = snapshot_id.to_string();
            // Rename the current hda file to *.bak
            let bak_file = hda_img.display().to_string() + ".bak";
            fs::rename(&hda_img, &bak_file).context("Failed to rename hda file")?;

            tokio::task::spawn_blocking(move || {
                /*
                    qmprestore merge --dir <backup_dir> --until <snapshot_id> --targetfile <hda_img>
                */
                let mut command = Command::new("qmprestore");
                command.arg("merge");
                command.arg("--dir").arg(&backup_dir);
                command.arg("--until").arg(snapshot_id);
                command.arg("--targetfile").arg(&hda_img);
                let output = command
                    .output()
                    .context("Failed to execute qmprestore command")?;
                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    bail!("Failed to restore backup: {stderr}:{stdout}");
                }
                Ok(())
            })
            .await
            .context("Failed to spawn restore command")?
            .context("Failed to restore backup")?;
        }
        Ok(())
    }
}

struct BackupLock {
    path: PathBuf,
}

impl BackupLock {
    fn try_lock(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let _file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .context("Failed to create backup lock file")?;
        Ok(BackupLock {
            path: path.to_path_buf(),
        })
    }
}

impl Drop for BackupLock {
    fn drop(&mut self) {
        fs::remove_file(&self.path).ok();
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
    devices: GpuConfig,
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
