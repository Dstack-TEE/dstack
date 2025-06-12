use crate::config::{Config, Protocol};

use anyhow::{bail, Context, Result};
use bon::Builder;
use fs_err as fs;
use guest_api::client::DefaultClient as GuestClient;
use id_pool::IdPool;
use kms_rpc::kms_client::KmsClient;
use ra_rpc::client::RaClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use supervisor_client::SupervisorClient;
use teepod_rpc::{self as pb, StatusRequest, StatusResponse, VmConfiguration};
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
}

#[derive(Clone)]
pub struct App {
    pub config: Arc<Config>,
    pub supervisor: SupervisorClient,
    state: Arc<Mutex<AppState>>,
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

impl App {
    pub(crate) fn lock(&self) -> MutexGuard<AppState> {
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
    ) -> Result<()> {
        let vm_work_dir = VmWorkDir::new(work_dir.as_ref());
        let manifest = vm_work_dir.manifest().context("Failed to read manifest")?;
        let todo = "sanitize the image name";
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
        let started = vm_work_dir.started().context("Failed to read VM state")?;
        if started {
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
            .map_or(false, |info| info.state.status.is_running());
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
                if path.exists() {
                    fs::remove_file(path)?;
                }
            }
            let process_config = vm_config.config_qemu(&work_dir, &self.config.cvm)?;
            self.supervisor
                .deploy(process_config)
                .await
                .with_context(|| format!("Failed to start VM {id}"))?;
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
        let is_running = info.as_ref().map_or(false, |i| i.state.status.is_running());
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
                    if let Err(err) = self.load_vm(vm_path, &occupied_cids).await {
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
        self.shared_dir(id).join("app-compose.json")
    }

    pub(crate) fn encrypted_env_path(&self, id: &str) -> PathBuf {
        self.shared_dir(id).join("encrypted-env")
    }

    pub(crate) fn shared_dir(&self, id: &str) -> PathBuf {
        self.config.run_path.join(id).join("shared")
    }

    pub(crate) fn prepare_work_dir(&self, id: &str, req: &VmConfiguration) -> Result<VmWorkDir> {
        let work_dir = self.work_dir(id);
        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(shared_dir.join("app-compose.json"), &req.compose_file)
            .context("Failed to write compose file")?;
        if !req.encrypted_env.is_empty() {
            fs::write(shared_dir.join("encrypted-env"), &req.encrypted_env)
                .context("Failed to write encrypted env")?;
        }
        let app_id = req.app_id.clone().unwrap_or_default();
        if !app_id.is_empty() {
            let instance_info = serde_json::json!({
                "app_id": app_id,
            });
            fs::write(
                shared_dir.join(".instance_info"),
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
        let certs_dir = shared_dir.join("certs");
        fs::create_dir_all(&certs_dir).context("Failed to create certs directory")?;
        let cfg = &self.config;
        let image_path = cfg.image_path.join(&manifest.image);
        let image_info = ImageInfo::load(image_path.join("metadata.json"))
            .context("Failed to load image info")?;
        let rootfs_hash = image_info
            .rootfs_hash
            .context("Rootfs hash not found in image info")?;
        let vm_config = serde_json::json!({
            "rootfs_hash": rootfs_hash,
            "kms_url": cfg.cvm.kms_url,
            "tproxy_url": cfg.cvm.tproxy_url,
            "docker_registry": cfg.cvm.docker_registry,
            "host_api_url": format!("vsock://2:{}/api", cfg.host_api.port),
        });
        let vm_config_str =
            serde_json::to_string(&vm_config).context("Failed to serialize vm config")?;
        fs::write(shared_dir.join("config.json"), vm_config_str)
            .context("Failed to write vm config")?;
        fs::copy(&cfg.cvm.ca_cert, certs_dir.join("ca.cert")).context("Failed to copy ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_cert, certs_dir.join("tmp-ca.cert"))
            .context("Failed to copy tmp ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_key, certs_dir.join("tmp-ca.key"))
            .context("Failed to copy tmp ca key")?;
        Ok(())
    }

    pub(crate) fn kms_client(&self) -> Result<KmsClient<RaClient>> {
        if self.config.kms_url.is_empty() {
            bail!("KMS is not configured");
        }
        let url = format!("{}/prpc", self.config.kms_url);
        let prpc_client = RaClient::new(url, true);
        Ok(KmsClient::new(prpc_client))
    }

    pub(crate) fn tappd_client(&self, id: &str) -> Result<GuestClient> {
        let cid = self.lock().get(id).context("vm not found")?.config.cid;
        Ok(guest_api::client::new_client(format!(
            "vsock://{cid}:8000/api"
        )))
    }
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
