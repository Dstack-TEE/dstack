//! App related code
//!
//! Directory structure:
//! ```text
//! .teepod/
//! ├── image
//! │   └── ubuntu-24.04
//! │       ├── hda.img
//! │       ├── info.json
//! │       ├── initrd.img
//! │       ├── kernel
//! │       └── rootfs.iso
//! └── vm
//!     └── e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//!         └── shared
//!             └── app-compose.json
//! ```
use crate::config::{Config, Protocol};

use anyhow::{bail, Context, Result};
use bon::Builder;
use fs_err as fs;
use id_pool::IdPool;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use supervisor_client::SupervisorClient;
use teepod_rpc as pb;
use tracing::error;

pub use image::{Image, ImageInfo};
pub use qemu::{TdxConfig, VmConfig, VmWorkDir};

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

impl App {
    fn lock(&self) -> MutexGuard<AppState> {
        self.state.lock().unwrap()
    }

    pub(crate) fn vm_dir(&self) -> PathBuf {
        self.config.run_path.clone().into()
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
                occupied_cids: HashMap::new(),
                vms: HashMap::new(),
            })),
            config: Arc::new(config),
        }
    }

    pub async fn load_vm(
        &self,
        work_dir: impl AsRef<Path>,
    ) -> Result<()> {
        let vm_work_dir = VmWorkDir::new(work_dir.as_ref());
        let manifest = vm_work_dir.manifest().context("Failed to read manifest")?;
        let todo = "sanitize the image name";
        let image_path = self.config.image_path.join(&manifest.image);
        let image = Image::load(&image_path).context("Failed to load image")?;
        let vm_config = VmConfig {
            manifest,
            image,
            tdx_config: None,
            networking: self.config.networking.clone(),
        };
        if vm_config.manifest.disk_size > self.config.cvm.max_disk_size {
            bail!(
                "disk size too large, max size is {}",
                self.config.cvm.max_disk_size
            );
        }
        let vm_id = vm_config.manifest.id.clone();
        self.lock().add(vm_config);
        let started = vm_work_dir.started().context("Failed to read VM state")?;
        if started {
            self.start_vm(&vm_id).await?;
        }
        Ok(())
    }

    pub async fn start_vm(&self, id: &str) -> Result<()> {
        let vm_config = self.lock().get(id).context("VM not found")?;
        let work_dir = self.work_dir(id);
        let cid = self.lock().allocate_cid(id)?;
        let process_config = vm_config.config_qemu(&self.config.qemu_path, &work_dir, cid)?;
        self.supervisor
            .deploy(process_config)
            .await
            .with_context(|| format!("Failed to start VM {id}"))?;
        work_dir
            .set_started(true)
            .with_context(|| format!("Failed to set started for VM {id}"))?;
        Ok(())
    }

    pub async fn stop_vm(&self, id: &str) -> Result<()> {
        let work_dir = self.work_dir(id);
        work_dir
            .set_started(false)
            .context("Failed to set started")?;
        self.supervisor.stop(id).await?;
        self.lock().free_cid(id)?;
        Ok(())
    }

    pub async fn remove_vm(&self, id: &str) -> Result<()> {
        let info = self.supervisor.info(id).await?;
        let is_running = info.map_or(false, |i| i.state.status.is_running());
        if is_running {
            bail!("VM is running, stop it first");
        }
        self.supervisor.remove(id).await?;
        self.lock().remove(id);
        let vm_path = self.work_dir(id);
        fs::remove_dir_all(&vm_path).context("Failed to remove VM directory")?;
        Ok(())
    }

    pub async fn reload_vms(&self) -> Result<()> {
        let vm_path = self.vm_dir();
        if vm_path.exists() {
            for entry in fs::read_dir(vm_path).context("Failed to read VM directory")? {
                let entry = entry.context("Failed to read directory entry")?;
                let vm_path = entry.path();
                if vm_path.is_dir() {
                    if let Err(err) = self.load_vm(vm_path).await {
                        error!("Failed to load VM: {err:?}");
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn list_vms(&self) -> Result<Vec<pb::VmInfo>> {
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
            .map(|vm| vm.merge_info(vms.get(&vm.manifest.id), &self.work_dir(&vm.manifest.id)))
            .collect::<Vec<_>>();

        infos.sort_by(|a, b| a.manifest.created_at_ms.cmp(&b.manifest.created_at_ms));
        let gw = &self.config.gateway;

        let lst = infos.into_iter().map(|info| info.to_pb(gw)).collect();
        Ok(lst)
    }

    pub fn list_image_names(&self) -> Result<Vec<String>> {
        let image_path = self.config.image_path.clone();
        let images = fs::read_dir(image_path).context("Failed to read image directory")?;
        Ok(images
            .flat_map(|e| {
                Some(
                    e.ok()?
                        .path()
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                )
            })
            .collect())
    }

    pub async fn get_vm(&self, id: &str) -> Result<Option<pb::VmInfo>> {
        let proc_state = self.supervisor.info(id).await?;
        let Some(cfg) = self.lock().get(id) else {
            return Ok(None);
        };
        let info = cfg
            .merge_info(proc_state.as_ref(), &self.work_dir(id))
            .to_pb(&self.config.gateway);
        Ok(Some(info))
    }
}

pub(crate) struct AppState {
    cid_pool: IdPool<u32>,
    occupied_cids: HashMap<String, u32>,
    vms: HashMap<String, Arc<VmConfig>>,
}

impl AppState {
    pub fn add(&mut self, vm: VmConfig) {
        self.vms.insert(vm.manifest.id.clone(), Arc::new(vm));
    }

    pub fn get(&self, id: &str) -> Option<Arc<VmConfig>> {
        self.vms.get(id).cloned()
    }

    pub fn remove(&mut self, id: &str) -> Option<Arc<VmConfig>> {
        self.vms.remove(id)
    }

    pub fn iter_vms(&self) -> impl Iterator<Item = &Arc<VmConfig>> {
        self.vms.values()
    }

    pub fn allocate_cid(&mut self, id: &str) -> Result<u32> {
        let _ = self.vms.get(id).context("VM not found")?;
        let cid = self.cid_pool
            .allocate()
            .context("CID pool exhausted")?;
        self.occupied_cids.insert(id.into(), cid);
        Ok(cid)
    }

    pub fn free_cid(&mut self, id: &str) -> Result<()> {
        let cid = self.occupied_cids.get(id).context("Not cid assigned for the VM.")?;
        self.cid_pool.free(*cid);
        self.occupied_cids.remove(id);
        Ok(())
    }
}
