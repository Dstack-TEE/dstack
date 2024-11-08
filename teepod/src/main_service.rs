use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs_err as fs;
use ra_rpc::{Attestation, RpcCall};
use teepod_rpc::teepod_server::{TeepodRpc, TeepodServer};
use teepod_rpc::{
    CreateVmRequest, Id, ImageInfo as RpcImageInfo, ImageListResponse, UpgradeAppRequest,
    VmListResponse,
};
use tracing::warn;

use crate::app::{App, Manifest, VmWorkDir};
use crate::vm::image::ImageInfo;

fn hex_sha256(data: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct RpcHandler {
    app: App,
}

impl RpcHandler {
    fn compose_file_path(&self, id: &str) -> PathBuf {
        self.app
            .config
            .run_path
            .join(id)
            .join("shared")
            .join("app-compose.json")
    }

    fn prepare_work_dir(&self, id: &str, compose_file: &str, image_name: &str) -> Result<PathBuf> {
        let cfg = self.app.config.clone();
        let work_dir = cfg.run_path.join(&id);
        if work_dir.exists() {
            anyhow::bail!("The instance is already exists at {}", work_dir.display());
        }
        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(shared_dir.join("app-compose.json"), compose_file)
            .context("Failed to write compose file")?;
        let certs_dir = shared_dir.join("certs");
        fs::create_dir_all(&certs_dir).context("Failed to create certs directory")?;

        fs::copy(&cfg.cvm.ca_cert, certs_dir.join("ca.cert")).context("Failed to copy ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_cert, certs_dir.join("tmp-ca.cert"))
            .context("Failed to copy tmp ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_key, certs_dir.join("tmp-ca.key"))
            .context("Failed to copy tmp ca key")?;

        let image_path = cfg.image_path.join(image_name);
        let image_info = ImageInfo::load(image_path.join("metadata.json"))
            .context("Failed to load image info")?;

        let rootfs_hash = image_info
            .rootfs_hash
            .context("Rootfs hash not found in image info")?;
        let vm_config = serde_json::json!({
            "rootfs_hash": rootfs_hash,
            "kms_url": cfg.cvm.kms_url,
            "tproxy_url": cfg.cvm.tproxy_url,
        });
        let vm_config_str =
            serde_json::to_string(&vm_config).context("Failed to serialize vm config")?;
        fs::write(shared_dir.join("config.json"), vm_config_str)
            .context("Failed to write vm config")?;

        Ok(work_dir)
    }
}

fn app_id_of(compose_file: &str) -> String {
    fn truncate40(s: &str) -> &str {
        if s.len() > 40 {
            &s[..40]
        } else {
            s
        }
    }
    truncate40(&hex_sha256(&compose_file)).to_string()
}

/// Validate the label of the VM. Valid chars are alphanumeric, dash and underscore.
fn validate_label(label: &str) -> Result<()> {
    if label
        .chars()
        .any(|c| !c.is_alphanumeric() && c != '-' && c != '_')
    {
        anyhow::bail!("Invalid label: {}", label);
    }
    Ok(())
}

impl TeepodRpc for RpcHandler {
    async fn create_vm(self, request: CreateVmRequest) -> Result<Id> {
        validate_label(&request.name)?;
        let app_id = app_id_of(&request.compose_file);
        let id = uuid::Uuid::new_v4().to_string();
        let work_dir = self.prepare_work_dir(&id, &request.compose_file, &request.image)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let manifest = Manifest::builder()
            .id(id.clone())
            .name(request.name)
            .app_id(app_id.clone())
            .image(request.image)
            .vcpu(request.vcpu)
            .memory(request.memory)
            .disk_size(request.disk_size)
            .port_map(Default::default())
            .created_at_ms(now)
            .build();

        let vm_work_dir = VmWorkDir::new(&work_dir);
        vm_work_dir
            .put_manifest(&manifest)
            .context("Failed to write manifest")?;
        if let Err(err) = vm_work_dir.set_started(true) {
            warn!("Failed to set started: {}", err);
        }

        self.app.load_vm(work_dir).context("Failed to load VM")?;

        Ok(Id { id })
    }

    async fn start_vm(self, request: Id) -> Result<()> {
        self.app.start_vm(&request.id)?;
        Ok(())
    }

    async fn stop_vm(self, request: Id) -> Result<()> {
        self.app.stop_vm(&request.id)?;
        Ok(())
    }

    async fn remove_vm(self, request: Id) -> Result<()> {
        self.app.remove_vm(&request.id)?;
        Ok(())
    }

    async fn list_vms(self) -> Result<VmListResponse> {
        Ok(VmListResponse {
            vms: self.app.list_vms(),
        })
    }

    async fn list_images(self) -> Result<ImageListResponse> {
        Ok(ImageListResponse {
            images: self
                .app
                .list_image_names()?
                .into_iter()
                .map(|name| RpcImageInfo {
                    name,
                    description: "".to_string(),
                })
                .collect(),
        })
    }

    async fn upgrade_app(self, request: UpgradeAppRequest) -> Result<Id> {
        let compose_file_path = self.compose_file_path(&request.id);
        if !compose_file_path.exists() {
            anyhow::bail!("The instance {} not found", request.id);
        }
        fs::write(compose_file_path, &request.compose_file)
            .context("Failed to write compose file")?;
        let new_app_id = app_id_of(&request.compose_file);
        Ok(Id { id: new_app_id })
    }
}

impl RpcCall<App> for RpcHandler {
    type PrpcService = TeepodServer<Self>;

    fn into_prpc_service(self) -> Self::PrpcService {
        TeepodServer::new(self)
    }

    fn construct(state: &App, _attestation: Option<Attestation>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(RpcHandler { app: state.clone() })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <TeepodServer<RpcHandler>>::supported_methods()
}
