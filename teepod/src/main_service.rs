use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use fs_err as fs;
use kms_rpc::kms_client::KmsClient;
use ra_rpc::client::RaClient;
use ra_rpc::{Attestation, RpcCall};
use teepod_rpc::teepod_server::{TeepodRpc, TeepodServer};
use teepod_rpc::{
    AppId, GetInfoResponse, Id, ImageInfo as RpcImageInfo, ImageListResponse, PublicKeyResponse,
    ResizeVmRequest, StatusResponse, UpgradeAppRequest, VmConfiguration, GetMetaResponse, KmsSettings,
    TProxySettings, ResourcesSettings,
};
use tracing::warn;

use crate::app::{App, ImageInfo, Manifest, PortMapping, VmWorkDir};

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
        self.shared_dir(id).join("app-compose.json")
    }

    fn encrypted_env_path(&self, id: &str) -> PathBuf {
        self.shared_dir(id).join("encrypted-env")
    }

    fn shared_dir(&self, id: &str) -> PathBuf {
        self.app.config.run_path.join(id).join("shared")
    }

    fn prepare_work_dir(&self, id: &str, req: &VmConfiguration) -> Result<VmWorkDir> {
        let work_dir = self.app.work_dir(id);
        if work_dir.exists() {
            anyhow::bail!("The instance is already exists at {}", work_dir.display());
        }
        let shared_dir = work_dir.join("shared");
        fs::create_dir_all(&shared_dir).context("Failed to create shared directory")?;
        fs::write(shared_dir.join("app-compose.json"), &req.compose_file)
            .context("Failed to write compose file")?;
        if !req.encrypted_env.is_empty() {
            fs::write(shared_dir.join("encrypted-env"), &req.encrypted_env)
                .context("Failed to write encrypted env")?;
        }
        let certs_dir = shared_dir.join("certs");
        fs::create_dir_all(&certs_dir).context("Failed to create certs directory")?;

        let cfg = &self.app.config;
        fs::copy(&cfg.cvm.ca_cert, certs_dir.join("ca.cert")).context("Failed to copy ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_cert, certs_dir.join("tmp-ca.cert"))
            .context("Failed to copy tmp ca cert")?;
        fs::copy(&cfg.cvm.tmp_ca_key, certs_dir.join("tmp-ca.key"))
            .context("Failed to copy tmp ca key")?;

        let image_path = cfg.image_path.join(&req.image);
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
        });
        let vm_config_str =
            serde_json::to_string(&vm_config).context("Failed to serialize vm config")?;
        fs::write(shared_dir.join("config.json"), vm_config_str)
            .context("Failed to write vm config")?;
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

    fn kms_client(&self) -> Result<KmsClient<RaClient>> {
        if self.app.config.kms_url.is_empty() {
            anyhow::bail!("KMS is not configured");
        }
        let url = format!("{}/prpc", self.app.config.kms_url);
        let prpc_client = RaClient::new(url, true);
        Ok(KmsClient::new(prpc_client))
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
    truncate40(&hex_sha256(compose_file)).to_string()
}

/// Validate the label of the VM. Valid chars are alphanumeric, dash and underscore.
fn validate_label(label: &str) -> Result<()> {
    if label
        .chars()
        .any(|c| !c.is_alphanumeric() && c != '-' && c != '_')
    {
        anyhow::bail!("Invalid name: {}", label);
    }
    Ok(())
}

impl TeepodRpc for RpcHandler {
    async fn create_vm(self, request: VmConfiguration) -> Result<Id> {
        validate_label(&request.name)?;

        let pm_cfg = &self.app.config.cvm.port_mapping;
        if !(request.ports.is_empty() || pm_cfg.enabled) {
            anyhow::bail!("Port mapping is disabled");
        }
        let port_map = request
            .ports
            .iter()
            .map(|p| {
                let from = p.host_port.try_into().context("Invalid host port")?;
                let to = p.vm_port.try_into().context("Invalid vm port")?;
                if !pm_cfg.is_allowed(&p.protocol, from) {
                    anyhow::bail!("Port mapping is not allowed for {}:{}", p.protocol, from);
                }
                let protocol = p.protocol.parse().context("Invalid protocol")?;
                Ok(PortMapping {
                    address: pm_cfg.address,
                    protocol,
                    from,
                    to,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        let app_id = match &request.app_id {
            Some(id) => id.clone(),
            None => app_id_of(&request.compose_file),
        };
        let id = uuid::Uuid::new_v4().to_string();
        let work_dir = self.prepare_work_dir(&id, &request)?;
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
            .port_map(port_map)
            .created_at_ms(now)
            .build();

        let vm_work_dir = VmWorkDir::new(&work_dir);
        vm_work_dir
            .put_manifest(&manifest)
            .context("Failed to write manifest")?;
        if let Err(err) = vm_work_dir.set_started(true) {
            warn!("Failed to set started: {}", err);
        }

        let result = self
            .app
            .load_vm(&work_dir, &Default::default())
            .await
            .context("Failed to load VM");
        if let Err(err) = result {
            if let Err(err) = fs::remove_dir_all(&work_dir) {
                warn!("Failed to remove work dir: {}", err);
            }
            return Err(err);
        }

        Ok(Id { id })
    }

    async fn start_vm(self, request: Id) -> Result<()> {
        self.app
            .start_vm(&request.id)
            .await
            .context("Failed to start VM")?;
        Ok(())
    }

    async fn stop_vm(self, request: Id) -> Result<()> {
        self.app
            .stop_vm(&request.id)
            .await
            .context("Failed to stop VM")?;
        Ok(())
    }

    async fn remove_vm(self, request: Id) -> Result<()> {
        self.app
            .remove_vm(&request.id)
            .await
            .context("Failed to remove VM")?;
        Ok(())
    }

    async fn status(self) -> Result<StatusResponse> {
        Ok(StatusResponse {
            vms: self.app.list_vms().await?,
            port_mapping_enabled: self.app.config.cvm.port_mapping.enabled,
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
        let new_id = if !request.compose_file.is_empty() {
            {
                // check the compose file is valid
                let todo = "import from external crate";
                #[allow(dead_code)]
                #[derive(serde::Deserialize)]
                struct AppCompose {
                    manifest_version: u32,
                    name: String,
                    version: String,
                    features: Vec<String>,
                    runner: String,
                    docker_compose_file: Option<String>,
                }
                let app_compose: AppCompose =
                    serde_json::from_str(&request.compose_file).context("Invalid compose file")?;
                if app_compose.docker_compose_file.is_none() {
                    anyhow::bail!("Docker compose file cannot be empty");
                }
            }
            let compose_file_path = self.compose_file_path(&request.id);
            if !compose_file_path.exists() {
                anyhow::bail!("The instance {} not found", request.id);
            }
            fs::write(compose_file_path, &request.compose_file)
                .context("Failed to write compose file")?;

            app_id_of(&request.compose_file)
        } else {
            Default::default()
        };
        if !request.encrypted_env.is_empty() {
            let encrypted_env_path = self.encrypted_env_path(&request.id);
            fs::write(encrypted_env_path, &request.encrypted_env)
                .context("Failed to write encrypted env")?;
        }
        Ok(Id { id: new_id })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let kms = self.kms_client()?;
        let response = kms
            .get_app_env_encrypt_pub_key(kms_rpc::AppId {
                app_id: request.app_id,
            })
            .await?;
        Ok(PublicKeyResponse {
            public_key: response.public_key,
        })
    }

    async fn get_info(self, request: Id) -> Result<GetInfoResponse> {
        if let Some(vm) = self.app.get_vm(&request.id).await? {
            Ok(GetInfoResponse {
                found: true,
                info: Some(vm),
            })
        } else {
            Ok(GetInfoResponse {
                found: false,
                info: None,
            })
        }
    }

    async fn resize_vm(self, request: ResizeVmRequest) -> Result<()> {
        let vm = self
            .app
            .get_vm(&request.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("vm not found: {}", request.id))?;
        if vm.status != "stopped" {
            return Err(anyhow::anyhow!(
                "vm should be stopped before resize: {}",
                request.id
            ));
        }
        let work_dir = self.app.config.run_path.join(&request.id);
        let vm_work_dir = VmWorkDir::new(&work_dir);
        let mut manifest = vm_work_dir.manifest().context("failed to read manifest")?;
        if let Some(vcpu) = request.vcpu {
            manifest.vcpu = vcpu;
        }
        if let Some(memory) = request.memory {
            manifest.memory = memory;
        }
        if let Some(disk_size) = request.disk_size {
            // it only updates the manifesta and does NOT affect the real storage alloc at this time.
            manifest.disk_size = disk_size;
        }
        vm_work_dir
            .put_manifest(&manifest)
            .context("failed to update manifest")?;
        self.app
            .load_vm(work_dir, &Default::default())
            .await
            .context("Failed to load VM")?;
        Ok(())
    }

    async fn get_meta(self) -> Result<GetMetaResponse> {
        Ok(GetMetaResponse {
            kms: Some(KmsSettings {
                url: self.app.config.cvm.kms_url.clone(),
            }),
            tproxy: Some(TProxySettings {
                url: self.app.config.cvm.tproxy_url.clone(),
                base_domain: self.app.config.gateway.base_domain.clone(),
                port: self.app.config.gateway.port.into(),
                tappd_port: self.app.config.gateway.tappd_port.into(),
            }),
            resources: Some(ResourcesSettings {
                max_cvm_number: self.app.config.cvm.cid_pool_size,
                max_allocable_vcpu: self.app.config.cvm.max_allocable_vcpu,
                max_allocable_memory_in_mb: self.app.config.cvm.max_allocable_memory_in_mb,
                max_disk_size_in_gb: self.app.config.cvm.max_disk_size,
            }),
        })
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
