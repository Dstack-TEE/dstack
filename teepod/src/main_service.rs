use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use fs_err as fs;
use ra_rpc::{CallContext, RpcCall};
use teepod_rpc::teepod_server::{TeepodRpc, TeepodServer};
use teepod_rpc::{
    AppId, GetInfoResponse, GetMetaResponse, Id, ImageInfo as RpcImageInfo, ImageListResponse,
    KmsSettings, PublicKeyResponse, ResizeVmRequest, ResourcesSettings, StatusRequest,
    StatusResponse, TProxySettings, UpgradeAppRequest, VersionResponse, VmConfiguration,
};
use tracing::{info, warn};

use crate::app::{App, Manifest, PortMapping, VmWorkDir};

fn hex_sha256(data: &str) -> String {
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct RpcHandler {
    app: App,
}

impl Deref for RpcHandler {
    type Target = App;

    fn deref(&self) -> &Self::Target {
        &self.app
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
        bail!("Invalid name: {}", label);
    }
    Ok(())
}

impl TeepodRpc for RpcHandler {
    async fn create_vm(self, request: VmConfiguration) -> Result<Id> {
        validate_label(&request.name)?;

        let pm_cfg = &self.app.config.cvm.port_mapping;
        if !(request.ports.is_empty() || pm_cfg.enabled) {
            bail!("Port mapping is disabled");
        }
        let port_map = request
            .ports
            .iter()
            .map(|p| {
                let from = p.host_port.try_into().context("Invalid host port")?;
                let to = p.vm_port.try_into().context("Invalid vm port")?;
                if !pm_cfg.is_allowed(&p.protocol, from) {
                    bail!("Port mapping is not allowed for {}:{}", p.protocol, from);
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let manifest = Manifest::builder()
            .id(id.clone())
            .name(request.name.clone())
            .app_id(app_id.clone())
            .image(request.image.clone())
            .vcpu(request.vcpu)
            .memory(request.memory)
            .disk_size(request.disk_size)
            .port_map(port_map)
            .created_at_ms(now)
            .build();
        let vm_work_dir = self.app.work_dir(&id);
        vm_work_dir
            .put_manifest(&manifest)
            .context("Failed to write manifest")?;
        let work_dir = self.prepare_work_dir(&id, &request)?;
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

    async fn status(self, request: StatusRequest) -> Result<StatusResponse> {
        self.app.list_vms(request).await
    }

    async fn list_images(self) -> Result<ImageListResponse> {
        Ok(ImageListResponse {
            images: self
                .app
                .list_images()?
                .into_iter()
                .map(|(name, info)| RpcImageInfo {
                    name,
                    description: serde_json::to_string(&info).unwrap_or_default(),
                    version: info.version,
                    is_dev: info.is_dev,
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
                    runner: String,
                    docker_compose_file: Option<String>,
                }
                let _app_compose: AppCompose =
                    serde_json::from_str(&request.compose_file).context("Invalid compose file")?;
            }
            let compose_file_path = self.compose_file_path(&request.id);
            if !compose_file_path.exists() {
                bail!("The instance {} not found", request.id);
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
        if let Some(vm) = self.app.vm_info(&request.id).await? {
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

    #[tracing::instrument(skip(self, request), fields(id = request.id))]
    async fn resize_vm(self, request: ResizeVmRequest) -> Result<()> {
        info!("Resizing VM: {:?}", request);
        let vm = self
            .app
            .vm_info(&request.id)
            .await?
            .context("vm not found")?;
        if !["stopped", "exited"].contains(&vm.status.as_str()) {
            return Err(anyhow!(
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
        if let Some(image) = request.image {
            manifest.image = image;
        }
        if let Some(disk_size) = request.disk_size {
            let max_disk_size = self.app.config.cvm.max_disk_size;
            if disk_size > max_disk_size {
                bail!("Disk size is too large, max is {max_disk_size}GB");
            }
            if disk_size < manifest.disk_size {
                bail!("Cannot shrink disk size");
            }
            manifest.disk_size = disk_size;

            // Run qemu-img resize to resize the disk
            info!("Resizing disk to {}GB", disk_size);
            let hda_path = vm_work_dir.hda_path();
            let new_size_str = format!("{}G", disk_size);
            let output = std::process::Command::new("qemu-img")
                .args(["resize", &hda_path.display().to_string(), &new_size_str])
                .output()
                .context("Failed to resize disk")?;
            if !output.status.success() {
                bail!(
                    "Failed to resize disk: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
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

    async fn shutdown_vm(self, request: Id) -> Result<()> {
        self.tappd_client(&request.id)?.shutdown().await?;
        Ok(())
    }

    async fn version(self) -> Result<VersionResponse> {
        Ok(VersionResponse {
            version: crate::CARGO_PKG_VERSION.to_string(),
            rev: crate::GIT_REV.to_string(),
        })
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

    fn construct(context: CallContext<'_, App>) -> Result<Self> {
        Ok(RpcHandler {
            app: context.state.clone(),
        })
    }
}
