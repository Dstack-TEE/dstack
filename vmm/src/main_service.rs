// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::ops::Deref;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use dstack_types::AppCompose;
use dstack_vmm_rpc as rpc;
use dstack_vmm_rpc::vmm_server::{VmmRpc, VmmServer};
use dstack_vmm_rpc::{
    AppId, ComposeHash as RpcComposeHash, DhcpLeaseRequest, GatewaySettings, GetInfoResponse,
    GetMetaResponse, Id, ImageInfo as RpcImageInfo, ImageListResponse, KmsSettings,
    ListGpusResponse, PublicKeyResponse, ReloadVmsResponse, ResizeVmRequest, ResourcesSettings,
    StatusRequest, StatusResponse, UpdateVmRequest, VersionResponse, VmConfiguration,
};
use fs_err as fs;
use ra_rpc::{CallContext, RpcCall};
use tracing::{info, warn};

use crate::app::{App, AttachMode, GpuConfig, GpuSpec, Manifest, PortMapping, VmWorkDir};

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

/// Validate the VM label, restricting it to a safe character set to prevent injection vectors.
fn validate_label(label: &str) -> Result<()> {
    fn is_valid_label_char(c: char) -> bool {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '-' | '_' | '.' | ' ' | '@' | '~' | '!' | '$' | '^' | '(' | ')'
            )
    }
    if !label.chars().all(is_valid_label_char) {
        bail!("Invalid name: {label}");
    }
    Ok(())
}

pub fn resolve_gpus_with_config(
    gpu_cfg: &rpc::GpuConfig,
    cvm_config: &crate::config::CvmConfig,
) -> Result<GpuConfig> {
    if !cvm_config.gpu.enabled && !gpu_cfg.is_empty() {
        bail!("GPU is not enabled");
    }
    let gpus = resolve_gpus(gpu_cfg)?;
    if !cvm_config.gpu.allow_attach_all && gpus.attach_mode.is_all() {
        bail!("Attaching all GPUs is not allowed");
    }
    Ok(gpus)
}

pub fn resolve_gpus(gpu_cfg: &rpc::GpuConfig) -> Result<GpuConfig> {
    // Check the attach mode to determine how to handle GPUs
    match gpu_cfg.attach_mode.as_str() {
        "listed" => {
            // If the mode is "listed", use the GPUs specified in the request
            let gpus = gpu_cfg
                .gpus
                .iter()
                .map(|g| GpuSpec {
                    slot: g.slot.clone(),
                })
                .collect();

            Ok(GpuConfig {
                attach_mode: AttachMode::Listed,
                gpus,
                bridges: Vec::new(),
            })
        }
        "all" => {
            // If the mode is "all", find all NVIDIA GPUs and NVSwitches
            let devices = lspci::lspci_filtered(|dev| {
                // Check if it's an NVIDIA device (vendor ID 10de)
                dev.vendor_id == "10de"
            })
            .context("Failed to list PCI devices")?;

            let mut gpus = Vec::new();
            let mut bridges = Vec::new();

            for dev in devices {
                // Check if it's a GPU (3D controller) or NVSwitch (Bridge)
                if dev.class.contains("3D controller") {
                    gpus.push(GpuSpec { slot: dev.slot });
                } else if dev.class.contains("Bridge") {
                    bridges.push(GpuSpec { slot: dev.slot });
                }
            }
            Ok(GpuConfig {
                attach_mode: AttachMode::All,
                gpus,
                bridges,
            })
        }
        _ => bail!("Invalid GPU attach mode: {}", gpu_cfg.attach_mode),
    }
}

// Shared function to create manifest from VM configuration
pub fn create_manifest_from_vm_config(
    request: VmConfiguration,
    cvm_config: &crate::config::CvmConfig,
) -> Result<Manifest> {
    validate_label(&request.name)?;

    let pm_cfg = &cvm_config.port_mapping;
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
            let address = if !p.host_address.is_empty() {
                p.host_address.parse().context("Invalid host address")?
            } else {
                pm_cfg.address
            };
            Ok(PortMapping {
                address,
                protocol,
                from,
                to,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let app_id = match &request.app_id {
        Some(id) => id.strip_prefix("0x").unwrap_or(id).to_lowercase(),
        None => app_id_of(&request.compose_file),
    };
    let id = uuid::Uuid::new_v4().to_string();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let gpus = match &request.gpus {
        Some(gpus) => resolve_gpus_with_config(gpus, cvm_config)?,
        None => GpuConfig::default(),
    };

    Ok(Manifest {
        id,
        name: request.name.clone(),
        app_id,
        vcpu: request.vcpu,
        memory: request.memory,
        disk_size: request.disk_size,
        image: request.image.clone(),
        port_map,
        created_at_ms: now,
        hugepages: request.hugepages,
        pin_numa: request.pin_numa,
        gpus: Some(gpus),
        kms_urls: request.kms_urls.clone(),
        gateway_urls: request.gateway_urls.clone(),
        no_tee: request.no_tee,
        networking: request.networking.as_ref().and_then(networking_from_proto),
    })
}

fn networking_from_proto(proto: &rpc::NetworkingConfig) -> Option<crate::config::Networking> {
    use crate::config::NetworkingMode;
    let mode = match proto.mode.as_str() {
        "bridge" => NetworkingMode::Bridge,
        "passt" => NetworkingMode::Passt,
        "user" => NetworkingMode::User,
        "custom" => NetworkingMode::Custom,
        "" => return None, // not set, use global default
        other => {
            tracing::warn!("unsupported per-VM networking mode '{other}', using global default");
            return None;
        }
    };
    // Only set mode; other fields will be merged from global config at runtime
    Some(crate::config::Networking {
        mode,
        bridge: String::new(),
        mac_prefix: String::new(),
        net: String::new(),
        dhcp_start: String::new(),
        restrict: false,
        passt_exec: String::new(),
        interface: String::new(),
        address: String::new(),
        netmask: String::new(),
        gateway: String::new(),
        dns: vec![],
        map_host_loopback: String::new(),
        map_guest_addr: String::new(),
        no_map_gw: false,
        ipv4_only: false,
        netdev: String::new(),
        forward_service_enabled: false,
    })
}

impl RpcHandler {
    fn resolve_gpus(&self, gpu_cfg: &rpc::GpuConfig) -> Result<GpuConfig> {
        resolve_gpus_with_config(gpu_cfg, &self.app.config.cvm)
    }

    #[allow(clippy::too_many_arguments)]
    async fn apply_resource_updates(
        &self,
        vm_id: &str,
        manifest: &mut Manifest,
        vm_work_dir: &VmWorkDir,
        vcpu: Option<u32>,
        memory: Option<u32>,
        disk_size: Option<u32>,
        image: Option<&str>,
    ) -> Result<bool> {
        let has_updates =
            vcpu.is_some() || memory.is_some() || disk_size.is_some() || image.is_some();
        if !has_updates {
            return Ok(false);
        }

        let vm = self.app.vm_info(vm_id).await?.context("vm not found")?;
        if !["stopped", "exited"].contains(&vm.status.as_str()) {
            bail!("vm should be stopped before resize: {}", vm_id);
        }

        if let Some(vcpu) = vcpu {
            manifest.vcpu = vcpu;
        }
        if let Some(memory) = memory {
            manifest.memory = memory;
        }
        if let Some(image) = image {
            manifest.image = image.to_string();
        }
        if let Some(disk_size) = disk_size {
            if disk_size < manifest.disk_size {
                bail!("Cannot shrink disk size");
            }
            manifest.disk_size = disk_size;

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

        Ok(true)
    }
}

impl VmmRpc for RpcHandler {
    async fn create_vm(self, request: VmConfiguration) -> Result<Id> {
        let manifest = create_manifest_from_vm_config(request.clone(), &self.app.config.cvm)?;
        let id = manifest.id.clone();
        let app_id = manifest.app_id.clone();
        let vm_work_dir = self.app.work_dir(&id);
        vm_work_dir
            .put_manifest(&manifest)
            .context("Failed to write manifest")?;
        let work_dir = self.prepare_work_dir(&id, &request, &app_id)?;
        if let Err(err) = vm_work_dir.set_started(!request.stopped) {
            warn!("Failed to set started: {}", err);
        }

        let result = self
            .app
            .load_vm(&work_dir, &Default::default(), false)
            .await
            .context("Failed to load VM");
        let result = match result {
            Ok(()) => {
                if !request.stopped {
                    self.app.start_vm(&id).await
                } else {
                    Ok(())
                }
            }
            Err(err) => Err(err),
        };
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

    async fn upgrade_app(self, request: UpdateVmRequest) -> Result<Id> {
        self.update_vm(request).await
    }

    async fn update_vm(self, request: UpdateVmRequest) -> Result<Id> {
        let new_id = if !request.compose_file.is_empty() {
            // check the compose file is valid
            let _app_compose: AppCompose =
                serde_json::from_str(&request.compose_file).context("Invalid compose file")?;
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
        if !request.user_config.is_empty() {
            let user_config_path = self.user_config_path(&request.id);
            fs::write(user_config_path, &request.user_config)
                .context("Failed to write user config")?;
        }
        let vm_work_dir = self.app.work_dir(&request.id);
        let mut manifest = vm_work_dir.manifest().context("Failed to read manifest")?;
        self.apply_resource_updates(
            &request.id,
            &mut manifest,
            &vm_work_dir,
            request.vcpu,
            request.memory,
            request.disk_size,
            request.image.as_deref(),
        )
        .await?;
        if let Some(gpus) = request.gpus {
            manifest.gpus = Some(self.resolve_gpus(&gpus)?);
        }
        if let Some(no_tee) = request.no_tee {
            manifest.no_tee = no_tee;
        }
        if request.update_ports {
            manifest.port_map = request
                .ports
                .iter()
                .map(|p| {
                    Ok(PortMapping {
                        address: p.host_address.parse().context("Invalid host address")?,
                        protocol: p.protocol.parse().context("Invalid protocol")?,
                        from: p.host_port.try_into().context("Invalid host port")?,
                        to: p.vm_port.try_into().context("Invalid vm port")?,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
        }
        if request.update_kms_urls {
            manifest.kms_urls = request.kms_urls.clone();
        }
        if request.update_gateway_urls {
            manifest.gateway_urls = request.gateway_urls.clone();
        }
        vm_work_dir
            .put_manifest(&manifest)
            .context("Failed to put manifest")?;

        self.app
            .load_vm(&vm_work_dir, &Default::default(), false)
            .await
            .context("Failed to load VM")?;
        if request.update_ports {
            self.app.reconfigure_port_forward(&new_id).await;
        }
        Ok(Id { id: new_id })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let kms = self.kms_client()?;
        let response = kms
            .get_app_env_encrypt_pub_key(dstack_kms_rpc::AppId {
                app_id: request.app_id,
            })
            .await?;
        Ok(PublicKeyResponse {
            public_key: response.public_key,
            signature: response.signature,
            timestamp: response.timestamp,
            signature_v1: response.signature_v1,
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
        let vm_work_dir = self.app.work_dir(&request.id);
        let mut manifest = vm_work_dir.manifest().context("failed to read manifest")?;
        self.apply_resource_updates(
            &request.id,
            &mut manifest,
            &vm_work_dir,
            request.vcpu,
            request.memory,
            request.disk_size,
            request.image.as_deref(),
        )
        .await?;
        vm_work_dir
            .put_manifest(&manifest)
            .context("failed to update manifest")?;
        self.app
            .load_vm(vm_work_dir.path(), &Default::default(), false)
            .await
            .context("Failed to load VM")?;
        Ok(())
    }

    async fn shutdown_vm(self, request: Id) -> Result<()> {
        self.guest_agent_client(&request.id)?.shutdown().await?;
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
                url: self
                    .app
                    .config
                    .cvm
                    .kms_urls
                    .first()
                    .cloned()
                    .unwrap_or_default(),
                urls: self.app.config.cvm.kms_urls.clone(),
            }),
            gateway: Some(GatewaySettings {
                url: self
                    .app
                    .config
                    .cvm
                    .gateway_urls
                    .first()
                    .cloned()
                    .unwrap_or_default(),
                urls: self.app.config.cvm.gateway_urls.clone(),
                base_domain: self.app.config.gateway.base_domain.clone(),
                port: self.app.config.gateway.port.into(),
                agent_port: self.app.config.gateway.agent_port.into(),
            }),
            resources: Some(ResourcesSettings {
                max_cvm_number: self.app.config.cvm.cid_pool_size,
                max_allocable_vcpu: self.app.config.cvm.max_allocable_vcpu,
                max_allocable_memory_in_mb: self.app.config.cvm.max_allocable_memory_in_mb,
            }),
        })
    }

    async fn list_gpus(self) -> Result<ListGpusResponse> {
        let gpus = self.app.list_gpus().await?;
        let allow_attach_all = self.app.config.cvm.gpu.allow_attach_all;
        Ok(ListGpusResponse {
            gpus,
            allow_attach_all,
        })
    }

    async fn get_compose_hash(self, request: VmConfiguration) -> Result<RpcComposeHash> {
        validate_label(&request.name)?;
        // check the compose file is valid
        let _app_compose: AppCompose =
            serde_json::from_str(&request.compose_file).context("Invalid compose file")?;
        let hash = hex_sha256(&request.compose_file);
        Ok(RpcComposeHash { hash })
    }

    async fn reload_vms(self) -> Result<ReloadVmsResponse> {
        info!("Reloading VMs directory and syncing with memory state");
        self.app.reload_vms_sync().await
    }

    async fn report_dhcp_lease(self, request: DhcpLeaseRequest) -> Result<()> {
        self.app.report_dhcp_lease(&request.mac, &request.ip).await;
        Ok(())
    }
}

impl RpcCall<App> for RpcHandler {
    type PrpcService = VmmServer<Self>;

    fn construct(context: CallContext<'_, App>) -> Result<Self> {
        Ok(RpcHandler {
            app: context.state.clone(),
        })
    }
}
