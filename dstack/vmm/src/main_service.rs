// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use dstack_types::AppCompose;
use dstack_vmm_rpc as rpc;
use dstack_vmm_rpc::vmm_server::{VmmRpc, VmmServer};
use dstack_vmm_rpc::{
    AppId, ComposeHash as RpcComposeHash, GatewaySettings, GetInfoResponse, GetMetaResponse, Id,
    ImageInfo as RpcImageInfo, ImageListResponse, KmsSettings, ListGpusResponse, PublicKeyResponse,
    PullRegistryImageRequest, RegistryImageInfo, RegistryImageListResponse, ReloadVmsResponse,
    ResizeVmRequest, ResourcesSettings, StatusRequest, StatusResponse, SvListResponse,
    SvProcessInfo, UpdateVmRequest, VersionResponse, VmConfiguration,
};
use fs_err as fs;
use or_panic::ResultOrPanic;
use path_absolutize::Absolutize;
use ra_rpc::{CallContext, RpcCall};
use tracing::{info, warn};

use crate::app::{
    needs_swtpm, resolve_networking, validate_resolved_network, validate_resolved_networks, App,
    AttachMode, GpuConfig, GpuSpec, Manifest, PortMapping, VmWorkDir,
};
use crate::config::{CvmConfig, Networking, NetworkingMode};

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

fn key_provider_from_compose(compose_file: &str) -> Result<dstack_types::KeyProviderKind> {
    let compose: serde_json::Value =
        serde_json::from_str(compose_file).context("invalid app compose JSON")?;
    if let Some(provider) = compose.get("key_provider").filter(|value| !value.is_null()) {
        return serde_json::from_value(provider.clone()).context("invalid key_provider");
    }
    if compose
        .get("kms_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(dstack_types::KeyProviderKind::Kms);
    }
    if compose
        .get("local_key_provider_enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(dstack_types::KeyProviderKind::Local);
    }
    Ok(dstack_types::KeyProviderKind::None)
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

fn port_mappings_conflict(left: &PortMapping, right: &PortMapping) -> bool {
    left.protocol.as_str() == right.protocol.as_str()
        && left.from == right.from
        && (left.address == right.address
            || left.address.is_unspecified()
            || right.address.is_unspecified())
}

fn validate_unique_port_mappings(mappings: &[PortMapping]) -> Result<()> {
    for (index, mapping) in mappings.iter().enumerate() {
        if mappings[..index]
            .iter()
            .any(|other| port_mappings_conflict(mapping, other))
        {
            bail!(
                "duplicate host port mapping: {} {}:{}",
                mapping.protocol.as_str(),
                mapping.address,
                mapping.from
            );
        }
    }
    Ok(())
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
    validate_unique_port_mappings(&port_map)?;

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
    let verity_volumes = extract_verity_volumes(&request.compose_file)?;
    dstack_types::validate_verity_volumes(&verity_volumes).map_err(anyhow::Error::msg)?;
    let volumes = resolve_volumes(&verity_volumes, cvm_config)?;

    let simulated_tee = request
        .simulated_tee
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    if simulated_tee.is_some() && cvm_config.tee_simulator.is_none() {
        bail!("tee simulator credentials are not configured on this VMM");
    }
    let key_provider = key_provider_from_compose(&request.compose_file)?;
    let swtpm = needs_swtpm(key_provider, simulated_tee);

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
        no_tee: request.no_tee || simulated_tee.is_some(),
        simulated_tee,
        swtpm,
        networks: networks_from_vm_config(&request, cvm_config)?,
        volumes,
    })
}

/// Extract only the field understood by this VMM. Keep every other app-compose
/// field opaque so newer guest schemas and legacy third-party clients remain
/// compatible with older VMMs.
fn extract_verity_volumes(compose: &str) -> Result<Vec<dstack_types::VerityVolume>> {
    let Ok(compose) = serde_json::from_str::<serde_json::Value>(compose) else {
        return Ok(vec![]);
    };
    let Some(volumes) = compose.get("verity_volumes") else {
        return Ok(vec![]);
    };
    serde_json::from_value(volumes.clone()).context("invalid verity_volumes in app-compose")
}

/// Resolve requested volumes against `cvm.volumes_dir`. Each `source` must be a
/// bare file name under that directory; the host attaches the bytes, and the
/// guest verifies content against the measured `verity_root`.
fn resolve_volumes(
    reqs: &[dstack_types::VerityVolume],
    cvm_config: &crate::config::CvmConfig,
) -> Result<Vec<crate::app::VmVolume>> {
    if reqs.is_empty() {
        return Ok(vec![]);
    }
    let dir = cvm_config.volumes_dir.trim();
    if dir.is_empty() {
        bail!("volumes requested but cvm.volumes_dir is not configured");
    }
    let base = fs::canonicalize(dir)?;
    let mut roots = HashSet::new();
    reqs.iter()
        .filter(|volume| {
            let first = roots.insert(volume.verity_root);
            if !first {
                warn!(
                    root = %hex::encode(volume.verity_root),
                    source = volume.source,
                    "not attaching duplicate verity root"
                );
            }
            first
        })
        .map(|v| {
            let real = resolve_volume_source(&base, &v.source)?;
            Ok(crate::app::VmVolume {
                source: real.to_string_lossy().into_owned(),
            })
        })
        .collect()
}

fn resolve_volume_source(base: &Path, source: &str) -> Result<PathBuf> {
    if source.is_empty() {
        bail!("invalid volume source: empty path");
    }

    let source_path = Path::new(source);
    let mut components = source_path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("invalid volume source '{source}': must be a bare file name");
    }

    let real = fs::canonicalize(base.join(source_path))?;
    real.absolutize_virtually(base)
        .with_context(|| format!("volume '{source}' escapes volumes_dir"))?;

    // QEMU's -drive parser treats ',' as an option separator and '=' as an
    // option key/value delimiter. Keep this guard while volumes are attached
    // through `-drive file=...`.
    let real_str = real.to_string_lossy();
    if real_str.contains(',') || real_str.contains('=') {
        bail!("volume '{source}' resolves to a path with ',' or '='");
    }

    Ok(real)
}

fn networking_from_proto(
    proto: &rpc::NetworkingConfig,
    cvm_config: &CvmConfig,
) -> Result<Option<Networking>> {
    let bridge = proto.bridge_name.trim().to_string();
    let mode = match proto.mode.as_str() {
        "bridge" => NetworkingMode::Bridge,
        "user" => NetworkingMode::User,
        "macvtap" => NetworkingMode::Macvtap,
        "" if bridge.is_empty() => return Ok(None),
        "" => bail!("networking mode is required when bridge is set"),
        "custom" => bail!("custom networking mode is manifest-only"),
        other => bail!("unsupported networking mode '{other}'"),
    };
    if !cvm_config.allowed_network_modes.contains(&mode) {
        bail!(
            "networking mode '{}' is not allowed by node policy",
            proto.mode
        );
    }
    if mode != NetworkingMode::Bridge && !bridge.is_empty() {
        bail!("bridge_name is only valid for bridge networking mode");
    }
    if mode != NetworkingMode::Macvtap && !proto.parent.trim().is_empty() {
        bail!("parent is only valid for macvtap networking mode");
    }
    if !proto.macvtap_mode.trim().is_empty() {
        bail!("macvtap_mode is node-controlled and cannot be set by deployment RPCs");
    }
    if !bridge.is_empty() && !cvm_config.allowed_bridges.contains(&bridge) {
        bail!("bridge_name '{bridge}' is not allowed by node policy");
    }
    let parent = proto.parent.trim().to_string();
    if !parent.is_empty() && !cvm_config.allowed_macvtap_parents.contains(&parent) {
        bail!("macvtap parent '{parent}' is not allowed by node policy");
    }
    Ok(Some(Networking {
        mode,
        bridge,
        parent,
        // The forwarding mode is always inherited from node configuration.
        macvtap_mode: String::new(),
        device: String::new(),
        mac_prefix: String::new(),
        net: String::new(),
        dhcp_start: String::new(),
        restrict: false,
        netdev: String::new(),
    }))
}

fn network_from_required_proto(
    proto: &rpc::NetworkingConfig,
    cvm_config: &CvmConfig,
) -> Result<Networking> {
    networking_from_proto(proto, cvm_config)?.context("networking mode is required")
}

fn networks_from_proto(
    networks: &[rpc::NetworkingConfig],
    cvm_config: &CvmConfig,
) -> Result<Vec<Networking>> {
    networks
        .iter()
        .map(|network| network_from_required_proto(network, cvm_config))
        .collect()
}

fn validate_default_network(cvm_config: &CvmConfig) -> Result<()> {
    validate_resolved_network(&cvm_config.networking)
}

fn resolve_requested_networks(
    networks: &[Networking],
    cvm_config: &CvmConfig,
) -> Result<Vec<Networking>> {
    let resolved = networks
        .iter()
        .map(|networking| resolve_networking(networking, cvm_config))
        .collect::<Vec<_>>();
    validate_resolved_networks(&resolved)?;
    Ok(resolved)
}

fn has_host_bridge_interface() -> bool {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return false;
    };
    entries
        .filter_map(|entry| entry.ok())
        .any(|entry| entry.path().join("bridge").exists())
}

fn networks_from_vm_config(
    request: &VmConfiguration,
    cvm_config: &CvmConfig,
) -> Result<Vec<Networking>> {
    if !request.networks.is_empty() {
        let networks = networks_from_proto(&request.networks, cvm_config)?;
        resolve_requested_networks(&networks, cvm_config)
    } else if let Some(networking) = request.networking.as_ref() {
        match networking_from_proto(networking, cvm_config)? {
            Some(networking) => resolve_requested_networks(&[networking], cvm_config),
            None => Ok(vec![]),
        }
    } else {
        Ok(vec![])
    }
}

fn validate_resize_request(request: &ResizeVmRequest) -> Result<()> {
    if request.vcpu.is_none()
        && request.memory.is_none()
        && request.disk_size.is_none()
        && request.image.is_none()
    {
        bail!("resize request contains no updates");
    }
    if request.vcpu == Some(0) {
        bail!("vcpu must be greater than zero");
    }
    if request.memory == Some(0) {
        bail!("memory must be greater than zero");
    }
    if request.disk_size == Some(0) {
        bail!("disk_size must be greater than zero");
    }
    if request.image.as_deref() == Some("") {
        bail!("image must not be empty");
    }
    Ok(())
}

impl RpcHandler {
    fn validate_port_mapping_conflicts(
        &self,
        vm_id: Option<&str>,
        mappings: &[PortMapping],
    ) -> Result<()> {
        validate_unique_port_mappings(mappings)?;
        let state = self.app.lock();
        for vm in state.iter_vms() {
            if vm_id == Some(vm.config.manifest.id.as_str()) {
                continue;
            }
            for mapping in mappings {
                if vm
                    .config
                    .manifest
                    .port_map
                    .iter()
                    .any(|existing| port_mappings_conflict(mapping, existing))
                {
                    bail!(
                        "host port mapping conflicts with VM {}: {} {}:{}",
                        vm.config.manifest.id,
                        mapping.protocol.as_str(),
                        mapping.address,
                        mapping.from
                    );
                }
            }
        }
        Ok(())
    }

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
            if disk_size > manifest.disk_size {
                let hda_path = vm_work_dir.hda_path();
                if hda_path.exists() {
                    info!("Resizing disk to {}GB", disk_size);
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
                } else {
                    // A never-started stopped VM has no data disk yet. Its
                    // first launch creates hda.img from manifest.disk_size.
                    info!("Recording {}GB disk size for uninitialized VM", disk_size);
                }
                manifest.disk_size = disk_size;
            }
        }

        Ok(true)
    }
}

impl VmmRpc for RpcHandler {
    async fn create_vm(self, request: VmConfiguration) -> Result<Id> {
        let manifest = create_manifest_from_vm_config(request.clone(), &self.app.config.cvm)?;
        self.validate_port_mapping_conflicts(None, &manifest.port_map)?;
        let id = manifest.id.clone();
        let app_id = manifest.app_id.clone();
        let vm_work_dir = self.app.work_dir(&id)?;
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
            let compose_file_path = self.compose_file_path(&request.id)?;
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
            let encrypted_env_path = self.encrypted_env_path(&request.id)?;
            fs::write(encrypted_env_path, &request.encrypted_env)
                .context("Failed to write encrypted env")?;
        }
        if !request.user_config.is_empty() {
            let user_config_path = self.user_config_path(&request.id)?;
            fs::write(user_config_path, &request.user_config)
                .context("Failed to write user config")?;
        }
        let vm_work_dir = self.app.work_dir(&request.id)?;
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
            let port_map = request
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
            self.validate_port_mapping_conflicts(Some(&request.id), &port_map)?;
            manifest.port_map = port_map;
        }
        if request.update_kms_urls {
            manifest.kms_urls = request.kms_urls.clone();
        }
        if request.update_gateway_urls {
            manifest.gateway_urls = request.gateway_urls.clone();
        }
        if request.update_networking {
            let networks = if request.networks.is_empty() {
                validate_default_network(&self.app.config.cvm)?;
                vec![]
            } else {
                let networks = networks_from_proto(&request.networks, &self.app.config.cvm)?;
                resolve_requested_networks(&networks, &self.app.config.cvm)?
            };
            let is_running = self
                .app
                .supervisor
                .info(&request.id)
                .await?
                .is_some_and(|info| info.state.status.is_running());
            if !is_running {
                let runtime_networks = vm_work_dir.runtime_networks();
                self.app
                    .remove_filtered_networks(&request.id, &runtime_networks)
                    .await
                    .context("failed to remove previous filtered networking")?;
                vm_work_dir.clear_runtime_networks()?;
            }
            manifest.networks = networks;
        }
        let compose_file = fs::read_to_string(vm_work_dir.app_compose_path())
            .context("failed to read app compose for swtpm decision")?;
        manifest.swtpm = needs_swtpm(
            key_provider_from_compose(&compose_file)?,
            manifest.simulated_tee,
        );
        vm_work_dir
            .put_manifest(&manifest)
            .context("Failed to put manifest")?;

        self.app
            .load_vm(&vm_work_dir, &Default::default(), false)
            .await
            .context("Failed to load VM")?;
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
        validate_resize_request(&request)?;
        let vm_work_dir = self.app.work_dir(&request.id)?;
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
        let mut supported_modes = vec!["user".to_string()];
        let default_networking = &self.app.config.cvm.networking;
        let mut bridge_networking = default_networking.clone();
        bridge_networking.mode = NetworkingMode::Bridge;
        if validate_resolved_network(&bridge_networking).is_ok() || has_host_bridge_interface() {
            supported_modes.push("bridge".to_string());
        }
        supported_modes.push("macvtap".to_string());
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
            networking: Some(rpc::NetworkingCapabilities {
                supported_modes,
                default_mode: match default_networking.mode {
                    NetworkingMode::User => "user".to_string(),
                    NetworkingMode::Bridge => "bridge".to_string(),
                    NetworkingMode::Custom => String::new(),
                    NetworkingMode::Macvtap => "macvtap".to_string(),
                },
                default_bridge: default_networking.bridge.clone(),
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

    async fn sv_list(self) -> Result<SvListResponse> {
        use supervisor_client::supervisor::ProcessStatus;
        let list = self.app.supervisor.list().await?;
        let processes = list
            .into_iter()
            .map(|p| {
                let status = match &p.state.status {
                    ProcessStatus::Running => "running".into(),
                    ProcessStatus::Stopped => "stopped".into(),
                    ProcessStatus::Exited(code) => format!("exited({code})"),
                    ProcessStatus::Error(msg) => format!("error({msg})"),
                };
                SvProcessInfo {
                    id: p.config.id,
                    name: p.config.name,
                    status,
                    pid: p.state.pid,
                    command: p.config.command,
                    note: p.config.note,
                }
            })
            .collect();
        Ok(SvListResponse { processes })
    }

    async fn sv_stop(self, request: Id) -> Result<()> {
        // VM launcher processes own QEMU and swtpm children. Route them through
        // the VM-aware stop path so the launcher can reap those children; the
        // same helper preserves generic Supervisor stop semantics for every
        // other process type.
        self.app
            .supervisor
            .info(&request.id)
            .await?
            .context("Supervisor process not found")?;
        self.app.stop_vm_process(&request.id).await
    }

    async fn sv_remove(self, request: Id) -> Result<()> {
        self.app.supervisor.remove(&request.id).await?;
        Ok(())
    }

    async fn list_registry_images(self) -> Result<RegistryImageListResponse> {
        let registry = &self.app.config.image.registry;
        if registry.is_empty() {
            return Ok(RegistryImageListResponse { images: vec![] });
        }

        let tags = crate::app::registry::list_registry_tags(registry)
            .await
            .context("failed to list registry tags")?;

        // Get local images to mark which are already downloaded
        let local_images = self.app.list_images()?;
        let local_names: std::collections::HashSet<String> =
            local_images.into_iter().map(|(name, _)| name).collect();

        let pull_status = self.app.pull_status.lock().or_panic("mutex poisoned");

        // Filter to version-like tags (skip sha256-* hash tags)
        let images = tags
            .into_iter()
            .filter(|tag| !tag.starts_with("sha256-"))
            .map(|tag| {
                let local_name = if tag.starts_with("dstack-") {
                    tag.clone()
                } else {
                    format!("dstack-{tag}")
                };
                let is_local = local_names.contains(&local_name);
                let (is_pulling, error) = match pull_status.get(&tag) {
                    Some(crate::app::PullStatus::Pulling) => (true, String::new()),
                    Some(crate::app::PullStatus::Failed(msg)) => (false, msg.clone()),
                    None => (false, String::new()),
                };
                RegistryImageInfo {
                    tag,
                    local: is_local,
                    pulling: is_pulling,
                    error,
                }
            })
            .collect();

        Ok(RegistryImageListResponse { images })
    }

    async fn delete_image(self, request: Id) -> Result<()> {
        let name = &request.id;
        if name.is_empty() || name.contains("..") || name.contains('/') {
            bail!("invalid image name");
        }

        // Check no VM uses this image
        {
            let state = self.app.lock();
            for vm in state.iter_vms() {
                if vm.config.manifest.image == *name {
                    bail!(
                        "cannot delete image '{}': in use by VM '{}'",
                        name,
                        vm.config.manifest.name,
                    );
                }
            }
        }

        let image_dir = self.app.config.image.path.join(name);
        if !image_dir.exists() {
            bail!("image '{}' not found", name);
        }

        fs_err::remove_dir_all(&image_dir).with_context(|| {
            format!("failed to delete image directory: {}", image_dir.display())
        })?;

        info!("deleted local image: {name}");
        Ok(())
    }

    async fn pull_registry_image(self, request: PullRegistryImageRequest) -> Result<()> {
        let registry = &self.app.config.image.registry;
        if registry.is_empty() {
            bail!("image registry is not configured");
        }

        // Check if already pulling
        {
            let mut status = self.app.pull_status.lock().or_panic("mutex poisoned");
            if matches!(
                status.get(&request.tag),
                Some(crate::app::PullStatus::Pulling)
            ) {
                bail!("image {} is already being pulled", request.tag);
            }
            status.insert(request.tag.clone(), crate::app::PullStatus::Pulling);
        }

        // Spawn background task
        let tag = request.tag.clone();
        let registry = registry.clone();
        let image_path = self.app.config.image.path.clone();
        let pull_status = self.app.pull_status.clone();

        info!("starting background pull for {tag}");
        tokio::spawn(async move {
            let result = crate::app::registry::pull_and_extract(&registry, &tag, &image_path).await;

            let mut status = pull_status.lock().unwrap_or_else(|e| e.into_inner());
            match result {
                Ok(()) => {
                    status.remove(&tag);
                    info!("registry image {tag} pulled successfully");
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    tracing::error!("failed to pull registry image {tag}: {msg}");
                    status.insert(tag, crate::app::PullStatus::Failed(msg));
                }
            }
        });

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

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::Figment;

    fn test_cvm_config() -> CvmConfig {
        let config: crate::config::Config = Figment::from(crate::config::load_config_figment(None))
            .extract()
            .unwrap();
        config.cvm
    }

    fn test_vm_configuration() -> VmConfiguration {
        VmConfiguration {
            name: "vm-test".to_string(),
            image: "dstack-test".to_string(),
            compose_file: "{}".to_string(),
            vcpu: 1,
            memory: 1024,
            disk_size: 10,
            ports: vec![],
            encrypted_env: vec![],
            app_id: None,
            user_config: String::new(),
            hugepages: false,
            pin_numa: false,
            gpus: None,
            kms_urls: vec![],
            gateway_urls: vec![],
            stopped: false,
            no_tee: false,
            simulated_tee: None,
            networking: None,
            networks: vec![],
        }
    }

    #[test]
    fn create_without_networking_persists_following_default() {
        let manifest =
            create_manifest_from_vm_config(test_vm_configuration(), &test_cvm_config()).unwrap();

        assert!(manifest.networks.is_empty());
    }

    #[test]
    fn resize_request_rejects_empty_zero_and_empty_image_updates() {
        let mut request = ResizeVmRequest {
            id: "vm-1".into(),
            ..Default::default()
        };
        assert!(validate_resize_request(&request).is_err());

        request.vcpu = Some(0);
        assert!(validate_resize_request(&request).is_err());
        request.vcpu = Some(1);
        assert!(validate_resize_request(&request).is_ok());

        request.vcpu = None;
        request.memory = Some(0);
        assert!(validate_resize_request(&request).is_err());
        request.memory = None;
        request.disk_size = Some(0);
        assert!(validate_resize_request(&request).is_err());
        request.disk_size = None;
        request.image = Some(String::new());
        assert!(validate_resize_request(&request).is_err());
    }

    #[test]
    fn simulated_tee_is_selected_per_instance_and_implies_no_tee() {
        let mut request = test_vm_configuration();
        request.simulated_tee = Some("dstack-amd-sev-snp".into());
        let mut config = test_cvm_config();
        config.tee_simulator = Some(dstack_types::TeeSimulatorConfig {
            mock_attestation_seed: Some("11".repeat(32)),
            ..Default::default()
        });

        let manifest = create_manifest_from_vm_config(request, &config).unwrap();

        assert_eq!(
            manifest.simulated_tee,
            Some(dstack_types::TeeVariant::DstackAmdSevSnp)
        );
        assert!(manifest.no_tee);
        assert!(!manifest.swtpm);
    }

    #[test]
    fn swtpm_is_decided_at_deployment_from_key_provider_and_simulator() {
        let cases = [
            (None, "tpm", true),
            (Some("dstack-tdx"), "tpm", true),
            (Some("dstack-gcp-tdx"), "tpm", false),
            (Some("dstack-aws-nitro-tpm"), "tpm", false),
            (Some("dstack-tdx"), "kms", false),
        ];
        let mut config = test_cvm_config();
        config.tee_simulator = Some(dstack_types::TeeSimulatorConfig {
            mock_attestation_seed: Some("11".repeat(32)),
            ..Default::default()
        });

        for (simulated_tee, key_provider, expected) in cases {
            let mut request = test_vm_configuration();
            request.simulated_tee = simulated_tee.map(str::to_string);
            request.compose_file = serde_json::json!({ "key_provider": key_provider }).to_string();

            let manifest = create_manifest_from_vm_config(request, &config).unwrap();

            assert_eq!(manifest.swtpm, expected);
        }
    }

    #[test]
    fn simulated_tee_requires_node_credentials() {
        let mut request = test_vm_configuration();
        request.simulated_tee = Some("dstack-tdx".into());

        let err = create_manifest_from_vm_config(request, &test_cvm_config()).unwrap_err();

        assert!(err
            .to_string()
            .contains("tee simulator credentials are not configured"));
    }

    #[test]
    fn invalid_simulated_tee_is_rejected() {
        let mut request = test_vm_configuration();
        request.simulated_tee = Some("not-a-platform".into());

        let err = create_manifest_from_vm_config(request, &test_cvm_config()).unwrap_err();

        assert!(err.to_string().contains("unsupported TEE variant"));
    }

    #[test]
    fn volume_extraction_keeps_other_compose_fields_opaque() -> Result<()> {
        assert!(extract_verity_volumes("not json")?.is_empty());
        assert!(extract_verity_volumes(r#"{"future_manifest":true}"#)?.is_empty());

        let compose = serde_json::json!({
            "unknown_future_field": { "anything": true },
            "verity_volumes": [{
                "source": "volume.img",
                "verity_root": "11".repeat(32),
                "target": "/run/volume"
            }]
        });
        let volumes = extract_verity_volumes(&compose.to_string())?;
        assert_eq!(volumes.len(), 1);
        assert_eq!(volumes[0].verity_root, [0x11; 32]);
        Ok(())
    }

    #[test]
    fn explicit_user_networking_is_resolved_before_persist() {
        let mut request = test_vm_configuration();
        request.networks = vec![rpc::NetworkingConfig {
            mode: "user".to_string(),
            bridge_name: String::new(),
            ..Default::default()
        }];

        let manifest = create_manifest_from_vm_config(request, &test_cvm_config()).unwrap();

        assert_eq!(manifest.networks.len(), 1);
        assert_eq!(manifest.networks[0].mode, NetworkingMode::User);
        assert!(!manifest.networks[0].net.is_empty());
    }

    #[test]
    fn authorized_macvtap_preserves_parent_and_inherits_forwarding_mode() {
        let mut cvm_config = test_cvm_config();
        cvm_config
            .allowed_network_modes
            .push(NetworkingMode::Macvtap);
        cvm_config.allowed_macvtap_parents.push("eth0".to_string());
        cvm_config.networking.parent = "node-default".to_string();
        cvm_config.networking.macvtap_mode = "private".to_string();
        let networks = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "macvtap".to_string(),
                parent: "eth0".to_string(),
                ..Default::default()
            }],
            &cvm_config,
        )
        .unwrap();

        assert_eq!(networks[0].mode, NetworkingMode::Macvtap);
        assert_eq!(networks[0].parent, "eth0");
        assert!(networks[0].macvtap_mode.is_empty());

        let resolved = resolve_requested_networks(&networks, &cvm_config).unwrap();
        assert_eq!(resolved[0].parent, "eth0");
        assert_eq!(resolved[0].macvtap_mode, "private");
    }

    #[test]
    fn macvtap_is_denied_by_default_rpc_policy() {
        let err = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "macvtap".to_string(),
                ..Default::default()
            }],
            &test_cvm_config(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("not allowed by node policy"));
    }

    #[test]
    fn bridge_override_requires_allowlist_entry() {
        let request = [rpc::NetworkingConfig {
            mode: "bridge".to_string(),
            bridge_name: "tenant-br0".to_string(),
            ..Default::default()
        }];
        let mut cvm_config = test_cvm_config();

        let err = networks_from_proto(&request, &cvm_config).unwrap_err();
        assert!(err.to_string().contains("bridge_name 'tenant-br0'"));

        cvm_config.allowed_bridges.push("tenant-br0".to_string());
        let networks = networks_from_proto(&request, &cvm_config).unwrap();
        assert_eq!(networks[0].bridge, "tenant-br0");
    }

    #[test]
    fn macvtap_parent_requires_allowlist_entry() {
        let request = [rpc::NetworkingConfig {
            mode: "macvtap".to_string(),
            parent: "eth1".to_string(),
            ..Default::default()
        }];
        let mut cvm_config = test_cvm_config();
        cvm_config
            .allowed_network_modes
            .push(NetworkingMode::Macvtap);

        let err = networks_from_proto(&request, &cvm_config).unwrap_err();
        assert!(err.to_string().contains("macvtap parent 'eth1'"));

        cvm_config.allowed_macvtap_parents.push("eth1".to_string());
        let networks = networks_from_proto(&request, &cvm_config).unwrap();
        assert_eq!(networks[0].parent, "eth1");
    }

    #[test]
    fn deployment_rpc_cannot_select_macvtap_forwarding_mode() {
        let mut cvm_config = test_cvm_config();
        cvm_config
            .allowed_network_modes
            .push(NetworkingMode::Macvtap);
        let err = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "macvtap".to_string(),
                macvtap_mode: "passthru".to_string(),
                ..Default::default()
            }],
            &cvm_config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("node-controlled"));
    }

    #[test]
    fn bridge_name_is_rejected_for_user_mode() {
        let err = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "user".to_string(),
                bridge_name: "dstack-br0".to_string(),
                ..Default::default()
            }],
            &test_cvm_config(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("bridge_name is only valid"));
    }

    #[test]
    fn repeated_networks_rejects_empty_entries() {
        let err = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: String::new(),
                bridge_name: String::new(),
                ..Default::default()
            }],
            &test_cvm_config(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("networking mode is required"));
    }

    #[test]
    fn repeated_networks_rejects_custom_entries() {
        let err = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "custom".to_string(),
                bridge_name: String::new(),
                ..Default::default()
            }],
            &test_cvm_config(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("custom networking mode"));
    }

    #[test]
    fn resolve_volume_source_rejects_escape_symlink_and_qemu_metachars() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        let volumes = tmp.path().join("volumes");
        fs::create_dir_all(&volumes)?;
        fs::write(volumes.join("ok.img"), b"ok")?;
        let base = fs::canonicalize(&volumes)?;

        let ok = resolve_volume_source(&base, "ok.img")?;
        assert_eq!(ok, base.join("ok.img"));

        let err = resolve_volume_source(&base, "../ok.img").unwrap_err();
        assert!(format!("{err:#}").contains("must be a bare file name"));

        fs::write(tmp.path().join("outside.img"), b"outside")?;
        std::os::unix::fs::symlink(tmp.path().join("outside.img"), volumes.join("link.img"))?;
        let err = resolve_volume_source(&base, "link.img").unwrap_err();
        assert!(format!("{err:#}").contains("escapes volumes_dir"));

        fs::write(volumes.join("bad,readonly=off"), b"bad")?;
        let err = resolve_volume_source(&base, "bad,readonly=off").unwrap_err();
        assert!(format!("{err:#}").contains("',' or '='"));

        Ok(())
    }

    #[test]
    fn resolve_volumes_resolves_measured_source() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        fs::write(tmp.path().join("volume.img"), b"volume")?;
        let mut cvm_config = test_cvm_config();
        cvm_config.volumes_dir = tmp.path().to_string_lossy().into_owned();

        let volumes = resolve_volumes(
            &[dstack_types::VerityVolume {
                source: "volume.img".into(),
                verity_root: [0; 32],
                target: "/run/volume".into(),
            }],
            &cvm_config,
        )?;

        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0].source,
            tmp.path().join("volume.img").display().to_string()
        );
        Ok(())
    }

    #[test]
    fn resolve_volumes_attaches_duplicate_root_once() -> Result<()> {
        let tmp = tempfile::tempdir()?;
        fs::write(tmp.path().join("first.img"), b"volume")?;
        let mut cvm_config = test_cvm_config();
        cvm_config.volumes_dir = tmp.path().to_string_lossy().into_owned();
        let root = [7; 32];

        let volumes = resolve_volumes(
            &[
                dstack_types::VerityVolume {
                    source: "first.img".into(),
                    verity_root: root,
                    target: "/run/first".into(),
                },
                dstack_types::VerityVolume {
                    // This source deliberately does not exist: the first entry
                    // owns the single attachment for this content root.
                    source: "duplicate.img".into(),
                    verity_root: root,
                    target: "/run/second".into(),
                },
            ],
            &cvm_config,
        )?;

        assert_eq!(volumes.len(), 1);
        assert_eq!(
            volumes[0].source,
            tmp.path().join("first.img").display().to_string()
        );
        Ok(())
    }
}
