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
use crate::config::{CvmConfig, Networking, NetworkingMode, NicNetworking};

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
) -> Result<Option<NicNetworking>> {
    let bridge = proto.bridge_name.trim().to_string();
    let parent = proto.parent.trim().to_string();
    // Checked before anything reads `queues`, because the "no override at all"
    // arm below returns early: a request of `{queues: 0}` and nothing else
    // would otherwise be answered with the vCPU-scaled default -- up to
    // sixteen queue pairs -- for a caller who asked for none.
    if proto.queues == Some(0) {
        bail!("networking queues must be at least 1, or unset to follow the vCPU count");
    }
    let tuned = proto.vhost.is_some() || proto.queues.is_some();
    // Naming a bridge or a macvtap parent is naming a backend, and a backend
    // needs a mode to go with it. Without one the entry would freeze whichever
    // mode the node happened to have, then report a mode-less override still
    // carrying a field only one mode accepts -- something nothing can send
    // back once the node moves on.
    let names_backend = !bridge.is_empty() || !parent.is_empty();
    // A request that only tunes the data plane keeps the node's backend. Node
    // policy governs which backend a caller may *choose*, so inheriting one
    // must not be denied by it.
    let (mode, chosen) = match proto.mode.as_str() {
        "bridge" => (NetworkingMode::Bridge, true),
        "user" => (NetworkingMode::User, true),
        "macvtap" => (NetworkingMode::Macvtap, true),
        "" if !names_backend && !tuned => return Ok(None),
        "" if !names_backend => (cvm_config.networking.nic.mode, false),
        "" => bail!("networking mode is required when a bridge or macvtap parent is set"),
        "custom" => bail!("custom networking mode is manifest-only"),
        other => bail!("unsupported networking mode '{other}'"),
    };
    if chosen && !cvm_config.allowed_network_modes.contains(&mode) {
        bail!(
            "networking mode '{}' is not allowed by node policy",
            proto.mode
        );
    }
    if mode != NetworkingMode::Bridge && !bridge.is_empty() {
        bail!("bridge_name is only valid for bridge networking mode");
    }
    if mode != NetworkingMode::Macvtap && !parent.is_empty() {
        bail!("parent is only valid for macvtap networking mode");
    }
    // `GetInfo` reports the resolved node defaults, and both vmm-cli and the
    // web UI read that, change one field, and send the rest back. Naming a
    // value the node would have supplied anyway therefore has to be accepted:
    // leaving the field empty already yields exactly it, so echoing it grants
    // nothing that policy was withholding.
    // Node values are compared trimmed, the way the request's are: node
    // configuration validation tolerates surrounding whitespace, and a value
    // resolution would supply must not become unsendable over a space.
    let node = &cvm_config.networking;
    let macvtap_mode = proto.macvtap_mode.trim();
    if !macvtap_mode.is_empty() && macvtap_mode != node.macvtap_mode.trim() {
        bail!("macvtap_mode is node-controlled and cannot be set by deployment RPCs");
    }
    if !bridge.is_empty()
        && bridge != node.nic.bridge.trim()
        && !cvm_config.allowed_bridges.contains(&bridge)
    {
        bail!("bridge_name '{bridge}' is not allowed by node policy");
    }
    if !parent.is_empty()
        && parent != node.nic.parent.trim()
        && !cvm_config.allowed_macvtap_parents.contains(&parent)
    {
        bail!("macvtap parent '{parent}' is not allowed by node policy");
    }
    // Same rule as the queue count below: a backend the caller chose and that
    // has no vhost data plane is a request they can fix, so say so. An
    // inherited one is not, and reads as off until the node moves.
    if chosen && proto.vhost == Some(true) && !Networking::mode_supports_vhost(mode) {
        bail!("{} networking has no vhost data plane", proto.mode);
    }
    // Queue pairs cost a host vhost thread and a pair of MSI-X vectors each, so
    // the node caps what a deployment may ask for.
    //
    let queues = proto.queues;
    if let Some(queues) = queues {
        if queues > cvm_config.max_net_queues {
            bail!(
                "networking queues must not exceed {} on this node",
                cvm_config.max_net_queues
            );
        }
        // Only a backend the caller *chose* is theirs to be wrong about. One
        // they inherited can change under them -- that is the point of
        // inheriting -- and refusing the request afterwards would strand the
        // VM: GetInfo would keep reporting a queue count that nothing is
        // allowed to send back. `queue_pairs()` already reads as one on both
        // of these, so the request simply lies dormant until the node moves to
        // a backend that can honour it.
        if chosen && queues > 1 && !Networking::mode_supports_multiqueue(mode) {
            bail!("{} networking does not support multiple queues", proto.mode);
        }
    }
    // Every field the node owns -- the macvtap forwarding mode, the MAC prefix,
    // the user-mode network parameters, a custom netdev string -- is absent by
    // construction now rather than by remembering to write `String::new()` for
    // each of them.
    Ok(Some(NicNetworking {
        mode,
        // The caller named no backend, so the node keeps owning which one this
        // NIC uses. `mode` above is only the node's current choice.
        inherit_mode: !chosen,
        bridge,
        parent,
        vhost: proto.vhost,
        queues,
    }))
}

/// Networking modes a client should offer.
///
/// A mode the host could serve but node policy forbids is not one of them:
/// offering it puts a choice in the deploy dialog whose only outcome is "not
/// allowed by node policy", with nothing for the operator to do about it. A VM
/// can still be given a data plane override without naming any mode, which is
/// how a node whose own backend is not caller-selectable stays tunable.
fn advertised_modes(cvm_config: &CvmConfig, host_can_bridge: bool) -> Vec<String> {
    [
        (NetworkingMode::User, "user", true),
        (NetworkingMode::Bridge, "bridge", host_can_bridge),
        (NetworkingMode::Macvtap, "macvtap", true),
    ]
    .into_iter()
    .filter(|(mode, _, host_supports)| {
        *host_supports && cvm_config.allowed_network_modes.contains(mode)
    })
    .map(|(_, name, _)| name.to_string())
    .collect()
}

/// The node's policy, widened by what this VM's own NICs already pin.
///
/// Deployment allowlists govern what a caller may *newly* select. A value one
/// of this VM's interfaces is already running on was selected when it was
/// still allowed, and it is reported back on every `GetInfo`; refusing it
/// would strand the VM rather than withhold anything.
fn held_networking_config(cvm_config: &CvmConfig, held: &[NicNetworking]) -> CvmConfig {
    let mut widened = cvm_config.clone();
    for networking in held {
        // Only a field the entry's own mode owns. Resolution starts from the
        // node's whole `[cvm.networking]` value, so a bridge entry also carries
        // whatever macvtap parent the node happened to have configured, and a
        // macvtap entry carries its bridge -- baggage the VM never used. Reading
        // those as "already running on it" would widen policy from a value
        // nothing ever attached to, and let a VM move to a backend the node
        // forbids.
        if networking.mode == NetworkingMode::Bridge && !networking.bridge.is_empty() {
            widened.allowed_bridges.push(networking.bridge.clone());
        }
        if networking.mode == NetworkingMode::Macvtap && !networking.parent.is_empty() {
            widened
                .allowed_macvtap_parents
                .push(networking.parent.clone());
        }
        // Same rule for the queue cap. Lowering `max_net_queues` bounds what a
        // deployment may newly ask for; it does not retroactively re-tune VMs
        // that are already pinned above it, and those keep reporting their
        // count on every `GetInfo`. Without this, lowering the cap makes every
        // networking update on such a VM fail on a field the operator never
        // typed -- including the `--net-queues auto` that would unpin it.
        if let Some(queues) = networking.queues {
            widened.max_net_queues = widened.max_net_queues.max(queues);
        }
    }
    widened
}

/// A NIC that overrides nothing: whatever the node's `[cvm.networking]` says,
/// now and after the operator changes it.
fn node_default_networking(cvm_config: &CvmConfig) -> NicNetworking {
    NicNetworking {
        mode: cvm_config.networking.nic.mode,
        inherit_mode: true,
        ..NicNetworking::default()
    }
}

fn network_from_required_proto(
    proto: &rpc::NetworkingConfig,
    cvm_config: &CvmConfig,
) -> Result<NicNetworking> {
    // An entry in a list that overrides nothing is not a missing mode: it is a
    // NIC that follows the node entirely. Only the singular `networking` field
    // can mean "no override at all", because there the absence is the message.
    Ok(networking_from_proto(proto, cvm_config)?
        .unwrap_or_else(|| node_default_networking(cvm_config)))
}

fn networks_from_proto(
    networks: &[rpc::NetworkingConfig],
    cvm_config: &CvmConfig,
) -> Result<Vec<NicNetworking>> {
    networks
        .iter()
        .map(|network| network_from_required_proto(network, cvm_config))
        .collect()
}

fn validate_default_network(cvm_config: &CvmConfig) -> Result<()> {
    validate_resolved_network(&cvm_config.networking)
}

fn resolve_requested_networks(
    requests: &[NicNetworking],
    cvm_config: &CvmConfig,
    vcpu: u32,
) -> Result<Vec<NicNetworking>> {
    let merged = requests
        .iter()
        .map(|request| resolve_networking(request, cvm_config, vcpu))
        .collect::<Vec<_>>();
    // Validate the merged view, because that is what the launch sees, then
    // record the narrower view the manifest keeps.
    validate_resolved_networks(&merged)?;
    Ok(manifest_networks(merged, requests))
}

/// What a deployment records against the VM, given the merged view its launch
/// would see.
///
/// The backend a deployment *chose* is pinned here -- its mode, and the bridge
/// or macvtap parent that names it -- so a VM keeps the segment it was put on
/// for life. Everything else stays owned by the node and is re-read at every
/// launch: the MAC prefix, the user-mode subnet and DHCP start, the macvtap
/// forwarding mode, and the data plane an operator may want to roll back
/// node-wide. A VM's own record cannot carry any of those.
fn manifest_networks(merged: Vec<Networking>, requests: &[NicNetworking]) -> Vec<NicNetworking> {
    merged
        .into_iter()
        .zip(requests)
        .map(|(entry, request)| {
            if request.inherit_mode {
                // The caller named no backend, so none of the node's matching
                // identity fields are theirs to keep.
                return request.clone();
            }
            // Taking `entry.nic` rather than the whole resolved value is what
            // keeps the node's half out of the VM's record; it used to take the
            // whole thing and then clear the one node field anybody noticed.
            //
            // The two identity fields still share one type, and resolution
            // fills both from the node, so scope them here -- once, where the
            // record is written -- rather than leaving every later reader to
            // remember which one its mode owns. Two already have to.
            let mode = entry.nic.mode;
            NicNetworking {
                bridge: if mode == NetworkingMode::Bridge {
                    entry.nic.bridge
                } else {
                    String::new()
                },
                parent: if mode == NetworkingMode::Macvtap {
                    entry.nic.parent
                } else {
                    String::new()
                },
                // Data plane tuning is not identity: leave what the caller did
                // not ask for unset.
                vhost: request.vhost,
                queues: request.queues,
                mode,
                inherit_mode: entry.nic.inherit_mode,
            }
        })
        .collect()
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
) -> Result<Vec<NicNetworking>> {
    if !request.networks.is_empty() {
        let networks = networks_from_proto(&request.networks, cvm_config)?;
        resolve_requested_networks(&networks, cvm_config, request.vcpu)
    } else if let Some(networking) = request.networking.as_ref() {
        match networking_from_proto(networking, cvm_config)? {
            Some(networking) => resolve_requested_networks(&[networking], cvm_config, request.vcpu),
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
        info!(vm_id = %id, "create_vm RPC called");
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
        info!(vm_id = %request.id, "start_vm RPC called");
        self.app
            .start_vm(&request.id)
            .await
            .context("Failed to start VM")?;
        Ok(())
    }

    async fn stop_vm(self, request: Id) -> Result<()> {
        info!(vm_id = %request.id, "stop_vm RPC called");
        self.app
            .stop_vm(&request.id)
            .await
            .context("Failed to stop VM")?;
        Ok(())
    }

    async fn remove_vm(self, request: Id) -> Result<()> {
        info!(vm_id = %request.id, "remove_vm RPC called");
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
        info!(vm_id = %request.id, "upgrade_app RPC called");
        self.update_vm(request).await
    }

    async fn update_vm(self, request: UpdateVmRequest) -> Result<Id> {
        info!(vm_id = %request.id, "update_vm RPC called");
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
                // A bridge or parent this VM already holds is not a new grant.
                // `GetInfo` keeps reporting it, and read-modify-write keeps
                // sending it back, so refusing it once the node changes its own
                // default would make the VM's configuration unsendable -- with
                // no flag anywhere to clear a field the caller never typed.
                let cvm = held_networking_config(&self.app.config.cvm, &manifest.networks);
                let networks = networks_from_proto(&request.networks, &cvm)?;
                resolve_requested_networks(&networks, &cvm, manifest.vcpu)?
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
        info!(vm_id = %request.id, "get_info RPC called");
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

    async fn resize_vm(self, request: ResizeVmRequest) -> Result<()> {
        info!(
            vm_id = %request.id,
            vcpu = ?request.vcpu,
            memory = ?request.memory,
            disk_size = ?request.disk_size,
            image = ?request.image,
            "resize_vm RPC called"
        );
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
        info!(vm_id = %request.id, "shutdown_vm RPC called");
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
        let default_networking = &self.app.config.cvm.networking;
        let mut bridge_networking = default_networking.clone();
        bridge_networking.nic.mode = NetworkingMode::Bridge;
        let host_can_bridge =
            validate_resolved_network(&bridge_networking).is_ok() || has_host_bridge_interface();
        let supported_modes = advertised_modes(&self.app.config.cvm, host_can_bridge);
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
                default_mode: match default_networking.nic.mode {
                    NetworkingMode::User => "user".to_string(),
                    NetworkingMode::Bridge => "bridge".to_string(),
                    NetworkingMode::Custom => String::new(),
                    NetworkingMode::Macvtap => "macvtap".to_string(),
                },
                default_bridge: default_networking.nic.bridge.clone(),
                max_queues: self.app.config.cvm.max_net_queues,
                default_vhost: default_networking.vhost_enabled(),
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
        info!(vm_id = %request.id, "sv_stop RPC called");
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
        info!(vm_id = %request.id, "sv_remove RPC called");
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
        // The node's user-mode network parameters are not the VM's to store;
        // the type it stores cannot carry them at all now.
        assert!(manifest.networks[0].bridge.is_empty());
    }

    #[test]
    fn authorized_macvtap_preserves_parent_and_inherits_forwarding_mode() {
        let mut cvm_config = test_cvm_config();
        cvm_config
            .allowed_network_modes
            .push(NetworkingMode::Macvtap);
        cvm_config.allowed_macvtap_parents.push("eth0".to_string());
        cvm_config.networking.nic.parent = "node-default".to_string();
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

        // The manifest keeps the parent, which is identity. The forwarding mode
        // the node owns and supplies at every launch is not a field this type
        // has.
        let stored = resolve_requested_networks(&networks, &cvm_config, 4).unwrap();
        assert_eq!(stored[0].parent, "eth0");

        let at_launch = resolve_networking(&stored[0], &cvm_config, 4);
        assert_eq!(at_launch.nic.parent, "eth0");
        assert_eq!(at_launch.macvtap_mode, "private");

        // Repointing the node's forwarding mode reaches the VM.
        cvm_config.networking.macvtap_mode = "bridge".to_string();
        assert_eq!(
            resolve_networking(&stored[0], &cvm_config, 4).macvtap_mode,
            "bridge"
        );
    }

    /// Node shapes a deployment can be reported against, each with the node
    /// default fields that mode populates.
    fn node_shapes() -> Vec<(&'static str, CvmConfig)> {
        let mut bridge = test_cvm_config();
        bridge.networking.nic.mode = NetworkingMode::Bridge;
        bridge.networking.nic.bridge = "br-node".into();

        let mut macvtap = test_cvm_config();
        macvtap.networking.nic.mode = NetworkingMode::Macvtap;
        macvtap.networking.nic.parent = "eth-node".into();
        macvtap.networking.macvtap_mode = "private".into();
        macvtap.allowed_network_modes.push(NetworkingMode::Macvtap);

        let user = test_cvm_config();
        vec![
            ("bridge node", bridge),
            ("macvtap node", macvtap),
            ("user node", user),
        ]
    }

    /// Every override a caller can express, including the tuning-only shape
    /// that names no backend.
    fn request_shapes(node: &CvmConfig) -> Vec<(String, rpc::NetworkingConfig)> {
        let mode = networking_mode_name_for_test(node.networking.nic.mode);
        // The user-mode backend has neither multiqueue nor vhost, and naming it
        // and then asking for either is a refusal rather than a round-trip
        // failure. Asking to turn vhost off is always legal.
        let multiqueue = Networking::mode_supports_multiqueue(node.networking.nic.mode);
        let vhost_on = Networking::mode_supports_vhost(node.networking.nic.mode).then_some(true);
        // Naming a backend's identity field is only legal alongside a mode, so
        // it varies with the named case. The node's own values are used because
        // that is what GetInfo reports back.
        let identity: &[(&str, &str, &str)] = &[
            ("", "", ""),
            ("+ bridge", node.networking.nic.bridge.as_str(), ""),
            ("+ parent", "", node.networking.nic.parent.as_str()),
        ];
        let mut shapes = vec![];
        for (named, mode) in [("named", mode.to_string()), ("inherited", String::new())] {
            for (tuning, vhost, queues) in [
                ("untuned", None, None),
                ("vhost off", Some(false), None),
                ("queues", None, multiqueue.then_some(2)),
                ("both", vhost_on, multiqueue.then_some(2)),
            ] {
                for (label, bridge, parent) in identity {
                    // An inherited entry may not name a backend at all, which
                    // is a refusal covered by its own test.
                    let inherited = mode.is_empty();
                    if inherited && !(bridge.is_empty() && parent.is_empty()) {
                        continue;
                    }
                    // Only the mode that owns a field may carry it.
                    let bridge_ok = node.networking.nic.mode == NetworkingMode::Bridge;
                    let parent_ok = node.networking.nic.mode == NetworkingMode::Macvtap;
                    if (!bridge.is_empty() && !bridge_ok) || (!parent.is_empty() && !parent_ok) {
                        continue;
                    }
                    shapes.push((
                        format!("{named} + {tuning} {label}"),
                        rpc::NetworkingConfig {
                            mode: mode.clone(),
                            bridge_name: bridge.to_string(),
                            parent: parent.to_string(),
                            vhost,
                            queues,
                            ..Default::default()
                        },
                    ));
                }
            }
        }
        shapes
    }

    /// A backend's identity field without a mode would freeze whichever mode
    /// the node had at deploy time, and then be reported alongside an empty
    /// mode -- a combination the RPC itself rejects, which would leave the VM's
    /// tuning permanently uneditable.
    #[test]
    fn an_inherited_entry_may_not_name_a_backend() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Macvtap;
        cvm.networking.nic.parent = "eth-node".into();
        cvm.allowed_macvtap_parents.push("eth1".into());
        cvm.allowed_network_modes.push(NetworkingMode::Macvtap);

        let err = networking_from_proto(
            &rpc::NetworkingConfig {
                parent: "eth1".into(),
                queues: Some(2),
                ..Default::default()
            },
            &cvm,
        )
        .unwrap_err();
        assert!(err.to_string().contains("networking mode is required"));

        // Naming the mode alongside it is fine.
        networking_from_proto(
            &rpc::NetworkingConfig {
                mode: "macvtap".into(),
                parent: "eth1".into(),
                queues: Some(2),
                ..Default::default()
            },
            &cvm,
        )
        .unwrap()
        .expect("a named backend is an override");
    }

    fn networking_mode_name_for_test(mode: NetworkingMode) -> &'static str {
        match mode {
            NetworkingMode::Bridge => "bridge",
            NetworkingMode::User => "user",
            NetworkingMode::Macvtap => "macvtap",
            NetworkingMode::Custom => "custom",
        }
    }

    /// `GetInfo` reports the configuration that `UpdateVm` and `UpgradeApp`
    /// take back, and both vmm-cli and the web UI read it, change one field,
    /// and resend the rest. So everything reportable has to be acceptable, and
    /// accepting it has to land on the same VM.
    ///
    /// This asserts the property over every mode and tuning combination on
    /// purpose. Asserting one shape is how an inherited `parent` on a bridge
    /// NIC, and then `macvtap_mode` and `bridge_name`, each reached a release:
    /// every one of them was a case the fixed example did not cover.
    #[test]
    fn everything_get_info_reports_is_accepted_back_unchanged() {
        for (node_label, cvm) in node_shapes() {
            for (shape_label, request) in request_shapes(&cvm) {
                let case = format!("{node_label} / {shape_label}");
                let Some(requested) = networking_from_proto(&request, &cvm)
                    .unwrap_or_else(|error| panic!("{case}: deployment rejected: {error:#}"))
                else {
                    // No override at all; nothing is recorded, nothing to report.
                    continue;
                };
                // Skip the host-dependent bridge existence check: this is
                // about what the RPC reports versus what it accepts.
                let merged = resolve_networking(&requested, &cvm, 4);
                let stored = manifest_networks(vec![merged.clone()], &[requested]);

                let reported = crate::app::networking_to_proto(&stored[0]);
                let accepted = networking_from_proto(&reported, &cvm)
                    .unwrap_or_else(|error| {
                        panic!("{case}: GetInfo output was rejected on the way back: {error:#}")
                    })
                    .unwrap_or_else(|| panic!("{case}: the override was lost in the round trip"));

                let restored =
                    manifest_networks(vec![resolve_networking(&accepted, &cvm, 4)], &[accepted]);
                assert_eq!(stored, restored, "{case}: round trip changed the manifest");
                assert_eq!(
                    resolve_networking(&restored[0], &cvm, 4),
                    merged,
                    "{case}: round trip changed what the launch sees"
                );
            }
        }
    }

    /// A VM must not become uneditable because its node moved somewhere its
    /// tuning does not apply. The report and the deployment RPC have to agree
    /// on every backend the node can be pointed at, not just the one it had
    /// when the VM was deployed.
    #[test]
    fn an_inherited_override_still_round_trips_after_the_node_moves() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        cvm.networking.nic.bridge = "br-node".into();

        let requested = networking_from_proto(
            &rpc::NetworkingConfig {
                queues: Some(4),
                ..Default::default()
            },
            &cvm,
        )
        .unwrap()
        .expect("tuning must produce an override");
        let stored = manifest_networks(vec![resolve_networking(&requested, &cvm, 8)], &[requested]);

        for mode in [
            NetworkingMode::User,
            NetworkingMode::Custom,
            NetworkingMode::Macvtap,
            NetworkingMode::Bridge,
        ] {
            cvm.networking.nic.mode = mode;
            cvm.networking.nic.parent = "eth-node".into();
            cvm.networking.netdev = "tap,id=net0,ifname=custom0".into();

            let reported = crate::app::networking_to_proto(&stored[0]);
            let accepted = networking_from_proto(&reported, &cvm)
                .unwrap_or_else(|error| panic!("{mode:?}: report was rejected: {error:#}"))
                .unwrap_or_else(|| panic!("{mode:?}: the override was lost"));
            let restored =
                manifest_networks(vec![resolve_networking(&accepted, &cvm, 8)], &[accepted]);
            // An inherited entry still has to hold *some* mode -- every
            // consumer matches on one -- and it is rewritten to whatever the
            // node has now. Resolution ignores it, so compare what the launch
            // sees rather than the field nothing reads.
            assert!(restored[0].inherit_mode, "{mode:?}: pinned a backend");
            assert_eq!(
                resolve_networking(&restored[0], &cvm, 8),
                resolve_networking(&stored[0], &cvm, 8),
                "{mode:?}: round trip changed what the launch sees"
            );
            assert_eq!(restored[0].queues, Some(4), "{mode:?}: lost the request");
        }
    }

    /// The counterpart: a node that changes its mind still reaches VMs that
    /// never named a backend, and never reaches ones that did.
    #[test]
    fn a_node_backend_change_reaches_exactly_the_vms_that_inherited_it() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        cvm.networking.nic.bridge = "br-node".into();

        let tuning_only = networking_from_proto(
            &rpc::NetworkingConfig {
                queues: Some(2),
                ..Default::default()
            },
            &cvm,
        )
        .unwrap()
        .expect("tuning must produce an override");
        let named = networking_from_proto(
            &rpc::NetworkingConfig {
                mode: "bridge".into(),
                queues: Some(2),
                ..Default::default()
            },
            &cvm,
        )
        .unwrap()
        .expect("a named backend is an override");

        let requests = vec![tuning_only, named];
        let merged = requests
            .iter()
            .map(|request| resolve_networking(request, &cvm, 4))
            .collect::<Vec<_>>();
        let stored = manifest_networks(merged, &requests);

        // The operator repoints the node at a different backend.
        cvm.networking.nic.mode = NetworkingMode::User;
        assert_eq!(
            resolve_networking(&stored[0], &cvm, 4).nic.mode,
            NetworkingMode::User,
            "a VM that never named a backend must follow the node"
        );
        assert_eq!(
            resolve_networking(&stored[1], &cvm, 4).nic.mode,
            NetworkingMode::Bridge,
            "a VM that named its backend keeps it for life"
        );
        // User mode has no multiqueue backend, so the inherited NIC drops to
        // one queue pair while it is there -- but the request is not lost.
        assert_eq!(resolve_networking(&stored[0], &cvm, 4).queue_pairs(), 1);
        assert_eq!(stored[0].queues, Some(2));
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        assert_eq!(
            resolve_networking(&stored[0], &cvm, 4).queue_pairs(),
            2,
            "tuning must survive an excursion through a backend that ignores it"
        );
    }

    #[test]
    fn queue_requests_are_bounded_by_node_policy() {
        let mut cvm_config = test_cvm_config();
        cvm_config.max_net_queues = 4;
        cvm_config.allowed_bridges.push("tenant-br0".to_string());
        let request = |queues: u32| {
            [rpc::NetworkingConfig {
                mode: "bridge".to_string(),
                bridge_name: "tenant-br0".to_string(),
                queues: Some(queues),
                ..Default::default()
            }]
        };

        let networks = networks_from_proto(&request(4), &cvm_config).unwrap();
        assert_eq!(networks[0].queues, Some(4));

        let err = networks_from_proto(&request(5), &cvm_config).unwrap_err();
        assert!(err.to_string().contains("must not exceed 4"));
    }

    /// A mode the deploy dialog offers has to be one the deployment RPC will
    /// take. Offering one node policy forbids puts a choice in front of an
    /// operator whose only outcome is "not allowed by node policy".
    #[test]
    fn advertised_modes_are_ones_the_rpc_would_accept() {
        let mut cvm = test_cvm_config();
        cvm.allowed_network_modes = vec![NetworkingMode::User];
        for mode in ["bridge", "macvtap"] {
            assert!(
                networking_from_proto(
                    &rpc::NetworkingConfig {
                        mode: mode.to_string(),
                        ..Default::default()
                    },
                    &cvm,
                )
                .is_err(),
                "{mode} should be refused by this policy"
            );
        }
        assert_eq!(advertised_modes(&cvm, true), vec!["user".to_string()]);

        cvm.allowed_network_modes = vec![NetworkingMode::User, NetworkingMode::Macvtap];
        assert_eq!(
            advertised_modes(&cvm, true),
            vec!["user".to_string(), "macvtap".to_string()]
        );

        // A mode policy allows but the host cannot serve is still not offered.
        cvm.allowed_network_modes.push(NetworkingMode::Bridge);
        assert!(!advertised_modes(&cvm, false).contains(&"bridge".to_string()));
        assert!(advertised_modes(&cvm, true).contains(&"bridge".to_string()));
    }

    /// A VM keeps its bridge for life, so the node dropping that bridge from
    /// its own configuration must not make the VM's reported configuration
    /// unsendable -- there is no flag anywhere to clear a field the caller
    /// never typed.
    /// Deployment allowlists govern what a caller may newly select. Widening
    /// them from a VM's own holdings is what keeps read-modify-write working
    /// across a node change -- but only from a field the entry's own mode
    /// owns. Resolution used to copy the node's whole networking value into
    /// every VM, so a bridge NIC carried whatever macvtap parent the node had
    /// configured, and widening from that let the VM move to a parent policy
    /// forbids. The split types make the node's other fields unreachable; the
    /// two identity fields still share one type, so the scoping stays explicit.
    #[test]
    fn holdings_widen_policy_only_for_the_mode_that_owns_them() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        cvm.networking.nic.parent = "eth1".into();
        cvm.allowed_network_modes = vec![
            NetworkingMode::Bridge,
            NetworkingMode::Macvtap,
            NetworkingMode::User,
        ];
        assert!(cvm.allowed_macvtap_parents.is_empty());

        // What a bridge NIC deployed on this node used to end up holding.
        let held = [NicNetworking {
            mode: NetworkingMode::Bridge,
            bridge: "br0".into(),
            parent: "eth0".into(),
            ..NicNetworking::default()
        }];
        let widened = held_networking_config(&cvm, &held);
        assert!(widened.allowed_bridges.contains(&"br0".to_string()));
        assert!(!widened
            .allowed_macvtap_parents
            .contains(&"eth0".to_string()));

        let request = [rpc::NetworkingConfig {
            mode: "macvtap".into(),
            parent: "eth0".into(),
            ..Default::default()
        }];
        let err = networks_from_proto(&request, &widened).unwrap_err();
        assert!(
            err.to_string().contains("not allowed by node policy"),
            "{err}"
        );
    }

    /// Lowering the node's queue cap bounds what a deployment may newly ask
    /// for. It does not retune VMs already pinned above it, and those keep
    /// reporting their count on every GetInfo -- so without this, lowering the
    /// cap makes every networking update on such a VM fail on a field the
    /// operator never typed, including the one that would unpin it.
    #[test]
    fn a_vm_may_restate_a_queue_count_the_node_has_since_capped() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        cvm.max_net_queues = 2;

        let held = [NicNetworking {
            mode: NetworkingMode::Bridge,
            queues: Some(8),
            ..NicNetworking::default()
        }];
        let request = [rpc::NetworkingConfig {
            mode: "bridge".into(),
            queues: Some(8),
            vhost: Some(false),
            ..Default::default()
        }];

        let err = networks_from_proto(&request, &cvm).unwrap_err();
        assert!(err.to_string().contains("must not exceed 2"), "{err}");

        let widened = held_networking_config(&cvm, &held);
        let networks = networks_from_proto(&request, &widened).unwrap();
        assert_eq!(networks[0].queues, Some(8));

        // Only up to what it holds, though.
        let more = [rpc::NetworkingConfig {
            mode: "bridge".into(),
            queues: Some(9),
            ..Default::default()
        }];
        let err = networks_from_proto(&more, &widened).unwrap_err();
        assert!(err.to_string().contains("must not exceed 8"), "{err}");
    }

    /// `optional uint32` tells an absent field from a typed zero, so reading
    /// zero as "unset" would answer a request for no queues with the
    /// vCPU-scaled default. Resize says the same about a zero vCPU count.
    #[test]
    fn an_explicit_zero_queue_count_is_an_error_not_an_absent_field() {
        let cvm = test_cvm_config();
        let request = rpc::NetworkingConfig {
            mode: "bridge".into(),
            queues: Some(0),
            ..Default::default()
        };
        let err = networking_from_proto(&request, &cvm).unwrap_err();
        assert!(err.to_string().contains("must be at least 1"), "{err}");

        // Including when it is the only thing the request says. That arm
        // returns "no override at all" before anything reads the count, so a
        // zero here used to be answered with up to sixteen queue pairs.
        let bare = rpc::NetworkingConfig {
            queues: Some(0),
            ..Default::default()
        };
        let err = networking_from_proto(&bare, &cvm).unwrap_err();
        assert!(err.to_string().contains("must be at least 1"), "{err}");
    }

    /// Resolution fills both identity fields from the node, so a bridge NIC's
    /// resolved value carries whatever macvtap parent the node happens to have
    /// configured. Storing that made every later reader responsible for knowing
    /// which field its mode owns, and the one that widens deployment policy
    /// from a VM's holdings got it wrong: repoint the node's parent and a
    /// bridge VM could move itself to a parent policy forbids.
    #[test]
    fn a_vm_records_only_the_identity_field_its_own_mode_owns() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        cvm.networking.nic.bridge = "br-node".into();
        cvm.networking.nic.parent = "eth-node".into();

        let networks = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "bridge".into(),
                ..Default::default()
            }],
            &cvm,
        )
        .unwrap();
        // `manifest_networks` directly: what a VM records is the question, and
        // `resolve_requested_networks` would first validate the merged view
        // against this host's real interfaces.
        let merged = networks
            .iter()
            .map(|request| resolve_networking(request, &cvm, 4))
            .collect::<Vec<_>>();
        let stored = manifest_networks(merged, &networks);
        assert_eq!(stored[0].bridge, "br-node");
        assert!(stored[0].parent.is_empty(), "{:?}", stored[0]);

        // And the launch still gets the node's parent, because that half was
        // never the VM's to hold in the first place.
        let at_launch = resolve_networking(&stored[0], &cvm, 4);
        assert_eq!(at_launch.nic.parent, "eth-node");
    }

    #[test]
    fn a_vm_may_restate_a_bridge_it_already_holds() {
        let mut cvm = test_cvm_config();
        cvm.networking.nic.mode = NetworkingMode::Bridge;
        cvm.networking.nic.bridge = "br-new".into();
        assert!(cvm.allowed_bridges.is_empty());

        let held = [NicNetworking {
            mode: NetworkingMode::Bridge,
            bridge: "br-old".into(),
            ..NicNetworking::default()
        }];
        let request = [rpc::NetworkingConfig {
            mode: "bridge".into(),
            bridge_name: "br-old".into(),
            queues: Some(2),
            ..Default::default()
        }];

        // Without the VM's own holdings this is a bridge it may not select.
        let err = networks_from_proto(&request, &cvm).unwrap_err();
        assert!(err.to_string().contains("not allowed by node policy"));

        let widened = held_networking_config(&cvm, &held);
        let networks = networks_from_proto(&request, &widened).unwrap();
        assert_eq!(networks[0].bridge, "br-old");

        // And it is still only this VM's own values that are permitted.
        let other = [rpc::NetworkingConfig {
            mode: "bridge".into(),
            bridge_name: "br-someone-else".into(),
            ..Default::default()
        }];
        assert!(networks_from_proto(&other, &widened).is_err());
    }

    /// vhost follows the same rule as the queue count: refused for a backend
    /// the caller chose and that has none, accepted and dormant for one they
    /// inherited. Accepting it silently on a chosen backend would leave the
    /// deploy dialog reporting `vhost: on` next to a NIC running without it.
    #[test]
    fn vhost_is_refused_only_for_a_backend_the_caller_chose() {
        let cvm_config = test_cvm_config();
        let err = networking_from_proto(
            &rpc::NetworkingConfig {
                mode: "user".into(),
                vhost: Some(true),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no vhost data plane"), "{err:#}");

        // Turning it off is a no-op that matches reality, so it is allowed.
        networking_from_proto(
            &rpc::NetworkingConfig {
                mode: "user".into(),
                vhost: Some(false),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap()
        .expect("tuning must produce an override");

        // Inherited from a user-mode node: accepted, dormant, and live again
        // when the node moves to a backend that has one.
        let mut cvm_config = test_cvm_config();
        assert_eq!(cvm_config.networking.nic.mode, NetworkingMode::User);
        let requested = networking_from_proto(
            &rpc::NetworkingConfig {
                vhost: Some(true),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap()
        .expect("tuning must produce an override");
        assert!(!resolve_networking(&requested, &cvm_config, 4).vhost_enabled());

        cvm_config.networking.nic.mode = NetworkingMode::Bridge;
        cvm_config.networking.nic.bridge = "br-node".into();
        assert!(resolve_networking(&requested, &cvm_config, 4).vhost_enabled());
    }

    /// A queue count is refused for a backend the caller chose and that cannot
    /// honour it, because the caller can fix the request. It is accepted for
    /// one they inherited, because they cannot: the node picked that backend
    /// and may pick another tomorrow, and refusing would leave GetInfo
    /// reporting a count nothing is allowed to send back.
    #[test]
    fn a_queue_count_is_refused_only_for_a_backend_the_caller_chose() {
        let cvm_config = test_cvm_config();
        let err = networking_from_proto(
            &rpc::NetworkingConfig {
                mode: "user".into(),
                queues: Some(4),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap_err();
        assert!(err.to_string().contains("does not support multiple queues"));

        // Inherited: accepted, and dormant until the node moves to a backend
        // that can honour it.
        for mode in [NetworkingMode::Custom, NetworkingMode::User] {
            let mut cvm_config = test_cvm_config();
            cvm_config.networking.nic.mode = mode;
            cvm_config.networking.netdev = "tap,id=net0,ifname=custom0".into();
            let requested = networking_from_proto(
                &rpc::NetworkingConfig {
                    queues: Some(4),
                    ..Default::default()
                },
                &cvm_config,
            )
            .unwrap()
            .expect("tuning must produce an override");
            assert_eq!(requested.queues, Some(4));
            assert_eq!(
                resolve_networking(&requested, &cvm_config, 8).queue_pairs(),
                1,
                "{mode:?} cannot carry multiqueue, whatever was asked for"
            );

            // And the request is still there when the node moves back.
            cvm_config.networking.nic.mode = NetworkingMode::Bridge;
            cvm_config.networking.nic.bridge = "br-node".into();
            assert_eq!(
                resolve_networking(&requested, &cvm_config, 8).queue_pairs(),
                4
            );
        }
    }

    #[test]
    fn user_mode_rejects_multiqueue_but_a_single_queue_is_fine() {
        let cvm_config = test_cvm_config();
        let request = |queues: u32| {
            [rpc::NetworkingConfig {
                mode: "user".to_string(),
                queues: Some(queues),
                ..Default::default()
            }]
        };

        networks_from_proto(&request(1), &cvm_config).unwrap();
        let err = networks_from_proto(&request(2), &cvm_config).unwrap_err();
        assert!(err.to_string().contains("does not support multiple queues"));
    }

    #[test]
    fn tuning_alone_keeps_the_node_backend_without_tripping_mode_policy() {
        let mut cvm_config = test_cvm_config();
        // A backend the node uses but does not let callers choose.
        cvm_config.networking.nic.mode = NetworkingMode::Macvtap;
        cvm_config.networking.nic.parent = "eth0".to_string();
        assert!(!cvm_config
            .allowed_network_modes
            .contains(&NetworkingMode::Macvtap));

        let networking = networking_from_proto(
            &rpc::NetworkingConfig {
                vhost: Some(false),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap()
        .expect("tuning must produce an override");
        assert_eq!(networking.mode, NetworkingMode::Macvtap);
        assert_eq!(networking.vhost, Some(false));

        // Naming that backend explicitly is still a choice, and still denied.
        let err = networking_from_proto(
            &rpc::NetworkingConfig {
                mode: "macvtap".to_string(),
                vhost: Some(false),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not allowed by node policy"));

        // An untouched request still means "no override at all".
        assert!(
            networking_from_proto(&rpc::NetworkingConfig::default(), &cvm_config)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn an_inherited_backend_is_never_pinned_into_the_manifest() {
        // Tuning must not become a way to pin a backend the caller was never
        // allowed to choose, nor to freeze one the node still owns.
        let mut cvm_config = test_cvm_config();
        cvm_config.networking.nic.mode = NetworkingMode::Macvtap;
        cvm_config.networking.nic.parent = "eth0".to_string();
        cvm_config.networking.macvtap_mode = "private".to_string();

        let requested = networking_from_proto(
            &rpc::NetworkingConfig {
                queues: Some(2),
                ..Default::default()
            },
            &cvm_config,
        )
        .unwrap()
        .expect("tuning must produce an override");
        assert!(requested.inherit_mode);

        let persisted = resolve_requested_networks(&[requested], &cvm_config, 4).unwrap();
        assert_eq!(persisted[0].queues, Some(2));
        // Nothing the node owns was copied in. The forwarding mode, the MAC
        // prefix and the user-mode network parameters are not fields this type
        // has any more; the parent is, and a NIC that named no backend does not
        // get to keep the node's.
        assert!(persisted[0].parent.is_empty());
        assert!(persisted[0].bridge.is_empty());

        // Repointing the node moves the VM with it.
        cvm_config.networking.nic.parent = "eth1".to_string();
        let at_launch = resolve_networking(&persisted[0], &cvm_config, 4);
        assert_eq!(at_launch.nic.parent, "eth1");
        assert_eq!(at_launch.queue_pairs(), 2);
    }

    #[test]
    fn deployment_pins_identity_but_not_data_plane_tuning() {
        let mut cvm_config = test_cvm_config();
        cvm_config.networking.nic.vhost = Some(true);
        cvm_config.networking.nic.queues = Some(2);
        let networks = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "user".to_string(),
                vhost: Some(false),
                ..Default::default()
            }],
            &cvm_config,
        )
        .unwrap();

        let resolved = resolve_requested_networks(&networks, &cvm_config, 4).unwrap();
        // The backend the caller chose is pinned.
        assert_eq!(resolved[0].mode, NetworkingMode::User);
        assert!(!resolved[0].inherit_mode);
        // The explicit request is kept.
        assert_eq!(resolved[0].vhost, Some(false));
        // What the caller never asked for stays unset, so the node still owns
        // it: an operator disabling vhost node-wide must reach this VM too.
        assert_eq!(resolved[0].queues, None);
    }

    #[test]
    fn a_node_wide_vhost_rollback_reaches_a_vm_deployed_with_an_override() {
        // macvtap keeps this independent of which interfaces the test host has.
        let mut cvm_config = test_cvm_config();
        cvm_config
            .allowed_network_modes
            .push(NetworkingMode::Macvtap);
        cvm_config.allowed_macvtap_parents.push("eth0".to_string());
        cvm_config.networking.nic.parent = "eth0".to_string();
        let networks = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: "macvtap".to_string(),
                parent: "eth0".to_string(),
                ..Default::default()
            }],
            &cvm_config,
        )
        .unwrap();
        let persisted = resolve_requested_networks(&networks, &cvm_config, 4).unwrap();
        assert!(persisted[0].vhost.is_none());

        cvm_config.networking.nic.vhost = Some(false);
        let at_launch = resolve_networking(&persisted[0], &cvm_config, 4);
        assert!(!at_launch.vhost_enabled());
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
    /// An entry in a list that overrides nothing describes a NIC that follows
    /// the node entirely -- which is a thing an operator can mean, and the
    /// only way the web UI can leave a NIC's backend unpinned. Rejecting it
    /// would make an inherited NIC uneditable the moment its tuning is cleared.
    fn repeated_networks_accepts_an_entry_that_overrides_nothing() {
        let mut cvm_config = test_cvm_config();
        cvm_config.networking.nic.mode = NetworkingMode::Bridge;
        cvm_config.networking.nic.bridge = "br-node".into();

        let networks = networks_from_proto(
            &[rpc::NetworkingConfig {
                mode: String::new(),
                bridge_name: String::new(),
                ..Default::default()
            }],
            &cvm_config,
        )
        .unwrap();
        assert_eq!(networks.len(), 1);
        assert!(networks[0].inherit_mode);
        assert_eq!(networks[0].queues, None);
        assert!(networks[0].bridge.is_empty());

        // It follows the node, like a VM with no networks at all.
        cvm_config.networking.nic.mode = NetworkingMode::User;
        assert_eq!(
            resolve_networking(&networks[0], &cvm_config, 4).nic.mode,
            NetworkingMode::User
        );
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
