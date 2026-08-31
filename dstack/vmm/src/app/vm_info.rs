// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM runtime-state aggregation and RPC presentation.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use dstack_vmm_rpc as pb;
use fs_err as fs;
use supervisor_client::supervisor::ProcessInfo;

use super::{network::mac_address_for_vm_index, Manifest, VmState, VmWorkDir};
use crate::config::{GatewayConfig, Networking, NetworkingMode, NicNetworking};

pub(crate) struct VmInfo {
    pub manifest: Manifest,
    pub workdir: PathBuf,
    pub status: &'static str,
    /// Whether a QEMU process exists for this VM right now. The NICs it built
    /// are real only while it does.
    pub running: bool,
    pub uptime: String,
    pub exited_at: Option<String>,
    pub instance_id: Option<String>,
    pub boot_progress: String,
    pub boot_error: String,
    pub shutdown_progress: String,
    pub image_version: String,
    pub gateway_enabled: bool,
    pub events: Vec<pb::GuestEvent>,
    pub runtime_networks: Vec<Networking>,
}

fn networking_backend_name(mode: NetworkingMode) -> &'static str {
    match mode {
        NetworkingMode::Bridge => "tap_bridge",
        NetworkingMode::User => "slirp",
        NetworkingMode::Custom => "custom",
        NetworkingMode::Macvtap => "macvtap",
    }
}

/// The resolved NICs a launch built, or would build, as the RPC reports them.
fn interfaces_to_proto(
    vm_id: &str,
    effective_networks: &[Networking],
) -> Vec<pb::NetworkInterfaceStatus> {
    effective_networks
        .iter()
        .enumerate()
        .map(|(index, networking)| {
            let mac = mac_address_for_vm_index(vm_id, &networking.mac_prefix_bytes(), index);
            pb::NetworkInterfaceStatus {
                mode: networking.nic.mode.as_str().into(),
                backend: networking_backend_name(networking.nic.mode).into(),
                mac,
                bridge_name: (networking.nic.mode == NetworkingMode::Bridge)
                    .then(|| networking.nic.bridge.clone()),
                netdev_id: Some(format!("net{index}")),
                // Custom mode hands the operator the whole netdev string and the
                // VMM never parses it, so it has no data-plane state to report.
                // Reporting the resolved fields anyway would assert "vhost: off,
                // queues: 1" over a netdev the operator may have written with
                // `vhost=on,queues=8`.
                //
                // Otherwise: settled at launch, so an entry carrying no decision
                // was written before this VMM recorded one -- by a build that
                // had no vhost at all, which is what it should read as.
                // Recomputing here instead would let an edit to node
                // configuration change what a running VM is said to use.
                vhost: (networking.nic.mode != NetworkingMode::Custom)
                    .then(|| networking.nic.vhost.is_some() && networking.vhost_enabled()),
                queues: (networking.nic.mode != NetworkingMode::Custom)
                    .then(|| networking.queue_pairs()),
                // Node-decided, so it belongs with the rest of the resolved
                // state. The VM's own record cannot carry one.
                macvtap_mode: (networking.nic.mode == NetworkingMode::Macvtap)
                    .then(|| networking.macvtap_mode.clone()),
            }
        })
        .collect()
}

pub(crate) fn networking_to_proto(networking: &NicNetworking) -> pb::NetworkingConfig {
    // An entry that inherited its backend reports no mode, so it must report
    // none of the fields that only make sense alongside one: a mode-less
    // override carrying, say, a parent is something the deployment RPC
    // rejects, which would strand the VM's tuning as uneditable.
    let pins_backend = !networking.inherit_mode;
    pb::NetworkingConfig {
        // An entry that only tuned the data plane named no backend, and the
        // deployment RPC spells that as an empty mode. Reporting the node's
        // current mode here would turn a read-modify-write into a request to
        // pin it -- which policy may not even permit the caller to make.
        mode: if networking.inherit_mode {
            String::new()
        } else {
            networking.mode.as_str().into()
        },
        bridge_name: if pins_backend && networking.mode == NetworkingMode::Bridge {
            networking.bridge.clone()
        } else {
            String::new()
        },
        // Scope the macvtap fields to macvtap, the way bridge_name is scoped to
        // bridge. Reporting an inherited parent on a bridge NIC produced a
        // configuration that could be read but not sent back: the deployment
        // RPC rejects `parent` outside macvtap mode.
        parent: if pins_backend && networking.mode == NetworkingMode::Macvtap {
            networking.parent.clone()
        } else {
            String::new()
        },
        // The forwarding mode is node-controlled, so a VM never pins one and
        // the type it stores can no longer carry one. It stays on the wire
        // because the deployment RPC still has to reject a caller that sets it.
        macvtap_mode: String::new(),
        vhost: networking.vhost,
        queues: networking.queues,
    }
}

fn sanitize_optional<T: AsRef<str>>(value: Option<T>) -> Option<T> {
    value.filter(|value| !value.as_ref().trim().is_empty())
}

impl VmInfo {
    /// Takes no `CvmConfig` on purpose. Everything it reports about a VM's
    /// data plane was decided when that VM launched and written into
    /// `effective_networks`; consulting node configuration here is what let an
    /// operator's edit change what a running VM was said to be using.
    ///
    /// `effective_networks` is passed in rather than derived for the same
    /// reason, plus one more: a stopped VM's NICs are a prediction, and only
    /// the caller can consult netd to make the prediction its launch would.
    pub fn to_pb(
        &self,
        gateway: &GatewayConfig,
        brief: bool,
        effective_networks: &[Networking],
    ) -> pb::VmInfo {
        let workdir = VmWorkDir::new(&self.workdir);
        let vm_config = workdir.manifest();
        let custom_gateway_urls = vm_config
            .as_ref()
            .map(|config| config.gateway_urls.clone())
            .unwrap_or_default();
        let configured_networks = self
            .manifest
            .networks
            .iter()
            .map(networking_to_proto)
            .collect::<Vec<_>>();
        let configured_networking = configured_networks.first().cloned();
        let interfaces = interfaces_to_proto(&self.manifest.id, effective_networks);
        pb::VmInfo {
            id: self.manifest.id.clone(),
            name: self.manifest.name.clone(),
            status: self.status.into(),
            // The one predicate that says whether `interfaces` above is what a
            // process built or what the next launch would build. Clients used to
            // re-derive it from `status`, which answers a different question:
            // a VM being removed with QEMU still up is not "running" by that
            // string, yet its NICs are real.
            running: self.running,
            uptime: self.uptime.clone(),
            boot_progress: self.boot_progress.clone(),
            boot_error: self.boot_error.clone(),
            shutdown_progress: self.shutdown_progress.clone(),
            image_version: self.image_version.clone(),
            configuration: if brief {
                None
            } else {
                let kms_urls = vm_config
                    .as_ref()
                    .map(|config| config.kms_urls.clone())
                    .unwrap_or_default();
                let no_tee = vm_config
                    .as_ref()
                    .map(|config| config.no_tee)
                    .unwrap_or(self.manifest.no_tee);
                let stopped = !workdir.started().unwrap_or(false);

                Some(pb::VmConfiguration {
                    name: self.manifest.name.clone(),
                    image: self.manifest.image.clone(),
                    compose_file: fs::read_to_string(workdir.app_compose_path())
                        .unwrap_or_default(),
                    encrypted_env: fs::read(workdir.encrypted_env_path()).unwrap_or_default(),
                    user_config: fs::read_to_string(workdir.user_config_path()).unwrap_or_default(),
                    vcpu: self.manifest.vcpu,
                    memory: self.manifest.memory,
                    disk_size: self.manifest.disk_size,
                    ports: self
                        .manifest
                        .port_map
                        .iter()
                        .map(|mapping| pb::PortMapping {
                            nic_index: mapping.nic_index.map(|index| index as u32),
                            protocol: mapping.protocol.as_str().into(),
                            host_address: mapping.address.to_string(),
                            host_port: mapping.from as u32,
                            vm_port: mapping.to as u32,
                        })
                        .collect(),
                    app_id: Some(self.manifest.app_id.clone()),
                    hugepages: self.manifest.hugepages,
                    pin_numa: self.manifest.pin_numa,
                    gpus: self.manifest.gpus.as_ref().map(|config| pb::GpuConfig {
                        attach_mode: config.attach_mode.to_string(),
                        gpus: config
                            .gpus
                            .iter()
                            .map(|gpu| pb::GpuSpec {
                                slot: gpu.slot.clone(),
                            })
                            .collect(),
                    }),
                    kms_urls,
                    gateway_urls: custom_gateway_urls.clone(),
                    stopped,
                    no_tee,
                    simulated_tee: self
                        .manifest
                        .simulated_tee
                        .map(|platform| platform.as_str().to_string()),
                    networking: configured_networking,
                    networks: configured_networks,
                })
            },
            app_url: self
                .gateway_enabled
                .then_some(self.instance_id.as_deref())
                .flatten()
                .and_then(|id| sanitize_optional(Some(id)))
                .map(|id| app_url(id, &custom_gateway_urls, gateway)),
            app_id: self.manifest.app_id.clone(),
            instance_id: sanitize_optional(self.instance_id.clone()),
            exited_at: self.exited_at.clone(),
            events: self.events.clone(),
            interfaces,
        }
    }
}

fn app_url(id: &str, custom_gateway_urls: &[String], gateway: &GatewayConfig) -> String {
    if let Some(custom_gateway_url) = custom_gateway_urls.first() {
        if let Ok(url) = url::Url::parse(custom_gateway_url) {
            let host = url.host_str().unwrap_or(&gateway.base_domain);
            let port = url.port().unwrap_or(443);
            if port == 443 {
                return format!("https://{id}-{}.{}", gateway.agent_port, host);
            }
            return format!("https://{id}-{}.{}:{port}", gateway.agent_port, host);
        }
    }

    if gateway.port == 443 {
        format!(
            "https://{id}-{}.{}",
            gateway.agent_port, gateway.base_domain
        )
    } else {
        format!(
            "https://{id}-{}.{}:{}",
            gateway.agent_port, gateway.base_domain, gateway.port
        )
    }
}

impl VmState {
    pub fn merged_info(&self, process: Option<&ProcessInfo>, workdir: &VmWorkDir) -> VmInfo {
        fn truncate(duration: Duration) -> Duration {
            Duration::from_secs(duration.as_secs())
        }

        fn display_timestamp(timestamp: Option<&SystemTime>) -> String {
            match timestamp {
                None => "never".into(),
                Some(timestamp) => {
                    let elapsed = timestamp.elapsed().unwrap_or(Duration::MAX);
                    humantime::format_duration(truncate(elapsed)).to_string()
                }
            }
        }

        let is_running = process.is_some_and(|info| info.state.status.is_running());
        let started = workdir.started().unwrap_or(false);
        let status = if self.state.removing {
            "removing"
        } else {
            match (started, is_running) {
                (true, true) => "running",
                (true, false) => "exited",
                (false, true) => "stopping",
                (false, false) => "stopped",
            }
        };
        let uptime = display_timestamp(process.and_then(|info| info.state.started_at.as_ref()));
        let exited_at = display_timestamp(process.and_then(|info| info.state.stopped_at.as_ref()));
        let instance_id = sanitize_optional(
            workdir
                .instance_info()
                .ok()
                .map(|info| hex::encode(info.instance_id)),
        );

        VmInfo {
            manifest: self.config.manifest.clone(),
            workdir: workdir.path().to_path_buf(),
            instance_id,
            status,
            running: is_running,
            uptime,
            exited_at: Some(exited_at),
            boot_progress: self.state.boot_progress.clone(),
            boot_error: self.state.boot_error.clone(),
            shutdown_progress: self.state.shutdown_progress.clone(),
            image_version: self.config.image.info.version.clone(),
            gateway_enabled: self.config.gateway_enabled,
            events: self.state.events.clone().into(),
            runtime_networks: self.state.runtime_networks.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{interfaces_to_proto, networking_to_proto, sanitize_optional};
    use crate::config::{NetworkingMode, NicNetworking};

    /// Custom mode hands the operator the whole netdev string and the VMM never
    /// parses it, so it has no data-plane state to report. Reporting the
    /// resolved defaults instead asserted "vhost off, one queue" over a netdev
    /// the operator may well have written as `vhost=on,queues=8`.
    #[test]
    fn a_custom_netdev_reports_no_data_plane_rather_than_the_wrong_one() {
        use crate::config::Networking;

        let custom = Networking {
            nic: NicNetworking {
                mode: NetworkingMode::Custom,
                ..NicNetworking::default()
            },
            netdev: "tap,id=net0,ifname=custom0,vhost=on,queues=8".into(),
            ..Networking::default()
        };
        let interfaces = interfaces_to_proto("vm-1", &[custom]);
        assert_eq!(interfaces[0].backend, "custom");
        assert_eq!(interfaces[0].vhost, None);
        assert_eq!(interfaces[0].queues, None);

        // Every other backend still answers the question.
        let bridge = Networking {
            nic: NicNetworking {
                mode: NetworkingMode::Bridge,
                vhost: Some(true),
                queues: Some(4),
                ..NicNetworking::default()
            },
            ..Networking::default()
        };
        let interfaces = interfaces_to_proto("vm-1", &[bridge]);
        assert_eq!(interfaces[0].vhost, Some(true));
        assert_eq!(interfaces[0].queues, Some(4));
    }

    #[test]
    fn a_reported_interface_can_be_sent_back_unchanged() {
        // GetInfo output feeds UpdateVm, so anything it reports has to satisfy
        // the deployment RPC's own validation. What a VM stores can no longer
        // carry a node-owned field at all -- `parent` here belongs to bridge
        // mode's own entry only because the type still allows both backends'
        // identity fields, and reporting still scopes it to the owning mode.
        let networking = NicNetworking {
            mode: NetworkingMode::Bridge,
            bridge: "br0".into(),
            parent: "eth0".into(),
            vhost: Some(false),
            queues: Some(2),
            ..NicNetworking::default()
        };
        let proto = networking_to_proto(&networking);
        assert_eq!(proto.mode, "bridge");
        assert_eq!(proto.bridge_name, "br0");
        assert!(proto.parent.is_empty());
        assert!(proto.macvtap_mode.is_empty());
        assert_eq!(proto.vhost, Some(false));
        assert_eq!(proto.queues, Some(2));
    }

    #[test]
    fn sanitize_optional_filters_empty_owned_values() {
        assert_eq!(sanitize_optional(Some(String::new())), None);
        assert_eq!(sanitize_optional(Some("   ".to_string())), None);
        assert_eq!(
            sanitize_optional(Some("instance-123".to_string())),
            Some("instance-123".to_string())
        );
    }

    #[test]
    fn sanitize_optional_filters_empty_borrowed_values() {
        assert_eq!(sanitize_optional(Some("")), None);
        assert_eq!(sanitize_optional(Some("   ")), None);
        assert_eq!(
            sanitize_optional(Some("instance-123")),
            Some("instance-123")
        );
    }
}
