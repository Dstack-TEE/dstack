// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VM runtime-state aggregation and RPC presentation.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use dstack_vmm_rpc as pb;
use fs_err as fs;
use supervisor_client::supervisor::ProcessInfo;

use super::{
    network::{mac_address_for_vm_index, resolved_networks},
    Manifest, VmState, VmWorkDir,
};
use crate::config::{CvmConfig, GatewayConfig, Networking, NetworkingMode};

pub(crate) struct VmInfo {
    pub manifest: Manifest,
    pub workdir: PathBuf,
    pub status: &'static str,
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

fn networking_mode_name(mode: NetworkingMode) -> &'static str {
    match mode {
        NetworkingMode::Bridge => "bridge",
        NetworkingMode::User => "user",
        NetworkingMode::Custom => "custom",
        NetworkingMode::Macvtap => "macvtap",
    }
}

fn networking_backend_name(mode: NetworkingMode) -> &'static str {
    match mode {
        NetworkingMode::Bridge => "tap_bridge",
        NetworkingMode::User => "slirp",
        NetworkingMode::Custom => "custom",
        NetworkingMode::Macvtap => "macvtap",
    }
}

fn networking_to_proto(networking: &Networking) -> pb::NetworkingConfig {
    pb::NetworkingConfig {
        mode: networking_mode_name(networking.mode).into(),
        bridge_name: if networking.mode == NetworkingMode::Bridge {
            networking.bridge.clone()
        } else {
            String::new()
        },
        parent: networking.parent.clone(),
        macvtap_mode: networking.macvtap_mode.clone(),
    }
}

fn sanitize_optional<T: AsRef<str>>(value: Option<T>) -> Option<T> {
    value.filter(|value| !value.as_ref().trim().is_empty())
}

impl VmInfo {
    pub fn effective_networks(&self, cvm: &CvmConfig) -> Vec<Networking> {
        if self.runtime_networks.is_empty() {
            resolved_networks(&self.manifest, cvm)
        } else {
            self.runtime_networks.clone()
        }
    }

    pub fn to_pb(&self, gateway: &GatewayConfig, cvm: &CvmConfig, brief: bool) -> pb::VmInfo {
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
        let interfaces = self
            .effective_networks(cvm)
            .iter()
            .enumerate()
            .map(|(index, networking)| {
                let mac = mac_address_for_vm_index(
                    &self.manifest.id,
                    &networking.mac_prefix_bytes(),
                    index,
                );
                pb::NetworkInterfaceStatus {
                    mode: networking_mode_name(networking.mode).into(),
                    backend: networking_backend_name(networking.mode).into(),
                    mac,
                    bridge_name: (networking.mode == NetworkingMode::Bridge)
                        .then(|| networking.bridge.clone()),
                    netdev_id: Some(format!("net{index}")),
                }
            })
            .collect();
        pb::VmInfo {
            id: self.manifest.id.clone(),
            name: self.manifest.name.clone(),
            status: self.status.into(),
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
    use super::sanitize_optional;

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
