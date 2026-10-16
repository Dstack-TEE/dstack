// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! What one poll of one node returns.
//!
//! `--json` prints these, so this is a wire format: fields are only added,
//! each new one with `#[serde(default)]`. It deliberately carries no secrets:
//! no encrypted env, no user config, no compose file.

use dstack_vmm_rpc as rpc;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct NodeSnapshot {
    /// Display name, unique within one source.
    pub name: String,
    /// Where the node is reached, without credentials.
    pub endpoint: String,
    /// Unix ms of the latest poll attempt.
    pub polled_at_ms: u64,
    /// Unix ms of the latest successful poll. Data below is from then.
    #[serde(default)]
    pub ok_at_ms: Option<u64>,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    /// Why the latest poll failed. The data below is then the last good copy.
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub rev: Option<String>,
    #[serde(default)]
    pub resources: Option<Resources>,
    #[serde(default)]
    pub kms_urls: Vec<String>,
    #[serde(default)]
    pub gateway_urls: Vec<String>,
    #[serde(default)]
    pub base_domain: Option<String>,
    #[serde(default)]
    pub vms: Vec<Vm>,
    #[serde(default)]
    pub gpus: Vec<Gpu>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Resources {
    pub max_cvms: u32,
    pub max_vcpu: u32,
    pub max_memory_mb: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Vm {
    pub id: String,
    pub name: String,
    /// VMM runtime status: running, exited, stopping, stopped, removing.
    pub status: String,
    #[serde(default)]
    pub running: bool,
    /// Seconds since QEMU started, when it has.
    #[serde(default)]
    pub uptime_secs: Option<u64>,
    #[serde(default)]
    pub app_id: String,
    #[serde(default)]
    pub instance_id: Option<String>,
    #[serde(default)]
    pub app_url: Option<String>,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub image_version: String,
    #[serde(default)]
    pub vcpu: u32,
    #[serde(default)]
    pub memory_mb: u32,
    #[serde(default)]
    pub disk_gb: u32,
    #[serde(default)]
    pub gpus: Vec<String>,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub networks: Vec<String>,
    #[serde(default)]
    pub no_tee: bool,
    #[serde(default)]
    pub boot_progress: String,
    #[serde(default)]
    pub boot_error: String,
    #[serde(default)]
    pub shutdown_progress: String,
    #[serde(default)]
    pub events: Vec<GuestEvent>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Port {
    pub protocol: String,
    pub host_address: String,
    pub host_port: u32,
    pub vm_port: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Gpu {
    pub slot: String,
    pub product_id: String,
    pub description: String,
    pub is_free: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuestEvent {
    pub event: String,
    pub body: String,
    pub timestamp_ms: u64,
}

/// Every node at once, as `--json` prints it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Report {
    pub version: String,
    pub nodes: Vec<NodeSnapshot>,
}

/// Where a VM is in its life, as an operator reads it. Folds `status`,
/// `boot_progress`, `boot_error` and `shutdown_progress` into one value, the
/// same way the web console does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Phase {
    // Declaration order is the default sort: trouble first, idle last.
    Failed,
    Exited,
    Booting,
    ShuttingDown,
    Stopping,
    Removing,
    Running,
    Stopped,
    Unknown,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Phase::Failed => "failed",
            Phase::Booting => "booting",
            Phase::ShuttingDown => "shutting down",
            Phase::Stopping => "stopping",
            Phase::Removing => "removing",
            Phase::Running => "running",
            Phase::Exited => "exited",
            Phase::Stopped => "stopped",
            Phase::Unknown => "unknown",
        }
    }

    /// Changing on its own right now; the UI animates these.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Phase::Booting | Phase::ShuttingDown | Phase::Stopping | Phase::Removing
        )
    }

    /// Holds host resources.
    pub fn is_live(self) -> bool {
        matches!(
            self,
            Phase::Running | Phase::Booting | Phase::ShuttingDown | Phase::Stopping | Phase::Failed
        )
    }

    /// Worth an operator's look.
    pub fn needs_attention(self) -> bool {
        matches!(self, Phase::Failed | Phase::Exited) || self.is_transient()
    }
}

fn unset(s: &str) -> bool {
    s.is_empty() || s == "N/A"
}

impl Vm {
    pub fn phase(&self) -> Phase {
        match self.status.as_str() {
            "running" => {
                if !self.boot_error.is_empty() {
                    Phase::Failed
                } else if !unset(&self.shutdown_progress) {
                    Phase::ShuttingDown
                } else if unset(&self.boot_progress)
                    || self.boot_progress == "done"
                    || self.boot_progress == "running"
                {
                    Phase::Running
                } else {
                    Phase::Booting
                }
            }
            "exited" => Phase::Exited,
            "stopping" => Phase::Stopping,
            "stopped" => Phase::Stopped,
            "removing" => Phase::Removing,
            _ => Phase::Unknown,
        }
    }

    /// One short phrase on what the VM is doing beyond its phase, if any.
    pub fn activity(&self) -> Option<&str> {
        match self.phase() {
            Phase::Failed => Some(&self.boot_error),
            Phase::Booting if self.boot_progress != "booting" => Some(&self.boot_progress),
            Phase::ShuttingDown => Some(&self.shutdown_progress),
            _ => None,
        }
    }

    pub fn short_id(&self) -> &str {
        short(&self.id, 8)
    }
}

pub fn short(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

impl NodeSnapshot {
    pub fn online(&self) -> bool {
        self.error.is_none() && self.ok_at_ms.is_some()
    }

    /// vCPUs held by VMs that hold host resources.
    pub fn vcpu_used(&self) -> u32 {
        self.live_vms().map(|vm| vm.vcpu).sum()
    }

    pub fn memory_used_mb(&self) -> u64 {
        self.live_vms().map(|vm| vm.memory_mb as u64).sum()
    }

    pub fn disk_gb(&self) -> u64 {
        self.vms.iter().map(|vm| vm.disk_gb as u64).sum()
    }

    pub fn gpus_used(&self) -> usize {
        self.gpus.iter().filter(|g| !g.is_free).count()
    }

    pub fn live_vms(&self) -> impl Iterator<Item = &Vm> {
        self.vms.iter().filter(|vm| vm.phase().is_live())
    }
}

/// Seconds out of the VMM's `humantime` uptime ("2days 3h 4m 5s"), or
/// `None` for "never" and anything unparseable.
pub fn parse_uptime(s: &str) -> Option<u64> {
    if s.is_empty() || s == "never" {
        return None;
    }
    humantime::parse_duration(s)
        .ok()
        .map(|d: Duration| d.as_secs())
}

impl From<rpc::VmInfo> for Vm {
    fn from(info: rpc::VmInfo) -> Self {
        let cfg = info.configuration.unwrap_or_default();
        let uptime_secs = if info.running {
            parse_uptime(&info.uptime)
        } else {
            None
        };
        let networks = if info.interfaces.is_empty() {
            cfg.networks.iter().map(|n| n.mode.clone()).collect()
        } else {
            info.interfaces
                .iter()
                .map(|i| match &i.bridge_name {
                    Some(b) if !b.is_empty() => format!("{}:{b}", i.mode),
                    _ => i.mode.clone(),
                })
                .collect()
        };
        Vm {
            id: info.id,
            name: info.name,
            status: info.status,
            running: info.running,
            uptime_secs,
            app_id: info.app_id,
            instance_id: info.instance_id.filter(|s| !s.is_empty()),
            app_url: info.app_url.filter(|s| !s.is_empty()),
            image: cfg.image,
            image_version: info.image_version,
            vcpu: cfg.vcpu,
            memory_mb: cfg.memory,
            disk_gb: cfg.disk_size,
            gpus: cfg
                .gpus
                .map(|g| g.gpus.into_iter().map(|s| s.slot).collect())
                .unwrap_or_default(),
            ports: cfg
                .ports
                .into_iter()
                .map(|p| Port {
                    protocol: p.protocol,
                    host_address: p.host_address,
                    host_port: p.host_port,
                    vm_port: p.vm_port,
                })
                .collect(),
            networks,
            no_tee: cfg.no_tee,
            boot_progress: info.boot_progress,
            boot_error: info.boot_error,
            shutdown_progress: info.shutdown_progress,
            events: info
                .events
                .into_iter()
                .map(|e| GuestEvent {
                    event: e.event,
                    body: e.body,
                    timestamp_ms: e.timestamp,
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vm(status: &str, boot: &str, err: &str, shutdown: &str) -> Vm {
        Vm {
            status: status.into(),
            boot_progress: boot.into(),
            boot_error: err.into(),
            shutdown_progress: shutdown.into(),
            ..Default::default()
        }
    }

    #[test]
    fn phase_folds_progress_into_status() {
        assert_eq!(vm("running", "done", "", "").phase(), Phase::Running);
        assert_eq!(vm("running", "running", "", "").phase(), Phase::Running);
        assert_eq!(vm("running", "N/A", "", "N/A").phase(), Phase::Running);
        assert_eq!(vm("running", "booting", "", "").phase(), Phase::Booting);
        assert_eq!(
            vm("running", "requesting app keys", "", "").phase(),
            Phase::Booting
        );
        assert_eq!(
            vm("running", "done", "", "powering off").phase(),
            Phase::ShuttingDown
        );
        assert_eq!(
            vm("running", "mounting data disk", "kms refused", "").phase(),
            Phase::Failed
        );
        assert_eq!(vm("exited", "", "", "").phase(), Phase::Exited);
        assert_eq!(vm("stopped", "", "", "").phase(), Phase::Stopped);
        assert_eq!(vm("what", "", "", "").phase(), Phase::Unknown);
    }

    #[test]
    fn activity_names_the_step() {
        assert_eq!(vm("running", "booting", "", "").activity(), None);
        assert_eq!(
            vm("running", "requesting app keys", "", "").activity(),
            Some("requesting app keys")
        );
        assert_eq!(vm("running", "done", "", "").activity(), None);
    }

    #[test]
    fn uptime_parses_vmm_format() {
        assert_eq!(parse_uptime("never"), None);
        assert_eq!(parse_uptime("5s"), Some(5));
        assert_eq!(parse_uptime("1h 2m 3s"), Some(3723));
        assert_eq!(parse_uptime("2days 1h"), Some(2 * 86400 + 3600));
    }

    #[test]
    fn short_is_char_safe() {
        assert_eq!(short("abcdef", 3), "abc");
        assert_eq!(short("ab", 3), "ab");
        assert_eq!(short("名字很长", 2), "名字");
    }
}
