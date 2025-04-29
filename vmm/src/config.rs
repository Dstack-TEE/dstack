use std::{net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use load_config::load_config;
use path_absolutize::Absolutize;
use rocket::figment::Figment;
use serde::{Deserialize, Serialize};

use lspci::{lspci_filtered, Device};
use tracing::info;

pub const DEFAULT_CONFIG: &str = include_str!("../vmm.toml");
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("vmm", DEFAULT_CONFIG, config_file, false)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl FromStr for Protocol {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            _ => bail!("Invalid protocol: {s}"),
        })
    }
}

impl Protocol {
    pub fn as_str(&self) -> &str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PortRange {
    pub protocol: Protocol,
    pub from: u16,
    pub to: u16,
}

impl PortRange {
    pub fn contains(&self, protocol: &str, port: u16) -> bool {
        self.protocol.as_str() == protocol && port >= self.from && port <= self.to
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PortMappingConfig {
    pub enabled: bool,
    pub address: IpAddr,
    pub range: Vec<PortRange>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AutoRestartConfig {
    pub enabled: bool,
    pub interval: u64,
}

impl PortMappingConfig {
    pub fn is_allowed(&self, protocol: &str, port: u16) -> bool {
        if !self.enabled {
            return false;
        }
        self.range.iter().any(|r| r.contains(protocol, port))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CvmConfig {
    pub qemu_path: PathBuf,
    /// The URL of the KMS server
    pub kms_urls: Vec<String>,
    /// The URL of the dstack-gateway server
    #[serde(alias = "tproxy_urls")]
    pub gateway_urls: Vec<String>,
    /// The URL of the PCCS server
    #[serde(default)]
    pub pccs_url: String,
    /// The URL of the Docker registry
    pub docker_registry: String,
    /// The start of the CID pool that allocates CIDs to VMs
    pub cid_start: u32,
    /// The size of the CID pool that allocates CIDs to VMs
    pub cid_pool_size: u32,
    /// Port mapping configuration
    pub port_mapping: PortMappingConfig,
    /// Max allocable resources. Not yet implement fully, only for inspect API `GetMeta`
    pub max_allocable_vcpu: u32,
    pub max_allocable_memory_in_mb: u32,
    /// Enable qmp socket
    pub qmp_socket: bool,
    /// GPU configuration
    pub gpu: GpuConfig,
    /// Use sudo to run the VM
    pub user: String,

    /// The CA certificate
    #[serde(default)]
    pub ca_cert: String,
    /// The tmp CA certificate
    #[serde(default)]
    pub tmp_ca_cert: String,
    /// The tmp CA key
    #[serde(default)]
    pub tmp_ca_key: String,

    /// Auto restart configuration
    pub auto_restart: AutoRestartConfig,

    /// Use mrconfigid instead of compose hash
    pub use_mrconfigid: bool,

    /// QEMU single pass add page
    pub qemu_single_pass_add_pages: bool,
    /// QEMU pic
    pub qemu_pic: bool,
    /// QEMU pci_hole64_size
    pub qemu_pci_hole64_size: u64,
    /// QEMU hotplug_off
    pub qemu_hotplug_off: bool,

    /// Networking configuration
    pub networking: Networking,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GpuConfig {
    /// Whether to enable GPU passthrough
    pub enabled: bool,
    /// The product IDs of the GPUs to discover
    pub listing: Vec<String>,
    /// The PCI addresses to exclude from passthrough
    pub exclude: Vec<String>,
    /// The PCI addresses to include in passthrough
    pub include: Vec<String>,
    /// Allow attach all GPUs
    pub allow_attach_all: bool,
}

impl GpuConfig {
    pub(crate) fn list_devices(&self) -> Result<Vec<Device>> {
        let devices = lspci_filtered(|dev| {
            if !self.listing.contains(&dev.full_product_id()) {
                return false;
            }
            if self.exclude.contains(&dev.slot) {
                return false;
            }
            if !self.include.is_empty() && !self.include.contains(&dev.slot) {
                return false;
            }
            true
        })
        .context("Failed to list GPU devices")?;

        info!(
            "Found {} GPUs, {} in use",
            devices.len(),
            devices.iter().filter(|d| d.in_use()).count()
        );
        Ok(devices)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthConfig {
    /// Whether to enable API token authentication
    pub enabled: bool,
    /// The API tokens
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SupervisorConfig {
    pub exe: String,
    pub sock: String,
    pub pid_file: String,
    pub log_file: String,
    pub detached: bool,
    pub auto_start: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub base_domain: String,
    pub port: u16,
    pub agent_port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub image_path: PathBuf,
    #[serde(default)]
    pub run_path: PathBuf,
    /// The URL of the KMS server
    pub kms_url: String,

    /// CVM configuration
    pub cvm: CvmConfig,
    /// Gateway configuration
    pub gateway: GatewayConfig,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Supervisor configuration
    pub supervisor: SupervisorConfig,

    /// Host API configuration
    pub host_api: HostApiConfig,

    /// Key provider configuration
    pub key_provider: KeyProviderConfig,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ProcessAnnotation {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub live_for: Option<String>,
}

impl ProcessAnnotation {
    pub fn is_cvm(&self) -> bool {
        if self.live_for.is_some() {
            return false;
        }
        self.kind.is_empty() || self.kind == "cvm"
    }
}

impl Config {
    pub fn abs_path(self) -> Result<Self> {
        Ok(Self {
            image_path: self.image_path.absolutize()?.to_path_buf(),
            run_path: self.run_path.absolutize()?.to_path_buf(),
            ..self
        })
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
pub enum Networking {
    User(UserNetworking),
    Passt(PasstNetworking),
    Custom(CustomNetworking),
}

impl Networking {
    pub fn is_passt(&self) -> bool {
        matches!(self, Networking::Passt(_))
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserNetworking {
    pub net: String,
    pub dhcp_start: String,
    pub restrict: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PasstNetworking {
    pub passt_exec: String,
    pub interface: String,
    pub address: String,
    pub netmask: String,
    pub gateway: String,
    pub dns: Vec<String>,
    pub map_host_loopback: String,
    pub map_guest_addr: String,
    pub no_map_gw: bool,
    pub ipv4_only: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CustomNetworking {
    pub netdev: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HostApiConfig {
    pub address: String,
    pub port: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyProviderConfig {
    pub enabled: bool,
    pub address: IpAddr,
    pub port: u16,
}

impl Config {
    pub fn extract_or_default(figment: &Figment) -> Result<Self> {
        let mut me: Self = figment.extract()?;
        {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            let app_home = home.join(".dstack-vmm");
            if me.image_path == PathBuf::default() {
                me.image_path = app_home.join("image");
            }
            if me.run_path == PathBuf::default() {
                me.run_path = app_home.join("vm");
            }
            if me.cvm.qemu_path == PathBuf::default() {
                let cpu_arch = std::env::consts::ARCH;
                let qemu_path = which::which(format!("qemu-system-{}", cpu_arch))
                    .context("Failed to find qemu executable")?;
                me.cvm.qemu_path = qemu_path;
            }
        }
        Ok(me)
    }
}
