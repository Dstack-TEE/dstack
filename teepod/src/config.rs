use std::{net::IpAddr, path::PathBuf, str::FromStr};

use anyhow::{bail, Context, Result};
use load_config::load_config;
use path_absolutize::Absolutize;
use rocket::figment::Figment;
use serde::{Deserialize, Serialize};

pub const DEFAULT_CONFIG: &str = include_str!("../teepod.toml");
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("teepod", DEFAULT_CONFIG, config_file, false)
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
    #[serde(default)]
    pub qemu_path: PathBuf,
    pub ca_cert: PathBuf,
    pub tmp_ca_cert: PathBuf,
    pub tmp_ca_key: PathBuf,
    /// The URL of the KMS server
    pub kms_url: String,
    /// The URL of the TProxy server
    pub tproxy_url: String,
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
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub base_domain: String,
    pub port: u16,
    pub tappd_port: u16,
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

    /// Networking configuration
    pub networking: Networking,

    /// Authentication configuration
    pub auth: AuthConfig,

    /// Supervisor configuration
    pub supervisor: SupervisorConfig,

    /// Host API configuration
    pub host_api: HostApiConfig,
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
    Custom(CustomNetworking),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserNetworking {
    pub net: String,
    pub dhcp_start: String,
    pub restrict: bool,
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

impl Config {
    pub fn extract_or_default(figment: &Figment) -> Result<Self> {
        let mut me: Self = figment.extract()?;
        {
            let home = dirs::home_dir().context("Failed to get home directory")?;
            let app_home = home.join(".teepod");
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
