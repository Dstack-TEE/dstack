// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use size_parser::human_size;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    // Deprecated
    #[serde(default)]
    pub features: Vec<String>,
    pub runner: String,
    #[serde(default)]
    pub docker_compose_file: Option<String>,
    #[serde(default)]
    pub public_logs: bool,
    #[serde(default)]
    pub public_sysinfo: bool,
    #[serde(default = "default_true")]
    pub public_tcbinfo: bool,
    #[serde(default)]
    pub kms_enabled: bool,
    #[serde(deserialize_with = "deserialize_gateway_enabled", flatten)]
    pub gateway_enabled: bool,
    #[serde(default)]
    pub local_key_provider_enabled: bool,
    #[serde(default)]
    pub key_provider: Option<KeyProviderKind>,
    #[serde(default, with = "hex_bytes")]
    pub key_provider_id: Vec<u8>,
    #[serde(default)]
    pub allowed_envs: Vec<String>,
    #[serde(default)]
    pub no_instance_id: bool,
    #[serde(default = "default_true")]
    pub secure_time: bool,
    #[serde(default)]
    pub storage_fs: Option<String>,
    #[serde(default, with = "human_size")]
    pub swap_size: u64,
}

fn default_true() -> bool {
    true
}

fn deserialize_gateway_enabled<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct GatewayEnabled {
        #[serde(default)]
        gateway_enabled: bool,
        #[serde(default)]
        tproxy_enabled: bool,
    }
    let value = GatewayEnabled::deserialize(deserializer)?;
    Ok(value.gateway_enabled || value.tproxy_enabled)
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    None,
    Kms,
    Local,
    Tpm,
}

impl KeyProviderKind {
    pub fn is_none(&self) -> bool {
        matches!(self, KeyProviderKind::None)
    }

    pub fn is_kms(&self) -> bool {
        matches!(self, KeyProviderKind::Kms)
    }

    pub fn is_tpm(&self) -> bool {
        matches!(self, KeyProviderKind::Tpm)
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct DockerConfig {
    /// The URL of the Docker registry.
    pub registry: Option<String>,
    /// The username of the registry account.
    pub username: Option<String>,
    /// The key of the encrypted environment variables for registry account token.
    pub token_key: Option<String>,
}

impl AppCompose {
    pub fn feature_enabled(&self, feature: &str) -> bool {
        self.features.contains(&feature.to_string())
    }

    pub fn gateway_enabled(&self) -> bool {
        self.gateway_enabled || self.feature_enabled("tproxy-net")
    }

    pub fn kms_enabled(&self) -> bool {
        self.key_provider().is_kms()
    }

    pub fn key_provider(&self) -> KeyProviderKind {
        match self.key_provider {
            Some(p) => p,
            None => {
                if self.kms_enabled {
                    KeyProviderKind::Kms
                } else if self.local_key_provider_enabled {
                    KeyProviderKind::Local
                } else {
                    KeyProviderKind::None
                }
            }
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct SysConfig {
    #[serde(default)]
    pub kms_urls: Vec<String>,
    #[serde(default, alias = "tproxy_urls")]
    pub gateway_urls: Vec<String>,
    pub pccs_url: Option<String>,
    pub docker_registry: Option<String>,
    pub host_api_url: Option<String>,
    // JSON serialized VmConfig
    pub vm_config: String,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VmConfig {
    #[serde(with = "hex_bytes", default)]
    pub os_image_hash: Vec<u8>,
    #[serde(default)]
    pub cpu_count: u32,
    #[serde(default)]
    pub memory_size: u64,
    // https://github.com/intel-staging/qemu-tdx/issues/1
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu_single_pass_add_pages: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pic: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu_version: Option<String>,
    #[serde(default)]
    pub pci_hole64_size: u64,
    #[serde(default)]
    pub hugepages: bool,
    #[serde(default)]
    pub num_gpus: u32,
    #[serde(default)]
    pub num_nvswitches: u32,
    #[serde(default)]
    pub hotplug_off: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// If true, shared files are provided via a second virtual disk (hd2)
    /// If false (default), shared files are provided via 9p virtfs
    #[serde(default)]
    pub host_share_mode: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppKeys {
    #[serde(with = "hex_bytes")]
    pub disk_crypt_key: Vec<u8>,
    #[serde(with = "hex_bytes", default)]
    pub env_crypt_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub k256_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub k256_signature: Vec<u8>,
    pub gateway_app_id: String,
    pub ca_cert: String,
    pub key_provider: KeyProvider,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyProvider {
    None {
        key: String,
    },
    Local {
        key: String,
        #[serde(with = "hex_bytes")]
        mr: Vec<u8>,
    },
    Tpm {
        key: String,
        #[serde(with = "hex_bytes")]
        pubkey: Vec<u8>,
    },
    Kms {
        url: String,
        #[serde(with = "hex_bytes")]
        pubkey: Vec<u8>,
        tmp_ca_key: String,
        tmp_ca_cert: String,
    },
}

impl KeyProvider {
    pub fn kind(&self) -> KeyProviderKind {
        match self {
            KeyProvider::None { .. } => KeyProviderKind::None,
            KeyProvider::Local { .. } => KeyProviderKind::Local,
            KeyProvider::Tpm { .. } => KeyProviderKind::Tpm,
            KeyProvider::Kms { .. } => KeyProviderKind::Kms,
        }
    }

    pub fn id(&self) -> &[u8] {
        match self {
            KeyProvider::None { .. } => &[],
            KeyProvider::Local { mr, .. } => mr,
            KeyProvider::Tpm { pubkey, .. } => pubkey,
            KeyProvider::Kms { pubkey, .. } => pubkey,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyProviderInfo {
    pub name: String,
    pub id: String,
}

impl KeyProviderInfo {
    pub fn new(name: String, id: String) -> Self {
        Self { name, id }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    pub cmdline: String,
    pub kernel: String,
    pub initrd: String,
    pub bios: String,
}

pub mod mr_config;
pub mod shared_filenames;
pub mod version;

/// Get the address of the dstack agent
pub fn dstack_agent_address() -> String {
    // Check env DSTACK_AGENT_ADDRESS
    if let Ok(address) = std::env::var("DSTACK_AGENT_ADDRESS") {
        return address;
    }
    "unix:/var/run/dstack.sock".into()
}

/// Hardware/Cloud Platform
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Encode, Decode)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// dstack bare platform
    Dstack,
    /// Google Cloud Platform
    Gcp,
    /// AWS Nitro Enclave
    NitroEnclave,
}

impl Platform {
    /// Detect platform from system DMI information
    pub fn detect() -> Option<Self> {
        // Nitro Enclave: NSM device exists only inside enclave
        if Path::new("/dev/nsm").exists() {
            return Some(Self::NitroEnclave);
        }

        if let Ok(board_name) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            match board_name.trim() {
                "dstack" | "qemu" => return Some(Self::Dstack),
                "Google Compute Engine" => return Some(Self::Gcp),
                _ => {}
            }
        }
        None
    }

    /// Detect platform from system DMI information, default to Dstack if cannot detect
    pub fn detect_or_dstack() -> Self {
        Self::detect().unwrap_or(Self::Dstack)
    }

    /// Get platform name as string
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Dstack => "dstack",
            Self::Gcp => "gcp",
            Self::NitroEnclave => "aws-nitro-enclave",
        }
    }
}
