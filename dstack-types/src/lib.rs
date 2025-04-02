use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

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
    pub docker_config: DockerConfig,
    #[serde(default)]
    pub public_logs: bool,
    #[serde(default)]
    pub public_sysinfo: bool,
    #[serde(default)]
    pub kms_enabled: bool,
    #[serde(default, alias = "tproxy_enabled")]
    pub gateway_enabled: bool,
    #[serde(default)]
    pub local_key_provider_enabled: bool,
    #[serde(default)]
    pub key_provider: Option<KeyProviderKind>,
    #[serde(default)]
    pub allowed_envs: Vec<String>,
    #[serde(default)]
    pub no_instance_id: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum KeyProviderKind {
    None,
    Kms,
    Local,
}

impl KeyProviderKind {
    pub fn is_none(&self) -> bool {
        matches!(self, KeyProviderKind::None)
    }

    pub fn is_kms(&self) -> bool {
        matches!(self, KeyProviderKind::Kms)
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
        self.kms_enabled || self.feature_enabled("kms")
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
    pub host_api_url: String,
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
    Local { key: String },
    Kms { url: String },
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

pub mod shared_filenames;
