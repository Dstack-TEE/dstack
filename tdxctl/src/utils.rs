use std::{
    io::{self, Read},
    path::Path,
};

use anyhow::{Context, Result};
use fs_err as fs;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use sha2::{digest::Output, Digest};
use tdx_attest as att;

/// This code is not defined in the TCG specification.
/// See https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
const DSTACK_EVENT_TAG: u32 = 0x08000001;

pub fn deserialize_json_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let data = fs::read_to_string(path).context("Failed to read file")?;
    serde_json::from_str(&data).context("Failed to parse json")
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(data);
    sha256.finalize().into()
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let data = fs::read(path).context("Failed to read file")?;
    Ok(sha256(&data))
}

pub struct HashingFile<H, F> {
    file: F,
    hasher: H,
}

impl<H: Digest, F: Read> Read for HashingFile<H, F> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let bytes_read = self.file.read(buf)?;
        self.hasher.update(&buf[..bytes_read]);
        Ok(bytes_read)
    }
}

impl<H: Digest, F> HashingFile<H, F> {
    pub fn new(file: F) -> Self {
        Self {
            file,
            hasher: H::new(),
        }
    }

    pub fn finalize(self) -> Output<H> {
        self.hasher.finalize()
    }
}

pub fn extend_rtmr3(event: &str, payload: &[u8]) -> Result<()> {
    extend_rtmr(3, DSTACK_EVENT_TAG, event, payload)
}

pub fn extend_rtmr(index: u32, event_type: u32, event: &str, payload: &[u8]) -> Result<()> {
    let log =
        att::eventlog::TdxEventLog::new(index, event_type, event.to_string(), payload.to_vec());
    att::extend_rtmr(index, event_type, log.digest).context("Failed to extend RTMR")?;
    let hexed_payload = hex::encode(payload);
    let hexed_digest = hex_fmt::HexFmt(&log.digest);
    println!("Extended RTMR{index}: event={event}, payload={hexed_payload}, digest={hexed_digest}");
    att::log_rtmr_event(&log).context("Failed to log RTMR extending event")?;
    Ok(())
}

#[derive(Deserialize)]
#[allow(unused)]
pub struct AppCompose {
    pub manifest_version: u32,
    pub name: String,
    // Deprecated
    #[serde(default)]
    pub features: Vec<String>,
    pub runner: String,
    pub docker_compose_file: Option<String>,
    #[serde(default)]
    pub docker_config: DockerConfig,
    #[serde(default)]
    pub public_logs: bool,
    #[serde(default)]
    pub public_sysinfo: bool,
    #[serde(default)]
    pub kms_enabled: bool,
    #[serde(default)]
    pub tproxy_enabled: bool,
    #[serde(default)]
    pub local_key_provider_enabled: bool,
    #[serde(default)]
    key_provider: Option<KeyProvider>,
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum KeyProvider {
    None,
    Kms,
    Local,
}

impl KeyProvider {
    pub fn is_none(&self) -> bool {
        matches!(self, KeyProvider::None)
    }
}

#[derive(Deserialize, Debug, Default)]
pub struct DockerConfig {
    /// The URL of the Docker registry.
    pub registry: Option<String>,
    /// The username of the registry account.
    pub username: Option<String>,
    /// The key of the encrypted environment variables for registry account token.
    pub token_key: Option<String>,
}

impl AppCompose {
    fn feature_enabled(&self, feature: &str) -> bool {
        self.features.contains(&feature.to_string())
    }

    pub fn tproxy_enabled(&self) -> bool {
        self.tproxy_enabled || self.feature_enabled("tproxy-net")
    }

    pub fn kms_enabled(&self) -> bool {
        self.kms_enabled || self.feature_enabled("kms")
    }

    pub fn key_provider(&self) -> KeyProvider {
        match self.key_provider {
            Some(p) => p,
            None => {
                if self.kms_enabled {
                    KeyProvider::Kms
                } else if self.local_key_provider_enabled {
                    KeyProvider::Local
                } else {
                    KeyProvider::None
                }
            }
        }
    }
}

#[derive(Deserialize)]
pub struct LocalConfig {
    pub kms_url: Option<String>,
    pub tproxy_url: Option<String>,
    pub pccs_url: Option<String>,
    pub docker_registry: Option<String>,
    pub host_api_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct AppKeys {
    pub app_key: String,
    pub disk_crypt_key: String,
    #[serde(with = "hex_bytes", default)]
    pub env_crypt_key: Vec<u8>,
    pub certificate_chain: Vec<String>,
}
