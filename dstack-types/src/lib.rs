// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use or_panic::ResultOrPanic;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use size_parser::human_size;

/// Identifies which OVMF flavour the guest image was built with.
///
/// The firmware switch happened in meta-dstack commit f9f11f3 (upgrade from an
/// untagged 2024-09 snapshot to edk2-stable202505): 0.5.7 and earlier shipped
/// `Pre202505`, 0.5.9 onwards ships `Stable202505`. The newer firmware emits
/// more boot-time events into RTMR[0], so quote replay needs a different
/// expected event list for the two flavours.
///
/// When the variant isn't carried explicitly in `VmConfig`, the runtime cutoff
/// rule in `dstack_mr::ovmf_variant_for_version` draws the line at OS version
/// `0.5.10` (and again at `0.6.1`) — a deliberate policy decision that doesn't
/// follow the firmware-flip date exactly. See that function's docs for the
/// authoritative selection rule.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OvmfVariant {
    /// Pre-edk2-stable202505 OVMF (13 RTMR[0] events).
    #[default]
    Pre202505,
    /// edk2-stable202505+ OVMF (17 RTMR[0] events: new fw_cfg, VARIABLE_AUTHORITY
    /// and BootXXXX entries).
    Stable202505,
}

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
    /// Per-port policy consumed by the gateway (PROXY protocol opt-in,
    /// optional port whitelist).
    #[serde(default)]
    pub port_policy: PortPolicy,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct PortPolicy {
    /// Per-port attributes (PROXY protocol opt-in, etc.).
    #[serde(default)]
    pub ports: Vec<PortAttrs>,
    /// When true, the gateway only forwards traffic to ports listed in `ports`.
    /// All other ports are rejected at TCP-accept time.
    #[serde(default)]
    pub restrict_mode: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct PortAttrs {
    pub port: u16,
    /// Whether the gateway should send a PROXY protocol header on outbound
    /// connections to this port.
    #[serde(default)]
    pub pp: bool,
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

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
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
    /// MrConfigV3 document string for platform app/config binding.
    ///
    /// Hosts generate this in JCS form, but verifiers hash the supplied string
    /// bytes directly because the platform carrier binds the exact document
    /// string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mr_config: Option<String>,
    // JSON serialized VmConfig
    pub vm_config: String,
}

impl SysConfig {
    /// Canonical MrConfigV3 document for this VM, if any.
    ///
    /// The document is carried in the top-level `mr_config` field; older hosts
    /// only embedded it inside the serialized `vm_config`, so fall back to that
    /// for backward compatibility. This is the single source of truth for all
    /// readers (guest quote generation and config-id verification) so they
    /// cannot disagree about where `mr_config` lives.
    pub fn mr_config_document(&self) -> Option<String> {
        if let Some(doc) = self.mr_config.as_deref() {
            if !doc.is_empty() {
                return Some(doc.to_string());
            }
        }
        serde_json::from_str::<serde_json::Value>(&self.vm_config)
            .ok()
            .and_then(|value| {
                value
                    .get("mr_config")
                    .and_then(|value| value.as_str())
                    .map(ToString::to_string)
            })
    }
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
    /// OVMF measurement layout declared by the OS image. When present, verifiers
    /// should treat this as the source of truth. Absent on images built before
    /// this field was introduced — callers must fall back to other heuristics
    /// (e.g. parsing the OS version out of `image`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovmf_variant: Option<OvmfVariant>,
}

/// One OVMF SEV metadata section (gpa/size/type) that affects the SEV-SNP
/// launch measurement. Mirrors the OVMF footer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OvmfSection {
    pub gpa: u64,
    pub size: u64,
    pub section_type: u32,
}

/// Image-invariant projection that determines the AMD SEV-SNP OS image identity.
///
/// `os_image_hash` is the SHA-256 of this projection, canonically serialized
/// (JCS). It is shared by the VMM/KMS (which derive it from a verified launch
/// measurement) and the image build (which precomputes `digest.sev.txt`), so
/// both sides agree. It deliberately EXCLUDES per-deployment values (vcpus,
/// vcpu_type, guest_features, app_id, compose_hash): the same OS image must hash
/// identically regardless of how it is launched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevOsImageMeasurement {
    pub rootfs_hash: String,
    pub base_cmdline: Option<String>,
    pub ovmf_hash: String,
    pub kernel_hash: String,
    pub initrd_hash: String,
    pub sev_hashes_table_gpa: u64,
    pub sev_es_reset_eip: u32,
    pub ovmf_sections: Vec<OvmfSection>,
}

impl SevOsImageMeasurement {
    /// SHA-256 over the canonical (JCS) serialization of this projection.
    pub fn os_image_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        // JCS serialization of this plain owned struct (strings/ints/array)
        // cannot fail; panic loudly if that invariant is ever broken.
        let canonical = serde_jcs::to_vec(self).or_panic("SevOsImageMeasurement JCS serialization");
        Sha256::digest(canonical).into()
    }
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
    /// Optional dstack OS version (e.g. "0.5.10"). Older metadata.json files
    /// may omit it, so callers should treat its absence as "unknown".
    #[serde(default)]
    pub version: String,
    /// dev vs prod image. absent in older metadata.json => prod.
    #[serde(default)]
    pub is_dev: bool,
    /// Optional OVMF measurement layout declared by the image. Older
    /// metadata.json files do not carry this — treat absence as "unknown" and
    /// fall back to version-based heuristics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ovmf_variant: Option<OvmfVariant>,
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
    // Try new path first, fall back to old path for backward compatibility
    const SOCKET_PATHS: &[&str] = &["/var/run/dstack/dstack.sock", "/var/run/dstack.sock"];
    for path in SOCKET_PATHS {
        if std::path::Path::new(path).exists() {
            return format!("unix:{}", path);
        }
    }
    format!("unix:{}", SOCKET_PATHS[0])
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
