// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{io::Cursor, path::Path};

use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use size_parser::human_size;

/// Identifies which OVMF flavour the guest image was built with.
///
/// Only the pre-202505 OVMF measurement layout is supported.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OvmfVariant {
    /// Pre-202505 OVMF (13 RTMR[0] events).
    #[default]
    Pre202505,
}

impl OvmfVariant {
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Pre202505 => 0,
        }
    }

    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Pre202505),
            _ => None,
        }
    }
}

/// Selects how a TDX attestation should bind the OS image.
///
/// `Legacy` preserves the existing verifier behavior: `vm_config.os_image_hash`
/// is the content digest (`digest.txt`) and the verifier recomputes the full
/// TDX launch measurement using the legacy image/QEMU-derived path.
///
/// `Lite` opts into the no-QEMU verifier path: `vm_config.os_image_hash`
/// is `measurement.json.tdx.os_image_hash`, `vm_config.tdx_measurement` carries
/// the self-contained measurement material, and KMS/verifier select the new
/// logic from this vm_config flag while the attestation quote remains the
/// existing `DstackTdx`.
#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TdxAttestationVariant {
    #[default]
    Legacy,
    Lite,
}

impl TdxAttestationVariant {
    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }

    pub fn is_lite(&self) -> bool {
        matches!(self, Self::Lite)
    }
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
    /// TDX-only attestation/hash scheme selector. Defaults to `legacy` and is
    /// omitted from legacy configs to keep old behavior and wire shape stable.
    #[serde(default, skip_serializing_if = "TdxAttestationVariant::is_legacy")]
    pub tdx_attestation_variant: TdxAttestationVariant,
    /// TDX-only no-image-download measurement material. Present only when
    /// `tdx_attestation_variant = "lite"` and omitted for legacy TDX.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_measurement: Option<TdxOsImageMeasurementDocument>,
}

/// One OVMF SEV metadata section (gpa/size/type) that affects the SEV-SNP
/// launch measurement. Mirrors the OVMF footer metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OvmfSection {
    pub gpa: u64,
    pub size: u64,
    pub section_type: u32,
}

fn cbor_to_vec<T: Serialize>(value: &T, context: &str) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out)
        .unwrap_or_else(|e| panic!("{context}: failed to encode CBOR: {e}"));
    out
}

fn cbor_from_slice<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    context: &str,
) -> Result<T, String> {
    ciborium::de::from_reader(Cursor::new(bytes))
        .map_err(|e| format!("{context}: failed to decode CBOR: {e}"))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(sha256(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborOvmfSection {
    gpa: u64,
    size: u64,
    #[serde(rename = "type")]
    section_type: u32,
}

impl From<&OvmfSection> for CborOvmfSection {
    fn from(section: &OvmfSection) -> Self {
        Self {
            gpa: section.gpa,
            size: section.size,
            section_type: section.section_type,
        }
    }
}

impl From<CborOvmfSection> for OvmfSection {
    fn from(section: CborOvmfSection) -> Self {
        Self {
            gpa: section.gpa,
            size: section.size,
            section_type: section.section_type,
        }
    }
}

/// Image-invariant projection that determines the AMD SEV-SNP OS image
/// identity. It deliberately excludes per-deployment values (vcpus, vcpu_type,
/// guest_features, app_id, compose_hash): the same OS image must hash
/// identically regardless of how it is launched.
///
/// `os_image_hash` is SHA-256 over the CBOR representation of this projection,
/// not over the outer measurement.json field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevOsImageMeasurement {
    /// SHA-256 of the kernel command line bytes as measured in the SEV-SNP hash
    /// table (trimmed command line plus trailing NUL byte). This avoids carrying
    /// the full plaintext command line in image metadata while preserving the
    /// exact measured value used by OVMF/QEMU.
    #[serde(with = "hex_bytes")]
    pub kernel_cmdline_sha256: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub ovmf_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub kernel_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub initrd_hash: Vec<u8>,
    pub sev_hashes_table_gpa: u64,
    pub sev_es_reset_eip: u32,
    pub ovmf_sections: Vec<OvmfSection>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborSevOsImageMeasurement {
    /// Measured kernel cmdline SHA-256.
    #[serde(rename = "cmdline_sha256", with = "hex_bytes")]
    kernel_cmdline_sha256: Vec<u8>,
    /// OVMF launch digest.
    #[serde(with = "hex_bytes")]
    ovmf_hash: Vec<u8>,
    /// Kernel SHA-256.
    #[serde(with = "hex_bytes")]
    kernel_hash: Vec<u8>,
    /// Initrd SHA-256.
    #[serde(with = "hex_bytes")]
    initrd_hash: Vec<u8>,
    /// SEV hash table GPA.
    hashes_table_gpa: u64,
    /// SEV-ES AP reset EIP.
    reset_eip: u32,
    /// OVMF metadata sections.
    ovmf_sections: Vec<CborOvmfSection>,
}

impl From<&SevOsImageMeasurement> for CborSevOsImageMeasurement {
    fn from(measurement: &SevOsImageMeasurement) -> Self {
        Self {
            kernel_cmdline_sha256: measurement.kernel_cmdline_sha256.clone(),
            ovmf_hash: measurement.ovmf_hash.clone(),
            kernel_hash: measurement.kernel_hash.clone(),
            initrd_hash: measurement.initrd_hash.clone(),
            hashes_table_gpa: measurement.sev_hashes_table_gpa,
            reset_eip: measurement.sev_es_reset_eip,
            ovmf_sections: measurement.ovmf_sections.iter().map(Into::into).collect(),
        }
    }
}

impl From<CborSevOsImageMeasurement> for SevOsImageMeasurement {
    fn from(measurement: CborSevOsImageMeasurement) -> Self {
        Self {
            kernel_cmdline_sha256: measurement.kernel_cmdline_sha256,
            ovmf_hash: measurement.ovmf_hash,
            kernel_hash: measurement.kernel_hash,
            initrd_hash: measurement.initrd_hash,
            sev_hashes_table_gpa: measurement.hashes_table_gpa,
            sev_es_reset_eip: measurement.reset_eip,
            ovmf_sections: measurement
                .ovmf_sections
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

impl SevOsImageMeasurement {
    /// CBOR representation used as the `os_image_hash` input.
    pub fn to_cbor_vec(&self) -> Vec<u8> {
        cbor_to_vec(
            &CborSevOsImageMeasurement::from(self),
            "SevOsImageMeasurement",
        )
    }

    pub fn from_cbor_slice(bytes: &[u8]) -> Result<Self, String> {
        cbor_from_slice::<CborSevOsImageMeasurement>(bytes, "SevOsImageMeasurement").map(Into::into)
    }

    pub fn cbor_json_value_from_slice(bytes: &[u8]) -> Result<serde_json::Value, String> {
        let cbor = cbor_from_slice::<CborSevOsImageMeasurement>(bytes, "SevOsImageMeasurement")?;
        serde_json::to_value(cbor)
            .map_err(|e| format!("SevOsImageMeasurement: failed to convert CBOR to JSON: {e}"))
    }

    /// SHA-256 over the CBOR representation of this projection.
    pub fn os_image_hash(&self) -> [u8; 32] {
        sha256(&self.to_cbor_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevOsImageMeasurementDocument {
    /// Document schema version.
    #[serde(alias = "v")]
    pub version: u32,
    /// SHA-256 over the CBOR `measurement` bytes. This field is not included in
    /// its own hash input.
    #[serde(alias = "h")]
    pub os_image_hash: String,
    /// CBOR bytes for `SevOsImageMeasurement`.
    #[serde(alias = "m", with = "hex_bytes")]
    pub measurement: Vec<u8>,
}

impl SevOsImageMeasurementDocument {
    pub const VERSION: u32 = 2;

    pub fn new(measurement: SevOsImageMeasurement) -> Self {
        let measurement = measurement.to_cbor_vec();
        let os_image_hash = sha256_hex(&measurement);
        Self {
            version: Self::VERSION,
            os_image_hash,
            measurement,
        }
    }

    pub fn decode_measurement(&self) -> Result<SevOsImageMeasurement, String> {
        SevOsImageMeasurement::from_cbor_slice(&self.measurement)
    }

    pub fn decode_measurement_value(&self) -> Result<serde_json::Value, String> {
        SevOsImageMeasurement::cbor_json_value_from_slice(&self.measurement)
    }

    pub fn measurement_os_image_hash(&self) -> [u8; 32] {
        sha256(&self.measurement)
    }
}

/// Image-invariant projection that determines the TDX OS image identity.
///
/// This is the build-time, image-static material for the verifier-side
/// no-image-download TDX path. Dynamic VM parameters (vCPU count, RAM size,
/// QEMU PCI topology, GPU count, etc.) are deliberately excluded and must be
/// supplied by `VmConfig` when replaying RTMRs.
///
/// `os_image_hash` is SHA-256 over the CBOR representation of this projection,
/// not over the outer measurement.json field names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxOsImageMeasurement {
    pub image: TdxImageMeasurement,
    pub tdvf: TdxTdvfMeasurement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxImageMeasurement {
    /// SHA-384 of the exact kernel command line event measured into RTMR[2].
    ///
    /// The measured value is the image-provided command line plus OVMF/QEMU's
    /// `initrd=initrd` suffix, encoded as UTF-16LE with a trailing NUL.
    #[serde(with = "hex_bytes")]
    pub kernel_cmdline_sha384: Vec<u8>,
    /// Authenticode SHA-384 digest of the QEMU-patched kernel image when the
    /// guest memory is at or above QEMU's high-memory TDX initrd placement
    /// threshold. Below that threshold the patched kernel header depends on the
    /// exact guest memory size, so the no-image-download verifier rejects it.
    #[serde(with = "hex_bytes")]
    pub kernel_authenticode: Vec<u8>,
    /// SHA-384 of the initrd file bytes. This is the second RTMR[2] event.
    #[serde(with = "hex_bytes")]
    pub initrd_sha384: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxTdvfMeasurement {
    /// OVMF RTMR[0] event layout.
    pub ovmf_variant: OvmfVariant,
    pub mrtd: TdxMrtdCandidates,
    /// Compact TdHobWitnessV1 byte string.
    #[serde(with = "hex_bytes")]
    pub td_hob_witness: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxMrtdCandidates {
    /// Candidate MRTD for QEMU's single-pass MEM.PAGE.ADD/MR.EXTEND order.
    #[serde(with = "hex_bytes")]
    pub single_pass: Vec<u8>,
    /// Candidate MRTD for QEMU's two-pass MEM.PAGE.ADD then MR.EXTEND order.
    #[serde(with = "hex_bytes")]
    pub two_pass: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborTdxImageMeasurement {
    /// Measured kernel cmdline SHA-384.
    #[serde(rename = "cmdline_sha384", with = "hex_bytes")]
    kernel_cmdline_sha384: Vec<u8>,
    /// QEMU-patched kernel Authenticode SHA-384.
    #[serde(with = "hex_bytes")]
    kernel_authenticode: Vec<u8>,
    /// Initrd SHA-384.
    #[serde(with = "hex_bytes")]
    initrd_sha384: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborTdxMrtdCandidates {
    #[serde(with = "hex_bytes")]
    single_pass: Vec<u8>,
    #[serde(with = "hex_bytes")]
    two_pass: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborTdxTdvfMeasurement {
    #[serde(rename = "ovmf")]
    ovmf_variant: OvmfVariant,
    mrtd: CborTdxMrtdCandidates,
    #[serde(rename = "td_hob", with = "hex_bytes")]
    td_hob_witness: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborTdxOsImageMeasurement {
    image: CborTdxImageMeasurement,
    tdvf: CborTdxTdvfMeasurement,
}

impl From<&TdxOsImageMeasurement> for CborTdxOsImageMeasurement {
    fn from(measurement: &TdxOsImageMeasurement) -> Self {
        Self {
            image: CborTdxImageMeasurement {
                kernel_cmdline_sha384: measurement.image.kernel_cmdline_sha384.clone(),
                kernel_authenticode: measurement.image.kernel_authenticode.clone(),
                initrd_sha384: measurement.image.initrd_sha384.clone(),
            },
            tdvf: CborTdxTdvfMeasurement {
                ovmf_variant: measurement.tdvf.ovmf_variant,
                mrtd: CborTdxMrtdCandidates {
                    single_pass: measurement.tdvf.mrtd.single_pass.clone(),
                    two_pass: measurement.tdvf.mrtd.two_pass.clone(),
                },
                td_hob_witness: measurement.tdvf.td_hob_witness.clone(),
            },
        }
    }
}

impl From<CborTdxOsImageMeasurement> for TdxOsImageMeasurement {
    fn from(measurement: CborTdxOsImageMeasurement) -> Self {
        Self {
            image: TdxImageMeasurement {
                kernel_cmdline_sha384: measurement.image.kernel_cmdline_sha384,
                kernel_authenticode: measurement.image.kernel_authenticode,
                initrd_sha384: measurement.image.initrd_sha384,
            },
            tdvf: TdxTdvfMeasurement {
                ovmf_variant: measurement.tdvf.ovmf_variant,
                mrtd: TdxMrtdCandidates {
                    single_pass: measurement.tdvf.mrtd.single_pass,
                    two_pass: measurement.tdvf.mrtd.two_pass,
                },
                td_hob_witness: measurement.tdvf.td_hob_witness,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TdxOsImageMeasurementDocument {
    /// Document schema version.
    #[serde(alias = "v")]
    pub version: u32,
    /// SHA-256 over the CBOR `measurement` bytes. This field is not included in
    /// its own hash input.
    #[serde(alias = "h")]
    pub os_image_hash: String,
    /// CBOR bytes for `TdxOsImageMeasurement`.
    #[serde(alias = "m", with = "hex_bytes")]
    pub measurement: Vec<u8>,
}

impl TdxOsImageMeasurement {
    /// CBOR representation used as the `os_image_hash` input.
    pub fn to_cbor_vec(&self) -> Vec<u8> {
        cbor_to_vec(
            &CborTdxOsImageMeasurement::from(self),
            "TdxOsImageMeasurement",
        )
    }

    pub fn from_cbor_slice(bytes: &[u8]) -> Result<Self, String> {
        let cbor = cbor_from_slice::<CborTdxOsImageMeasurement>(bytes, "TdxOsImageMeasurement")?;
        Ok(cbor.into())
    }

    pub fn cbor_json_value_from_slice(bytes: &[u8]) -> Result<serde_json::Value, String> {
        let cbor = cbor_from_slice::<CborTdxOsImageMeasurement>(bytes, "TdxOsImageMeasurement")?;
        serde_json::to_value(cbor)
            .map_err(|e| format!("TdxOsImageMeasurement: failed to convert CBOR to JSON: {e}"))
    }

    /// SHA-256 over the CBOR representation of this projection.
    pub fn os_image_hash(&self) -> [u8; 32] {
        sha256(&self.to_cbor_vec())
    }
}

impl TdxOsImageMeasurementDocument {
    pub const VERSION: u32 = 2;

    pub fn new(measurement: TdxOsImageMeasurement) -> Self {
        let measurement = measurement.to_cbor_vec();
        let os_image_hash = sha256_hex(&measurement);
        Self {
            version: Self::VERSION,
            os_image_hash,
            measurement,
        }
    }

    pub fn decode_measurement(&self) -> Result<TdxOsImageMeasurement, String> {
        TdxOsImageMeasurement::from_cbor_slice(&self.measurement)
    }

    pub fn decode_measurement_value(&self) -> Result<serde_json::Value, String> {
        TdxOsImageMeasurement::cbor_json_value_from_slice(&self.measurement)
    }

    pub fn measurement_os_image_hash(&self) -> [u8; 32] {
        sha256(&self.measurement)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsImageMeasurementDocument {
    /// Document schema version.
    #[serde(alias = "v")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx: Option<TdxOsImageMeasurementDocument>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snp: Option<SevOsImageMeasurementDocument>,
}

impl OsImageMeasurementDocument {
    pub const VERSION: u32 = 2;

    pub fn new(
        tdx: Option<TdxOsImageMeasurementDocument>,
        snp: Option<SevOsImageMeasurementDocument>,
    ) -> Self {
        Self {
            version: Self::VERSION,
            tdx,
            snp,
        }
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
