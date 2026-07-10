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

/// Records which TDX attestation/hash scheme the VMM resolved for this boot
/// (used by KMS's own key-release check and by the guest's fail-closed
/// `requirements.tdx_measure_acpi_tables` gate). It does not restrict what a
/// verifier can do: the guest's event log always retains the RTMR0 ACPI
/// digest events and `vm_config.tdx_measurement` is attached whenever the
/// image provides it, regardless of this flag, so any verifier can
/// independently pick `Legacy` or `Lite` verification for the same
/// attestation by supplying its own vm_config.
///
/// `Legacy` recomputes the full TDX launch measurement using the
/// image/QEMU-derived path (`vm_config.os_image_hash` is `digest.txt`, i.e.
/// `sha256(sha256sum.txt)`).
///
/// `Lite` recomputes measurements from `vm_config.tdx_measurement`
/// (`sha256sum.txt` plus the TDX measurement CBOR file) and the event log's
/// ACPI digests, without downloading the image or running QEMU. The
/// attestation quote remains the existing `DstackTdx` in both cases.
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
    #[serde(deserialize_with = "deserialize_manifest_version")]
    pub manifest_version: String,
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
    /// Development only. Disables TEE and storage encryption.
    #[serde(default)]
    pub no_tee: bool,
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
    /// Guest-side requirements enforced by guests that understand this field.
    ///
    /// Use manifest_version "3" (string) when setting this field so older
    /// guests, which only accept numeric manifest versions, fail closed instead
    /// of silently ignoring the requirements.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requirements: Option<Requirements>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Requirements {
    /// OS-version requirement parsed with Rust semver requirement semantics,
    /// e.g. `">=0.6.0"` or `">=0.6.0, <0.7.0"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Allowed attestation platforms. Omitted means any supported platform;
    /// an explicit empty list means no platform is allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<String>>,
    /// TDX-only ACPI table measurement requirement. When set, this overrides
    /// the VMM-side TDX lite attestation policy: `true` requires legacy mode
    /// with ACPI tables measured, while `false` requires lite mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_measure_acpi_tables: Option<bool>,
    /// Hex digest of the launch token carried in `user_config` at JSON path
    /// `dstack.launch_token`, computed as
    /// `sha256("dstack-launch-token/v1:" || token)` (see
    /// [`launch_token_hash`]). When set, guests fail closed before key
    /// provisioning unless the token hashes to this value; when absent,
    /// `user_config` is not parsed at all.
    ///
    /// This hash is public, so the token must not be guessable: guests reject
    /// tokens shorter than 32 bytes, and deployers should use a random token
    /// (e.g. 32 random alphanumeric characters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_token_hash: Option<String>,
    /// GPU TEE attestation requirement, defaults to `true` when omitted.
    ///
    /// On guests with an NVIDIA GPU attached, `true` means the guest runs
    /// local GPU attestation (nvattest) during system setup and refuses to
    /// boot — before key provisioning — if the GPU fails to attest (e.g. a
    /// non-CC GPU or CC mode disabled by the host). `false` skips attestation
    /// and sets the GPU ready state directly. Guests without a GPU attached
    /// are unaffected either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attest_gpu: Option<bool>,
}

impl Requirements {
    pub fn is_empty(&self) -> bool {
        self.os_version.is_none()
            && self.platforms.is_none()
            && self.tdx_measure_acpi_tables.is_none()
            && self.launch_token_hash.is_none()
            && self.attest_gpu.is_none()
    }
}

/// Domain-separation prefix for [`launch_token_hash`]. It keeps the digest
/// distinct from a plain `sha256(token)` (as used by the legacy app-layer
/// top-level `launch_token_hash` convention) and from generic precomputed
/// tables.
pub const LAUNCH_TOKEN_HASH_DOMAIN: &str = "dstack-launch-token/v1:";

/// Canonical `requirements.launch_token_hash` digest of a launch token:
/// `sha256("dstack-launch-token/v1:" || token)`.
///
/// Shell equivalent: `printf 'dstack-launch-token/v1:%s' "$TOKEN" | sha256sum`.
pub fn launch_token_hash(token: &str) -> [u8; 32] {
    let mut data = Vec::with_capacity(LAUNCH_TOKEN_HASH_DOMAIN.len() + token.len());
    data.extend_from_slice(LAUNCH_TOKEN_HASH_DOMAIN.as_bytes());
    data.extend_from_slice(token.as_bytes());
    sha256(&data)
}

fn deserialize_manifest_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct ManifestVersionVisitor;

    impl<'de> serde::de::Visitor<'de> for ManifestVersionVisitor {
        type Value = String;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a string manifest version, or legacy numeric 1/2")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            parse_manifest_version_string(value).map_err(E::custom)
        }

        fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            self.visit_str(&value)
        }

        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            match value {
                1 | 2 => Ok(value.to_string()),
                _ => Err(E::custom(
                    "numeric manifest_version is only supported for legacy versions 1 and 2; use a string for newer versions",
                )),
            }
        }

        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            let value = u64::try_from(value)
                .map_err(|_| E::custom("manifest_version must be a positive integer"))?;
            self.visit_u64(value)
        }
    }

    deserializer.deserialize_any(ManifestVersionVisitor)
}

fn parse_manifest_version_string(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("manifest_version must not be empty".to_string());
    }
    let parsed = value.parse::<u32>().map_err(|_| {
        format!("manifest_version must be a positive integer string, got {value:?}")
    })?;
    if parsed == 0 {
        return Err("manifest_version must be greater than 0".to_string());
    }
    if parsed.to_string() != value {
        return Err(format!(
            "manifest_version must be a canonical integer string, got {value:?}"
        ));
    }
    Ok(parsed.to_string())
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
    pub fn manifest_version_u32(&self) -> Option<u32> {
        self.manifest_version.parse().ok()
    }

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

    /// Whether an attached GPU must pass local TEE attestation before the
    /// guest continues booting. Defaults to `true` when
    /// `requirements.attest_gpu` is omitted.
    ///
    /// `requirements` are only valid on manifest_version >= 3 (guests reject
    /// older manifests carrying them); the opt-out is additionally ignored on
    /// legacy manifests here so a caller that skipped that validation still
    /// fails closed.
    pub fn attest_gpu(&self) -> bool {
        if !matches!(self.manifest_version_u32(), Some(v) if v >= 3) {
            return true;
        }
        self.requirements
            .as_ref()
            .and_then(|r| r.attest_gpu)
            .unwrap_or(true)
    }
}

#[cfg(test)]
mod app_compose_tests {
    use super::*;

    fn parse_compose(manifest_version: serde_json::Value) -> serde_json::Result<AppCompose> {
        serde_json::from_value(serde_json::json!({
            "manifest_version": manifest_version,
            "name": "test",
            "runner": "docker-compose"
        }))
    }

    #[test]
    fn manifest_version_accepts_string_versions() {
        let compose = parse_compose(serde_json::json!("3")).unwrap();
        assert_eq!(compose.manifest_version, "3");
        assert_eq!(compose.manifest_version_u32(), Some(3));
    }

    #[test]
    fn manifest_version_accepts_legacy_numeric_1_and_2() {
        assert_eq!(
            parse_compose(serde_json::json!(1))
                .unwrap()
                .manifest_version,
            "1"
        );
        assert_eq!(
            parse_compose(serde_json::json!(2))
                .unwrap()
                .manifest_version,
            "2"
        );
    }

    #[test]
    fn manifest_version_rejects_new_numeric_versions() {
        let err = parse_compose(serde_json::json!(3)).unwrap_err();
        assert!(err.to_string().contains("legacy versions 1 and 2"));
    }

    #[test]
    fn manifest_version_rejects_invalid_numeric_values() {
        let err = parse_compose(serde_json::json!(0)).unwrap_err();
        assert!(err.to_string().contains("legacy versions 1 and 2"));
        let err = parse_compose(serde_json::json!(-1)).unwrap_err();
        assert!(err.to_string().contains("positive integer"));
        assert!(parse_compose(serde_json::json!(2.5)).is_err());
    }

    #[test]
    fn manifest_version_rejects_non_canonical_strings() {
        let err = parse_compose(serde_json::json!("0")).unwrap_err();
        assert!(err.to_string().contains("greater than 0"));
        let err = parse_compose(serde_json::json!("03")).unwrap_err();
        assert!(err.to_string().contains("canonical integer string"));
        let err = parse_compose(serde_json::json!("+3")).unwrap_err();
        assert!(err.to_string().contains("canonical integer string"));
        let err = parse_compose(serde_json::json!("")).unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
        assert!(parse_compose(serde_json::json!("3.0")).is_err());
    }

    #[test]
    fn requirements_support_os_version_and_platforms() {
        let compose: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "os_version": ">=0.6.1",
                "platforms": ["dstack-gcp-tdx", "dstack-tdx"],
                "tdx_measure_acpi_tables": true,
                "launch_token_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            }
        }))
        .unwrap();
        let requirements = compose.requirements.as_ref().unwrap();
        assert_eq!(requirements.os_version.as_deref(), Some(">=0.6.1"));
        assert_eq!(
            requirements.platforms,
            Some(vec!["dstack-gcp-tdx".to_string(), "dstack-tdx".to_string()])
        );
        assert_eq!(requirements.tdx_measure_acpi_tables, Some(true));
        assert_eq!(
            requirements.launch_token_hash.as_deref(),
            Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );

        let err = serde_json::from_value::<AppCompose>(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "os_version_policy": ">=0.6.1"
            }
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn requirements_distinguish_omitted_and_empty_platforms() {
        let omitted: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {}
        }))
        .unwrap();
        let requirements = omitted.requirements.as_ref().unwrap();
        assert_eq!(requirements.platforms, None);
        assert!(requirements.is_empty());

        let explicit_empty: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "platforms": []
            }
        }))
        .unwrap();
        let requirements = explicit_empty.requirements.as_ref().unwrap();
        assert_eq!(requirements.platforms, Some(vec![]));
        assert!(!requirements.is_empty());

        let acpi_tables: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "tdx_measure_acpi_tables": false
            }
        }))
        .unwrap();
        let requirements = acpi_tables.requirements.as_ref().unwrap();
        assert_eq!(requirements.tdx_measure_acpi_tables, Some(false));
        assert!(!requirements.is_empty());

        let launch_token: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "launch_token_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
            }
        }))
        .unwrap();
        let requirements = launch_token.requirements.as_ref().unwrap();
        assert!(requirements.launch_token_hash.is_some());
        assert!(!requirements.is_empty());
    }

    #[test]
    fn attest_gpu_defaults_to_true() {
        let no_requirements: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose"
        }))
        .unwrap();
        assert!(no_requirements.attest_gpu());

        let omitted: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {}
        }))
        .unwrap();
        assert!(omitted.attest_gpu());
        assert!(omitted.requirements.as_ref().unwrap().is_empty());

        let disabled: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "attest_gpu": false
            }
        }))
        .unwrap();
        assert!(!disabled.attest_gpu());
        let requirements = disabled.requirements.as_ref().unwrap();
        assert_eq!(requirements.attest_gpu, Some(false));
        assert!(!requirements.is_empty());

        // The opt-out is ignored on legacy manifests (requirements are only
        // valid on manifest_version >= 3; guests reject such composes anyway).
        let legacy_optout: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "attest_gpu": false
            }
        }))
        .unwrap();
        assert!(legacy_optout.attest_gpu());
    }

    #[test]
    fn launch_token_hash_is_domain_separated() {
        assert_eq!(
            hex::encode(launch_token_hash("unit-test-launch-token-0000000001")),
            "28faa1319055d733ad9651f5ab7689c15b04609846bcd27b3c5bc8df6246f5a3"
        );
        // Not a plain sha256 of the token (the legacy app-layer convention).
        use sha2::{Digest, Sha256};
        assert_ne!(
            launch_token_hash("unit-test-launch-token-0000000001").to_vec(),
            Sha256::digest("unit-test-launch-token-0000000001".as_bytes()).to_vec()
        );
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
    /// TDX-only no-image-download measurement material. Attached whenever
    /// the OS image provides it, regardless of `tdx_attestation_variant`, so
    /// a verifier can choose lite verification even for a boot that resolved
    /// to `Legacy`. Omitted only when the image predates this measurement
    /// material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_measurement: Option<TdxOsImageMeasurementDocument>,
    /// GCP TDX no-image-download measurement material. Present for GCP
    /// deployments so `os_image_hash` can remain the unified image digest
    /// (`sha256(sha256sum.txt)`) while the verifier still binds the TPM UKI
    /// Authenticode event to that digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_measurement: Option<GcpOsImageMeasurementDocument>,
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

pub const TDX_MEASUREMENT_FILENAME: &str = "measurement.tdx.cbor";
pub const SNP_MEASUREMENT_FILENAME: &str = "measurement.snp.cbor";
pub const GCP_MEASUREMENT_FILENAME: &str = "measurement.gcp.cbor";

pub fn image_hash_from_sha256sum(checksum_file: &[u8]) -> [u8; 32] {
    sha256(checksum_file)
}

pub fn sha256sum_entry_hash(checksum_file: &[u8], filename: &str) -> Result<[u8; 32], String> {
    let text = std::str::from_utf8(checksum_file)
        .map_err(|e| format!("sha256sum.txt is not valid UTF-8: {e}"))?;
    let mut found = None;
    for (line_no, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(hash_hex) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else {
            return Err(format!(
                "sha256sum.txt line {} is missing filename",
                line_no + 1
            ));
        };
        if path != filename {
            continue;
        }
        if found.is_some() {
            return Err(format!(
                "sha256sum.txt contains duplicate {filename} entries"
            ));
        }
        let hash = hex::decode(hash_hex)
            .map_err(|e| format!("sha256sum.txt {filename} hash is not valid hex: {e}"))?;
        let hash: [u8; 32] = hash.try_into().map_err(|hash: Vec<u8>| {
            format!(
                "sha256sum.txt {filename} hash has invalid length {}, expected 32",
                hash.len()
            )
        })?;
        found = Some(hash);
    }
    found.ok_or_else(|| format!("sha256sum.txt is missing {filename}"))
}

pub fn verify_measurement_material(
    os_image_hash: &[u8],
    checksum_file: &[u8],
    measurement: &[u8],
    filename: &str,
) -> Result<(), String> {
    if image_hash_from_sha256sum(checksum_file).as_slice() != os_image_hash {
        return Err(format!(
            "os_image_hash mismatch: expected sha256(sha256sum.txt)={}, actual={}",
            hex::encode(os_image_hash),
            hex::encode(image_hash_from_sha256sum(checksum_file))
        ));
    }
    let expected_measurement_hash = sha256sum_entry_hash(checksum_file, filename)?;
    let actual_measurement_hash = sha256(measurement);
    if expected_measurement_hash != actual_measurement_hash {
        return Err(format!(
            "{filename} hash mismatch: sha256sum.txt={}, actual={}",
            hex::encode(expected_measurement_hash),
            hex::encode(actual_measurement_hash)
        ));
    }
    Ok(())
}

/// Image-invariant GCP TDX measurement material. GCP's TPM event log measures
/// the UKI as a PE/COFF Authenticode SHA-256 digest. The unified image identity
/// remains `sha256(sha256sum.txt)`; this material is bound to that identity by
/// the `measurement.gcp.cbor` entry in `sha256sum.txt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpOsImageMeasurement {
    #[serde(with = "hex_bytes")]
    pub uki_authenticode_sha256: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CborGcpOsImageMeasurement {
    version: u32,
    #[serde(rename = "uki_auth", with = "hex_bytes")]
    uki_authenticode_sha256: Vec<u8>,
}

impl From<&GcpOsImageMeasurement> for CborGcpOsImageMeasurement {
    fn from(measurement: &GcpOsImageMeasurement) -> Self {
        Self {
            version: GcpOsImageMeasurement::VERSION,
            uki_authenticode_sha256: measurement.uki_authenticode_sha256.clone(),
        }
    }
}

impl From<CborGcpOsImageMeasurement> for GcpOsImageMeasurement {
    fn from(measurement: CborGcpOsImageMeasurement) -> Self {
        Self {
            uki_authenticode_sha256: measurement.uki_authenticode_sha256,
        }
    }
}

impl GcpOsImageMeasurement {
    pub const VERSION: u32 = 1;
    pub const UKI_AUTHENTICODE_SHA256_LEN: usize = 32;

    pub fn new(uki_authenticode_sha256: Vec<u8>) -> Result<Self, String> {
        if uki_authenticode_sha256.len() != Self::UKI_AUTHENTICODE_SHA256_LEN {
            return Err(format!(
                "GcpOsImageMeasurement: UKI Authenticode hash has invalid length {}, expected {}",
                uki_authenticode_sha256.len(),
                Self::UKI_AUTHENTICODE_SHA256_LEN
            ));
        }
        Ok(Self {
            uki_authenticode_sha256,
        })
    }

    pub fn to_cbor_vec(&self) -> Vec<u8> {
        cbor_to_vec(
            &CborGcpOsImageMeasurement::from(self),
            "GcpOsImageMeasurement",
        )
    }

    pub fn from_cbor_slice(bytes: &[u8]) -> Result<Self, String> {
        let measurement: CborGcpOsImageMeasurement =
            cbor_from_slice(bytes, "GcpOsImageMeasurement")?;
        if measurement.version != Self::VERSION {
            return Err(format!(
                "GcpOsImageMeasurement unsupported version {}, expected {}",
                measurement.version,
                Self::VERSION
            ));
        }
        Self::new(measurement.uki_authenticode_sha256)
    }

    pub fn cbor_json_value_from_slice(bytes: &[u8]) -> Result<serde_json::Value, String> {
        let measurement: CborGcpOsImageMeasurement =
            cbor_from_slice(bytes, "GcpOsImageMeasurement")?;
        serde_json::to_value(measurement)
            .map_err(|e| format!("GcpOsImageMeasurement: failed to convert to JSON: {e}"))
    }

    pub fn measurement_hash(&self) -> [u8; 32] {
        sha256(&self.to_cbor_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GcpOsImageMeasurementDocument {
    /// Raw checksum file bytes (`sha256sum.txt`). `sha256(checksum_file)` is
    /// the unified `os_image_hash`.
    #[serde(with = "serde_human_bytes::base64")]
    pub checksum_file: Vec<u8>,
    /// Raw bytes of `measurement.gcp.cbor`.
    #[serde(with = "serde_human_bytes::base64")]
    pub measurement: Vec<u8>,
}

impl GcpOsImageMeasurementDocument {
    pub fn new(checksum_file: Vec<u8>, measurement: Vec<u8>) -> Self {
        Self {
            checksum_file,
            measurement,
        }
    }

    pub fn from_measurement(checksum_file: Vec<u8>, measurement: GcpOsImageMeasurement) -> Self {
        Self::new(checksum_file, measurement.to_cbor_vec())
    }

    pub fn decode_measurement(&self) -> Result<GcpOsImageMeasurement, String> {
        GcpOsImageMeasurement::from_cbor_slice(&self.measurement)
    }

    pub fn decode_measurement_value(&self) -> Result<serde_json::Value, String> {
        GcpOsImageMeasurement::cbor_json_value_from_slice(&self.measurement)
    }

    pub fn verify(&self, os_image_hash: &[u8]) -> Result<(), String> {
        verify_measurement_material(
            os_image_hash,
            &self.checksum_file,
            &self.measurement,
            GCP_MEASUREMENT_FILENAME,
        )
    }
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

/// Image-invariant AMD SEV-SNP measurement material. It deliberately excludes
/// per-deployment values (vcpus, vcpu_type, guest_features, app_id,
/// compose_hash): the same OS image carries identical SNP material regardless of
/// how it is launched. The OS image identity itself is always
/// `sha256(sha256sum.txt)`; this material is bound to that identity by the
/// `measurement.snp.cbor` entry in `sha256sum.txt`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevOsImageMeasurement {
    /// Original image kernel cmdline used for SNP measured launch.
    pub base_cmdline: String,
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
    version: u32,
    /// Original image kernel cmdline used for SNP measured launch.
    #[serde(rename = "cmdline")]
    base_cmdline: String,
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
            version: SevOsImageMeasurement::VERSION,
            base_cmdline: measurement.base_cmdline.clone(),
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
            base_cmdline: measurement.base_cmdline,
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
    pub const VERSION: u32 = 3;

    /// CBOR representation stored as `measurement.snp.cbor`.
    pub fn to_cbor_vec(&self) -> Vec<u8> {
        cbor_to_vec(
            &CborSevOsImageMeasurement::from(self),
            "SevOsImageMeasurement",
        )
    }

    pub fn from_cbor_slice(bytes: &[u8]) -> Result<Self, String> {
        let cbor = cbor_from_slice::<CborSevOsImageMeasurement>(bytes, "SevOsImageMeasurement")?;
        if cbor.version != Self::VERSION {
            return Err(format!(
                "SevOsImageMeasurement: unsupported version {}, expected {}",
                cbor.version,
                Self::VERSION
            ));
        }
        Ok(cbor.into())
    }

    pub fn cbor_json_value_from_slice(bytes: &[u8]) -> Result<serde_json::Value, String> {
        let cbor = cbor_from_slice::<CborSevOsImageMeasurement>(bytes, "SevOsImageMeasurement")?;
        serde_json::to_value(cbor)
            .map_err(|e| format!("SevOsImageMeasurement: failed to convert CBOR to JSON: {e}"))
    }

    /// SHA-256 over the CBOR measurement material.
    pub fn measurement_hash(&self) -> [u8; 32] {
        sha256(&self.to_cbor_vec())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevOsImageMeasurementDocument {
    /// Raw checksum file bytes (`sha256sum.txt`). `sha256(checksum_file)` is
    /// the unified `os_image_hash`.
    #[serde(with = "serde_human_bytes::base64")]
    pub checksum_file: Vec<u8>,
    /// Raw bytes of `measurement.snp.cbor`.
    #[serde(with = "serde_human_bytes::base64")]
    pub measurement: Vec<u8>,
}

impl SevOsImageMeasurementDocument {
    pub fn new(checksum_file: Vec<u8>, measurement: Vec<u8>) -> Self {
        Self {
            checksum_file,
            measurement,
        }
    }

    pub fn from_measurement(checksum_file: Vec<u8>, measurement: SevOsImageMeasurement) -> Self {
        Self::new(checksum_file, measurement.to_cbor_vec())
    }

    pub fn decode_measurement(&self) -> Result<SevOsImageMeasurement, String> {
        SevOsImageMeasurement::from_cbor_slice(&self.measurement)
    }

    pub fn decode_measurement_value(&self) -> Result<serde_json::Value, String> {
        SevOsImageMeasurement::cbor_json_value_from_slice(&self.measurement)
    }

    pub fn verify(&self, os_image_hash: &[u8]) -> Result<(), String> {
        verify_measurement_material(
            os_image_hash,
            &self.checksum_file,
            &self.measurement,
            SNP_MEASUREMENT_FILENAME,
        )
    }
}

/// Image-invariant TDX measurement material for the verifier-side
/// no-image-download TDX path. Dynamic VM parameters (vCPU count, RAM size,
/// QEMU PCI topology, GPU count, etc.) are deliberately excluded and must be
/// supplied by `VmConfig` when replaying RTMRs. The OS image identity itself is
/// always `sha256(sha256sum.txt)`; this material is bound to that identity by
/// the `measurement.tdx.cbor` entry in `sha256sum.txt`.
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
    version: u32,
    image: CborTdxImageMeasurement,
    tdvf: CborTdxTdvfMeasurement,
}

impl From<&TdxOsImageMeasurement> for CborTdxOsImageMeasurement {
    fn from(measurement: &TdxOsImageMeasurement) -> Self {
        Self {
            version: TdxOsImageMeasurement::VERSION,
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
    /// Raw checksum file bytes (`sha256sum.txt`). `sha256(checksum_file)` is
    /// the unified `os_image_hash`.
    #[serde(with = "serde_human_bytes::base64")]
    pub checksum_file: Vec<u8>,
    /// Raw bytes of `measurement.tdx.cbor`.
    #[serde(with = "serde_human_bytes::base64")]
    pub measurement: Vec<u8>,
}

impl TdxOsImageMeasurement {
    pub const VERSION: u32 = 3;

    /// CBOR representation stored as `measurement.tdx.cbor`.
    pub fn to_cbor_vec(&self) -> Vec<u8> {
        cbor_to_vec(
            &CborTdxOsImageMeasurement::from(self),
            "TdxOsImageMeasurement",
        )
    }

    pub fn from_cbor_slice(bytes: &[u8]) -> Result<Self, String> {
        let cbor = cbor_from_slice::<CborTdxOsImageMeasurement>(bytes, "TdxOsImageMeasurement")?;
        if cbor.version != Self::VERSION {
            return Err(format!(
                "TdxOsImageMeasurement: unsupported version {}, expected {}",
                cbor.version,
                Self::VERSION
            ));
        }
        Ok(cbor.into())
    }

    pub fn cbor_json_value_from_slice(bytes: &[u8]) -> Result<serde_json::Value, String> {
        let cbor = cbor_from_slice::<CborTdxOsImageMeasurement>(bytes, "TdxOsImageMeasurement")?;
        serde_json::to_value(cbor)
            .map_err(|e| format!("TdxOsImageMeasurement: failed to convert CBOR to JSON: {e}"))
    }

    /// SHA-256 over the CBOR measurement material.
    pub fn measurement_hash(&self) -> [u8; 32] {
        sha256(&self.to_cbor_vec())
    }
}

impl TdxOsImageMeasurementDocument {
    pub fn new(checksum_file: Vec<u8>, measurement: Vec<u8>) -> Self {
        Self {
            checksum_file,
            measurement,
        }
    }

    pub fn from_measurement(checksum_file: Vec<u8>, measurement: TdxOsImageMeasurement) -> Self {
        Self::new(checksum_file, measurement.to_cbor_vec())
    }

    pub fn decode_measurement(&self) -> Result<TdxOsImageMeasurement, String> {
        TdxOsImageMeasurement::from_cbor_slice(&self.measurement)
    }

    pub fn decode_measurement_value(&self) -> Result<serde_json::Value, String> {
        TdxOsImageMeasurement::cbor_json_value_from_slice(&self.measurement)
    }

    pub fn verify(&self, os_image_hash: &[u8]) -> Result<(), String> {
        verify_measurement_material(
            os_image_hash,
            &self.checksum_file,
            &self.measurement,
            TDX_MEASUREMENT_FILENAME,
        )
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp: Option<GcpOsImageMeasurementDocument>,
}

impl OsImageMeasurementDocument {
    pub const VERSION: u32 = 3;

    pub fn new(
        tdx: Option<TdxOsImageMeasurementDocument>,
        snp: Option<SevOsImageMeasurementDocument>,
        gcp: Option<GcpOsImageMeasurementDocument>,
    ) -> Self {
        Self {
            version: Self::VERSION,
            tdx,
            snp,
            gcp,
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

    /// Stable key-provider identity used for launch measurement and compose pins.
    ///
    /// - KMS: root CA public key
    /// - Local: sealing-provider MR
    /// - TPM: always empty — the derived app root pubkey is instance-specific
    ///   (from a TPM-sealed seed) and must not be treated as a stable provider id
    ///   or measured as one. Mode is already carried by [`Self::kind`].
    /// - None: empty
    pub fn id(&self) -> &[u8] {
        match self {
            KeyProvider::None { .. } => &[],
            KeyProvider::Local { mr, .. } => mr,
            KeyProvider::Tpm { .. } => &[],
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

#[cfg(test)]
mod key_provider_tests {
    use super::*;

    #[test]
    fn tpm_key_provider_id_is_empty() {
        let tpm = KeyProvider::Tpm {
            key: "dummy".into(),
            // Instance app-root pubkey may still be stored on the key handle, but
            // it must not be reported as the stable provider id.
            pubkey: vec![0x04; 65],
        };
        assert!(tpm.id().is_empty());
        assert_eq!(tpm.kind(), KeyProviderKind::Tpm);

        let kms = KeyProvider::Kms {
            url: "https://kms.example".into(),
            pubkey: vec![0xab; 32],
            tmp_ca_key: String::new(),
            tmp_ca_cert: String::new(),
        };
        assert_eq!(kms.id(), &[0xab; 32]);
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
