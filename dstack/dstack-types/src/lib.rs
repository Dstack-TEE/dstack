// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{io::Cursor, path::Path};

use or_panic::ResultOrPanic;
use scale::{Decode, Encode};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use size_parser::human_size;

/// Bound event-log growth and MrConfigV3 size while supporting independent
/// infrastructure-provider initialization stages.
pub const MAX_INIT_SCRIPTS: usize = 5;

pub mod init_script_hashes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_human_bytes::ByteBuf;

    pub fn serialize<S>(values: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        values
            .iter()
            .cloned()
            .map(ByteBuf::from)
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<ByteBuf>::deserialize(deserializer)?;
        if values.len() > super::MAX_INIT_SCRIPTS {
            return Err(serde::de::Error::custom(format!(
                "init_script_hashes supports at most {} hashes",
                super::MAX_INIT_SCRIPTS
            )));
        }
        if values.iter().any(|value| value.len() != 32) {
            return Err(serde::de::Error::custom(
                "each init_script_hash must be 32 bytes",
            ));
        }
        Ok(values.into_iter().map(ByteBuf::into_vec).collect())
    }

    pub mod option {
        use serde::{Deserialize, Deserializer, Serialize, Serializer};
        use serde_human_bytes::ByteBuf;

        pub fn serialize<S>(values: &Option<Vec<Vec<u8>>>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            values
                .as_ref()
                .map(|values| {
                    values
                        .iter()
                        .cloned()
                        .map(ByteBuf::from)
                        .collect::<Vec<_>>()
                })
                .serialize(serializer)
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<Vec<u8>>>, D::Error>
        where
            D: Deserializer<'de>,
        {
            Option::<Vec<ByteBuf>>::deserialize(deserializer)?
                .map(|values| {
                    if values.len() > super::super::MAX_INIT_SCRIPTS {
                        return Err(serde::de::Error::custom(format!(
                            "init_script_hashes supports at most {} hashes",
                            super::super::MAX_INIT_SCRIPTS
                        )));
                    }
                    if values.iter().any(|value| value.len() != 32) {
                        return Err(serde::de::Error::custom(
                            "each init_script_hash must be 32 bytes",
                        ));
                    }
                    Ok(values.into_iter().map(ByteBuf::into_vec).collect())
                })
                .transpose()
        }
    }
}

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

/// Event log version controlling the digest format.
///
/// Using an enum ensures exhaustive matching — adding a new version
/// forces all match sites to be updated.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventLogVersion {
    /// Legacy binary digest: `SHA384(event_type_le || ":" || name || ":" || payload)`
    #[default]
    V1,
    /// JSON canonical digest (JCS RFC 8785), hashed as canonical JSON bytes:
    /// `SHA384({"name":"...","payload":"hex...","type":134217729})`
    V2,
}

impl EventLogVersion {
    pub fn is_v1(&self) -> bool {
        matches!(self, Self::V1)
    }

    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(EventLogVersion::V1),
            2 => Some(EventLogVersion::V2),
            _ => None,
        }
    }
}

impl Serialize for EventLogVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            EventLogVersion::V1 => serializer.serialize_u32(1),
            EventLogVersion::V2 => serializer.serialize_u32(2),
        }
    }
}

impl<'de> Deserialize<'de> for EventLogVersion {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(deserializer)?;
        EventLogVersion::from_u32(v)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown event log version: {v}")))
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
    /// containerd snapshotter used by the `nerdctl-compose` runner.
    /// The field is invalid for other runners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshotter: Option<ContainerSnapshotter>,
    #[serde(default)]
    pub docker_compose_file: Option<String>,
    /// Bash scripts executed before the application runner starts.
    ///
    /// A single string is accepted for backward compatibility and is treated
    /// as a one-element list.
    #[serde(
        default,
        deserialize_with = "deserialize_init_scripts",
        serialize_with = "serialize_init_scripts",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub init_script: Vec<String>,
    #[serde(default)]
    pub public_logs: bool,
    #[serde(default)]
    pub public_sysinfo: bool,
    #[serde(default = "default_true")]
    pub public_tcbinfo: bool,
    #[serde(default)]
    pub kms_enabled: bool,
    #[serde(
        deserialize_with = "deserialize_gateway_enabled",
        serialize_with = "serialize_gateway_enabled",
        flatten
    )]
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
    #[serde(default, skip_serializing_if = "EventLogVersion::is_v1")]
    pub event_log_version: EventLogVersion,
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
    /// Read-only, dm-verity-protected volumes pre-seeded into the CVM. Each
    /// `verity_root` is measured (it is part of these compose bytes), so the
    /// guest only mounts content matching the attested app. See
    /// docs/verity-volumes.md.
    #[serde(default)]
    pub verity_volumes: Vec<VerityVolume>,
}

fn deserialize_init_scripts<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum InitScripts {
        One(String),
        Many(Vec<String>),
    }

    let scripts = match Option::<InitScripts>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(InitScripts::One(script)) => vec![script],
        Some(InitScripts::Many(scripts)) => scripts,
    };
    if scripts.len() > MAX_INIT_SCRIPTS {
        return Err(serde::de::Error::custom(format!(
            "init_script supports at most {MAX_INIT_SCRIPTS} scripts"
        )));
    }
    Ok(scripts)
}

fn serialize_init_scripts<S>(scripts: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if let [script] = scripts {
        serializer.serialize_str(script)
    } else {
        scripts.serialize(serializer)
    }
}

/// A pre-baked, read-only dm-verity volume attached to the CVM.
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VerityVolume {
    /// Bare image file name resolved by the VMM under `cvm.volumes_dir`.
    pub source: String,
    /// dm-verity root hash (hex): the volume's content identity and integrity
    /// check. The guest matches attached devices against it.
    #[serde(with = "hex_bytes")]
    pub verity_root: [u8; 32],
    /// Absolute path where the volume's filesystem is mounted.
    #[serde(deserialize_with = "deserialize_absolute_path")]
    pub target: std::path::PathBuf,
}

/// Reject ambiguous mount declarations before any disk is attached or
/// activated. The same root may intentionally be mounted at multiple targets,
/// but a target can only be owned by one volume.
pub fn validate_verity_volumes(volumes: &[VerityVolume]) -> Result<(), String> {
    let mut targets = std::collections::HashSet::new();
    for volume in volumes {
        if !targets.insert(&volume.target) {
            return Err(format!(
                "duplicate verity volume target {}",
                volume.target.display()
            ));
        }
    }
    Ok(())
}

fn deserialize_absolute_path<'de, D>(deserializer: D) -> Result<std::path::PathBuf, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    let path = std::path::PathBuf::from(&value);
    if !path.is_absolute() {
        return Err(serde::de::Error::custom(format!(
            "volume target must be an absolute path, got '{value}'"
        )));
    }
    Ok(path)
}

#[cfg(test)]
mod verity_volume_tests {
    use super::{validate_verity_volumes, VerityVolume};

    fn volume(root: u8, target: &str) -> VerityVolume {
        VerityVolume {
            source: format!("{root}.img"),
            verity_root: [root; 32],
            target: target.into(),
        }
    }

    #[test]
    fn allows_duplicate_roots_but_rejects_duplicate_targets() {
        validate_verity_volumes(&[volume(1, "/a"), volume(1, "/b")]).unwrap();
        assert!(validate_verity_volumes(&[volume(1, "/a"), volume(2, "/a")])
            .unwrap_err()
            .contains("duplicate verity volume target"));
        validate_verity_volumes(&[volume(1, "/a"), volume(2, "/b")]).unwrap();
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ContainerSnapshotter {
    Overlayfs,
    Stargz,
}

/// Canonical source for the policy used when `requirements.gpu_policy` is
/// absent. Both typed defaults and measurement are derived from this JSON.
pub const DEFAULT_GPU_POLICY: &str = "{}";

/// Path containing the complete output of the NVIDIA GPU attestation command.
pub const GPU_ATTESTATION_OUTPUT: &str = "/run/nvidia-gpu-attestation/attestation.out";

/// Computes the SHA-256 digest of the JCS-canonicalized raw
/// `requirements.gpu_policy` JSON value. An absent policy is equivalent to
/// the default empty object.
pub fn gpu_policy_hash(compose_json: &[u8]) -> Result<[u8; 32], serde_json::Error> {
    use sha2::{Digest, Sha256};

    let compose: serde_json::Value = serde_json::from_slice(compose_json)?;
    let default_policy: serde_json::Value = serde_json::from_str(DEFAULT_GPU_POLICY)?;
    let policy = compose
        .pointer("/requirements/gpu_policy")
        .unwrap_or(&default_policy);
    let canonical = serde_jcs::to_vec(policy)?;
    Ok(Sha256::digest(canonical).into())
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GpuPolicy {
    /// Whether an attached GPU must pass local TEE attestation before the
    /// guest continues booting. Defaults to true.
    #[serde(default = "default_true")]
    pub attest_gpu: bool,
    /// Optional Rego v0 policy evaluated against NVIDIA nvattest's `claims`
    /// array. It must define the boolean rule `data.policy.nv_match`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rego: Option<String>,
    /// Permit NVIDIA DevTools mode. This defaults to false because DevTools
    /// disables the GPU memory-confidentiality guarantees expected in
    /// production.
    #[serde(default)]
    pub allow_devtools: bool,
    /// Permit claims whose GPU attestation debug status is `enabled`. Defaults
    /// to false.
    #[serde(default)]
    pub allow_debug: bool,
    /// Permit claims that do not assert GPU secure boot. Defaults to false.
    #[serde(default)]
    pub allow_insecure_boot: bool,
}

impl Default for GpuPolicy {
    fn default() -> Self {
        serde_json::from_str(DEFAULT_GPU_POLICY)
            .or_panic("DEFAULT_GPU_POLICY must be a valid GPU policy")
    }
}

impl GpuPolicy {
    /// Returns true when no application-specific GPU policy setting is set.
    pub fn is_default(&self) -> bool {
        self == &Self::default()
    }
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
    /// Application GPU policy applied before key provisioning. An omitted
    /// field is parsed and measured as the default empty policy `{}`.
    ///
    /// Its original JSON value is JCS-canonicalized and its SHA-256 digest is
    /// emitted as the `gpu-policy-hash` launch event immediately after
    /// `compose-hash`. When the field is absent, `{}` is measured. An explicitly
    /// present default-valued field remains part of the raw measurement.
    /// Rego receives an empty claims array when no GPU attestation is produced,
    /// allowing applications to enforce an expected GPU count.
    #[serde(default, skip_serializing_if = "GpuPolicy::is_default")]
    pub gpu_policy: GpuPolicy,
}

impl Requirements {
    pub fn is_empty(&self) -> bool {
        self.os_version.is_none()
            && self.platforms.is_none()
            && self.tdx_measure_acpi_tables.is_none()
            && self.launch_token_hash.is_none()
            && self.gpu_policy.is_default()
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

fn serialize_gateway_enabled<S>(enabled: &bool, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    #[derive(Serialize)]
    struct GatewayEnabled {
        gateway_enabled: bool,
    }

    GatewayEnabled {
        gateway_enabled: *enabled,
    }
    .serialize(serializer)
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
    fn init_script_accepts_string_array_and_null() {
        assert!(parse_compose(serde_json::json!(2))
            .unwrap()
            .init_script
            .is_empty());

        let single: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose",
            "init_script": "echo one"
        }))
        .unwrap();
        assert_eq!(single.init_script, ["echo one"]);
        assert_eq!(
            serde_json::to_value(&single).unwrap()["init_script"],
            "echo one"
        );

        let multiple: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose",
            "init_script": ["echo one", "echo two"]
        }))
        .unwrap();
        assert_eq!(multiple.init_script, ["echo one", "echo two"]);
        assert_eq!(
            serde_json::to_value(&multiple).unwrap()["init_script"],
            serde_json::json!(["echo one", "echo two"])
        );

        let null: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose",
            "init_script": null
        }))
        .unwrap();
        assert!(null.init_script.is_empty());
        assert!(serde_json::to_value(&null)
            .unwrap()
            .get("init_script")
            .is_none());

        assert!(serde_json::from_value::<AppCompose>(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose",
            "init_script": ["echo one", 2]
        }))
        .is_err());

        assert!(serde_json::from_value::<AppCompose>(serde_json::json!({
            "manifest_version": 2,
            "name": "test",
            "runner": "docker-compose",
            "init_script": ["1", "2", "3", "4", "5", "6"]
        }))
        .unwrap_err()
        .to_string()
        .contains("at most 5"));
    }

    #[test]
    fn manifest_version_accepts_string_versions() {
        let compose = parse_compose(serde_json::json!("3")).unwrap();
        assert_eq!(compose.manifest_version, "3");
        assert_eq!(compose.manifest_version_u32(), Some(3));
    }

    #[test]
    fn event_log_v1_is_omitted_but_v2_is_serialized() {
        #[derive(Serialize)]
        struct VersionField {
            #[serde(skip_serializing_if = "EventLogVersion::is_v1")]
            event_log_version: EventLogVersion,
        }

        let v1 = serde_json::to_value(VersionField {
            event_log_version: EventLogVersion::V1,
        })
        .unwrap();
        assert!(v1.get("event_log_version").is_none());

        let v2 = serde_json::to_value(VersionField {
            event_log_version: EventLogVersion::V2,
        })
        .unwrap();
        assert_eq!(v2["event_log_version"], 2);
    }

    #[test]
    fn parses_supported_container_snapshotters() {
        let compose: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "nerdctl-compose",
            "snapshotter": "stargz"
        }))
        .unwrap();
        assert_eq!(compose.snapshotter, Some(ContainerSnapshotter::Stargz));

        let invalid = serde_json::from_value::<AppCompose>(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "nerdctl-compose",
            "snapshotter": "unknown"
        }));
        assert!(invalid.is_err());
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
                "launch_token_hash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "gpu_policy": {
                    "rego": "package policy\n\ndefault nv_match = false\n",
                    "allow_devtools": true,
                    "allow_debug": true,
                    "allow_insecure_boot": true
                }
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
        let gpu_policy = &requirements.gpu_policy;
        assert!(gpu_policy.attest_gpu);
        assert_eq!(
            gpu_policy.rego.as_deref(),
            Some("package policy\n\ndefault nv_match = false\n")
        );
        assert!(gpu_policy.allow_devtools);
        assert!(gpu_policy.allow_debug);
        assert!(gpu_policy.allow_insecure_boot);

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
        assert!(requirements.gpu_policy.is_default());
        assert!(requirements.is_empty());
        let serialized = serde_json::to_value(requirements).unwrap();
        assert!(serialized.get("gpu_policy").is_none());

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

        let gpu_policy: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "gpu_policy": {
                    "rego": "package policy\n\ndefault nv_match = false\n"
                }
            }
        }))
        .unwrap();
        let requirements = gpu_policy.requirements.as_ref().unwrap();
        let gpu_policy = &requirements.gpu_policy;
        assert!(gpu_policy.attest_gpu);
        assert!(gpu_policy.rego.is_some());
        assert!(!gpu_policy.allow_devtools);
        assert!(!gpu_policy.allow_debug);
        assert!(!gpu_policy.allow_insecure_boot);
        assert!(!requirements.is_empty());

        let err = serde_json::from_value::<AppCompose>(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "gpu_policy": {
                    "rego": "package policy",
                    "allow_debugger": true
                }
            }
        }))
        .unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn attest_gpu_defaults_to_true() {
        assert!(GpuPolicy::default().attest_gpu);

        let omitted: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {}
        }))
        .unwrap();
        let requirements = omitted.requirements.as_ref().unwrap();
        assert!(requirements.gpu_policy.attest_gpu);
        assert!(requirements.is_empty());

        let explicit_empty: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "gpu_policy": {}
            }
        }))
        .unwrap();
        assert_eq!(
            explicit_empty.requirements.unwrap().gpu_policy,
            requirements.gpu_policy
        );

        let disabled: AppCompose = serde_json::from_value(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "gpu_policy": {
                    "attest_gpu": false
                }
            }
        }))
        .unwrap();
        let requirements = disabled.requirements.as_ref().unwrap();
        assert!(!requirements.gpu_policy.attest_gpu);
        assert!(!requirements.is_empty());

        let old_location = serde_json::from_value::<AppCompose>(serde_json::json!({
            "manifest_version": "3",
            "name": "test",
            "runner": "docker-compose",
            "requirements": {
                "attest_gpu": false
            }
        }))
        .unwrap_err();
        assert!(old_location.to_string().contains("unknown field"));
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
    /// Independently operated gateway clusters. URLs within one entry are
    /// failover endpoints for the same cluster. When empty, `gateway_urls` is
    /// treated as one legacy cluster.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_clusters: Vec<GatewayClusterConfig>,
    /// Backward-compatible input for sys-config files produced by older hosts.
    #[serde(default, rename = "pccs_url", skip_serializing)]
    legacy_pccs_url: Option<String>,
    /// Attestation collateral service endpoints. Platform defaults are used
    /// for fields that are absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_urls: Option<CollateralUrls>,
    /// Optional NVIDIA attestation collateral proxy. When present, nvattest
    /// fetches both OCSP responses and RIM documents through this endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nvidia_attestation_proxy_url: Option<String>,
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

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayClusterConfig {
    /// Stable local name used for the per-cluster key cache.
    pub name: String,
    /// Failover RPC endpoints belonging to this cluster.
    pub urls: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollateralUrls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pccs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amd_kds: Option<String>,
}

impl SysConfig {
    pub fn collateral_urls(&self) -> CollateralUrls {
        let mut urls = self.collateral_urls.clone().unwrap_or_default();
        if urls.pccs.is_none() {
            urls.pccs.clone_from(&self.legacy_pccs_url);
        }
        urls
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, Default)]
pub struct TeeSimulatorConfig {
    /// Platform ABI exposed by dstack-tee-simulator. Defaults to `dstack-tdx`.
    #[serde(default)]
    pub platform: TeeVariant,
    /// Hex-encoded 32-byte development PKI seed. The host collateral service
    /// and guest simulator must receive the same seed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mock_attestation_seed: Option<String>,
    /// Base URL used in mock collateral certificates (AIA/CRL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_base_url: Option<String>,
    /// MrConfigV3 document used to generate mock platform evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mr_config: Option<String>,
    /// JSON serialized VmConfig used to generate mock platform evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_config: Option<String>,
    /// Ordered SHA-384 PCR extensions used to reproduce the AWS boot state in
    /// the development NitroTPM simulator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_pcr_replay: Option<AwsPcrReplay>,
    /// Image-specific GCP TPM event log replayed by the development simulator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_tpm_replay: Option<GcpTpmReplay>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct GcpTpmReplay {
    #[serde(with = "serde_human_bytes::base64")]
    pub event_log: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct AwsPcrReplay {
    pub version: u32,
    pub events: Vec<AwsPcrReplayEvent>,
    #[serde(with = "hex_bytes")]
    pub pcr4: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub pcr7: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub pcr12: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct AwsPcrReplayEvent {
    pub pcr: u16,
    pub event_type: String,
    #[serde(with = "hex_bytes")]
    pub digest: Vec<u8>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy, Default, PartialEq, Eq, Encode, Decode)]
pub enum TeeVariant {
    #[default]
    #[serde(rename = "dstack-tdx")]
    DstackTdx,
    #[serde(rename = "dstack-gcp-tdx")]
    DstackGcpTdx,
    #[serde(rename = "dstack-nitro-enclave")]
    DstackNitroEnclave,
    #[serde(rename = "dstack-amd-sev-snp")]
    DstackAmdSevSnp,
    #[serde(rename = "dstack-aws-nitro-tpm")]
    DstackAwsNitroTpm,
}

impl TeeVariant {
    pub fn has_tdx(self) -> bool {
        matches!(self, Self::DstackTdx | Self::DstackGcpTdx)
    }

    pub fn tpm_event_pcr_and_bank(self) -> Option<(u32, &'static str)> {
        match self {
            Self::DstackGcpTdx => Some((14, "sha256")),
            Self::DstackAwsNitroTpm => Some((14, "sha384")),
            Self::DstackTdx | Self::DstackAmdSevSnp | Self::DstackNitroEnclave => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::DstackTdx => "dstack-tdx",
            Self::DstackGcpTdx => "dstack-gcp-tdx",
            Self::DstackAmdSevSnp => "dstack-amd-sev-snp",
            Self::DstackNitroEnclave => "dstack-nitro-enclave",
            Self::DstackAwsNitroTpm => "dstack-aws-nitro-tpm",
        }
    }
}

impl std::str::FromStr for TeeVariant {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "dstack-tdx" => Ok(Self::DstackTdx),
            "dstack-gcp-tdx" => Ok(Self::DstackGcpTdx),
            "dstack-amd-sev-snp" => Ok(Self::DstackAmdSevSnp),
            "dstack-nitro-enclave" => Ok(Self::DstackNitroEnclave),
            "dstack-aws-nitro-tpm" => Ok(Self::DstackAwsNitroTpm),
            _ => Err(format!("unsupported TEE variant: {value}")),
        }
    }
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

fn default_num_nics() -> u32 {
    1
}

fn is_default_num_nics(n: &u32) -> bool {
    *n == default_num_nics()
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

fn is_false(value: &bool) -> bool {
    !value
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
    /// Number of virtio-net NICs attached to the guest. Each NIC adds a PCI
    /// device to the ACPI/DSDT layout and therefore changes RTMR0, so it must
    /// be measured. Defaults to 1 and is omitted from the serialized form when
    /// equal to 1, keeping configs (and their cache keys / hashes) produced
    /// before this field existed byte-for-byte stable.
    #[serde(
        default = "default_num_nics",
        skip_serializing_if = "is_default_num_nics"
    )]
    pub num_nics: u32,
    /// Number of read-only verity volume devices attached to the guest. Each
    /// volume adds a virtio-blk PCI device before the NICs and therefore
    /// changes the measured ACPI/DSDT layout.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub num_verity_volumes: u32,
    /// Whether QEMU attaches a software TPM device. The TPM changes the ACPI
    /// table layout and must therefore be included in TDX measurement inputs.
    #[serde(default, skip_serializing_if = "is_false")]
    pub swtpm: bool,
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
    /// the OS image provides it, regardless of `tdx_attestation_variant`, and
    /// omitted only when the image predates this measurement material.
    ///
    /// Its presence does not select lite verification: `tdx_attestation_variant`
    /// alone does. A `Legacy` boot is verified through the image download even
    /// when this document is attached, because the two paths disagree on what
    /// `os_image_hash` means and honoring the document would move a boot the
    /// app pinned to `Legacy` onto the weaker image-identity check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tdx_measurement: Option<TdxOsImageMeasurementDocument>,
    /// GCP TDX no-image-download measurement material. Present for GCP
    /// deployments so `os_image_hash` can remain the unified image digest
    /// (`sha256(sha256sum.txt)`) while the verifier still binds the TPM UKI
    /// Authenticode event to that digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gcp_measurement: Option<GcpOsImageMeasurementDocument>,
    /// AWS NitroTPM image measurement material. When present, `os_image_hash`
    /// is the unified digest `sha256(sha256sum.txt)` and boot identity is bound
    /// via `boot_pcr_digest = sha256(PCR4||PCR7||PCR12)` in the measurement
    /// document (like GCP / TDX lite).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aws_measurement: Option<AwsOsImageMeasurementDocument>,
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
        .or_panic(format!("{context}: CBOR serialization should not fail"));
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

/// AWS NitroTPM boot-image measurement material.
///
/// Stores a single digest of the three boot PCRs rather than the raw PCR
/// values, to keep `measurement.aws.cbor` small while still binding the full
/// boot path. Composition is identical to the legacy image hash:
/// `sha256(PCR4 || PCR7 || PCR12)` (each PCR is 48-byte SHA384).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsOsImageMeasurement {
    /// `sha256(PCR4 || PCR7 || PCR12)` — 32 bytes.
    #[serde(with = "hex_bytes")]
    pub boot_pcr_digest: Vec<u8>,
}

impl AwsOsImageMeasurement {
    pub const BOOT_PCR_DIGEST_LEN: usize = 32;
    pub const PCR_SHA384_LEN: usize = 48;

    pub fn new(boot_pcr_digest: Vec<u8>) -> Result<Self, String> {
        if boot_pcr_digest.len() != Self::BOOT_PCR_DIGEST_LEN {
            return Err(format!(
                "AwsOsImageMeasurement: boot_pcr_digest has invalid length {}, expected {}",
                boot_pcr_digest.len(),
                Self::BOOT_PCR_DIGEST_LEN
            ));
        }
        Ok(Self { boot_pcr_digest })
    }

    /// Build from the three SHA384 boot PCRs (same order as
    /// `aws_nitro_tpm_boot_pcr_digest`: 4, 7, 12).
    pub fn from_boot_pcrs(pcr4: &[u8], pcr7: &[u8], pcr12: &[u8]) -> Result<Self, String> {
        for (label, pcr) in [("pcr4", pcr4), ("pcr7", pcr7), ("pcr12", pcr12)] {
            if pcr.len() != Self::PCR_SHA384_LEN {
                return Err(format!(
                    "AwsOsImageMeasurement: {label} has invalid length {}, expected {}",
                    pcr.len(),
                    Self::PCR_SHA384_LEN
                ));
            }
        }
        let mut buf = Vec::with_capacity(Self::PCR_SHA384_LEN * 3);
        buf.extend_from_slice(pcr4);
        buf.extend_from_slice(pcr7);
        buf.extend_from_slice(pcr12);
        Self::new(sha256(&buf).to_vec())
    }

    pub fn to_cbor_vec(&self) -> Vec<u8> {
        cbor_to_vec(self, "AwsOsImageMeasurement")
    }

    pub fn from_cbor_slice(bytes: &[u8]) -> Result<Self, String> {
        let measurement: Self = cbor_from_slice(bytes, "AwsOsImageMeasurement")?;
        Self::new(measurement.boot_pcr_digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AwsOsImageMeasurementDocument {
    /// Raw checksum file bytes (`sha256sum.txt`). `sha256(checksum_file)` is
    /// the unified `os_image_hash`.
    #[serde(with = "serde_human_bytes::base64")]
    pub checksum_file: Vec<u8>,
    /// Raw bytes of measurement.aws.cbor (AwsOsImageMeasurement).
    #[serde(with = "serde_human_bytes::base64")]
    pub measurement: Vec<u8>,
}

impl AwsOsImageMeasurementDocument {
    pub fn new(checksum_file: Vec<u8>, measurement: Vec<u8>) -> Self {
        Self {
            checksum_file,
            measurement,
        }
    }

    pub fn decode_measurement(&self) -> Result<AwsOsImageMeasurement, String> {
        AwsOsImageMeasurement::from_cbor_slice(&self.measurement)
    }

    pub fn verify(&self, os_image_hash: &[u8]) -> Result<(), String> {
        verify_measurement_material(
            os_image_hash,
            &self.checksum_file,
            &self.measurement,
            "measurement.aws.cbor",
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
    /// AWS EC2 instance with NitroTPM
    #[serde(rename = "aws-ec2")]
    AwsEc2,
}

impl Platform {
    fn detect_from_dmi(product_name: Option<&str>, sys_vendor: Option<&str>) -> Option<Self> {
        match product_name.map(str::trim) {
            Some("dstack" | "qemu") => return Some(Self::Dstack),
            Some("Google Compute Engine") => return Some(Self::Gcp),
            Some("Nitro Enclave") => return Some(Self::NitroEnclave),
            _ => {}
        }

        match sys_vendor.map(str::trim) {
            Some("Amazon EC2") => Some(Self::AwsEc2),
            _ => None,
        }
    }

    /// Detect platform from system DMI information
    pub fn detect() -> Option<Self> {
        // `/dev/nsm` is the authoritative Nitro Enclave ABI. Check it before
        // DMI because an enclave may inherit EC2-identifying DMI strings from
        // its parent host, while a regular EC2 instance does not expose NSM.
        if Path::new("/dev/nsm").exists() {
            return Some(Self::NitroEnclave);
        }
        let product_name = std::fs::read_to_string("/sys/class/dmi/id/product_name").ok();
        let sys_vendor = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor").ok();
        Self::detect_from_dmi(product_name.as_deref(), sys_vendor.as_deref())
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
            Self::AwsEc2 => "aws-ec2",
        }
    }
}

#[cfg(test)]
mod platform_tests {
    use super::Platform;

    #[test]
    fn detects_aws_ec2_from_dmi_vendor() {
        assert_eq!(
            Platform::detect_from_dmi(Some("HVM domU"), Some("Amazon EC2")),
            Some(Platform::AwsEc2)
        );
    }

    #[test]
    fn product_name_takes_precedence_over_vendor() {
        assert_eq!(
            Platform::detect_from_dmi(Some("Google Compute Engine"), Some("Amazon EC2")),
            Some(Platform::Gcp)
        );
    }

    #[test]
    fn detects_nitro_enclave_from_simulated_dmi() {
        assert_eq!(
            Platform::detect_from_dmi(Some("Nitro Enclave"), Some("AWS Nitro Enclaves")),
            Some(Platform::NitroEnclave)
        );
    }
}

#[cfg(test)]
mod vm_config_device_count_tests {
    use super::VmConfig;

    fn legacy_json() -> serde_json::Value {
        serde_json::json!({
            "cpu_count": 4,
            "memory_size": 4294967296u64,
            "num_gpus": 0,
            "num_nvswitches": 0,
        })
    }

    #[test]
    fn legacy_config_without_num_nics_defaults_to_one() {
        let cfg: VmConfig = serde_json::from_value(legacy_json()).unwrap();
        assert_eq!(cfg.num_nics, 1);
        assert_eq!(cfg.num_verity_volumes, 0);
    }

    #[test]
    fn single_nic_is_omitted_to_keep_cache_key_stable() {
        // A config with the default single NIC must serialize identically to a
        // legacy config, so the verifier's measurement cache key (a hash of the
        // serialized VmConfig) is unchanged for existing deployments.
        let cfg: VmConfig = serde_json::from_value(legacy_json()).unwrap();
        let serialized = serde_json::to_value(&cfg).unwrap();
        assert!(
            serialized.get("num_nics").is_none(),
            "num_nics must be omitted when equal to 1, got {serialized}"
        );
    }

    #[test]
    fn multi_nic_is_serialized() {
        let mut cfg: VmConfig = serde_json::from_value(legacy_json()).unwrap();
        cfg.num_nics = 2;
        let serialized = serde_json::to_value(&cfg).unwrap();
        assert_eq!(serialized.get("num_nics").and_then(|v| v.as_u64()), Some(2));
    }

    #[test]
    fn verity_volume_count_is_serialized_only_when_nonzero() {
        let mut cfg: VmConfig = serde_json::from_value(legacy_json()).unwrap();
        let serialized = serde_json::to_value(&cfg).unwrap();
        assert!(serialized.get("num_verity_volumes").is_none());

        cfg.num_verity_volumes = 2;
        let serialized = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            serialized
                .get("num_verity_volumes")
                .and_then(|v| v.as_u64()),
            Some(2)
        );
    }

    #[test]
    fn swtpm_is_serialized_only_when_enabled() {
        let mut cfg: VmConfig = serde_json::from_value(legacy_json()).unwrap();
        let serialized = serde_json::to_value(&cfg).unwrap();
        assert!(serialized.get("swtpm").is_none());

        cfg.swtpm = true;
        let serialized = serde_json::to_value(&cfg).unwrap();
        assert_eq!(
            serialized.get("swtpm").and_then(|v| v.as_bool()),
            Some(true)
        );
    }
}
