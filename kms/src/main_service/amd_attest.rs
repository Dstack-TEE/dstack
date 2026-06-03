// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed AMD SEV-SNP measurement/app binding validation.
//!
//! This module does not release keys by itself. It recomputes the expected SNP
//! MEASUREMENT from validated KMS configuration and launch inputs, then compares
//! the recomputed value to the hardware-verified report measurement. KMS release
//! paths must apply their own explicit local release gate after auth succeeds.
//!
//! Important: this is launch measurement binding, not a complete authorization
//! decision. `app_id`, compose hash, and rootfs hash are included in the SNP
//! measured kernel command line so the recomputed launch `MEASUREMENT` changes
//! with app identity, matching dstack's TDX measured-identity semantics. Do not
//! use this helper by itself to release app keys.

#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use ra_tls::attestation::{AttestationMode, VerifiedAttestation};
use sha2::{Digest, Sha256, Sha384};
use std::fs;

use crate::config::SevSnpMeasureConfig;

use super::upgrade_authority::BootInfo;

const LD_BYTES: usize = 48;
const ZEROS_LD: [u8; LD_BYTES] = [0u8; LD_BYTES];
const MAX_VCPUS: u32 = 512;
const MAX_OVMF_SECTIONS: usize = 64;
/// 64 GiB worth of 4 KiB pages.
const MAX_OVMF_METADATA_PAGES: u64 = 16_777_216;
// VMSA page GPA: (u64)(-1) page-aligned, bits >51 cleared.
const VMSA_GPA: u64 = 0x0000_FFFF_FFFF_F000;

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub(crate) struct OvmfSectionParam {
    pub gpa: u64,
    pub size: u64,
    /// Raw OVMF SEV metadata section type:
    /// 1=SNP_SEC_MEMORY, 2=SNP_SECRETS, 3=CPUID, 4=SVSM_CAA,
    /// 0x10=SNP_KERNEL_HASHES.
    pub section_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(deny_unknown_fields)]
pub(crate) struct MeasurementInput {
    /// 20-byte app identity included in the measured kernel cmdline for SNP,
    /// matching TDX's app-id-in-measured-identity semantics.
    pub app_id: String,
    /// 32-byte docker compose hash included in the measured kernel cmdline.
    pub compose_hash: String,
    /// 32-byte rootfs hash included in the measured kernel cmdline.
    pub rootfs_hash: String,
    /// Original image kernel cmdline used as the base for SNP measured launch
    /// before app identity fields are appended.
    pub base_cmdline: Option<String>,
    /// Optional 32-byte additional docker files hash included in the measured
    /// kernel cmdline when present.
    pub docker_files_hash: Option<String>,
    /// 48-byte OVMF GCTX launch digest seed. Required when OVMF sections are
    /// supplied by the request; optional only when KMS can load ovmf_path.
    pub ovmf_hash: String,
    /// 32-byte kernel SHA-256 hash.
    pub kernel_hash: String,
    /// 32-byte initrd SHA-256 hash. An empty string is treated as the SHA-256 of
    /// an empty initrd, matching QEMU/sev-snp-measure behavior.
    pub initrd_hash: String,
    /// GPA of the SevHashTable, from OVMF footer metadata.
    pub sev_hashes_table_gpa: u64,
    /// AP reset EIP, from OVMF footer metadata.
    pub sev_es_reset_eip: u32,
    pub vcpus: u32,
    pub vcpu_type: Option<String>,
    #[serde(deserialize_with = "deserialize_ovmf_sections_bounded")]
    pub ovmf_sections: Vec<OvmfSectionParam>,
}

fn deserialize_ovmf_sections_bounded<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<OvmfSectionParam>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct BoundedOvmfSections;

    impl<'de> serde::de::Visitor<'de> for BoundedOvmfSections {
        type Value = Vec<OvmfSectionParam>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {MAX_OVMF_SECTIONS} OVMF metadata sections"
            )
        }

        fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Vec<OvmfSectionParam>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut sections =
                Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_OVMF_SECTIONS));
            while let Some(section) = seq.next_element()? {
                if sections.len() >= MAX_OVMF_SECTIONS {
                    return Err(serde::de::Error::custom(format!(
                        "ovmf section count must not exceed {MAX_OVMF_SECTIONS}"
                    )));
                }
                sections.push(section);
            }
            Ok(sections)
        }
    }

    deserializer.deserialize_seq(BoundedOvmfSections)
}

pub(crate) fn validate_amd_snp_measurement_binding(
    config: Option<&SevSnpMeasureConfig>,
    verified_measurement: &[u8; 48],
    input: &MeasurementInput,
) -> Result<()> {
    let config = config.ok_or_else(|| anyhow::anyhow!("sev-snp measurement config is required"))?;
    validate_measurement_input(config, input)?;

    let expected_measurement = compute_expected_measurement(config, input)?;
    if expected_measurement.as_slice() != verified_measurement {
        bail!("amd sev-snp measurement mismatch");
    }

    Ok(())
}

/// Builds a deterministic authorization `BootInfo` for an already-verified AMD
/// SEV-SNP report without releasing KMS key material by itself.
///
/// This helper first recomputes and validates the QEMU SNP launch measurement.
/// `mr_aggregated` is the hardware-verified 48-byte SNP `MEASUREMENT`, and
/// `device_id` is the hardware-verified 64-byte SNP `chip_id`. `app_id`,
/// `compose_hash`, and `rootfs_hash` are bound through the measured kernel
/// command line; `os_image_hash` is therefore represented by `rootfs_hash`.
///
/// Authorization-specific digests are domain separated and deterministic:
/// * `mr_system = sha256("dstack-amd-sev-snp:mr-system:v1" || launch/system inputs)`
/// * `key_provider_info = sha256("dstack-amd-sev-snp:app-binding:v1" || mr_system || app_id || compose_hash || chip_id)`
/// * `instance_id = sha256("dstack-amd-sev-snp:instance-id:v1" || chip_id || measurement || app_id || compose_hash)`
///
/// Keeping these values explicit lets authorization/release policy inspect
/// exactly which SNP-specific inputs were bound before any sensitive output path
/// returns key material.
#[cfg(test)]
pub(crate) fn build_amd_snp_boot_info(
    config: &SevSnpMeasureConfig,
    verified_measurement: &[u8; 48],
    verified_chip_id: &[u8; 64],
    input: &MeasurementInput,
) -> Result<BootInfo> {
    build_amd_snp_boot_info_with_tcb_status(
        config,
        verified_measurement,
        verified_chip_id,
        "UpToDate",
        &[],
        input,
    )
}

fn build_amd_snp_boot_info_with_tcb_status(
    config: &SevSnpMeasureConfig,
    verified_measurement: &[u8; 48],
    verified_chip_id: &[u8; 64],
    tcb_status: &str,
    advisory_ids: &[String],
    input: &MeasurementInput,
) -> Result<BootInfo> {
    validate_amd_snp_measurement_binding(Some(config), verified_measurement, input)?;

    let app_id = decode_required_hex("app_id", &input.app_id, 20)?;
    let compose_hash = decode_required_hex("compose_hash", &input.compose_hash, 32)?;
    let rootfs_hash = decode_required_hex("rootfs_hash", &input.rootfs_hash, 32)?;
    let mr_system = snp_mr_system_digest(config, verified_measurement, input)?;
    let key_provider_info = snp_app_binding_digest(
        &mr_system,
        &app_id,
        &compose_hash,
        verified_chip_id.as_slice(),
    );
    let instance_id = snp_instance_id_digest(
        verified_chip_id.as_slice(),
        verified_measurement,
        &app_id,
        &compose_hash,
    );

    Ok(BootInfo {
        attestation_mode: AttestationMode::DstackAmdSevSnp,
        mr_aggregated: verified_measurement.to_vec(),
        os_image_hash: rootfs_hash,
        mr_system,
        app_id,
        compose_hash,
        instance_id,
        device_id: verified_chip_id.to_vec(),
        key_provider_info,
        tcb_status: tcb_status.to_string(),
        advisory_ids: advisory_ids.to_vec(),
    })
}

/// Extracts the verified AMD SEV-SNP report from a verified attestation and
/// materializes the helper-only SNP `BootInfo` used by future authorization.
///
/// This is the safe integration seam: the attestation verifier has already
/// checked the report signature/collateral/report_data, while this KMS helper
/// recomputes the launch measurement from trusted config and request inputs.
/// It still does not release keys by itself.
pub(crate) fn build_amd_snp_boot_info_from_verified_attestation(
    config: &SevSnpMeasureConfig,
    attestation: &VerifiedAttestation,
    input: &MeasurementInput,
) -> Result<BootInfo> {
    let verified = attestation
        .report
        .amd_snp_report()
        .ok_or_else(|| anyhow::anyhow!("verified attestation is not amd sev-snp"))?;
    build_amd_snp_boot_info_with_tcb_status(
        config,
        &verified.measurement,
        &verified.chip_id,
        verified.tcb_info.tcb_status(),
        &verified.advisory_ids,
        input,
    )
}

#[derive(Debug, serde::Deserialize)]
struct SevSnpMeasurementVmConfig {
    sev_snp_measurement: Option<MeasurementInput>,
}

/// Parses SNP launch-measurement inputs from the KMS request `vm_config` and
/// builds helper-only SNP `BootInfo` from an already verified attestation.
///
/// The field is intentionally explicit (`sev_snp_measurement`) so missing SNP
/// launch inputs fail closed instead of falling back to TDX event-log decoding.
pub(crate) fn build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
    config: &SevSnpMeasureConfig,
    attestation: &VerifiedAttestation,
    vm_config: &str,
) -> Result<BootInfo> {
    let input = parse_measurement_input_from_vm_config(vm_config)?;
    build_amd_snp_boot_info_from_verified_attestation(config, attestation, &input)
}

fn parse_measurement_input_from_vm_config(vm_config: &str) -> Result<MeasurementInput> {
    let parsed: SevSnpMeasurementVmConfig = serde_json::from_str(vm_config)
        .context("failed to parse vm_config for amd sev-snp measurement")?;
    parsed
        .sev_snp_measurement
        .ok_or_else(|| anyhow::anyhow!("sev_snp_measurement is required for amd sev-snp"))
}

/// Explicit helper-only AMD SEV-SNP authorization policy.
///
/// Explicit AMD SEV-SNP authorization policy: an SNP `BootInfo` must match
/// allowlisted hardware measurement, app/config identity, device identity, and
/// TCB/advisory policy. Empty allowlists fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AmdSnpAuthPolicy {
    pub allowed_measurements: Vec<Vec<u8>>,
    pub allowed_app_ids: Vec<Vec<u8>>,
    pub allowed_compose_hashes: Vec<Vec<u8>>,
    pub allowed_os_image_hashes: Vec<Vec<u8>>,
    pub allowed_device_ids: Vec<Vec<u8>>,
    pub allowed_tcb_statuses: Vec<String>,
    pub allowed_advisory_ids: Vec<String>,
}

impl AmdSnpAuthPolicy {
    /// Build a narrow exact-match policy from an already verified SNP boot
    /// identity. This is useful for tests and for future allowlist materializing
    /// logic, but still does not release keys by itself.
    pub(crate) fn from_boot_info(boot_info: &BootInfo) -> Result<Self> {
        ensure_snp_boot_info_shape(boot_info)?;
        Ok(Self {
            allowed_measurements: vec![boot_info.mr_aggregated.clone()],
            allowed_app_ids: vec![boot_info.app_id.clone()],
            allowed_compose_hashes: vec![boot_info.compose_hash.clone()],
            allowed_os_image_hashes: vec![boot_info.os_image_hash.clone()],
            allowed_device_ids: vec![boot_info.device_id.clone()],
            allowed_tcb_statuses: vec![boot_info.tcb_status.clone()],
            allowed_advisory_ids: boot_info.advisory_ids.clone(),
        })
    }
}

pub(crate) fn validate_amd_snp_auth_policy(
    boot_info: &BootInfo,
    policy: &AmdSnpAuthPolicy,
) -> Result<()> {
    ensure_snp_boot_info_shape(boot_info)?;
    ensure_allowed_bytes(
        "measurement",
        &boot_info.mr_aggregated,
        &policy.allowed_measurements,
    )?;
    ensure_allowed_bytes("app_id", &boot_info.app_id, &policy.allowed_app_ids)?;
    ensure_allowed_bytes(
        "compose_hash",
        &boot_info.compose_hash,
        &policy.allowed_compose_hashes,
    )?;
    ensure_allowed_bytes(
        "os_image_hash",
        &boot_info.os_image_hash,
        &policy.allowed_os_image_hashes,
    )?;
    ensure_allowed_bytes(
        "device_id",
        &boot_info.device_id,
        &policy.allowed_device_ids,
    )?;
    ensure_allowed_string(
        "tcb_status",
        &boot_info.tcb_status,
        &policy.allowed_tcb_statuses,
    )?;
    for advisory_id in &boot_info.advisory_ids {
        ensure_allowed_string("advisory_id", advisory_id, &policy.allowed_advisory_ids)?;
    }
    Ok(())
}

fn ensure_snp_boot_info_shape(boot_info: &BootInfo) -> Result<()> {
    if boot_info.attestation_mode != AttestationMode::DstackAmdSevSnp {
        bail!("attestation mode is not amd sev-snp");
    }
    ensure_len("measurement", &boot_info.mr_aggregated, 48)?;
    ensure_len("app_id", &boot_info.app_id, 20)?;
    ensure_len("compose_hash", &boot_info.compose_hash, 32)?;
    ensure_len("os_image_hash", &boot_info.os_image_hash, 32)?;
    ensure_len("device_id", &boot_info.device_id, 64)?;
    ensure_len("mr_system", &boot_info.mr_system, 32)?;
    ensure_len("key_provider_info", &boot_info.key_provider_info, 32)?;
    ensure_len("instance_id", &boot_info.instance_id, 32)?;
    if boot_info.tcb_status.trim().is_empty() {
        bail!("tcb_status is not allowed");
    }
    Ok(())
}

fn ensure_len(name: &str, value: &[u8], expected_len: usize) -> Result<()> {
    if value.len() != expected_len {
        bail!("{name} must be {expected_len} bytes");
    }
    Ok(())
}

fn ensure_allowed_bytes(name: &str, value: &[u8], allowed: &[Vec<u8>]) -> Result<()> {
    if allowed
        .iter()
        .any(|candidate| candidate.as_slice() == value)
    {
        return Ok(());
    }
    bail!("{name} is not allowed")
}

fn ensure_allowed_string(name: &str, value: &str, allowed: &[String]) -> Result<()> {
    if allowed.iter().any(|candidate| candidate == value) {
        return Ok(());
    }
    bail!("{name} is not allowed")
}

fn snp_mr_system_digest(
    config: &SevSnpMeasureConfig,
    verified_measurement: &[u8; 48],
    input: &MeasurementInput,
) -> Result<Vec<u8>> {
    let ovmf_hash = decode_optional_hex("ovmf_hash", &input.ovmf_hash, 48)?;
    let kernel_hash = decode_required_hex("kernel_hash", &input.kernel_hash, 32)?;
    let initrd_hash = if input.initrd_hash.is_empty() {
        Sha256::digest(b"").to_vec()
    } else {
        decode_required_hex("initrd_hash", &input.initrd_hash, 32)?
    };
    let rootfs_hash = decode_required_hex("rootfs_hash", &input.rootfs_hash, 32)?;
    let docker_files_hash = input
        .docker_files_hash
        .as_deref()
        .map(|value| decode_required_hex("docker_files_hash", value, 32))
        .transpose()?;
    let vcpu_type = input
        .vcpu_type
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("vcpu_type is required"))?;

    let mut h = Sha256::new();
    h.update(b"dstack-amd-sev-snp:mr-system:v1");
    h.update(verified_measurement);
    h.update(len_prefixed(&ovmf_hash));
    h.update(kernel_hash);
    h.update(initrd_hash);
    h.update(rootfs_hash);
    h.update(input.vcpus.to_le_bytes());
    h.update(len_prefixed(vcpu_type.as_bytes()));
    h.update(config.guest_features.to_le_bytes());
    match docker_files_hash {
        Some(value) => {
            h.update([1]);
            h.update(value);
        }
        None => h.update([0]),
    }
    h.update(input.sev_hashes_table_gpa.to_le_bytes());
    h.update(input.sev_es_reset_eip.to_le_bytes());
    h.update((input.ovmf_sections.len() as u64).to_le_bytes());
    for section in &input.ovmf_sections {
        h.update(section.gpa.to_le_bytes());
        h.update(section.size.to_le_bytes());
        h.update(section.section_type.to_le_bytes());
    }
    Ok(h.finalize().to_vec())
}

fn snp_app_binding_digest(
    mr_system: &[u8],
    app_id: &[u8],
    compose_hash: &[u8],
    chip_id: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"dstack-amd-sev-snp:app-binding:v1");
    h.update(mr_system);
    h.update(app_id);
    h.update(compose_hash);
    h.update(chip_id);
    h.finalize().to_vec()
}

fn snp_instance_id_digest(
    chip_id: &[u8],
    measurement: &[u8],
    app_id: &[u8],
    compose_hash: &[u8],
) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"dstack-amd-sev-snp:instance-id:v1");
    h.update(chip_id);
    h.update(measurement);
    h.update(app_id);
    h.update(compose_hash);
    h.finalize().to_vec()
}

fn len_prefixed(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + bytes.len());
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

fn validate_measurement_input(
    config: &SevSnpMeasureConfig,
    input: &MeasurementInput,
) -> Result<()> {
    if config.guest_features == 0 {
        bail!("guest_features must be non-zero");
    }

    let app_id = decode_required_hex("app_id", &input.app_id, 20)?;
    if app_id.iter().all(|&b| b == 0) {
        bail!("app_id must not be all-zeros");
    }
    decode_required_hex("compose_hash", &input.compose_hash, 32)?;
    decode_required_hex("rootfs_hash", &input.rootfs_hash, 32)?;
    decode_required_hex("kernel_hash", &input.kernel_hash, 32)?;
    decode_optional_hex("initrd_hash", &input.initrd_hash, 32)?;
    if let Some(docker_files_hash) = &input.docker_files_hash {
        decode_required_hex("docker_files_hash", docker_files_hash, 32)?;
    }

    if input.vcpus == 0 {
        bail!("vcpus must be greater than zero");
    }
    if input.vcpus > MAX_VCPUS {
        bail!("vcpus must not exceed {MAX_VCPUS}");
    }
    match input.vcpu_type.as_deref() {
        Some(vcpu_type) if !vcpu_type.trim().is_empty() => {
            vcpu_sig_from_type(vcpu_type)?;
        }
        _ => bail!("vcpu_type is required"),
    }

    if input.ovmf_sections.is_empty() {
        if config
            .ovmf_path
            .as_deref()
            .unwrap_or_default()
            .trim()
            .is_empty()
        {
            bail!("ovmf_sections are required when ovmf_path is not configured");
        }
        if !input.ovmf_hash.is_empty() {
            bail!("ovmf_hash must be empty when ovmf_path is used");
        }
        return Ok(());
    }

    decode_required_hex("ovmf_hash", &input.ovmf_hash, 48)?;
    if input.ovmf_sections.len() > MAX_OVMF_SECTIONS {
        bail!("ovmf section count must not exceed {MAX_OVMF_SECTIONS}");
    }
    if input.sev_hashes_table_gpa == 0 {
        bail!("sev_hashes_table_gpa must be non-zero");
    }
    if input.sev_es_reset_eip == 0 {
        bail!("sev_es_reset_eip must be non-zero");
    }

    let mut has_kernel_hashes_section = false;
    let mut measured_pages = 0u64;
    for section in &input.ovmf_sections {
        if section.size == 0 {
            bail!("ovmf section size must be greater than zero");
        }
        let pages = section.size.div_ceil(4096);
        measured_pages = measured_pages
            .checked_add(pages)
            .ok_or_else(|| anyhow::anyhow!("ovmf metadata page count overflow"))?;
        if measured_pages > MAX_OVMF_METADATA_PAGES {
            bail!("ovmf metadata page count must not exceed {MAX_OVMF_METADATA_PAGES}");
        }
        let section_type = SectionType::from_u32(section.section_type).ok_or_else(|| {
            anyhow::anyhow!("unknown ovmf section_type {:#x}", section.section_type)
        })?;
        has_kernel_hashes_section |= section_type == SectionType::SnpKernelHashes;
    }
    if !has_kernel_hashes_section {
        bail!("ovmf metadata does not include a snp_kernel_hashes section");
    }

    Ok(())
}

fn decode_required_hex(name: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    decode_optional_hex(name, value, expected_len)
}

fn decode_optional_hex(name: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let bytes = hex::decode(value).map_err(|_| anyhow::anyhow!("{name} must be valid hex"))?;
    if bytes.len() != expected_len {
        bail!("{name} must be {expected_len} bytes");
    }
    Ok(bytes)
}

struct Gctx {
    ld: [u8; LD_BYTES],
}

impl Gctx {
    fn new() -> Self {
        Self { ld: ZEROS_LD }
    }

    fn from_ovmf_hash(hex_value: &str) -> Result<Self> {
        let raw = hex::decode(hex_value).context("ovmf_hash must be valid hex")?;
        let ld: [u8; LD_BYTES] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("ovmf_hash must be 48 bytes"))?;
        Ok(Self { ld })
    }

    /// SNP spec §8.17.2 PAGE_INFO layout (112 bytes): current digest,
    /// contents digest, length, page type, permissions/reserved, and GPA.
    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8; LD_BYTES]) {
        let mut buf = [0u8; 0x70];
        buf[..LD_BYTES].copy_from_slice(&self.ld);
        buf[48..96].copy_from_slice(contents);
        buf[96..98].copy_from_slice(&0x70u16.to_le_bytes());
        buf[98] = page_type;
        buf[104..112].copy_from_slice(&gpa.to_le_bytes());
        let mut digest = [0u8; LD_BYTES];
        digest.copy_from_slice(&Sha384::digest(buf));
        self.ld = digest;
    }

    fn sha384(data: &[u8]) -> [u8; LD_BYTES] {
        let mut out = [0u8; LD_BYTES];
        out.copy_from_slice(&Sha384::digest(data));
        out
    }

    fn update_normal_pages(&mut self, start_gpa: u64, data: &[u8]) {
        for (i, chunk) in data.chunks(4096).enumerate() {
            self.update(0x01, start_gpa + (i * 4096) as u64, &Self::sha384(chunk));
        }
    }

    fn update_zero_pages(&mut self, gpa: u64, len: usize) {
        for i in (0..len).step_by(4096) {
            self.update(0x03, gpa + i as u64, &ZEROS_LD);
        }
    }

    fn update_secrets_page(&mut self, gpa: u64) {
        self.update(0x05, gpa, &ZEROS_LD);
    }

    fn update_cpuid_page(&mut self, gpa: u64) {
        self.update(0x06, gpa, &ZEROS_LD);
    }

    fn update_vmsa_page(&mut self, page: &[u8]) {
        self.update(0x02, VMSA_GPA, &Self::sha384(page));
    }
}

const GUID_LE_HASH_TABLE_HEADER: [u8; 16] = [
    0x06, 0xd6, 0x38, 0x94, 0x22, 0x4f, 0xc9, 0x4c, 0xb4, 0x79, 0xa7, 0x93, 0xd4, 0x11, 0xfd, 0x21,
];
const GUID_LE_KERNEL_ENTRY: [u8; 16] = [
    0x37, 0x94, 0xe7, 0x4d, 0xd2, 0xab, 0x7f, 0x42, 0xb8, 0x35, 0xd5, 0xb1, 0x72, 0xd2, 0x04, 0x5b,
];
const GUID_LE_INITRD_ENTRY: [u8; 16] = [
    0x31, 0xf7, 0xba, 0x44, 0x2f, 0x3a, 0xd7, 0x4b, 0x9a, 0xf1, 0x41, 0xe2, 0x91, 0x69, 0x78, 0x1d,
];
const GUID_LE_CMDLINE_ENTRY: [u8; 16] = [
    0xd8, 0x2d, 0xd0, 0x97, 0x20, 0xbd, 0x94, 0x4c, 0xaa, 0x78, 0xe7, 0x71, 0x4d, 0x36, 0xab, 0x2a,
];

fn sev_entry(guid: &[u8; 16], hash: &[u8; 32]) -> [u8; 50] {
    let mut entry = [0u8; 50];
    entry[..16].copy_from_slice(guid);
    entry[16..18].copy_from_slice(&50u16.to_le_bytes());
    entry[18..].copy_from_slice(hash);
    entry
}

fn build_sev_hashes_page(
    kernel_hash_hex: &str,
    initrd_hash_hex: &str,
    append: &str,
    page_offset: usize,
) -> Result<[u8; 4096]> {
    let kernel_hash: [u8; 32] = hex::decode(kernel_hash_hex)
        .context("kernel_hash must be valid hex")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("kernel_hash must be 32 bytes"))?;

    let initrd_hash: [u8; 32] = if initrd_hash_hex.is_empty() {
        let mut h = [0u8; 32];
        h.copy_from_slice(&Sha256::digest(b""));
        h
    } else {
        hex::decode(initrd_hash_hex)
            .context("initrd_hash must be valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("initrd_hash must be 32 bytes"))?
    };

    let mut cmdline_bytes = append.as_bytes().to_vec();
    cmdline_bytes.push(0);
    let mut cmdline_hash = [0u8; 32];
    cmdline_hash.copy_from_slice(&Sha256::digest(&cmdline_bytes));

    let cmdline_entry = sev_entry(&GUID_LE_CMDLINE_ENTRY, &cmdline_hash);
    let initrd_entry = sev_entry(&GUID_LE_INITRD_ENTRY, &initrd_hash);
    let kernel_entry = sev_entry(&GUID_LE_KERNEL_ENTRY, &kernel_hash);

    const TABLE_SIZE: usize = 16 + 2 + 50 + 50 + 50;
    let mut table = [0u8; TABLE_SIZE];
    table[..16].copy_from_slice(&GUID_LE_HASH_TABLE_HEADER);
    table[16..18].copy_from_slice(&(TABLE_SIZE as u16).to_le_bytes());
    table[18..68].copy_from_slice(&cmdline_entry);
    table[68..118].copy_from_slice(&initrd_entry);
    table[118..168].copy_from_slice(&kernel_entry);

    const PADDED: usize = (TABLE_SIZE + 15) & !(15usize);
    if page_offset + PADDED > 4096 {
        bail!("sev hash table overflows 4096-byte page");
    }
    let mut page = [0u8; 4096];
    page[page_offset..page_offset + TABLE_SIZE].copy_from_slice(&table);
    Ok(page)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SectionType {
    SnpSecMemory = 1,
    SnpSecrets = 2,
    Cpuid = 3,
    SvsmCaa = 4,
    SnpKernelHashes = 0x10,
}

impl SectionType {
    fn from_u32(value: u32) -> Option<Self> {
        match value {
            1 => Some(Self::SnpSecMemory),
            2 => Some(Self::SnpSecrets),
            3 => Some(Self::Cpuid),
            4 => Some(Self::SvsmCaa),
            0x10 => Some(Self::SnpKernelHashes),
            _ => None,
        }
    }
}

struct MetadataSection {
    gpa: u64,
    size: u64,
    section_type: SectionType,
}

struct OvmfInfo {
    data: Vec<u8>,
    gpa: u64,
    sections: Vec<MetadataSection>,
    sev_hashes_table_gpa: u64,
    sev_es_reset_eip: u32,
}

const GUID_FOOTER_TABLE: [u8; 16] = [
    0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
];
const GUID_SEV_HASH_TABLE_RV: [u8; 16] = [
    0x1f, 0x37, 0x55, 0x72, 0x3b, 0x3a, 0x04, 0x4b, 0x92, 0x7b, 0x1d, 0xa6, 0xef, 0xa8, 0xd4, 0x54,
];
const GUID_SEV_ES_RESET_BLK: [u8; 16] = [
    0xde, 0x71, 0xf7, 0x00, 0x7e, 0x1a, 0xcb, 0x4f, 0x89, 0x0e, 0x68, 0xc7, 0x7e, 0x2f, 0xb4, 0x4e,
];
const GUID_SEV_META_DATA: [u8; 16] = [
    0x66, 0x65, 0x88, 0xdc, 0x4a, 0x98, 0x98, 0x47, 0xa7, 0x5e, 0x55, 0x85, 0xa7, 0xbf, 0x67, 0xcc,
];

fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

impl OvmfInfo {
    fn load(path: &str) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("cannot read ovmf binary '{path}'"))?;
        let size = data.len();
        let gpa = (0x1_0000_0000u64)
            .checked_sub(size as u64)
            .context("ovmf binary is larger than 4 gib")?;

        const ENTRY_HDR: usize = 18;
        let footer_off = size.saturating_sub(32 + ENTRY_HDR);
        if footer_off + ENTRY_HDR > size {
            bail!("ovmf binary too small to contain footer table");
        }
        if data[footer_off + 2..footer_off + 18] != GUID_FOOTER_TABLE {
            bail!("ovmf footer guid not found");
        }
        let footer_total_size = read_u16_le(&data, footer_off) as usize;
        if footer_total_size < ENTRY_HDR {
            bail!("ovmf footer table has invalid total size");
        }
        let table_size = footer_total_size - ENTRY_HDR;
        if table_size > footer_off {
            bail!("ovmf footer table is out of bounds");
        }
        let table_start = footer_off - table_size;
        let table_bytes = &data[table_start..footer_off];

        let mut sev_hashes_table_gpa = 0u64;
        let mut sev_es_reset_eip = 0u32;
        let mut meta_offset_from_end = None;

        let mut pos = table_bytes.len();
        while pos >= ENTRY_HDR {
            let entry_off = pos - ENTRY_HDR;
            let entry_size = read_u16_le(table_bytes, entry_off) as usize;
            if entry_size < ENTRY_HDR || entry_size > pos {
                bail!("ovmf footer table has invalid entry size");
            }
            let guid = &table_bytes[entry_off + 2..entry_off + 18];
            let data_start = pos - entry_size;
            let data_end = pos - ENTRY_HDR;
            let entry_data = &table_bytes[data_start..data_end];

            if guid == GUID_SEV_HASH_TABLE_RV && entry_data.len() >= 4 {
                sev_hashes_table_gpa = read_u32_le(entry_data, 0) as u64;
            } else if guid == GUID_SEV_ES_RESET_BLK && entry_data.len() >= 4 {
                sev_es_reset_eip = read_u32_le(entry_data, 0);
            } else if guid == GUID_SEV_META_DATA && entry_data.len() >= 4 {
                meta_offset_from_end = Some(read_u32_le(entry_data, 0) as usize);
            }
            pos -= entry_size;
        }

        if sev_hashes_table_gpa == 0 {
            bail!("ovmf sev hash table entry not found in footer table");
        }
        if sev_es_reset_eip == 0 {
            bail!("ovmf sev_es_reset_block entry not found in footer table");
        }

        let mut sections = Vec::new();
        let off_from_end = meta_offset_from_end
            .ok_or_else(|| anyhow::anyhow!("ovmf sev metadata entry not found in footer table"))?;
        if off_from_end > size {
            bail!("ovmf sev metadata offset exceeds file size");
        }
        let meta_start = size - off_from_end;
        if meta_start + 16 > size {
            bail!("ovmf sev metadata header out of bounds");
        }
        if &data[meta_start..meta_start + 4] != b"ASEV" {
            bail!("ovmf sev metadata has bad signature");
        }
        let meta_version = read_u32_le(&data, meta_start + 8);
        if meta_version != 1 {
            bail!("ovmf sev metadata has unsupported version {meta_version}");
        }
        let num_items = read_u32_le(&data, meta_start + 12) as usize;
        let items_start = meta_start + 16;
        if items_start + num_items * 12 > size {
            bail!("ovmf sev metadata sections out of bounds");
        }
        for i in 0..num_items {
            let off = items_start + i * 12;
            let section_type_value = read_u32_le(&data, off + 8);
            let section_type = SectionType::from_u32(section_type_value).ok_or_else(|| {
                anyhow::anyhow!("unknown ovmf section_type {section_type_value:#x}")
            })?;
            sections.push(MetadataSection {
                gpa: read_u32_le(&data, off) as u64,
                size: read_u32_le(&data, off + 4) as u64,
                section_type,
            });
        }

        Ok(Self {
            data,
            gpa,
            sections,
            sev_hashes_table_gpa,
            sev_es_reset_eip,
        })
    }
}

fn write_u16_le_at(buf: &mut [u8], off: usize, value: u16) {
    buf[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_le_at(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_le_at(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_vmcb_seg(buf: &mut [u8], off: usize, selector: u16, attrib: u16, limit: u32, base: u64) {
    write_u16_le_at(buf, off, selector);
    write_u16_le_at(buf, off + 2, attrib);
    write_u32_le_at(buf, off + 4, limit);
    write_u64_le_at(buf, off + 8, base);
}

fn amd_cpu_sig(family: u32, model: u32, stepping: u32) -> u32 {
    let (family_low, family_high) = if family > 0xf {
        (0xf, (family - 0xf) & 0xff)
    } else {
        (family, 0)
    };
    let model_low = model & 0xf;
    let model_high = (model >> 4) & 0xf;
    (family_high << 20)
        | (model_high << 16)
        | (family_low << 8)
        | (model_low << 4)
        | (stepping & 0xf)
}

fn vcpu_sig_from_type(vcpu_type: &str) -> Result<u32> {
    match vcpu_type.trim().to_lowercase().as_str() {
        "epyc" | "epyc-v1" | "epyc-v2" | "epyc-ibpb" | "epyc-v3" | "epyc-v4" => {
            Ok(amd_cpu_sig(23, 1, 2))
        }
        "epyc-rome" | "epyc-rome-v1" | "epyc-rome-v2" | "epyc-rome-v3" => {
            Ok(amd_cpu_sig(23, 49, 0))
        }
        "epyc-milan" | "epyc-milan-v1" | "epyc-milan-v2" => Ok(amd_cpu_sig(25, 1, 1)),
        "epyc-genoa" | "epyc-genoa-v1" => Ok(amd_cpu_sig(25, 17, 0)),
        other => bail!("unknown vcpu_type {other:?}"),
    }
}

fn build_vmsa_page(eip: u32, vcpu_sig: u32, sev_features: u64) -> Box<[u8; 4096]> {
    let mut page = Box::new([0u8; 4096]);
    let p = page.as_mut_slice();

    let cs_base = (eip as u64) & 0xffff_0000;
    let rip = (eip as u64) & 0x0000_ffff;

    write_vmcb_seg(p, 0x000, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x010, 0xf000, 0x009b, 0xffff, cs_base);
    write_vmcb_seg(p, 0x020, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x030, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x040, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x050, 0, 0x0093, 0xffff, 0);
    write_vmcb_seg(p, 0x060, 0, 0x0000, 0xffff, 0);
    write_vmcb_seg(p, 0x070, 0, 0x0082, 0xffff, 0);
    write_vmcb_seg(p, 0x080, 0, 0x0000, 0xffff, 0);
    write_vmcb_seg(p, 0x090, 0, 0x008b, 0xffff, 0);

    write_u64_le_at(p, 0x0D0, 0x1000);
    write_u64_le_at(p, 0x148, 0x40);
    write_u64_le_at(p, 0x158, 0x10);
    write_u64_le_at(p, 0x160, 0x400);
    write_u64_le_at(p, 0x168, 0xffff_0ff0);
    write_u64_le_at(p, 0x170, 0x2);
    write_u64_le_at(p, 0x178, rip);
    write_u64_le_at(p, 0x268, 0x0007_0406_0007_0406);
    write_u64_le_at(p, 0x310, vcpu_sig as u64);
    write_u64_le_at(p, 0x3B0, sev_features);
    write_u64_le_at(p, 0x3E8, 0x1);
    write_u32_le_at(p, 0x408, 0x1f80);
    write_u16_le_at(p, 0x410, 0x037f);

    page
}

pub(crate) fn compute_expected_measurement(
    config: &SevSnpMeasureConfig,
    input: &MeasurementInput,
) -> Result<[u8; 48]> {
    let vcpu_type = input
        .vcpu_type
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("vcpu_type is required"))?;

    let mut cmdline = match input.base_cmdline.as_deref() {
        Some(base) if !base.trim().is_empty() => format!(
            "{} docker_compose_hash={} rootfs_hash={} app_id={}",
            base.trim(),
            input.compose_hash,
            input.rootfs_hash,
            input.app_id
        ),
        _ => format!(
            "console=ttyS0 loglevel=7 docker_compose_hash={} rootfs_hash={} app_id={}",
            input.compose_hash, input.rootfs_hash, input.app_id
        ),
    };
    if let Some(docker_files_hash) = input.docker_files_hash.as_deref() {
        cmdline.push_str(&format!(
            " docker_additional_files_hash={docker_files_hash}"
        ));
    }

    let (mut gctx, effective_hashes_gpa, effective_reset_eip, resolved_sections) =
        if !input.ovmf_sections.is_empty() {
            let sections = input
                .ovmf_sections
                .iter()
                .map(|section| {
                    let section_type =
                        SectionType::from_u32(section.section_type).ok_or_else(|| {
                            anyhow::anyhow!("unknown ovmf section_type {:#x}", section.section_type)
                        })?;
                    Ok(MetadataSection {
                        gpa: section.gpa,
                        size: section.size,
                        section_type,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            (
                Gctx::from_ovmf_hash(&input.ovmf_hash)?,
                input.sev_hashes_table_gpa,
                input.sev_es_reset_eip,
                sections,
            )
        } else {
            let path = config.ovmf_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!("ovmf_sections are required when ovmf_path is not configured")
            })?;
            let ovmf = OvmfInfo::load(path)?;
            let gctx = if input.ovmf_hash.is_empty() {
                let mut g = Gctx::new();
                g.update_normal_pages(ovmf.gpa, &ovmf.data);
                g
            } else {
                Gctx::from_ovmf_hash(&input.ovmf_hash)?
            };
            (
                gctx,
                ovmf.sev_hashes_table_gpa,
                ovmf.sev_es_reset_eip,
                ovmf.sections,
            )
        };

    let mut has_kernel_hashes_section = false;
    for section in &resolved_sections {
        let gpa = section.gpa;
        let size = usize::try_from(section.size)
            .map_err(|_| anyhow::anyhow!("ovmf section size is too large"))?;
        match section.section_type {
            SectionType::SnpSecMemory => gctx.update_zero_pages(gpa, size),
            SectionType::SnpSecrets => gctx.update_secrets_page(gpa),
            SectionType::Cpuid => gctx.update_cpuid_page(gpa),
            SectionType::SvsmCaa => gctx.update_zero_pages(gpa, size),
            SectionType::SnpKernelHashes => {
                has_kernel_hashes_section = true;
                if effective_hashes_gpa == 0 {
                    bail!("snp_kernel_hashes section present but sev_hashes_table_gpa is 0");
                }
                let page_offset = (effective_hashes_gpa & 0xfff) as usize;
                let page = build_sev_hashes_page(
                    &input.kernel_hash,
                    &input.initrd_hash,
                    &cmdline,
                    page_offset,
                )?;
                gctx.update_normal_pages(gpa, &page);
            }
        }
    }
    if !has_kernel_hashes_section {
        bail!("ovmf metadata does not include a snp_kernel_hashes section");
    }

    let vcpu_sig = vcpu_sig_from_type(vcpu_type)?;
    let bsp_vmsa = build_vmsa_page(0xffff_fff0, vcpu_sig, config.guest_features);
    let ap_vmsa = build_vmsa_page(effective_reset_eip, vcpu_sig, config.guest_features);

    for i in 0..input.vcpus as usize {
        let vmsa_page = if i == 0 {
            bsp_vmsa.as_ref()
        } else {
            ap_vmsa.as_ref()
        };
        gctx.update_vmsa_page(vmsa_page);
    }

    Ok(gctx.ld)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SevSnpMeasureConfig {
        SevSnpMeasureConfig {
            ovmf_path: None,
            guest_features: 1,
        }
    }

    fn config_with_path(path: &str) -> SevSnpMeasureConfig {
        SevSnpMeasureConfig {
            ovmf_path: Some(path.to_string()),
            guest_features: 1,
        }
    }

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn valid_input() -> MeasurementInput {
        MeasurementInput {
            app_id: hex_of(0x11, 20),
            compose_hash: hex_of(0x22, 32),
            rootfs_hash: hex_of(0x33, 32),
            base_cmdline: None,
            docker_files_hash: Some(hex_of(0x77, 32)),
            ovmf_hash: hex_of(0x44, 48),
            kernel_hash: hex_of(0x55, 32),
            initrd_hash: hex_of(0x66, 32),
            sev_hashes_table_gpa: 0x80_1000,
            sev_es_reset_eip: 0xffff_fff0,
            vcpus: 2,
            vcpu_type: Some("epyc-v4".to_string()),
            ovmf_sections: vec![
                OvmfSectionParam {
                    gpa: 0x100000,
                    size: 0x2000,
                    section_type: 1,
                },
                OvmfSectionParam {
                    gpa: 0x80_0000,
                    size: 0x1000,
                    section_type: 0x10,
                },
                OvmfSectionParam {
                    gpa: 0x81_0000,
                    size: 0x1000,
                    section_type: 2,
                },
                OvmfSectionParam {
                    gpa: 0x82_0000,
                    size: 0x1000,
                    section_type: 3,
                },
            ],
        }
    }

    fn assert_rejects(input: MeasurementInput, msg: &str) {
        let verified = [0xaa; 48];
        let err = validate_amd_snp_measurement_binding(Some(&config()), &verified, &input)
            .expect_err("binding should reject invalid input");
        assert!(
            err.to_string().contains(msg),
            "expected error containing {msg:?}, got {err:?}"
        );
    }

    #[test]
    fn gctx_update_is_deterministic_and_order_sensitive() {
        let contents = Gctx::sha384(b"page");
        let mut first = Gctx::new();
        first.update(0x01, 0x1000, &contents);
        assert_eq!(
            hex::encode(first.ld),
            "3ebc1a70acc0bae5ae2788fae29a0371f983b19a68faf9843064f36040f58571ce5bb6bcdc9c361087073f8cffd92635"
        );

        let mut second = Gctx::new();
        second.update(0x01, 0x2000, &contents);
        assert_ne!(first.ld, second.ld);
    }

    #[test]
    fn builds_sev_hashes_page_at_requested_offset() {
        let page = build_sev_hashes_page(&hex_of(0x55, 32), "", "console=ttyS0", 0x80)
            .expect("sev hashes page should build");
        assert_eq!(&page[..0x80], &[0u8; 0x80]);
        assert_eq!(&page[0x80..0x90], &GUID_LE_HASH_TABLE_HEADER);
        assert_eq!(u16::from_le_bytes([page[0x90], page[0x91]]), 168);
        assert_eq!(
            &page[0x92..0xa2],
            &GUID_LE_CMDLINE_ENTRY,
            "cmdline entry must be first"
        );
        let empty_hash = Sha256::digest(b"");
        assert_eq!(&page[0x80 + 68 + 18..0x80 + 68 + 50], empty_hash.as_slice());
    }

    #[test]
    fn vcpu_type_mapping_is_strict() {
        assert_eq!(
            vcpu_sig_from_type("EPYC-v4").unwrap(),
            amd_cpu_sig(23, 1, 2)
        );
        assert_eq!(
            vcpu_sig_from_type("epyc-genoa-v1").unwrap(),
            amd_cpu_sig(25, 17, 0)
        );
        let err = vcpu_sig_from_type("not-a-cpu").expect_err("unknown vcpu should reject");
        assert!(err.to_string().contains("unknown vcpu_type"));
    }

    #[test]
    fn accepts_recomputed_matching_measurement_and_rejects_mismatch() {
        let input = valid_input();
        let expected = compute_expected_measurement(&config(), &input).unwrap();
        assert_eq!(
            hex::encode(expected),
            "4753950048f296ea9cc36be3ba3e26f9cb014411188134d2ea40580a76edf277268cc46b67dfd213d1a7dfc9a9006e0f",
            "synthetic measurement vector should not drift silently"
        );
        validate_amd_snp_measurement_binding(Some(&config()), &expected, &input)
            .expect("matching recomputed binding should be accepted");

        let mut mismatched = expected;
        mismatched[0] ^= 0xff;
        let err = validate_amd_snp_measurement_binding(Some(&config()), &mismatched, &input)
            .expect_err("mismatched measurement must reject");
        assert!(err.to_string().contains("amd sev-snp measurement mismatch"));
    }

    #[test]
    fn builds_snp_boot_info_for_matching_measurement_only() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0xab; 64];

        let boot_info = build_amd_snp_boot_info(&config(), &verified, &chip_id, &input)
            .expect("matching measurement should build snp boot info");
        assert_eq!(boot_info.attestation_mode, AttestationMode::DstackAmdSevSnp);
        assert_eq!(boot_info.mr_aggregated, verified.to_vec());
        assert_eq!(boot_info.device_id, chip_id.to_vec());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
        assert_eq!(boot_info.compose_hash, vec![0x22; 32]);
        assert_eq!(boot_info.os_image_hash, vec![0x33; 32]);
        assert_eq!(boot_info.mr_system.len(), 32);
        assert_eq!(boot_info.key_provider_info.len(), 32);
        assert_eq!(boot_info.instance_id.len(), 32);
        assert_eq!(boot_info.tcb_status, "UpToDate");
        assert_ne!(boot_info.tcb_status, "snp-verified-basic-policy");
        assert!(boot_info.advisory_ids.is_empty());

        let mut mismatched = verified;
        mismatched[0] ^= 0xff;
        let err = build_amd_snp_boot_info(&config(), &mismatched, &chip_id, &input)
            .expect_err("mismatched measurement must not build boot info");
        assert!(err.to_string().contains("amd sev-snp measurement mismatch"));
    }

    #[test]
    fn builds_snp_boot_info_from_verified_attestation_report() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0xab; 64];
        let attestation = ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAmdSevSnp(
                ra_tls::attestation::SnpQuote {
                    report: Vec::new(),
                    cert_chain: Vec::new(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement: verified,
                    report_data: [0x42; 64],
                    chip_id,
                    tcb_info: dstack_attest::amd_sev_snp::AmdSnpTcbInfo::default(),
                    advisory_ids: Vec::new(),
                },
            ),
        };

        let boot_info =
            build_amd_snp_boot_info_from_verified_attestation(&config(), &attestation, &input)
                .expect("verified snp attestation should feed boot info helper");

        assert_eq!(boot_info.mr_aggregated, verified.to_vec());
        assert_eq!(boot_info.device_id, chip_id.to_vec());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
        assert_eq!(boot_info.tcb_status, "UpToDate");
    }

    #[test]
    fn verified_attestation_tcb_status_replaces_snp_placeholder() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0xbc; 64];
        let tcb = dstack_attest::amd_sev_snp::AmdSnpTcbVersion {
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };
        let stale_tcb = dstack_attest::amd_sev_snp::AmdSnpTcbVersion {
            microcode: 3,
            ..tcb
        };
        let attestation = ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAmdSevSnp(
                ra_tls::attestation::SnpQuote {
                    report: Vec::new(),
                    cert_chain: Vec::new(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement: verified,
                    report_data: [0x42; 64],
                    chip_id,
                    tcb_info: dstack_attest::amd_sev_snp::AmdSnpTcbInfo {
                        current: tcb,
                        reported: tcb,
                        committed: tcb,
                        launch: stale_tcb,
                    },
                    advisory_ids: vec!["SNP-TEST-ADVISORY".to_string()],
                },
            ),
        };

        let boot_info =
            build_amd_snp_boot_info_from_verified_attestation(&config(), &attestation, &input)
                .expect("verified snp attestation should feed boot info helper");

        assert_eq!(boot_info.tcb_status, "OutOfDate");
        assert_eq!(boot_info.advisory_ids, vec!["SNP-TEST-ADVISORY"]);
        assert_ne!(boot_info.tcb_status, "snp-verified-basic-policy");
        let policy = AmdSnpAuthPolicy::from_boot_info(&boot_info).unwrap();
        let mut up_to_date_only = policy.clone();
        up_to_date_only.allowed_tcb_statuses = vec!["UpToDate".to_string()];
        let err = validate_amd_snp_auth_policy(&boot_info, &up_to_date_only)
            .expect_err("out-of-date snp tcb must not satisfy up-to-date policy");
        assert!(
            err.to_string().contains("tcb_status is not allowed"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn builds_snp_boot_info_from_verified_attestation_and_vm_config_json() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0xab; 64];
        let attestation = ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAmdSevSnp(
                ra_tls::attestation::SnpQuote {
                    report: Vec::new(),
                    cert_chain: Vec::new(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement: verified,
                    report_data: [0x42; 64],
                    chip_id,
                    tcb_info: dstack_attest::amd_sev_snp::AmdSnpTcbInfo::default(),
                    advisory_ids: Vec::new(),
                },
            ),
        };
        let vm_config = serde_json::json!({
            "sev_snp_measurement": input,
        })
        .to_string();

        let boot_info = build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
            &config(),
            &attestation,
            &vm_config,
        )
        .expect("vm_config-carried snp measurement inputs should build boot info");

        assert_eq!(boot_info.mr_aggregated, verified.to_vec());
        assert_eq!(boot_info.device_id, chip_id.to_vec());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
    }

    #[test]
    fn verified_attestation_vm_config_helper_requires_snp_measurement_input() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let attestation = ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAmdSevSnp(
                ra_tls::attestation::SnpQuote {
                    report: Vec::new(),
                    cert_chain: Vec::new(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement: verified,
                    report_data: [0x42; 64],
                    chip_id: [0xab; 64],
                    tcb_info: dstack_attest::amd_sev_snp::AmdSnpTcbInfo::default(),
                    advisory_ids: Vec::new(),
                },
            ),
        };

        let err = build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
            &config(),
            &attestation,
            r#"{"os_image_hash":"0x00"}"#,
        )
        .expect_err("missing sev_snp_measurement must fail closed");
        assert!(
            err.to_string().contains("sev_snp_measurement is required"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn vm_config_measurement_parser_rejects_unknown_measurement_fields() {
        let mut measurement = serde_json::to_value(valid_input()).unwrap();
        measurement["unexpected"] = serde_json::json!(true);
        let vm_config = serde_json::json!({
            "sev_snp_measurement": measurement,
        })
        .to_string();

        let err = parse_measurement_input_from_vm_config(&vm_config)
            .expect_err("unknown measurement fields must reject");
        assert!(
            format!("{err:?}").contains("unknown field"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn vm_config_measurement_parser_bounds_ovmf_sections_during_deserialization() {
        let mut measurement = serde_json::to_value(valid_input()).unwrap();
        measurement["ovmf_sections"] = serde_json::Value::Array(
            (0..=MAX_OVMF_SECTIONS)
                .map(|_| {
                    serde_json::json!({
                        "gpa": 0x100000u64,
                        "size": 0x1000u64,
                        "section_type": 1u32,
                    })
                })
                .collect(),
        );
        let vm_config = serde_json::json!({
            "sev_snp_measurement": measurement,
        })
        .to_string();

        let err = parse_measurement_input_from_vm_config(&vm_config)
            .expect_err("oversized ovmf_sections must reject during parse");
        assert!(
            format!("{err:?}").contains("ovmf section count must not exceed"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn verified_attestation_helper_rejects_non_snp_reports() {
        let input = valid_input();
        let attestation = ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackGcpTdx,
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackGcpTdx,
        };

        let err =
            build_amd_snp_boot_info_from_verified_attestation(&config(), &attestation, &input)
                .expect_err("non-snp verified attestation must reject");
        assert!(
            err.to_string()
                .contains("verified attestation is not amd sev-snp"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn app_id_changes_launch_measurement_and_authorization_binding() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0xcd; 64];
        let boot_info = build_amd_snp_boot_info(&config(), &verified, &chip_id, &input).unwrap();

        let mut changed = input.clone();
        changed.app_id = hex_of(0x12, 20);
        let changed_measurement = compute_expected_measurement(&config(), &changed).unwrap();
        assert_ne!(
            changed_measurement, verified,
            "app_id must be launch-measured for SNP to match TDX app identity semantics"
        );
        let err = build_amd_snp_boot_info(&config(), &verified, &chip_id, &changed)
            .expect_err("stale measurement must reject changed app_id");
        assert!(err.to_string().contains("amd sev-snp measurement mismatch"));

        let changed_boot_info =
            build_amd_snp_boot_info(&config(), &changed_measurement, &chip_id, &changed).unwrap();

        assert_ne!(boot_info.app_id, changed_boot_info.app_id);
        assert_ne!(boot_info.instance_id, changed_boot_info.instance_id);
        assert_ne!(
            boot_info.key_provider_info,
            changed_boot_info.key_provider_info
        );
        assert_ne!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
        assert_ne!(boot_info.mr_system, changed_boot_info.mr_system);
    }

    #[test]
    fn measured_input_changes_reject_until_measurement_is_recomputed() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0xef; 64];
        let boot_info = build_amd_snp_boot_info(&config(), &verified, &chip_id, &input).unwrap();

        for mutate in [
            |i: &mut MeasurementInput| i.compose_hash = hex_of(0x23, 32),
            |i: &mut MeasurementInput| i.rootfs_hash = hex_of(0x34, 32),
            |i: &mut MeasurementInput| i.kernel_hash = hex_of(0x56, 32),
            |i: &mut MeasurementInput| i.vcpus = 3,
        ] {
            let mut changed = input.clone();
            mutate(&mut changed);
            let err = build_amd_snp_boot_info(&config(), &verified, &chip_id, &changed)
                .expect_err("stale verified measurement must reject changed measured input");
            assert!(err.to_string().contains("amd sev-snp measurement mismatch"));

            let changed_verified = compute_expected_measurement(&config(), &changed).unwrap();
            let changed_boot_info =
                build_amd_snp_boot_info(&config(), &changed_verified, &chip_id, &changed)
                    .expect("recomputed measurement should build boot info");
            assert_ne!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
            assert_ne!(boot_info.mr_system, changed_boot_info.mr_system);
        }
    }

    #[test]
    fn chip_id_maps_to_device_id_and_changes_chip_bound_digests() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let boot_info = build_amd_snp_boot_info(&config(), &verified, &[0x01; 64], &input).unwrap();
        let changed_boot_info =
            build_amd_snp_boot_info(&config(), &verified, &[0x02; 64], &input).unwrap();

        assert_eq!(boot_info.device_id, vec![0x01; 64]);
        assert_eq!(changed_boot_info.device_id, vec![0x02; 64]);
        assert_ne!(boot_info.device_id, changed_boot_info.device_id);
        assert_ne!(boot_info.instance_id, changed_boot_info.instance_id);
        assert_ne!(
            boot_info.key_provider_info,
            changed_boot_info.key_provider_info
        );
        assert_eq!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
        assert_eq!(boot_info.mr_system, changed_boot_info.mr_system);
    }

    #[test]
    #[ignore = "requires sev-snp-measure and an SNP-capable OVMF binary"]
    fn recomputation_matches_sev_snp_measure_live_golden_vector() {
        let ovmf_path = std::env::var("DSTACK_SEV_SNP_GOLDEN_OVMF")
            .unwrap_or_else(|_| "/opt/AMDSEV/usr/local/share/qemu/OVMF.fd".to_string());
        assert!(
            std::path::Path::new(&ovmf_path).exists(),
            "set DSTACK_SEV_SNP_GOLDEN_OVMF to an SNP-capable OVMF binary"
        );

        let dir = tempfile::tempdir().expect("tempdir should be available");
        let kernel_path = dir.path().join("kernel.bin");
        let initrd_path = dir.path().join("initrd.bin");
        let kernel_bytes = b"golden-kernel-for-dstack-sev-snp-measure\n";
        let initrd_bytes = b"golden-initrd-for-dstack-sev-snp-measure\n";
        std::fs::write(&kernel_path, kernel_bytes).expect("kernel fixture should be written");
        std::fs::write(&initrd_path, initrd_bytes).expect("initrd fixture should be written");

        let kernel_hash = hex::encode(Sha256::digest(kernel_bytes));
        let initrd_hash = hex::encode(Sha256::digest(initrd_bytes));
        let mut input = valid_input();
        input.docker_files_hash = None;
        input.ovmf_hash.clear();
        input.ovmf_sections.clear();
        input.kernel_hash = kernel_hash;
        input.initrd_hash = initrd_hash;
        input.vcpus = 2;
        input.vcpu_type = Some("EPYC-v4".to_string());

        let config = config_with_path(&ovmf_path);
        let recomputed = compute_expected_measurement(&config, &input)
            .expect("dstack recomputation should succeed");

        let append = format!(
            "console=ttyS0 loglevel=7 docker_compose_hash={} rootfs_hash={} app_id={}",
            input.compose_hash, input.rootfs_hash, input.app_id
        );
        let output = std::process::Command::new("sev-snp-measure")
            .args([
                "--mode",
                "snp",
                "--vcpus",
                "2",
                "--vcpu-type",
                "EPYC-v4",
                "--ovmf",
                &ovmf_path,
                "--kernel",
                kernel_path.to_str().unwrap(),
                "--initrd",
                initrd_path.to_str().unwrap(),
                "--append",
                &append,
                "--guest-features",
                "0x1",
                "--output-format",
                "hex",
            ])
            .output()
            .expect("sev-snp-measure should be installed");
        assert!(
            output.status.success(),
            "sev-snp-measure failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let tool_measurement = String::from_utf8(output.stdout)
            .expect("sev-snp-measure output should be utf8")
            .trim()
            .to_string();

        assert_eq!(hex::encode(recomputed), tool_measurement);
        assert_eq!(
            tool_measurement,
            "6497fb9f90dc4a322228a8a5eb14742e09067bc44c184c2068d583ef628b5bae8c6cf15d91fe1bc0b7a8cbcc575be370",
            "live sev-snp-measure golden vector should not drift silently"
        );
    }

    #[test]
    fn explicit_snp_auth_policy_accepts_only_exact_verified_identity() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0x42; 64];
        let boot_info = build_amd_snp_boot_info(&config(), &verified, &chip_id, &input).unwrap();
        let policy = AmdSnpAuthPolicy::from_boot_info(&boot_info)
            .expect("boot info should produce an exact SNP auth policy");

        validate_amd_snp_auth_policy(&boot_info, &policy)
            .expect("exact verified SNP identity should satisfy policy");

        let mut changed = boot_info;
        changed.compose_hash[0] ^= 0xff;
        let err = validate_amd_snp_auth_policy(&changed, &policy)
            .expect_err("compose hash mismatch must reject");
        assert!(err.to_string().contains("compose_hash is not allowed"));
    }

    #[test]
    fn explicit_snp_auth_policy_rejects_incomplete_or_unsafe_tcb() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0x24; 64];
        let boot_info = build_amd_snp_boot_info(&config(), &verified, &chip_id, &input).unwrap();
        let policy = AmdSnpAuthPolicy::from_boot_info(&boot_info).unwrap();

        let mut wrong_mode = boot_info.clone();
        wrong_mode.attestation_mode = AttestationMode::DstackTdx;
        let err = validate_amd_snp_auth_policy(&wrong_mode, &policy)
            .expect_err("non-SNP mode must reject");
        assert!(err
            .to_string()
            .contains("attestation mode is not amd sev-snp"));

        let mut wrong_status = boot_info.clone();
        wrong_status.tcb_status = "OutOfDate".to_string();
        let err = validate_amd_snp_auth_policy(&wrong_status, &policy)
            .expect_err("unexpected tcb status must reject");
        assert!(err.to_string().contains("tcb_status is not allowed"));

        let mut advisory = boot_info.clone();
        advisory.advisory_ids.push("SNP-TEST-ADVISORY".to_string());
        let err = validate_amd_snp_auth_policy(&advisory, &policy)
            .expect_err("unexpected advisory must reject by default");
        assert!(err.to_string().contains("advisory_id is not allowed"));
    }

    #[test]
    fn explicit_snp_auth_policy_rejects_partial_allowlists() {
        let input = valid_input();
        let verified = compute_expected_measurement(&config(), &input).unwrap();
        let chip_id = [0x35; 64];
        let boot_info = build_amd_snp_boot_info(&config(), &verified, &chip_id, &input).unwrap();

        for mutate in [
            |p: &mut AmdSnpAuthPolicy| p.allowed_measurements.clear(),
            |p: &mut AmdSnpAuthPolicy| p.allowed_app_ids.clear(),
            |p: &mut AmdSnpAuthPolicy| p.allowed_compose_hashes.clear(),
            |p: &mut AmdSnpAuthPolicy| p.allowed_os_image_hashes.clear(),
            |p: &mut AmdSnpAuthPolicy| p.allowed_device_ids.clear(),
            |p: &mut AmdSnpAuthPolicy| p.allowed_tcb_statuses.clear(),
        ] {
            let mut policy = AmdSnpAuthPolicy::from_boot_info(&boot_info).unwrap();
            mutate(&mut policy);
            let err = validate_amd_snp_auth_policy(&boot_info, &policy)
                .expect_err("partial SNP policy allowlist must reject");
            assert!(
                err.to_string().contains("is not allowed"),
                "unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_config() {
        let verified = [0xaa; 48];
        let err = validate_amd_snp_measurement_binding(None, &verified, &valid_input())
            .expect_err("missing config must fail closed");
        assert!(err
            .to_string()
            .contains("sev-snp measurement config is required"));
    }

    #[test]
    fn rejects_empty_or_malformed_binding_hashes() {
        let mut input = valid_input();
        input.app_id.clear();
        assert_rejects(input, "app_id must not be empty");

        let mut input = valid_input();
        input.app_id = hex_of(0x00, 20);
        assert_rejects(input, "app_id must not be all-zeros");

        let mut input = valid_input();
        input.compose_hash = "not hex".to_string();
        assert_rejects(input, "compose_hash must be valid hex");

        let mut input = valid_input();
        input.rootfs_hash = hex_of(0x33, 31);
        assert_rejects(input, "rootfs_hash must be 32 bytes");

        let mut input = valid_input();
        input.ovmf_hash = hex_of(0x44, 47);
        assert_rejects(input, "ovmf_hash must be 48 bytes");

        let mut input = valid_input();
        input.kernel_hash = hex_of(0x55, 31);
        assert_rejects(input, "kernel_hash must be 32 bytes");

        let mut input = valid_input();
        input.initrd_hash = hex_of(0x66, 31);
        assert_rejects(input, "initrd_hash must be 32 bytes");

        let mut input = valid_input();
        input.initrd_hash.clear();
        let expected = compute_expected_measurement(&config(), &input).unwrap();
        validate_amd_snp_measurement_binding(Some(&config()), &expected, &input)
            .expect("empty initrd hash should mean empty initrd");

        let mut input = valid_input();
        input.docker_files_hash = Some(String::new());
        assert_rejects(input, "docker_files_hash must not be empty");
    }

    #[test]
    fn rejects_missing_machine_binding_inputs() {
        let mut input = valid_input();
        input.vcpus = 0;
        assert_rejects(input, "vcpus must be greater than zero");

        let mut input = valid_input();
        input.vcpus = MAX_VCPUS + 1;
        assert_rejects(input, "vcpus must not exceed");

        let mut input = valid_input();
        input.vcpu_type = None;
        assert_rejects(input, "vcpu_type is required");

        let mut input = valid_input();
        input.vcpu_type = Some("mystery".to_string());
        assert_rejects(input, "unknown vcpu_type");

        let mut input = valid_input();
        input.ovmf_sections.clear();
        assert_rejects(
            input,
            "ovmf_sections are required when ovmf_path is not configured",
        );

        let mut input = valid_input();
        input.ovmf_sections.clear();
        input.ovmf_hash.clear();
        let verified = [0xaa; 48];
        let err = validate_amd_snp_measurement_binding(
            Some(&config_with_path("/path/that/does/not/exist/ovmf.fd")),
            &verified,
            &input,
        )
        .expect_err("configured ovmf_path should be used for recomputation");
        assert!(err.to_string().contains("cannot read ovmf binary"));

        let mut input = valid_input();
        input.ovmf_sections.clear();
        let err = validate_amd_snp_measurement_binding(
            Some(&config_with_path("/opt/amd/ovmf.fd")),
            &verified,
            &input,
        )
        .expect_err("request ovmf_hash must not override configured ovmf_path");
        assert!(err
            .to_string()
            .contains("ovmf_hash must be empty when ovmf_path is used"));
    }

    #[test]
    fn rejects_unsafe_machine_config() {
        let verified = [0xaa; 48];
        let err = validate_amd_snp_measurement_binding(
            Some(&SevSnpMeasureConfig {
                ovmf_path: None,
                guest_features: 0,
            }),
            &verified,
            &valid_input(),
        )
        .expect_err("zero guest_features must fail closed");
        assert!(err.to_string().contains("guest_features must be non-zero"));

        let mut input = valid_input();
        input.ovmf_sections[0].size = 0;
        assert_rejects(input, "ovmf section size must be greater than zero");

        let mut input = valid_input();
        input.ovmf_sections = vec![
            OvmfSectionParam {
                gpa: 0x1000,
                size: 0x1000,
                section_type: 1,
            };
            MAX_OVMF_SECTIONS + 1
        ];
        assert_rejects(input, "ovmf section count must not exceed");

        let mut input = valid_input();
        input.ovmf_sections[0].size = (MAX_OVMF_METADATA_PAGES + 1) * 4096;
        assert_rejects(input, "ovmf metadata page count must not exceed");

        let mut input = valid_input();
        input.ovmf_sections[0].section_type = 0xff;
        assert_rejects(input, "unknown ovmf section_type 0xff");

        let mut input = valid_input();
        input.ovmf_sections.retain(|s| s.section_type != 0x10);
        assert_rejects(
            input,
            "ovmf metadata does not include a snp_kernel_hashes section",
        );

        let mut input = valid_input();
        input.sev_hashes_table_gpa = 0;
        assert_rejects(input, "sev_hashes_table_gpa must be non-zero");

        let mut input = valid_input();
        input.sev_es_reset_eip = 0;
        assert_rejects(input, "sev_es_reset_eip must be non-zero");

        let mut input = valid_input();
        input.ovmf_sections.clear();
        let err =
            validate_amd_snp_measurement_binding(Some(&config_with_path("   ")), &verified, &input)
                .expect_err("blank ovmf_path must not bypass section metadata requirement");
        assert!(err
            .to_string()
            .contains("ovmf_sections are required when ovmf_path is not configured"));
    }
}
