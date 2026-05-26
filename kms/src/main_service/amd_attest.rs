// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed AMD SEV-SNP measurement/app binding validation.
//!
//! This module intentionally does not release keys and does not enable any AMD
//! KMS key-release endpoint. Until full in-KMS SNP measurement recomputation is
//! wired in, callers must provide the expected measurement from a trusted
//! recomputation path; this helper validates every required binding input and
//! compares that expected value to the hardware-verified report measurement.

#![allow(dead_code)]

use anyhow::{bail, Result};

use crate::config::SevSnpMeasureConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OvmfSectionParam {
    pub gpa: u64,
    pub size: u64,
    /// Raw OVMF SEV metadata section type:
    /// 1=SNP_SEC_MEMORY, 2=SNP_SECRETS, 3=CPUID, 4=SVSM_CAA,
    /// 0x10=SNP_KERNEL_HASHES.
    pub section_type: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MeasurementInput {
    pub app_id: String,
    pub compose_hash: String,
    pub rootfs_hash: String,
    pub ovmf_hash: String,
    pub kernel_hash: String,
    pub initrd_hash: String,
    pub vcpus: u32,
    pub vcpu_type: Option<String>,
    pub ovmf_sections: Vec<OvmfSectionParam>,
    /// Trusted expected SNP MEASUREMENT from an out-of-band recomputation or
    /// allowlist. This must never be copied from untrusted client input.
    pub trusted_expected_measurement: Option<String>,
}

pub(crate) fn validate_amd_snp_measurement_binding(
    config: Option<&SevSnpMeasureConfig>,
    verified_measurement: &[u8; 48],
    input: &MeasurementInput,
) -> Result<()> {
    let config = config.ok_or_else(|| anyhow::anyhow!("sev-snp measurement config is required"))?;
    if config.guest_features == 0 {
        bail!("guest_features must be non-zero");
    }

    decode_required_hex("app_id", &input.app_id, 20)?;
    decode_required_hex("compose_hash", &input.compose_hash, 32)?;
    decode_required_hex("rootfs_hash", &input.rootfs_hash, 32)?;
    decode_required_hex("ovmf_hash", &input.ovmf_hash, 48)?;
    decode_required_hex("kernel_hash", &input.kernel_hash, 32)?;
    decode_required_hex("initrd_hash", &input.initrd_hash, 32)?;

    if input.vcpus == 0 {
        bail!("vcpus must be greater than zero");
    }
    match input.vcpu_type.as_deref() {
        Some(vcpu_type) if !vcpu_type.trim().is_empty() => {}
        _ => bail!("vcpu_type is required"),
    }
    if config
        .ovmf_path
        .as_deref()
        .unwrap_or_default()
        .trim()
        .is_empty()
        && input.ovmf_sections.is_empty()
    {
        bail!("ovmf_sections are required when ovmf_path is not configured");
    }
    for section in &input.ovmf_sections {
        if section.size == 0 {
            bail!("ovmf section size must be greater than zero");
        }
        if !matches!(section.section_type, 1 | 2 | 3 | 4 | 0x10) {
            bail!("unknown ovmf section_type {:#x}", section.section_type);
        }
    }

    let expected_measurement = input
        .trusted_expected_measurement
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("trusted_expected_measurement is required"))?;
    let expected_measurement =
        decode_required_hex("trusted_expected_measurement", expected_measurement, 48)?;
    if expected_measurement.as_slice() != verified_measurement {
        bail!("amd sev-snp measurement mismatch");
    }

    Ok(())
}

fn decode_required_hex(name: &str, value: &str, expected_len: usize) -> Result<Vec<u8>> {
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    let bytes = hex::decode(value).map_err(|_| anyhow::anyhow!("{name} must be valid hex"))?;
    if bytes.len() != expected_len {
        bail!("{name} must be {expected_len} bytes");
    }
    Ok(bytes)
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

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn valid_input() -> MeasurementInput {
        MeasurementInput {
            app_id: hex_of(0x11, 20),
            compose_hash: hex_of(0x22, 32),
            rootfs_hash: hex_of(0x33, 32),
            ovmf_hash: hex_of(0x44, 48),
            kernel_hash: hex_of(0x55, 32),
            initrd_hash: hex_of(0x66, 32),
            vcpus: 2,
            vcpu_type: Some("epyc-v4".to_string()),
            ovmf_sections: vec![OvmfSectionParam {
                gpa: 0x100000,
                size: 0x200000,
                section_type: 1,
            }],
            trusted_expected_measurement: Some(hex_of(0xaa, 48)),
        }
    }

    fn config_with_path(path: &str) -> SevSnpMeasureConfig {
        SevSnpMeasureConfig {
            ovmf_path: Some(path.to_string()),
            guest_features: 1,
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
    fn accepts_fully_bound_matching_measurement() {
        let verified = [0xaa; 48];
        validate_amd_snp_measurement_binding(Some(&config()), &verified, &valid_input())
            .expect("valid binding should be accepted");
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
    }

    #[test]
    fn rejects_missing_machine_binding_inputs() {
        let mut input = valid_input();
        input.vcpus = 0;
        assert_rejects(input, "vcpus must be greater than zero");

        let mut input = valid_input();
        input.vcpu_type = None;
        assert_rejects(input, "vcpu_type is required");

        let mut input = valid_input();
        input.ovmf_sections.clear();
        assert_rejects(
            input,
            "ovmf_sections are required when ovmf_path is not configured",
        );

        let mut input = valid_input();
        input.ovmf_sections.clear();
        let verified = [0xaa; 48];
        validate_amd_snp_measurement_binding(
            Some(&config_with_path("/opt/amd/ovmf.fd")),
            &verified,
            &input,
        )
        .expect("configured ovmf_path should allow sections to be loaded later");
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
        input.ovmf_sections[0].section_type = 0xff;
        assert_rejects(input, "unknown ovmf section_type 0xff");

        let mut input = valid_input();
        input.ovmf_sections.clear();
        let err =
            validate_amd_snp_measurement_binding(Some(&config_with_path("   ")), &verified, &input)
                .expect_err("blank ovmf_path must not bypass section metadata requirement");
        assert!(err
            .to_string()
            .contains("ovmf_sections are required when ovmf_path is not configured"));
    }

    #[test]
    fn rejects_missing_or_mismatched_measurement() {
        let mut input = valid_input();
        input.trusted_expected_measurement = None;
        assert_rejects(input, "trusted_expected_measurement is required");

        let mut input = valid_input();
        input.trusted_expected_measurement = Some(hex_of(0xaa, 47));
        assert_rejects(input, "trusted_expected_measurement must be 48 bytes");

        let mut input = valid_input();
        input.trusted_expected_measurement = Some(hex_of(0xbb, 48));
        assert_rejects(input, "amd sev-snp measurement mismatch");
    }
}
