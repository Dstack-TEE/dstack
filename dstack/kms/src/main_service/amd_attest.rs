// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed AMD SEV-SNP measurement/app binding validation.
//!
//! This module does not release keys by itself. It recomputes the expected SNP
//! MEASUREMENT from the self-contained launch inputs, then compares the
//! recomputed value to the hardware-verified report measurement. KMS release
//! paths must apply their own explicit local release gate after auth succeeds.
//!
//! Important: this is launch measurement binding plus HOST_DATA app binding,
//! not a complete authorization decision. Launch `MEASUREMENT` covers the SNP
//! boot inputs; app identity is bound by checking that the verified report
//! `HOST_DATA` equals the attached MrConfigV3 document hash. Do not use this
//! helper by itself to release app keys.
//!
//! The launch-measurement recomputation and `os_image_hash` derivation live in
//! `dstack_mr::sev` so the KMS (key release) and the verifier (attestation
//! verification) compute identical values from a single source of truth. The
//! pieces below materialize the KMS-specific `BootInfo` passed to the external
//! auth API.

#![allow(dead_code)]

use anyhow::{bail, Context, Result};
use dstack_types::{mr_config::MrConfigV3, KeyProviderInfo};
use ra_tls::attestation::{AttestationMode, VerifiedAttestation};
use sha2::{Digest, Sha256};

use super::upgrade_authority::BootInfo;

// Shared SEV-SNP launch-measurement primitives now live in `dstack-mr::sev`
// (single source of truth shared with `dstack-verifier`). Re-export the symbols
// the rest of the KMS and its tests reference so existing call sites keep
// working. `allow(unused_imports)` because some are consumed only by tests.
#[allow(unused_imports)]
pub(crate) use dstack_mr::sev::{
    compute_expected_measurement, parse_snp_inputs_from_vm_config, snp_mr_aggregated_digest,
    validate_measurement_input, validate_snp_mr_config_binding, MeasurementInput, OvmfSectionParam,
    SnpLaunchInputs, MAX_OVMF_METADATA_PAGES, MAX_OVMF_SECTIONS, MAX_VCPUS,
};

pub(crate) fn validate_amd_snp_measurement_binding(
    verified_measurement: &[u8; 48],
    input: &MeasurementInput,
) -> Result<()> {
    validate_measurement_input(input)?;

    let expected_measurement = compute_expected_measurement(input)?;
    if expected_measurement.as_slice() != verified_measurement {
        bail!("amd sev-snp measurement mismatch");
    }

    Ok(())
}

/// Builds a deterministic authorization `BootInfo` for an already-verified AMD
/// SEV-SNP report without releasing KMS key material by itself.
///
/// This helper first recomputes and validates the QEMU SNP launch measurement.
/// `mr_system` is `sha256(MEASUREMENT)`, `mr_aggregated` is
/// `sha256(MEASUREMENT || HOST_DATA)`, and `device_id` is the
/// hardware-verified 64-byte SNP `chip_id`. `app_id`, `compose_hash`,
/// `instance_id`, and key provider identity come from the MrConfigV3 document
/// bound by HOST_DATA.
///
/// Keeping these values explicit lets authorization/release policy inspect
/// exactly which SNP-specific inputs were bound before any sensitive output path
/// returns key material.
#[cfg(test)]
pub(crate) fn build_amd_snp_boot_info(
    verified_measurement: &[u8; 48],
    verified_chip_id: &[u8; 64],
    input: &MeasurementInput,
) -> Result<BootInfo> {
    let mr_config = test_mr_config(vec![0x11; 20], vec![0x22; 32]);
    let mr_config_document = mr_config.to_canonical_json();
    let os_image_hash = test_os_image_hash(input)?;
    let host_data = MrConfigV3::snp_host_data_from_document(&mr_config_document);
    build_amd_snp_boot_info_with_tcb_status(
        verified_measurement,
        &host_data,
        verified_chip_id,
        "UpToDate",
        &[],
        input,
        &os_image_hash,
        &mr_config_document,
    )
}

#[allow(clippy::too_many_arguments)]
fn build_amd_snp_boot_info_with_tcb_status(
    verified_measurement: &[u8; 48],
    verified_host_data: &[u8; 32],
    verified_chip_id: &[u8; 64],
    tcb_status: &str,
    advisory_ids: &[String],
    input: &MeasurementInput,
    os_image_hash: &[u8],
    mr_config_document: &str,
) -> Result<BootInfo> {
    validate_amd_snp_measurement_binding(verified_measurement, input)?;
    let mr_config = validate_snp_mr_config_binding(verified_host_data, mr_config_document)?;

    let mr_system = Sha256::digest(verified_measurement).to_vec();
    let mr_aggregated = snp_mr_aggregated_digest(verified_measurement, verified_host_data);
    let key_provider_info = mr_config_key_provider_info(&mr_config)?;

    Ok(BootInfo {
        attestation_mode: AttestationMode::DstackAmdSevSnp,
        mr_aggregated,
        os_image_hash: os_image_hash.to_vec(),
        mr_system,
        app_id: mr_config.app_id.clone(),
        compose_hash: mr_config.compose_hash.clone(),
        instance_id: mr_config.instance_id.clone(),
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
    attestation: &VerifiedAttestation,
    input: &MeasurementInput,
    mr_config_document: &str,
    os_image_hash: &[u8],
) -> Result<BootInfo> {
    let verified = attestation
        .report
        .amd_snp_report()
        .ok_or_else(|| anyhow::anyhow!("verified attestation is not amd sev-snp"))?;
    build_amd_snp_boot_info_with_tcb_status(
        &verified.measurement,
        &verified.host_data,
        &verified.chip_id,
        verified.tcb_info.tcb_status(),
        &verified.advisory_ids,
        input,
        os_image_hash,
        mr_config_document,
    )
}

/// Parses SNP launch-measurement inputs from the KMS request `vm_config` and
/// builds helper-only SNP `BootInfo` from an already verified attestation.
///
/// The field is intentionally explicit (`sev_snp_measurement`) so missing SNP
/// launch inputs fail closed instead of falling back to TDX event-log decoding.
pub(crate) fn build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
    attestation: &VerifiedAttestation,
    vm_config: &str,
) -> Result<BootInfo> {
    let SnpLaunchInputs {
        input,
        os_image_hash,
        mr_config_document,
        ..
    } = parse_snp_inputs_from_vm_config(vm_config)?;
    build_amd_snp_boot_info_from_verified_attestation(
        attestation,
        &input,
        &mr_config_document,
        &os_image_hash,
    )
}

fn parse_measurement_input_from_vm_config(vm_config: &str) -> Result<MeasurementInput> {
    Ok(parse_snp_inputs_from_vm_config(vm_config)?.input)
}

fn mr_config_key_provider_info(mr_config: &MrConfigV3) -> Result<Vec<u8>> {
    serde_json::to_vec(&KeyProviderInfo::new(
        mr_config.key_provider_name().to_string(),
        hex::encode(&mr_config.key_provider_id),
    ))
    .context("failed to serialize key provider info")
}

#[cfg(test)]
fn test_mr_config(app_id: Vec<u8>, compose_hash: Vec<u8>) -> MrConfigV3 {
    let instance_id = Sha256::digest(&app_id)[..20].to_vec();
    MrConfigV3::new(
        app_id,
        compose_hash,
        dstack_types::KeyProviderKind::None,
        Vec::new(),
        instance_id,
    )
}

#[cfg(test)]
fn test_snp_measurement_document(
    input: &MeasurementInput,
) -> Result<dstack_mr::sev::SnpMeasurementDocument> {
    let measurement = dstack_mr::sev::sev_os_image_measurement_from_input(input)?.to_cbor_vec();
    let measurement_hash = Sha256::digest(&measurement);
    let sha256sum = format!(
        "{}  {}\n",
        hex::encode(measurement_hash),
        dstack_types::SNP_MEASUREMENT_FILENAME
    )
    .into_bytes();
    Ok(dstack_mr::sev::SnpMeasurementDocument {
        checksum_file: sha256sum,
        measurement,
        vcpus: input.vcpus,
        vcpu_type: input.vcpu_type.clone(),
        guest_features: input.guest_features,
    })
}

#[cfg(test)]
fn test_os_image_hash(input: &MeasurementInput) -> Result<Vec<u8>> {
    Ok(dstack_types::image_hash_from_sha256sum(
        &test_snp_measurement_document(input)?.checksum_file,
    )
    .to_vec())
}

#[cfg(test)]
fn test_snp_measurement_document_json(input: &MeasurementInput) -> Result<String> {
    serde_json::to_string(&test_snp_measurement_document(input)?)
        .context("failed to serialize test SNP measurement document")
}

#[cfg(test)]
fn test_vm_config(input: &MeasurementInput, mr_config: &MrConfigV3) -> Result<String> {
    Ok(serde_json::json!({
        "os_image_hash": hex::encode(test_os_image_hash(input)?),
        "sev_snp_measurement": test_snp_measurement_document_json(input)?,
        "mr_config": mr_config.to_canonical_json(),
    })
    .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn valid_input() -> MeasurementInput {
        let rootfs_hash = hex_of(0x33, 32);
        MeasurementInput {
            base_cmdline: format!("console=ttyS0 dstack.rootfs_hash={rootfs_hash}"),
            ovmf_hash: hex_of(0x44, 48),
            kernel_hash: hex_of(0x55, 32),
            initrd_hash: hex_of(0x66, 32),
            sev_hashes_table_gpa: 0x80_1000,
            sev_es_reset_eip: 0xffff_fff0,
            vcpus: 2,
            vcpu_type: Some("epyc-v4".to_string()),
            guest_features: 1,
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

    fn valid_mr_config(_input: &MeasurementInput) -> Result<MrConfigV3> {
        Ok(test_mr_config(vec![0x11; 20], vec![0x22; 32]))
    }

    fn measurement_document(input: &MeasurementInput) -> String {
        test_snp_measurement_document_json(input).expect("measurement input should serialize")
    }

    fn verified_snp_attestation(
        measurement: [u8; 48],
        chip_id: [u8; 64],
        mr_config: &MrConfigV3,
    ) -> ra_tls::attestation::VerifiedAttestation {
        ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAmdSevSnp(
                ra_tls::attestation::SnpQuote {
                    report: Vec::new(),
                    cert_chain: Vec::new(),
                    mr_config: mr_config.to_canonical_json(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement,
                    report_data: [0x42; 64],
                    host_data: MrConfigV3::snp_host_data_from_document(
                        &mr_config.to_canonical_json(),
                    ),
                    chip_id,
                    tcb_info: dstack_attest::amd_sev_snp::AmdSnpTcbInfo::default(),
                    advisory_ids: Vec::new(),
                },
            ),
        }
    }

    fn assert_rejects(input: MeasurementInput, msg: &str) {
        let verified = [0xaa; 48];
        let err = validate_amd_snp_measurement_binding(&verified, &input)
            .expect_err("binding should reject invalid input");
        assert!(
            err.to_string().contains(msg),
            "expected error containing {msg:?}, got {err:?}"
        );
    }

    #[test]
    fn accepts_recomputed_matching_measurement_and_rejects_mismatch() {
        let input = valid_input();
        let expected = compute_expected_measurement(&input).unwrap();
        assert_eq!(
            hex::encode(expected),
            "88b48404819692fd2a5068f1a07bf1973bbcaa1314adc670705f9388762a759faf889f8e2c71fe1ec892554415257960",
            "synthetic measurement vector should not drift silently"
        );
        validate_amd_snp_measurement_binding(&expected, &input)
            .expect("matching recomputed binding should be accepted");

        let mut mismatched = expected;
        mismatched[0] ^= 0xff;
        let err = validate_amd_snp_measurement_binding(&mismatched, &input)
            .expect_err("mismatched measurement must reject");
        assert!(err.to_string().contains("amd sev-snp measurement mismatch"));
    }

    #[test]
    fn builds_snp_boot_info_for_matching_measurement_only() {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let chip_id = [0xab; 64];

        let boot_info = build_amd_snp_boot_info(&verified, &chip_id, &input)
            .expect("matching measurement should build snp boot info");
        assert_eq!(boot_info.attestation_mode, AttestationMode::DstackAmdSevSnp);
        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(boot_info.device_id, chip_id.to_vec());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
        assert_eq!(boot_info.compose_hash, vec![0x22; 32]);
        assert_eq!(boot_info.os_image_hash, test_os_image_hash(&input).unwrap());
        assert_eq!(boot_info.mr_system.len(), 32);
        assert!(!boot_info.key_provider_info.is_empty());
        assert_eq!(boot_info.instance_id.len(), 20);
        assert_eq!(boot_info.tcb_status, "UpToDate");
        assert_ne!(boot_info.tcb_status, "snp-verified-basic-policy");
        assert!(boot_info.advisory_ids.is_empty());

        let mut mismatched = verified;
        mismatched[0] ^= 0xff;
        let err = build_amd_snp_boot_info(&mismatched, &chip_id, &input)
            .expect_err("mismatched measurement must not build boot info");
        assert!(err.to_string().contains("amd sev-snp measurement mismatch"));
    }

    #[test]
    fn builds_snp_boot_info_from_verified_attestation_report() -> Result<()> {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let chip_id = [0xab; 64];
        let mr_config = valid_mr_config(&input)?;
        let mr_config_document = mr_config.to_canonical_json();
        let attestation = verified_snp_attestation(verified, chip_id, &mr_config);

        let boot_info = build_amd_snp_boot_info_from_verified_attestation(
            &attestation,
            &input,
            &mr_config_document,
            &test_os_image_hash(&input)?,
        )
        .expect("verified snp attestation should feed boot info helper");

        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(boot_info.device_id, chip_id.to_vec());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
        assert_eq!(boot_info.tcb_status, "UpToDate");
        Ok(())
    }

    #[test]
    fn verified_attestation_tcb_status_replaces_snp_placeholder() -> Result<()> {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let chip_id = [0xbc; 64];
        let mr_config = valid_mr_config(&input)?;
        let mr_config_document = mr_config.to_canonical_json();
        let tcb = dstack_attest::amd_sev_snp::AmdSnpTcbVersion {
            fmc: None,
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
                    mr_config: mr_config_document.clone(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement: verified,
                    report_data: [0x42; 64],
                    host_data: MrConfigV3::snp_host_data_from_document(&mr_config_document),
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

        let boot_info = build_amd_snp_boot_info_from_verified_attestation(
            &attestation,
            &input,
            &mr_config_document,
            &test_os_image_hash(&input)?,
        )
        .expect("verified snp attestation should feed boot info helper");

        assert_eq!(boot_info.tcb_status, "OutOfDate");
        assert_eq!(boot_info.advisory_ids, vec!["SNP-TEST-ADVISORY"]);
        assert_ne!(boot_info.tcb_status, "snp-verified-basic-policy");
        Ok(())
    }

    #[test]
    fn builds_snp_boot_info_from_verified_attestation_and_vm_config_json() -> Result<()> {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let chip_id = [0xab; 64];
        let mr_config = valid_mr_config(&input)?;
        let attestation = verified_snp_attestation(verified, chip_id, &mr_config);
        let vm_config = test_vm_config(&input, &mr_config)?;

        let boot_info = build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
            &attestation,
            &vm_config,
        )
        .expect("vm_config-carried snp measurement inputs should build boot info");

        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(boot_info.device_id, chip_id.to_vec());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
        Ok(())
    }

    #[test]
    fn verified_attestation_vm_config_helper_requires_snp_measurement_input() -> Result<()> {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_mr_config(&input)?;
        let attestation = verified_snp_attestation(verified, [0xab; 64], &mr_config);

        let err = build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
            &attestation,
            &serde_json::json!({ "os_image_hash": hex::encode([0u8; 32]) }).to_string(),
        )
        .expect_err("missing sev_snp_measurement must fail closed");
        assert!(
            err.to_string().contains("sev_snp_measurement is required"),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn vm_config_measurement_parser_rejects_unknown_measurement_fields() {
        let input = valid_input();
        let mr_config = valid_mr_config(&input).unwrap();
        let mut measurement =
            serde_json::to_value(test_snp_measurement_document(&input).unwrap()).unwrap();
        measurement["unexpected"] = serde_json::json!(true);
        let vm_config = serde_json::json!({
            "os_image_hash": hex::encode(test_os_image_hash(&input).unwrap()),
            "sev_snp_measurement": measurement.to_string(),
            "mr_config": mr_config.to_canonical_json(),
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
        let input = valid_input();
        let mr_config = valid_mr_config(&input).unwrap();
        let mut image = dstack_mr::sev::sev_os_image_measurement_from_input(&input).unwrap();
        image.ovmf_sections = (0..=MAX_OVMF_SECTIONS)
            .map(|_| dstack_types::OvmfSection {
                gpa: 0x100000,
                size: 0x1000,
                section_type: 1,
            })
            .collect();
        let measurement_cbor = image.to_cbor_vec();
        let sha256sum = format!(
            "{}  {}\n",
            hex::encode(Sha256::digest(&measurement_cbor)),
            dstack_types::SNP_MEASUREMENT_FILENAME
        )
        .into_bytes();
        let document = dstack_mr::sev::SnpMeasurementDocument {
            checksum_file: sha256sum,
            measurement: measurement_cbor,
            vcpus: input.vcpus,
            vcpu_type: input.vcpu_type.clone(),
            guest_features: input.guest_features,
        };
        let vm_config = serde_json::json!({
            "os_image_hash": hex::encode(dstack_types::image_hash_from_sha256sum(&document.checksum_file)),
            "sev_snp_measurement": serde_json::to_string(&document).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
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
    fn verified_attestation_helper_rejects_non_snp_reports() -> Result<()> {
        let input = valid_input();
        let attestation = ra_tls::attestation::VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackNitroEnclave(
                ra_tls::attestation::DstackNitroQuote {
                    nsm_quote: Vec::new(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackNitroEnclave(
                ra_tls::attestation::NitroVerifiedReport {
                    module_id: String::new(),
                    pcrs: ra_tls::attestation::NitroPcrs {
                        pcr0: Vec::new(),
                        pcr1: Vec::new(),
                        pcr2: Vec::new(),
                    },
                    user_data: Vec::new(),
                    timestamp: 0,
                },
            ),
        };

        let mr_config = valid_mr_config(&input)?;
        let mr_config_document = mr_config.to_canonical_json();
        let err = build_amd_snp_boot_info_from_verified_attestation(
            &attestation,
            &input,
            &mr_config_document,
            &test_os_image_hash(&input)?,
        )
        .expect_err("non-snp verified attestation must reject");
        assert!(
            err.to_string()
                .contains("verified attestation is not amd sev-snp"),
            "unexpected error: {err:?}"
        );
        Ok(())
    }

    #[test]
    fn app_id_changes_host_data_and_authorization_binding() -> Result<()> {
        let input = valid_input();
        let verified = compute_expected_measurement(&input)?;
        let chip_id = [0xcd; 64];
        let mr_config = test_mr_config(vec![0x11; 20], vec![0x22; 32]);
        let mr_config_document = mr_config.to_canonical_json();
        let os_image_hash = test_os_image_hash(&input)?;
        let host_data = MrConfigV3::snp_host_data_from_document(&mr_config_document);
        let boot_info = build_amd_snp_boot_info_with_tcb_status(
            &verified,
            &host_data,
            &chip_id,
            "UpToDate",
            &[],
            &input,
            &os_image_hash,
            &mr_config_document,
        )?;

        let changed_mr_config = test_mr_config(vec![0x12; 20], vec![0x22; 32]);
        let changed_mr_config_document = changed_mr_config.to_canonical_json();
        let changed_host_data =
            MrConfigV3::snp_host_data_from_document(&changed_mr_config_document);
        let changed_measurement = compute_expected_measurement(&input)?;
        assert_eq!(
            changed_measurement, verified,
            "app_id must not be added to the SNP measured cmdline"
        );
        let changed_boot_info = build_amd_snp_boot_info_with_tcb_status(
            &verified,
            &changed_host_data,
            &chip_id,
            "UpToDate",
            &[],
            &input,
            &os_image_hash,
            &changed_mr_config_document,
        )?;

        assert_ne!(boot_info.app_id, changed_boot_info.app_id);
        assert_ne!(boot_info.instance_id, changed_boot_info.instance_id);
        // app_id is an authorization input, not part of the OS image identity.
        assert_eq!(
            boot_info.os_image_hash, changed_boot_info.os_image_hash,
            "app_id must not change the os_image_hash"
        );
        assert_ne!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
        assert_eq!(boot_info.mr_system, changed_boot_info.mr_system);
        Ok(())
    }

    #[test]
    fn measured_input_changes_reject_until_measurement_is_recomputed() {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let chip_id = [0xef; 64];
        let boot_info = build_amd_snp_boot_info(&verified, &chip_id, &input).unwrap();

        // (mutation, is_image_field): both change the SNP measurement (so a stale
        // verified measurement rejects), but only image fields change os_image_hash.
        let cases: [(fn(&mut MeasurementInput), bool); 2] = [
            (|i| i.kernel_hash = hex_of(0x56, 32), true),
            (|i| i.vcpus = 3, false),
        ];
        for (mutate, is_image_field) in cases {
            let mut changed = input.clone();
            mutate(&mut changed);
            let err = build_amd_snp_boot_info(&verified, &chip_id, &changed)
                .expect_err("stale verified measurement must reject changed measured input");
            assert!(err.to_string().contains("amd sev-snp measurement mismatch"));

            let changed_verified = compute_expected_measurement(&changed).unwrap();
            let changed_boot_info = build_amd_snp_boot_info(&changed_verified, &chip_id, &changed)
                .expect("recomputed measurement should build boot info");
            assert_ne!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
            assert_ne!(boot_info.mr_system, changed_boot_info.mr_system);
            if is_image_field {
                assert_ne!(
                    boot_info.os_image_hash, changed_boot_info.os_image_hash,
                    "image fields must change os_image_hash"
                );
            } else {
                assert_eq!(
                    boot_info.os_image_hash, changed_boot_info.os_image_hash,
                    "per-deployment fields (vcpus) must not change os_image_hash"
                );
            }
        }
    }

    #[test]
    fn chip_id_maps_to_device_id_and_changes_chip_bound_digests() {
        let input = valid_input();
        let verified = compute_expected_measurement(&input).unwrap();
        let boot_info = build_amd_snp_boot_info(&verified, &[0x01; 64], &input).unwrap();
        let changed_boot_info = build_amd_snp_boot_info(&verified, &[0x02; 64], &input).unwrap();

        assert_eq!(boot_info.device_id, vec![0x01; 64]);
        assert_eq!(changed_boot_info.device_id, vec![0x02; 64]);
        assert_ne!(boot_info.device_id, changed_boot_info.device_id);
        assert_eq!(boot_info.instance_id, changed_boot_info.instance_id);
        assert_eq!(
            boot_info.key_provider_info,
            changed_boot_info.key_provider_info
        );
        assert_eq!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
        assert_eq!(boot_info.mr_system, changed_boot_info.mr_system);
    }

    #[test]
    fn accepts_self_contained_measurement_input() {
        let input = valid_input();
        let expected = compute_expected_measurement(&input).unwrap();
        validate_amd_snp_measurement_binding(&expected, &input)
            .expect("self-contained SNP launch input should validate");
    }

    #[test]
    fn rejects_empty_or_malformed_binding_hashes() {
        let mut input = valid_input();
        input.base_cmdline = format!("console=ttyS0 dstack.rootfs_hash={}", hex_of(0x33, 31));
        assert_rejects(input, "dstack.rootfs_hash must be 32 bytes");

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
        let expected = compute_expected_measurement(&input).unwrap();
        validate_amd_snp_measurement_binding(&expected, &input)
            .expect("empty initrd hash should mean empty initrd");
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
        assert_rejects(input, "ovmf_sections are required for amd sev-snp");
    }

    #[test]
    fn rejects_unsafe_machine_config() {
        let mut input = valid_input();
        input.guest_features = 0;
        assert_rejects(input, "guest_features must be non-zero");

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
    }
}
