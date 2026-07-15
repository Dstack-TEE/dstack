// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Integration test: verify a real AMD SEV-SNP attestation end-to-end, offline.
//!
//! The fixtures were captured from a live dstack SEV-SNP CVM (see
//! `sev_snp_fixture.README.md`). Verification is fully offline: the VCEK and ASK
//! are bundled so the test never reaches AMD KDS, and the AMD root (ARK) is the
//! one built into `sev-snp-qvl`.

use dstack_attest::attestation::{AttestationQuote, VersionedAttestation};
use dstack_mr::sev::{sev_os_image_measurement_from_input, verify_sev_launch, MeasurementInput};
use dstack_types::{mr_config::MrConfigV3, KeyProviderKind};
use sev_snp_qvl::{verify_amd_snp_attestation, AmdSnpAttestationInput, VerifiedAmdSnpReport};
use sha2::{Digest, Sha256};

/// Real SEV-SNP attestation captured from a dstack CVM (VersionedAttestation, SCALE V0).
const SEV_ATTESTATION_BIN: &[u8] = include_bytes!("sev_snp_attestation.bin");
/// AMD SEV intermediate (ASK / CN=SEV-Milan) for the chip that produced the report.
const SEV_ASK_PEM: &[u8] = include_bytes!("sev_snp_ask.pem");
/// Per-chip VCEK (CN=SEV-VCEK) for the report's chip_id + reported TCB.
const SEV_VCEK_PEM: &[u8] = include_bytes!("sev_snp_vcek.pem");

/// report_data marker passed to `dstack-util quote-report` when capturing the fixture.
const REPORT_DATA_MARKER: &[u8] = b"attest-test-fixture-2026";

fn expected_report_data() -> [u8; 64] {
    let mut rd = [0u8; 64];
    rd[..REPORT_DATA_MARKER.len()].copy_from_slice(REPORT_DATA_MARKER);
    rd
}

#[test]
fn verify_sev_snp_attestation_bin() {
    // Decode the VersionedAttestation captured from the CVM.
    let versioned =
        VersionedAttestation::from_scale(SEV_ATTESTATION_BIN).expect("decode VersionedAttestation");
    let VersionedAttestation::V0 { attestation } = versioned else {
        panic!("expected V0 attestation");
    };

    // The outer report_data carries our capture marker.
    assert_eq!(
        attestation.report_data,
        expected_report_data(),
        "outer attestation report_data marker"
    );

    let AttestationQuote::DstackAmdSevSnp(quote) = &attestation.quote else {
        panic!("expected an AMD SEV-SNP quote");
    };
    assert_eq!(quote.report.len(), 1184, "raw SNP report length");
    assert!(
        !quote.mr_config.is_empty(),
        "SEV-SNP quote must carry the mr_config document"
    );

    // Offline hardware verification: ARK (builtin) -> ASK -> VCEK -> report signature.
    let verified = verify_amd_snp_attestation(&AmdSnpAttestationInput {
        report: &quote.report,
        ask_pem: SEV_ASK_PEM,
        vcek_pem: SEV_VCEK_PEM,
    })
    .expect("verify SEV-SNP attestation offline");

    // The signed report_data matches the marker we requested.
    assert_eq!(
        verified.report_data,
        expected_report_data(),
        "signed report_data marker"
    );
    // A real launch measurement is present.
    assert_ne!(verified.measurement, [0u8; 48], "measurement must be set");
    // HOST_DATA binds the mr_config document; it must be non-zero for a dstack CVM.
    assert_ne!(verified.host_data, [0u8; 32], "host_data must be set");

    println!("measurement: {}", hex::encode(verified.measurement));
    println!("host_data:   {}", hex::encode(verified.host_data));
    println!("chip_id:     {}", hex::encode(verified.chip_id));
    println!("tcb_status:  {}", verified.tcb_info.tcb_status());

    // End-to-end OS image binding, fully offline — exactly what dstack-verifier
    // does after the hardware report verifies. Recompute the launch measurement
    // from the self-contained `sev_snp_measurement` document embedded in the
    // attestation config, require it to equal the hardware MEASUREMENT, require
    // HOST_DATA to bind the MrConfigV3 document, and verify the unified
    // os_image_hash against sha256sum.txt + measurement.snp.cbor.
    let config = upgrade_snp_config_for_split_measurement(&attestation.config);
    let binding =
        dstack_mr::sev::verify_sev_launch(&verified.measurement, &verified.host_data, &config)
            .expect("recompute SEV launch + verify os_image_hash from the attestation config");

    // The os_image_hash matches the value advertised in the CVM config.
    let config_value: serde_json::Value = serde_json::from_str(&config).expect("config json");
    assert_eq!(
        hex::encode(&binding.os_image_hash),
        config_value["os_image_hash"]
            .as_str()
            .expect("os_image_hash"),
        "verified os_image_hash"
    );
    // The HOST_DATA-bound app identity is recovered from the mr_config document.
    assert_eq!(
        hex::encode(&binding.mr_config.app_id),
        "86e59625be93207bc2351c4d1bba20037cec8e16",
        "mr_config app_id bound by HOST_DATA"
    );
    println!("os_image_hash: {}", hex::encode(&binding.os_image_hash));
}

// ---------------------------------------------------------------------------
// Forged / tampered quote coverage (all offline, using the real fixture).
// ---------------------------------------------------------------------------

fn decoded_attestation() -> dstack_attest::attestation::Attestation {
    let versioned =
        VersionedAttestation::from_scale(SEV_ATTESTATION_BIN).expect("decode VersionedAttestation");
    let VersionedAttestation::V0 { attestation } = versioned else {
        panic!("expected V0 attestation");
    };
    attestation
}

fn fixture_report() -> Vec<u8> {
    let attestation = decoded_attestation();
    let AttestationQuote::DstackAmdSevSnp(quote) = &attestation.quote else {
        panic!("expected an AMD SEV-SNP quote");
    };
    quote.report.clone()
}

fn upgrade_snp_config_for_split_measurement(config: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(config).expect("config json");
    let measurement_doc = value["sev_snp_measurement"]
        .as_str()
        .expect("sev_snp_measurement string")
        .to_string();
    let measurement_value: serde_json::Value =
        serde_json::from_str(&measurement_doc).expect("measurement json");
    if measurement_value.get("measurement").is_some()
        && measurement_value.get("checksum_file").is_some()
    {
        return config.to_string();
    }

    let input: MeasurementInput =
        serde_json::from_value(measurement_value).expect("legacy SNP measurement input");
    let measurement = sev_os_image_measurement_from_input(&input)
        .expect("image measurement")
        .to_cbor_vec();
    let sha256sum = format!(
        "{}  {}\n",
        hex::encode(Sha256::digest(&measurement)),
        dstack_types::SNP_MEASUREMENT_FILENAME
    )
    .into_bytes();
    let document = dstack_mr::sev::SnpMeasurementDocument {
        checksum_file: sha256sum,
        measurement,
        vcpus: input.vcpus,
        vcpu_type: input.vcpu_type,
        guest_features: input.guest_features,
    };
    value["os_image_hash"] = serde_json::Value::String(hex::encode(
        dstack_types::image_hash_from_sha256sum(&document.checksum_file),
    ));
    value["sev_snp_measurement"] =
        serde_json::Value::String(serde_json::to_string(&document).expect("serialize document"));
    value.to_string()
}

fn fixture_config() -> String {
    upgrade_snp_config_for_split_measurement(&decoded_attestation().config)
}

fn verified_fixture_report() -> VerifiedAmdSnpReport {
    let report = fixture_report();
    verify_amd_snp_attestation(&AmdSnpAttestationInput {
        report: &report,
        ask_pem: SEV_ASK_PEM,
        vcek_pem: SEV_VCEK_PEM,
    })
    .expect("verify SEV-SNP attestation offline")
}

/// Rewrite the image CBOR inside the embedded `sev_snp_measurement` document.
fn with_image_measurement(
    config: &str,
    f: impl FnOnce(&mut dstack_types::SevOsImageMeasurement),
) -> String {
    let mut value: serde_json::Value = serde_json::from_str(config).expect("config json");
    let measurement_doc = value["sev_snp_measurement"]
        .as_str()
        .expect("sev_snp_measurement string")
        .to_string();
    let mut document: dstack_mr::sev::SnpMeasurementDocument =
        serde_json::from_str(&measurement_doc).expect("measurement json");
    let mut image = dstack_types::SevOsImageMeasurement::from_cbor_slice(&document.measurement)
        .expect("decode measurement.snp.cbor");
    f(&mut image);
    document.measurement = image.to_cbor_vec();
    document.checksum_file = format!(
        "{}  {}\n",
        hex::encode(Sha256::digest(&document.measurement)),
        dstack_types::SNP_MEASUREMENT_FILENAME
    )
    .into_bytes();
    value["os_image_hash"] = serde_json::Value::String(hex::encode(
        dstack_types::image_hash_from_sha256sum(&document.checksum_file),
    ));
    value["sev_snp_measurement"] =
        serde_json::Value::String(serde_json::to_string(&document).expect("reserialize"));
    value.to_string()
}

/// Replace the embedded MrConfigV3 document with a different one.
fn set_mr_config(config: &str, mr_config_doc: &str) -> String {
    let mut value: serde_json::Value = serde_json::from_str(config).expect("config json");
    value["mr_config"] = serde_json::Value::String(mr_config_doc.to_string());
    value.to_string()
}

#[test]
fn forged_report_bytes_fail_signature_verification() {
    let report = fixture_report();
    // Flip a byte in each signed field (and the signature itself); the VCEK
    // signature over the report must no longer verify.
    // SNP ATTESTATION_REPORT offsets: report_data 0x50, measurement 0x90,
    // host_data 0xC0, signature 0x2A0.
    for (name, offset) in [
        ("report_data", 0x50usize),
        ("measurement", 0x90),
        ("host_data", 0xC0),
        ("signature", 0x2A0),
    ] {
        let mut tampered = report.clone();
        tampered[offset] ^= 0xff;
        let result = verify_amd_snp_attestation(&AmdSnpAttestationInput {
            report: &tampered,
            ask_pem: SEV_ASK_PEM,
            vcek_pem: SEV_VCEK_PEM,
        });
        assert!(
            result.is_err(),
            "tampering the {name} field must invalidate the report signature"
        );
    }

    // A well-formed-length but zeroed report has no valid signature.
    let zeroed = vec![0u8; 1184];
    assert!(
        verify_amd_snp_attestation(&AmdSnpAttestationInput {
            report: &zeroed,
            ask_pem: SEV_ASK_PEM,
            vcek_pem: SEV_VCEK_PEM,
        })
        .is_err(),
        "a zeroed report must not verify"
    );

    // A truncated report must be rejected, not parsed.
    assert!(
        verify_amd_snp_attestation(&AmdSnpAttestationInput {
            report: &report[..200],
            ask_pem: SEV_ASK_PEM,
            vcek_pem: SEV_VCEK_PEM,
        })
        .is_err(),
        "a truncated report must be rejected"
    );
}

#[test]
fn wrong_collateral_is_rejected() {
    let report = fixture_report();
    // The ASK presented as the VCEK leaf: the report signature won't verify
    // against the intermediate key.
    assert!(
        verify_amd_snp_attestation(&AmdSnpAttestationInput {
            report: &report,
            ask_pem: SEV_ASK_PEM,
            vcek_pem: SEV_ASK_PEM,
        })
        .is_err(),
        "using the ASK as the VCEK must be rejected"
    );

    // Garbage VCEK PEM.
    let junk = b"-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n";
    assert!(
        verify_amd_snp_attestation(&AmdSnpAttestationInput {
            report: &report,
            ask_pem: SEV_ASK_PEM,
            vcek_pem: junk,
        })
        .is_err(),
        "a malformed VCEK must be rejected"
    );
}

#[test]
fn forged_launch_measurement_is_rejected() {
    let verified = verified_fixture_report();
    let config = fixture_config();
    let mut forged = verified.measurement;
    forged[0] ^= 0xff;
    let err = verify_sev_launch(&forged, &verified.host_data, &config)
        .expect_err("a measurement that disagrees with the launch inputs must reject");
    assert!(
        err.to_string().contains("amd sev-snp measurement mismatch"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn forged_host_data_is_rejected() {
    let verified = verified_fixture_report();
    let config = fixture_config();
    let mut forged = verified.host_data;
    forged[0] ^= 0xff;
    let err = verify_sev_launch(&verified.measurement, &forged, &config)
        .expect_err("host_data that does not bind the mr_config must reject");
    assert!(
        err.to_string().contains("amd sev-snp host_data mismatch"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn tampered_launch_inputs_break_os_image_binding() {
    // Swap in a different kernel hash in the advertised launch inputs: the
    // recomputed measurement no longer equals the hardware MEASUREMENT, so the
    // forged (allow-listed-looking) os_image_hash is never trusted.
    let verified = verified_fixture_report();
    let tampered = with_image_measurement(&fixture_config(), |m| {
        m.kernel_hash = vec![0; 32];
    });
    let err = verify_sev_launch(&verified.measurement, &verified.host_data, &tampered)
        .expect_err("tampered launch inputs must reject");
    assert!(
        err.to_string().contains("amd sev-snp measurement mismatch"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn substituted_mr_config_breaks_host_data_binding() {
    // Present a well-formed but different-identity MrConfigV3 document. The
    // hardware HOST_DATA still binds the original document, so this is rejected.
    let verified = verified_fixture_report();
    let evil = MrConfigV3::new(
        vec![0xab; 20],
        vec![0xcd; 32],
        KeyProviderKind::None,
        Vec::new(),
        vec![0xef; 20],
    );
    let tampered = set_mr_config(&fixture_config(), &evil.to_canonical_json());
    let err = verify_sev_launch(&verified.measurement, &verified.host_data, &tampered)
        .expect_err("a substituted mr_config must reject");
    assert!(
        err.to_string().contains("amd sev-snp host_data mismatch"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn advertised_os_image_hash_must_match_sha256sum() {
    // A forged top-level os_image_hash is rejected because it must equal
    // sha256(sha256sum.txt) for the supplied measurement material.
    let verified = verified_fixture_report();
    let mut value: serde_json::Value =
        serde_json::from_str(&fixture_config()).expect("config json");
    value["os_image_hash"] = serde_json::Value::String("de".repeat(32));
    let tampered = value.to_string();

    let err = verify_sev_launch(&verified.measurement, &verified.host_data, &tampered)
        .expect_err("a bogus advertised os_image_hash must reject");
    assert!(
        err.to_string()
            .contains("amd sev-snp measurement material does not match os_image_hash"),
        "unexpected error: {err:?}"
    );
}
