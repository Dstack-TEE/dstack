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
use sev_snp_qvl::{verify_amd_snp_attestation, AmdSnpAttestationInput};

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
    // HOST_DATA to bind the MrConfigV3 document, and derive the os_image_hash.
    let binding = dstack_mr::sev::verify_sev_launch(
        &verified.measurement,
        &verified.host_data,
        &attestation.config,
    )
    .expect("recompute SEV launch + derive os_image_hash from the attestation config");

    // The os_image_hash matches the value advertised in the CVM config and the
    // image build's digest.sev.txt.
    assert_eq!(
        hex::encode(&binding.os_image_hash),
        "32b4767373ad7fa0f9c418925006194d5c3f5619529f309fe81156789fecd8bc",
        "derived os_image_hash"
    );
    // The HOST_DATA-bound app identity is recovered from the mr_config document.
    assert_eq!(
        hex::encode(&binding.mr_config.app_id),
        "86e59625be93207bc2351c4d1bba20037cec8e16",
        "mr_config app_id bound by HOST_DATA"
    );
    println!("os_image_hash: {}", hex::encode(&binding.os_image_hash));
}
