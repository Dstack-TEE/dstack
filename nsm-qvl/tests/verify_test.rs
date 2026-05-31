// SPDX-FileCopyrightText: Copyright (c) 2024-2025 The Project Contributors
// SPDX-License-Identifier: BUSL-1.1
// Test for NSM attestation verification
use nsm_qvl::{AttestationDocument, CoseSign1};
use std::io::Cursor;

// Real attestation captured from Nitro Enclave
const ATTESTATION_BIN: &[u8] = include_bytes!("nitro_attestation.bin");

fn extract_cose_sign1(data: &[u8]) -> Vec<u8> {
    // Find COSE Sign1 structure (starts with 0x84 for 4-element array)
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0x84 && data[i + 1] == 0x44 {
            let mut reader = Cursor::new(&data[i..]);
            let _: ciborium::Value =
                ciborium::from_reader(&mut reader).expect("Failed to parse COSE Sign1 CBOR");
            let len = reader.position() as usize;
            return data[i..i + len].to_vec();
        }
    }
    panic!("Could not find COSE Sign1 marker in attestation data");
}

#[test]
fn test_parse_cose_sign1() {
    let cose_data = extract_cose_sign1(ATTESTATION_BIN);

    let cose = CoseSign1::from_bytes(&cose_data).expect("Failed to parse COSE Sign1");

    // Verify algorithm is ES384 (-35)
    let alg = cose.algorithm().expect("Failed to get algorithm");
    assert_eq!(alg, -35, "Algorithm should be ES384 (-35)");

    // Verify signature is 96 bytes (P-384)
    assert_eq!(
        cose.signature.len(),
        96,
        "P-384 signature should be 96 bytes"
    );

    println!("COSE Sign1 parsed successfully");
    println!("  Protected header: {} bytes", cose.protected.len());
    println!("  Payload: {} bytes", cose.payload.len());
    println!("  Signature: {} bytes", cose.signature.len());
}

#[test]
fn test_parse_attestation_document() {
    let cose_data = extract_cose_sign1(ATTESTATION_BIN);
    let cose = CoseSign1::from_bytes(&cose_data).expect("Failed to parse COSE Sign1");

    let doc = AttestationDocument::from_cbor(&cose.payload)
        .expect("Failed to parse attestation document");

    println!("Attestation document parsed:");
    println!("  Module ID: {}", doc.module_id);
    println!("  Digest: {}", doc.digest);
    println!("  Timestamp: {}", doc.timestamp);
    println!("  Certificate: {} bytes", doc.certificate.len());
    println!("  CA bundle: {} certificates", doc.cabundle.len());
    println!("  PCRs: {} entries", doc.pcrs.len());

    assert!(!doc.module_id.is_empty());
    assert_eq!(doc.digest, "SHA384");
    assert!(!doc.certificate.is_empty());
    assert!(!doc.cabundle.is_empty());
}

#[tokio::test]
async fn test_verify_attestation_full() {
    tracing_subscriber::fmt::try_init().ok();

    let cose_data = extract_cose_sign1(ATTESTATION_BIN);
    let cose = CoseSign1::from_bytes(&cose_data).expect("Failed to parse COSE Sign1");
    let doc = AttestationDocument::from_cbor(&cose.payload)
        .expect("Failed to parse attestation document");
    let attestation_time = std::time::UNIX_EPOCH + std::time::Duration::from_millis(doc.timestamp);

    let report = nsm_qvl::verify_attestation_with_crl(
        &cose_data,
        nsm_qvl::AWS_NITRO_ENCLAVES_ROOT_G1,
        std::env::var("TEST_FETCH_CRL").is_ok(),
        Some(attestation_time),
    )
    .await
    .unwrap();
    println!("✓ Attestation verified successfully!");
    println!("  Module ID: {}", report.module_id);
    println!("  Digest: {}", report.digest);
    println!("  Timestamp: {}", report.timestamp);
    println!("  PCRs: {} entries", report.pcrs.len());

    // Print non-zero PCR values
    for (idx, value) in &report.pcrs {
        if !value.iter().all(|&b| b == 0) {
            println!("  PCR{idx}: {value:02x?}");
        }
    }
}
