// SPDX-FileCopyrightText: Copyright (c) 2024-2025 The Project Contributors
// SPDX-License-Identifier: BUSL-1.1

// Test for NSM attestation document parsing
use nsm_attest::AttestationDocument;

// Real attestation captured from Nitro Enclave
const ATTESTATION_BIN: &[u8] = include_bytes!("nitro_attestation.bin");

#[test]
fn test_parse_versioned_attestation_and_extract_nsm_quote() {
    // The attestation.bin is a VersionedAttestation (SCALE encoded)
    // Format: version (1 byte) + SCALE-encoded Attestation
    // Attestation contains: quote (AttestationQuote), runtime_events, report_data, config

    // For DstackNitroEnclave, the quote contains nsm_quote which is the COSE Sign1 document
    // Let's find the COSE Sign1 marker (0x8444 = CBOR array tag for COSE_Sign1)

    let data = ATTESTATION_BIN;
    println!("Total attestation length: {} bytes", data.len());

    // Find COSE Sign1 structure (starts with 0x84 0x44 for protected header)
    let mut cose_start = None;
    for i in 0..data.len().saturating_sub(2) {
        if data[i] == 0x84 && data[i + 1] == 0x44 {
            cose_start = Some(i);
            break;
        }
    }

    let cose_start = cose_start.expect("Should find COSE Sign1 marker");
    println!("COSE Sign1 starts at offset: {}", cose_start);

    // The COSE Sign1 structure length is encoded before it in SCALE
    // For now, let's try parsing from the marker to the end
    let cose_data = &data[cose_start..];

    // Try to parse the attestation document
    let result = AttestationDocument::from_cose(cose_data);
    match result {
        Ok(doc) => {
            println!("Successfully parsed attestation document!");
            println!("Module ID: {}", doc.module_id);
            println!("Digest: {}", doc.digest);
            println!("Timestamp: {}", doc.timestamp);
            println!("PCR count: {}", doc.pcrs.len());

            // Verify expected values
            assert!(!doc.module_id.is_empty(), "Module ID should not be empty");
            assert_eq!(doc.digest, "SHA384", "Digest should be SHA384");
            assert!(doc.pcrs.contains_key(&0), "Should have PCR0");
            assert!(doc.pcrs.contains_key(&1), "Should have PCR1");
            assert!(doc.pcrs.contains_key(&2), "Should have PCR2");

            // Print all PCR values
            for idx in 0..16u16 {
                if let Some(value) = doc.pcrs.get(&idx) {
                    let is_zero = value.iter().all(|&b| b == 0);
                    if is_zero {
                        println!("PCR{}: ALL ZEROS (len={})", idx, value.len());
                    } else {
                        println!("PCR{}: {:02x?} (len={})", idx, value, value.len());
                    }
                }
            }
        }
        Err(e) => {
            panic!("Failed to parse attestation document: {}", e);
        }
    }
}

#[test]
fn test_attestation_document_structure() {
    // Verify the COSE Sign1 structure is present
    let data = ATTESTATION_BIN;

    // COSE Sign1 is a CBOR array with 4 elements
    // The marker 0x84 indicates a 4-element array
    let has_cose_marker = data.windows(2).any(|w| w[0] == 0x84 && w[1] == 0x44);
    assert!(
        has_cose_marker,
        "Should contain COSE Sign1 marker (0x84 0x44)"
    );

    // Verify module_id string is present
    let module_id_marker = b"module_id";
    let has_module_id = data
        .windows(module_id_marker.len())
        .any(|w| w == module_id_marker);
    assert!(has_module_id, "Should contain module_id field");
}
