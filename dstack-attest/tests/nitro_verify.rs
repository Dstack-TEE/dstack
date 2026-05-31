// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

//! Integration test: verify Nitro Enclave attestation end-to-end

use dstack_attest::attestation::{AttestationQuote, DstackVerifiedReport, VersionedAttestation};
use nsm_qvl::{AttestationDocument, CoseSign1};
use std::time::{Duration, SystemTime};

// Real Nitro Enclave attestation captured from an enclave
const NITRO_ATTESTATION_BIN: &[u8] = include_bytes!("nitro_attestation.bin");

#[tokio::test]
async fn verify_nitro_attestation_bin() {
    // Decode VersionedAttestation from SCALE
    let versioned = VersionedAttestation::from_scale(NITRO_ATTESTATION_BIN)
        .expect("decode VersionedAttestation");
    let VersionedAttestation::V0 { attestation } = versioned else {
        panic!("expected V0 attestation");
    };

    let app_info = attestation.decode_app_info(false).unwrap();
    let app_info_str = serde_json::to_string_pretty(&app_info).unwrap();

    println!("App Info: {app_info_str}");
    insta::assert_snapshot!("app_info", app_info_str);

    // Perform full verification (COSE signature + cert chain + user_data).
    // Use the attestation's own timestamp to keep freshness checks stable for this sample.
    let fixed_now = match &attestation.quote {
        AttestationQuote::DstackNitroEnclave(quote) => {
            let cose =
                CoseSign1::from_bytes(&quote.nsm_quote).expect("parse COSE Sign1 from quote");
            let doc =
                AttestationDocument::from_cbor(&cose.payload).expect("parse attestation document");
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_millis(doc.timestamp))
                .expect("attestation timestamp overflow")
        }
        _ => panic!("unexpected quote type"),
    };
    let verified = attestation
        .verify_with_time(None, Some(fixed_now))
        .await
        .unwrap();
    let DstackVerifiedReport::DstackNitroEnclave(report) = verified.report else {
        panic!("Nitro attestation verification failed");
    };
    println!("✓ Nitro attestation verified successfully");
    insta::assert_snapshot!(
        "nitro_report",
        serde_json::to_string_pretty(&report).unwrap()
    );
}
