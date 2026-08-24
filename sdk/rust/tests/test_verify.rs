// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Drives the shared cross-SDK vectors in `sdk/tests/vectors/signature_chain.json`.
//! The Python, Go and JavaScript suites assert against the same file, so any port
//! that disagrees about the byte format fails here too.

use dstack_sdk::verify::{verify_signature, verify_signature_chain, SignatureChain, SIGN_PURPOSE};
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tests/vectors/signature_chain.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse")
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string")).expect("valid hex")
}

#[test]
fn valid_signatures_verify() {
    let v = vectors();
    for case in v["cases"].as_array().unwrap() {
        let algorithm = case["algorithm"].as_str().unwrap();
        assert!(
            verify_signature(
                algorithm,
                &unhex(&case["data"]),
                &unhex(&case["signature"]),
                &unhex(&case["public_key"]),
            )
            .unwrap_or_else(|e| panic!("{algorithm}: {e}")),
            "{algorithm}: valid signature was rejected"
        );
    }
}

#[test]
fn invalid_signatures_are_rejected() {
    let v = vectors();
    for case in v["invalid_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let verdict = verify_signature(
            case["algorithm"].as_str().unwrap(),
            &unhex(&case["data"]),
            &unhex(&case["signature"]),
            &unhex(&case["public_key"]),
        );
        // High-S is refused outright rather than reported false, because it is a
        // malformed encoding rather than a legitimate signature that fails to match.
        match verdict {
            Ok(valid) => assert!(!valid, "{name}: should not have verified"),
            Err(_) if name == "secp256k1_high_s" => {}
            Err(e) => panic!("{name}: unexpected error {e}"),
        }
    }
}

#[test]
fn k256_is_an_alias_for_secp256k1() {
    let v = vectors();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["algorithm"] == "secp256k1")
        .unwrap();
    assert!(verify_signature(
        "k256",
        &unhex(&case["data"]),
        &unhex(&case["signature"]),
        &unhex(&case["public_key"]),
    )
    .unwrap());
}

fn chain_of(case: &Value) -> Vec<Vec<u8>> {
    case["signature_chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(unhex)
        .collect()
}

#[test]
fn full_chain_verifies_to_the_kms_root() {
    let v = vectors();
    let app_id = unhex(&v["app_id"]);
    let kms_root = unhex(&v["kms_root_pubkey"]);
    let expected_app_root = unhex(&v["app_root_pubkey"]);

    for case in v["cases"].as_array().unwrap() {
        let algorithm = case["algorithm"].as_str().unwrap();
        let data = unhex(&case["data"]);
        let public_key = unhex(&case["public_key"]);
        let chain = chain_of(case);
        let verified = verify_signature_chain(&SignatureChain::from_sign_response(
            algorithm,
            &data,
            &public_key,
            &chain,
            &app_id,
            &kms_root,
        ))
        .unwrap_or_else(|e| panic!("{algorithm}: {e}"));
        assert_eq!(
            verified.app_root_pubkey, expected_app_root,
            "{algorithm}: recovered the wrong app root key"
        );
    }
}

#[test]
fn chain_anchored_at_a_foreign_kms_root_is_rejected() {
    let v = vectors();
    let app_id = unhex(&v["app_id"]);
    let wrong_root = unhex(&v["wrong_kms_root_pubkey"]);
    let case = &v["cases"].as_array().unwrap()[0];
    let data = unhex(&case["data"]);
    let public_key = unhex(&case["public_key"]);
    let chain = chain_of(case);

    let err = verify_signature_chain(&SignatureChain::from_sign_response(
        case["algorithm"].as_str().unwrap(),
        &data,
        &public_key,
        &chain,
        &app_id,
        &wrong_root,
    ))
    .expect_err("a chain not anchored at our KMS root must be rejected");
    assert!(
        err.to_string().contains("not anchored"),
        "unexpected error: {err}"
    );
}

#[test]
fn chain_for_a_different_app_id_is_rejected() {
    let v = vectors();
    let kms_root = unhex(&v["kms_root_pubkey"]);
    let case = &v["cases"].as_array().unwrap()[0];
    let data = unhex(&case["data"]);
    let public_key = unhex(&case["public_key"]);
    let chain = chain_of(case);
    let mut app_id = unhex(&v["app_id"]);
    app_id[0] ^= 0xff;

    assert!(verify_signature_chain(&SignatureChain::from_sign_response(
        case["algorithm"].as_str().unwrap(),
        &data,
        &public_key,
        &chain,
        &app_id,
        &kms_root,
    ))
    .is_err());
}

#[test]
fn tampered_payload_breaks_the_chain() {
    let v = vectors();
    let app_id = unhex(&v["app_id"]);
    let kms_root = unhex(&v["kms_root_pubkey"]);
    let case = &v["cases"].as_array().unwrap()[0];
    let public_key = unhex(&case["public_key"]);
    let chain = chain_of(case);
    let tampered = b"a different payload entirely".to_vec();

    assert!(verify_signature_chain(&SignatureChain::from_sign_response(
        case["algorithm"].as_str().unwrap(),
        &tampered,
        &public_key,
        &chain,
        &app_id,
        &kms_root,
    ))
    .is_err());
}

#[test]
fn malformed_inputs_error_rather_than_report_false() {
    assert!(verify_signature("rsa", b"x", &[0; 64], &[0; 32]).is_err());
    assert!(verify_signature("ed25519", b"x", &[0; 64], &[0; 31]).is_err());
    // A prehashed digest must be exactly 32 bytes.
    let v = vectors();
    let case = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["algorithm"] == "secp256k1_prehashed")
        .unwrap();
    assert!(verify_signature(
        "secp256k1_prehashed",
        b"short",
        &unhex(&case["signature"]),
        &unhex(&case["public_key"]),
    )
    .is_err());
}

#[test]
fn sign_purpose_is_the_agent_side_constant() {
    assert_eq!(SIGN_PURPOSE, "signing");
}
