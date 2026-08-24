// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Generates and pins the cross-SDK signature-chain test vectors.
//!
//! The Rust, Python, Go and JavaScript SDKs each reimplement `verify_signature`
//! and `verify_signature_chain`. Four independent ports of the same byte-exact
//! format is precisely how this project has shipped cross-language digest bugs
//! before -- the Go compose-hash helper HTML-escaped `<`, so it hashed an
//! app-compose differently from every other SDK, and that digest is what gets
//! whitelisted on chain.
//!
//! So the format lives in one committed file, `sdk/tests/vectors/signature_chain.json`,
//! generated here from the same primitives KMS and the guest agent actually use,
//! and every SDK asserts against it. If the chain format ever changes, this test
//! fails first and the SDK suites fail right after.
//!
//! Run `UPDATE_VECTORS=1 cargo test -p dstack-guest-agent --test signature_chain_vectors`
//! to regenerate after an intentional format change.

use ed25519_dalek::{Signer as _, SigningKey as Ed25519SigningKey};
use k256::ecdsa::SigningKey;
use serde_json::json;
use sha2::{Digest as _, Sha256};
use sha3::Keccak256;

const VECTORS_PATH: &str = "../../sdk/tests/vectors/signature_chain.json";

/// Fixed, obviously-fake KMS root scalar. Never a real key.
const KMS_ROOT_SCALAR: [u8; 32] = [
    0x4b, 0x4d, 0x53, 0x2d, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x74, 0x65, 0x73, 0x74, 0x2d, 0x6b, 0x65,
    0x79, 0x2d, 0x64, 0x6f, 0x2d, 0x6e, 0x6f, 0x74, 0x2d, 0x75, 0x73, 0x65, 0x21, 0x21, 0x21, 0x01,
];
/// 20-byte app id, as `ensure_app_id_len` enforces.
const APP_ID: [u8; 20] = [
    0xa9, 0x01, 0x9d, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7,
    0xe8, 0xf9, 0x0a, 0x1b,
];

/// `ra_tls::kdf::derive_key` -- HKDF-SHA256, salt "RATLS", info = concat(context_data).
fn derive_key(ikm: &[u8], context: &[&[u8]], len: usize) -> Vec<u8> {
    ra_tls::kdf::derive_key(ikm, context, len).expect("derive_key")
}

/// `kms::crypto::sign_message` -- keccak256(prefix ‖ ":" ‖ app_id ‖ message), recoverable.
fn sign_message(key: &SigningKey, prefix: &[u8], appid: &[u8], message: &[u8]) -> Vec<u8> {
    let digest =
        <Keccak256 as sha3::Digest>::new_with_prefix([prefix, b":", appid, message].concat());
    let (sig, recid) = key
        .sign_digest_recoverable(digest)
        .expect("sign_digest_recoverable");
    let mut out = sig.to_vec();
    out.push(recid.to_byte());
    out
}

#[test]
fn signature_chain_vectors_are_stable() {
    let kms_root = SigningKey::from_bytes(&KMS_ROOT_SCALAR.into()).expect("kms root key");
    let kms_root_pubkey = kms_root.verifying_key().to_sec1_bytes().to_vec();

    // Link [2]: KMS root signs the derived app root pubkey. Mirrors derive_k256_key().
    let app_root_scalar: [u8; 32] = derive_key(&kms_root.to_bytes(), &[&APP_ID, b"app-key"], 32)
        .try_into()
        .expect("app root scalar");
    let app_root = SigningKey::from_bytes(&app_root_scalar.into()).expect("app root key");
    let app_root_pubkey = app_root.verifying_key().to_sec1_bytes().to_vec();
    let kms_signature = sign_message(&kms_root, b"dstack-kms-issued", &APP_ID, &app_root_pubkey);

    // Sign() hardcodes path "vms" / purpose "signing".
    let path = "vms";
    let purpose = "signing";
    let derived = derive_key(&app_root_scalar, &[path.as_bytes()], 32);
    let derived_arr: [u8; 32] = derived.clone().try_into().expect("derived key");

    let data = b"dstack signature chain test vector".to_vec();
    let prehash: Vec<u8> = Sha256::digest(&data).to_vec();

    let mut cases = Vec::new();
    for algorithm in ["ed25519", "secp256k1", "secp256k1_prehashed"] {
        // The signing pubkey, encoded exactly as get_key() hexes it for link [1].
        let (public_key, signature, signed_data) = match algorithm {
            "ed25519" => {
                let sk = Ed25519SigningKey::from_bytes(&derived_arr);
                let pk = sk.verifying_key().to_bytes().to_vec();
                (pk, sk.sign(&data).to_bytes().to_vec(), data.clone())
            }
            "secp256k1" => {
                let sk = SigningKey::from_slice(&derived).expect("k256 key");
                let pk = sk.verifying_key().to_sec1_bytes().to_vec();
                let sig: k256::ecdsa::Signature = sk.sign(&data);
                (pk, sig.to_bytes().to_vec(), data.clone())
            }
            "secp256k1_prehashed" => {
                use k256::ecdsa::signature::hazmat::PrehashSigner;
                let sk = SigningKey::from_slice(&derived).expect("k256 key");
                let pk = sk.verifying_key().to_sec1_bytes().to_vec();
                let sig: k256::ecdsa::Signature = sk.sign_prehash(&prehash).expect("prehash sign");
                (pk, sig.to_bytes().to_vec(), prehash.clone())
            }
            _ => unreachable!(),
        };

        // Link [1]: app root signs "{purpose}:{lowerhex(pubkey)}".
        let msg = format!("{purpose}:{}", hex::encode(&public_key));
        let app_signature = {
            let digest = <Keccak256 as sha3::Digest>::new_with_prefix(msg.as_bytes());
            let (sig, recid) = app_root
                .sign_digest_recoverable(digest)
                .expect("app root sign");
            let mut out = sig.to_vec();
            out.push(recid.to_byte());
            out
        };

        cases.push(json!({
            "algorithm": algorithm,
            // What Sign() hashes over. For secp256k1_prehashed this is the digest itself.
            "data": hex::encode(&signed_data),
            "public_key": hex::encode(&public_key),
            "signature": hex::encode(&signature),
            "signature_chain": [
                hex::encode(&signature),
                hex::encode(&app_signature),
                hex::encode(&kms_signature),
            ],
        }));
    }

    // Negative cases. These pin behaviour that differs between crypto libraries,
    // so a port cannot quietly disagree with what the guest agent used to do.
    let mut invalid_cases = Vec::new();

    // 1. High-S malleability. For every ECDSA signature (r, s), the pair (r, n-s)
    //    is also arithmetically valid. k256 -- and therefore the Sign RPC that used
    //    to back Verify -- rejects the high-S form. `@noble/curves` rejects it by
    //    default too, but Python's `cryptography` and Go's decred secp256k1 accept
    //    it unless the caller checks explicitly. Accepting it would mean a signature
    //    is not a unique identifier for a signed message.
    {
        let sk = SigningKey::from_slice(&derived).expect("k256 key");
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        let sig: k256::ecdsa::Signature = sk.sign(&data);
        let high_s =
            k256::ecdsa::Signature::from_scalars(*sig.r(), -*sig.s()).expect("high-s signature");
        assert!(
            high_s.normalize_s().is_some(),
            "mutated signature must actually be high-S"
        );
        invalid_cases.push(json!({
            "name": "secp256k1_high_s",
            "reason": "high-S form of an otherwise valid signature; must be rejected",
            "algorithm": "secp256k1",
            "data": hex::encode(&data),
            "public_key": hex::encode(&pk),
            "signature": hex::encode(high_s.to_bytes()),
        }));
    }

    // 2. A valid signature checked against data it does not cover.
    {
        let sk = SigningKey::from_slice(&derived).expect("k256 key");
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        let sig: k256::ecdsa::Signature = sk.sign(&data);
        invalid_cases.push(json!({
            "name": "secp256k1_wrong_data",
            "reason": "signature is valid, but not over this data",
            "algorithm": "secp256k1",
            "data": hex::encode(b"not the data that was signed"),
            "public_key": hex::encode(&pk),
            "signature": hex::encode(sig.to_bytes()),
        }));
    }
    {
        let sk = Ed25519SigningKey::from_bytes(&derived_arr);
        let pk = sk.verifying_key().to_bytes().to_vec();
        invalid_cases.push(json!({
            "name": "ed25519_wrong_data",
            "reason": "signature is valid, but not over this data",
            "algorithm": "ed25519",
            "data": hex::encode(b"not the data that was signed"),
            "public_key": hex::encode(&pk),
            "signature": hex::encode(sk.sign(&data).to_bytes()),
        }));
    }

    // 3. A self-consistent chain that simply is not anchored at our KMS root.
    //    A verifier that skips the final comparison accepts this, and accepting it
    //    means the chain proves nothing at all.
    let foreign_root = SigningKey::from_bytes(&[0x5au8; 32].into()).expect("foreign root");
    let foreign_pubkey = foreign_root.verifying_key().to_sec1_bytes().to_vec();

    let vectors = json!({
        "_comment": "Generated by dstack/guest-agent/tests/signature_chain_vectors.rs. \
                     Do not edit by hand; run with UPDATE_VECTORS=1 to regenerate.",
        "app_id": hex::encode(APP_ID),
        "purpose": purpose,
        "path": path,
        "kms_root_pubkey": hex::encode(&kms_root_pubkey),
        "app_root_pubkey": hex::encode(&app_root_pubkey),
        "cases": cases,
        "invalid_cases": invalid_cases,
        "wrong_kms_root_pubkey": hex::encode(&foreign_pubkey),
    });
    let rendered = format!("{}\n", serde_json::to_string_pretty(&vectors).unwrap());

    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(VECTORS_PATH, &rendered).expect("write vectors");
        return;
    }

    let committed = std::fs::read_to_string(VECTORS_PATH).unwrap_or_else(|e| {
        panic!("{VECTORS_PATH} missing ({e}); run with UPDATE_VECTORS=1 to generate")
    });
    assert_eq!(
        committed.trim(),
        rendered.trim(),
        "signature chain format drifted from the committed cross-SDK vectors; \
         if intentional, regenerate with UPDATE_VECTORS=1 and update all four SDKs"
    );
}
