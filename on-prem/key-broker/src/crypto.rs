// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeR,
    Serializable,
};
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

// HPKE suite for courier root delivery (must match the authority's seal_root):
//   KEM = DHKEM(X25519, HKDF-SHA256), KDF = HKDF-SHA256, AEAD = AES-256-GCM.
type CourierKem = X25519HkdfSha256;
const HPKE_INFO: &[u8] = b"dstack-courier-root-v1";

/// Generate a per-session X25519 transport keypair. Returns the raw 32-byte
/// private scalar (kept in TEE memory) and the raw 32-byte public key that the
/// authority seals the root payload to.
pub fn generate_transport_keypair() -> ([u8; 32], [u8; 32]) {
    // Use x25519-dalek for the random clamped scalar, then reconstruct the HPKE
    // key from its bytes (avoids any rand_core version coupling with `hpke`).
    let scalar = StaticSecret::random_from_rng(OsRng).to_bytes();
    let sk = <CourierKem as Kem>::PrivateKey::from_bytes(&scalar)
        .expect("32-byte x25519 scalar is a valid private key");
    let pk = CourierKem::sk_to_pk(&sk);
    let mut pub_bytes = [0u8; 32];
    pub_bytes.copy_from_slice(&pk.to_bytes());
    (scalar, pub_bytes)
}

/// HPKE-open the sealed root payload using the session transport private key.
/// Wire format: base64( enc(32 bytes) || ciphertext ).
pub fn unseal_root(sealed_root_b64: &str, transport_secret: &[u8; 32]) -> Result<Vec<u8>> {
    let blob = STANDARD
        .decode(sealed_root_b64)
        .context("failed to base64-decode sealed_root")?;
    if blob.len() < 32 {
        bail!("sealed_root too short: {} bytes", blob.len());
    }
    let (enc_bytes, ciphertext) = blob.split_at(32);

    let sk = <CourierKem as Kem>::PrivateKey::from_bytes(transport_secret)
        .map_err(|e| anyhow!("invalid transport private key: {e:?}"))?;
    let enc = <CourierKem as Kem>::EncappedKey::from_bytes(enc_bytes)
        .map_err(|e| anyhow!("invalid HPKE encapped key: {e:?}"))?;

    hpke::single_shot_open::<AesGcm256, HkdfSha256, CourierKem>(
        &OpModeR::Base,
        &sk,
        &enc,
        HPKE_INFO,
        ciphertext,
        b"",
    )
    .map_err(|e| anyhow!("HPKE open failed: {e:?}"))
}

/// Verify the Ed25519 signature on an AuthBundle.
///
/// The signed payload is the canonical JSON of the bundle with the
/// `authority_sig` field removed (keys sorted, no extra whitespace).
pub fn verify_auth_bundle(bundle: &serde_json::Value, authority_pubkey_b64: &str) -> Result<()> {
    if authority_pubkey_b64.is_empty() {
        // no pubkey configured — skip verification (useful in dev/test)
        return Ok(());
    }

    let sig_b64 = bundle["authority_sig"]
        .as_str()
        .context("missing authority_sig in auth bundle")?;

    let sig_bytes = STANDARD
        .decode(sig_b64)
        .context("failed to base64-decode authority_sig")?;
    let sig = Signature::from_slice(&sig_bytes).context("invalid ed25519 signature bytes")?;

    let pubkey_bytes = STANDARD
        .decode(authority_pubkey_b64)
        .context("failed to base64-decode authority_pubkey")?;
    if pubkey_bytes.len() != 32 {
        bail!(
            "authority pubkey must be 32 bytes, got {}",
            pubkey_bytes.len()
        );
    }
    let pubkey_arr: [u8; 32] = pubkey_bytes.try_into().expect("length checked above");
    let verifying_key =
        VerifyingKey::from_bytes(&pubkey_arr).context("invalid ed25519 public key")?;

    // build bundle_without_sig: clone the object and remove authority_sig
    let mut bundle_obj = bundle
        .as_object()
        .context("auth bundle must be a JSON object")?
        .clone();
    bundle_obj.remove("authority_sig");

    // canonical JSON: sort keys, no extra whitespace
    let canonical = canonical_json(&serde_json::Value::Object(bundle_obj));

    use ed25519_dalek::Verifier;
    verifying_key
        .verify(canonical.as_bytes(), &sig)
        .context("ed25519 signature verification failed")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-language HPKE interop: the authority (pyhpke) seals, key-broker
    /// (this crate) opens. Driven from a shell harness that sets:
    ///   KB_TEST_TRANSPORT_SK_HEX  — the 32-byte transport scalar (hex)
    ///   KB_TEST_SEALED_B64        — base64(enc||ct) produced by pyhpke
    ///   KB_TEST_EXPECT            — expected plaintext
    /// No-op when the env vars are absent (so `cargo test` stays self-contained).
    #[test]
    fn hpke_interop_python_seal_rust_open() {
        let (Ok(sk_hex), Ok(sealed), Ok(expect)) = (
            std::env::var("KB_TEST_TRANSPORT_SK_HEX"),
            std::env::var("KB_TEST_SEALED_B64"),
            std::env::var("KB_TEST_EXPECT"),
        ) else {
            return;
        };
        let sk_bytes = hex::decode(sk_hex).expect("hex sk");
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&sk_bytes);
        let pt = unseal_root(&sealed, &sk).expect("HPKE open should succeed");
        assert_eq!(String::from_utf8(pt).unwrap(), expect);
    }
}

/// Produce a canonical JSON string: object keys sorted, no extra whitespace.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            let pairs: Vec<String> = sorted
                .iter()
                .map(|(k, v)| format!("\"{}\":{}", k, canonical_json(v)))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        other => other.to_string(),
    }
}
