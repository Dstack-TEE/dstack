// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! NEAR MPC Chain Key Derivation (CKD) for deterministic root key generation
//!
//! This module implements deterministic root key generation using NEAR MPC network.
//! The root key is derived deterministically and can only be generated inside a verified TEE.
//!
//! Flow:
//! 1. Generate ephemeral BLS12-381 G1 keypair
//! 2. Call NEAR KMS contract's request_kms_root_key() with attestation
//! 3. KMS contract verifies attestation and calls MPC contract
//! 4. MPC contract returns encrypted response (big_y, big_c)
//! 5. Decrypt and verify the response
//! 6. Derive final 32-byte key using HKDF
//! 7. Convert to CA and K256 keys

use anyhow::{Context, Result};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use elliptic_curve::{group::prime::PrimeCurveAffine as _, Field as _, Group as _};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use serde::{Deserialize, Serialize};

// Constants matching NEAR MPC contract
const BLS12381G1_PUBLIC_KEY_SIZE: usize = 48;
const NEAR_CKD_DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";
const OUTPUT_SECRET_SIZE: usize = 32;
const APP_ID_DERIVATION_PREFIX: &str = "near-mpc v0.1.0 app_id derivation:";
const KMS_ROOT_KEY_DERIVATION_PATH: &str = "kms-root-key";

/// MPC configuration for key derivation
#[derive(Debug, Clone)]
pub struct MpcConfig {
    /// MPC contract ID (e.g., "v1.signer.testnet")
    pub mpc_contract_id: String,
    /// MPC domain ID for BLS12-381 (usually 2)
    pub mpc_domain_id: u64,
    /// MPC public key for the domain (BLS12-381 G2) in NEAR format
    pub mpc_public_key: String,
    /// NEAR KMS contract ID
    pub kms_contract_id: String,
    /// NEAR RPC URL
    pub near_rpc_url: String,
}

#[derive(Deserialize)]
struct Bls12381G1PublicKey(String);

/// MPC CKD response (big_y, big_c from MPC network)
#[derive(Debug, Clone, Deserialize)]
pub struct CkdResponse {
    pub big_y: Bls12381G1PublicKey,
    pub big_c: Bls12381G1PublicKey,
}

/// Derive app_id the same way MPC contract does
/// app_id = SHA3-256("{prefix}{account_id},{derivation_path}")
fn derive_app_id(account_id: &str, derivation_path: &str) -> [u8; 32] {
    let derivation_string = format!(
        "{}{},{}",
        APP_ID_DERIVATION_PREFIX, account_id, derivation_path
    );
    let mut hasher = Sha3_256::new();
    hasher.update(derivation_string.as_bytes());
    hasher.finalize().into()
}

/// Generate ephemeral BLS12-381 G1 keypair
pub fn generate_ephemeral_keypair() -> (Scalar, G1Projective) {
    let mut rng = OsRng;
    let private_key = Scalar::random(&mut rng);
    let public_key = G1Projective::generator() * private_key;
    (private_key, public_key)
}

/// Convert G1 point to NEAR format (bls12381g1:base58...)
pub fn g1_to_near_format(point: G1Projective) -> Result<String> {
    let compressed = point.to_compressed();
    let base58 = bs58::encode(&compressed).into_string();
    Ok(format!("bls12381g1:{}", base58))
}

/// Parse NEAR format to G1 point
pub fn near_format_to_g1(s: &str) -> Result<G1Projective> {
    let base58_part = s
        .strip_prefix("bls12381g1:")
        .context("Invalid BLS12-381 G1 format - missing prefix")?;

    let bytes = bs58::decode(base58_part)
        .into_vec()
        .context("Invalid base58 encoding")?;

    if bytes.len() != 48 {
        anyhow::bail!(
            "Invalid G1 point length: expected 48 bytes, got {}",
            bytes.len()
        );
    }

    let mut compressed = [0u8; 48];
    compressed.copy_from_slice(&bytes[..48]);

    G1Projective::from_compressed(&compressed)
        .into_option()
        .context("Invalid G1 point - not on curve")
}

/// Parse NEAR format to G2 point
pub fn near_format_to_g2(s: &str) -> Result<G2Projective> {
    let base58_part = s
        .strip_prefix("bls12381g2:")
        .context("Invalid BLS12-381 G2 format - missing prefix")?;

    let bytes = bs58::decode(base58_part)
        .into_vec()
        .context("Invalid base58 encoding")?;

    if bytes.len() != 96 {
        anyhow::bail!(
            "Invalid G2 point length: expected 96 bytes, got {}",
            bytes.len()
        );
    }

    let mut compressed = [0u8; 96];
    compressed.copy_from_slice(&bytes[..96]);

    G2Projective::from_compressed(&compressed)
        .into_option()
        .context("Invalid G2 point - not on curve")
}

/// Decrypt MPC response and verify signature
pub fn decrypt_and_verify_mpc_response(
    big_y: &str,
    big_c: &str,
    ephemeral_private_key: Scalar,
    mpc_public_key: &str,
    app_id: &[u8],
) -> Result<[u8; BLS12381G1_PUBLIC_KEY_SIZE]> {
    // Parse G1 points
    let big_y_point = near_format_to_g1(big_y)?;
    let big_c_point = near_format_to_g1(big_c)?;

    // Parse MPC public key (G2)
    let mpc_pk = near_format_to_g2(mpc_public_key)?;

    // Decrypt the secret: secret = big_c - big_y * private_key
    let secret = big_c_point - big_y_point * ephemeral_private_key;

    // Verify the signature using pairing
    if !verify_mpc_signature(&mpc_pk, app_id, &secret) {
        anyhow::bail!("MPC signature verification failed");
    }

    // Return secret as compressed bytes
    Ok(secret.to_compressed())
}

/// Verify MPC signature using BLS pairing
fn verify_mpc_signature(
    public_key: &G2Projective,
    app_id: &[u8],
    signature: &G1Projective,
) -> bool {
    let element1: G1Affine = signature.into();
    if (!element1.is_on_curve() | !element1.is_torsion_free() | element1.is_identity()).into() {
        return false;
    }

    let element2: G2Affine = public_key.into();
    if (!element2.is_on_curve() | !element2.is_torsion_free() | element2.is_identity()).into() {
        return false;
    }

    // Hash input = MPC public key || app_id (must match MPC contract)
    let hash_input = [public_key.to_compressed().as_slice(), app_id].concat();
    let base1 = G1Projective::hash_to_curve(&hash_input, NEAR_CKD_DOMAIN, &[]).into();
    let base2 = G2Affine::generator();

    // Verify pairing equation: e(H(mpk||app_id), mpk) == e(signature, G2)
    blstrs::pairing(&base1, &element2) == blstrs::pairing(&element1, &base2)
}

/// Derive final 32-byte key using HKDF
pub fn derive_final_key(
    ikm: [u8; BLS12381G1_PUBLIC_KEY_SIZE],
    info: &[u8],
) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; OUTPUT_SECRET_SIZE];
    hk.expand(info, &mut okm)
        .map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e))?;
    Ok(okm)
}

/// Derive root keys from MPC response
///
/// This function:
/// 1. Decrypts the MPC response using the ephemeral private key
/// 2. Verifies the MPC signature
/// 3. Derives the final 32-byte key using HKDF
/// 4. Returns the key that can be used as K256 signing key
pub fn derive_root_key_from_mpc(
    mpc_response: &CKDResponse,
    ephemeral_private_key: Scalar,
    mpc_config: &MpcConfig,
    kms_account_id: &str,
) -> Result<[u8; OUTPUT_SECRET_SIZE]> {
    // Derive app_id (must match MPC contract derivation)
    let app_id = derive_app_id(kms_account_id, KMS_ROOT_KEY_DERIVATION_PATH);

    // Decrypt and verify MPC response
    let secret_bytes = decrypt_and_verify_mpc_response(
        &mpc_response.big_y,
        &mpc_response.big_c,
        ephemeral_private_key,
        &mpc_config.mpc_public_key,
        &app_id,
    )?;

    // Derive final 32-byte key using HKDF
    let final_key = derive_final_key(secret_bytes, b"")?;

    Ok(final_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_app_id() {
        let app_id = derive_app_id("kms.testnet", "kms-root-key");
        assert_eq!(app_id.len(), 32);

        // Same inputs should produce same app_id
        let app_id2 = derive_app_id("kms.testnet", "kms-root-key");
        assert_eq!(app_id, app_id2);

        // Different inputs should produce different app_id
        let app_id3 = derive_app_id("kms.testnet", "different-path");
        assert_ne!(app_id, app_id3);
    }

    #[test]
    fn test_g1_format_conversion() {
        let (_, public_key) = generate_ephemeral_keypair();
        let near_format = g1_to_near_format(public_key).unwrap();
        assert!(near_format.starts_with("bls12381g1:"));

        let parsed = near_format_to_g1(&near_format).unwrap();
        assert_eq!(parsed.to_compressed(), public_key.to_compressed());
    }

    #[test]
    fn test_derive_final_key() {
        let ikm = [0u8; 48];
        let key = derive_final_key(ikm, b"").unwrap();
        assert_eq!(key.len(), 32);

        // Same input should produce same output
        let key2 = derive_final_key(ikm, b"").unwrap();
        assert_eq!(key, key2);

        // Different info should produce different output
        let key3 = derive_final_key(ikm, b"different").unwrap();
        assert_ne!(key, key3);
    }
}
