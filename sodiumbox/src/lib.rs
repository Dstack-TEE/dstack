// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust implementation of libsodium's sealed box encryption/decryption.
//!
//! This crate provides a standalone implementation of the sealed box functionality
//! from libsodium (NaCl) using only pure Rust cryptographic libraries.
//! It is fully compatible with sealed boxes created by libsodium/sodiumoxide.
//!
//! # Features
//!
//! - `seal`: Create a sealed box for a recipient's public key
//! - `open_sealed_box`: Open a sealed box using the recipient's keypair
//! - Pure Rust implementation with no C dependencies

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand_core::OsRng;
use xsalsa20poly1305::{aead::Aead, consts::U10, KeyInit, XSalsa20Poly1305};

pub use x25519_dalek::{PublicKey, StaticSecret};

/// The length of a Curve25519 public key in bytes (for compatibility with sealed box format)
pub const PUBLICKEYBYTES: usize = 32;

/// Generate a new X25519 keypair for use with sealed box operations
///
/// Returns a tuple of (PublicKey, StaticSecret)
pub fn generate_keypair() -> (PublicKey, StaticSecret) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (public, secret)
}

/// Derives a nonce from the ephemeral public key and recipient's public key.
///
/// Uses Blake2b to hash the concatenation of both keys to create a 24-byte nonce.
#[inline]
fn derive_nonce(ephemeral_pk: &[u8], recipient_pk: &[u8]) -> Result<xsalsa20poly1305::Nonce, ()> {
    let mut nonce_material = Vec::with_capacity(PUBLICKEYBYTES * 2);
    nonce_material.extend_from_slice(ephemeral_pk);
    nonce_material.extend_from_slice(recipient_pk);

    let mut hasher = Blake2bVar::new(24).map_err(|_| ())?;
    hasher.update(&nonce_material);

    let mut nonce_bytes = [0u8; 24];
    hasher.finalize_variable(&mut nonce_bytes).map_err(|_| ())?;

    Ok(xsalsa20poly1305::Nonce::from(nonce_bytes))
}

/// Derives a symmetric key from the shared secret using HSalsa20.
#[inline]
fn derive_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let hsalsa_nonce = [0u8; 16];
    let key = salsa20::hsalsa::<U10>(shared_secret.into(), &hsalsa_nonce.into());
    let mut result = [0u8; 32];
    result.copy_from_slice(key.as_slice());
    result
}

/// Creates a sealed box for a message using a recipient's public key.
///
/// The sealed box format is compatible with libsodium's sealed box encryption.
/// It uses an ephemeral keypair to perform the encryption, so only the recipient
/// with the corresponding secret key can decrypt the message.
///
/// The sealed box format is:
/// - First 32 bytes: Ephemeral public key
/// - Remaining bytes: XSalsa20Poly1305 encrypted data with a nonce derived from both public keys
///
/// # Arguments
///
/// * `message` - The plaintext message to encrypt
/// * `recipient_pk` - The recipient's public key
///
/// # Returns
///
/// A Vec<u8> containing the sealed box ciphertext
pub fn seal(message: &[u8], recipient_pk: &PublicKey) -> Vec<u8> {
    // Generate an ephemeral keypair for this sealed box
    let ephemeral_sk = StaticSecret::random_from_rng(OsRng);
    let ephemeral_pk = PublicKey::from(&ephemeral_sk);

    // Compute the shared secret using X25519 Diffie-Hellman
    let shared_secret = ephemeral_sk.diffie_hellman(recipient_pk);

    // Derive the symmetric key using HSalsa20
    let key_bytes = derive_key(shared_secret.as_bytes());

    // Compute nonce: blake2b(ephemeral_pk || recipient_pk, outlen=24)
    let nonce = derive_nonce(ephemeral_pk.as_bytes(), recipient_pk.as_bytes())
        .expect("Failed to derive nonce");

    // Create the XSalsa20Poly1305 cipher with the derived key
    let cipher = XSalsa20Poly1305::new_from_slice(&key_bytes)
        .expect("Failed to create XSalsa20Poly1305 cipher");

    // Encrypt the message
    let ciphertext = cipher.encrypt(&nonce, message).expect("Encryption failed");

    // Combine the ephemeral public key and ciphertext to form the sealed box
    let mut sealed_box = Vec::with_capacity(PUBLICKEYBYTES + ciphertext.len());
    sealed_box.extend_from_slice(ephemeral_pk.as_bytes());
    sealed_box.extend_from_slice(&ciphertext);

    sealed_box
}

/// Opens a sealed box using RustCrypto libraries.
///
/// This function is compatible with sealed boxes created by libsodium's sealed box encryption.
/// It uses modern RustCrypto libraries which are actively maintained.
///
/// The sealed box format from libsodium is:
/// - First 32 bytes: Ephemeral public key
/// - Remaining bytes: XSalsa20Poly1305 encrypted data with a nonce derived from both public keys
///
/// # Arguments
///
/// * `sealed_box` - The sealed box ciphertext to decrypt
/// * `public_key` - Recipient's public key
/// * `secret_key` - Recipient's secret key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext on success
/// * `Err(())` - Decryption error (invalid format, authentication failure, etc.)
#[allow(clippy::result_unit_err)]
pub fn open_sealed_box(
    sealed_box: &[u8],
    public_key: &PublicKey,
    secret_key: &StaticSecret,
) -> Result<Vec<u8>, ()> {
    if sealed_box.len() <= PUBLICKEYBYTES {
        return Err(());
    }

    let ephemeral_pk_bytes = &sealed_box[..PUBLICKEYBYTES];
    let ciphertext = &sealed_box[PUBLICKEYBYTES..];

    // Derive the nonce using the ephemeral public key and recipient's public key
    let nonce = derive_nonce(ephemeral_pk_bytes, public_key.as_bytes())?;

    // Convert ephemeral public key bytes to x25519-dalek type
    let ephemeral_pk_array = <[u8; 32]>::try_from(ephemeral_pk_bytes).map_err(|_| ())?;
    let ephemeral_pk = PublicKey::from(ephemeral_pk_array);

    // Compute the shared secret using X25519 Diffie-Hellman
    let shared_secret = secret_key.diffie_hellman(&ephemeral_pk);

    // Derive the symmetric key using HSalsa20
    let key_bytes = derive_key(shared_secret.as_bytes());

    // Create the XSalsa20Poly1305 cipher with the derived key
    let cipher = XSalsa20Poly1305::new_from_slice(&key_bytes).map_err(|_| ())?;

    // Decrypt the ciphertext
    match cipher.decrypt(&nonce, ciphertext) {
        Ok(pt) => Ok(pt),
        Err(_) => Err(()),
    }
}

/// Convenience function to convert a public key from bytes to the PublicKey type
pub fn public_key_from_bytes(bytes: &[u8; 32]) -> PublicKey {
    PublicKey::from(*bytes)
}

/// Convenience function to convert a secret key from bytes to the StaticSecret type
pub fn secret_key_from_bytes(bytes: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test vectors generated from libsodium
    struct SealedBoxTestVector {
        public_key: [u8; 32],
        secret_key: [u8; 32],
        message: &'static [u8],
        sealed_box: &'static [u8],
    }

    const TEST_VECTORS: &[SealedBoxTestVector] = &[
        // Test vector 1
        SealedBoxTestVector {
            public_key: [
                0xef, 0x3f, 0x98, 0xa8, 0x93, 0x0d, 0xe6, 0x73, 0xa9, 0xb2, 0xf1, 0xc6, 0xfc, 0x48,
                0x21, 0x98, 0xd9, 0x6e, 0x92, 0x54, 0xe4, 0x97, 0xd9, 0x58, 0x9b, 0x6b, 0xbc, 0x16,
                0xed, 0xd5, 0x6f, 0x1f,
            ],
            secret_key: [
                0x25, 0xf4, 0x43, 0x72, 0x82, 0x0a, 0xd7, 0x3c, 0xa7, 0x9d, 0x1e, 0x33, 0xd0, 0x2c,
                0x04, 0x4c, 0x86, 0xe3, 0xe0, 0xa8, 0x79, 0xa8, 0xee, 0x9b, 0x96, 0x40, 0x45, 0x9f,
                0x9c, 0x95, 0xa8, 0xc4,
            ],
            message: &[
                0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x65, 0x73, 0x74,
                0x20, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x73,
                0x65, 0x61, 0x6c, 0x65, 0x64, 0x20, 0x62, 0x6f, 0x78,
            ],
            sealed_box: &[
                0x5d, 0xc7, 0x24, 0xbd, 0x8d, 0x64, 0x87, 0xf5, 0xe7, 0x98, 0x4b, 0x1f, 0xd1, 0xa2,
                0x9c, 0xf4, 0xd1, 0x25, 0xe3, 0x43, 0x54, 0x03, 0x4f, 0xa5, 0xe2, 0xaf, 0x0a, 0x12,
                0x9a, 0x93, 0xad, 0x17, 0x28, 0xd0, 0x5e, 0x60, 0x45, 0x7b, 0xbb, 0x7f, 0xe2, 0x77,
                0x3c, 0xc5, 0x68, 0x7d, 0x75, 0x11, 0x20, 0x4b, 0x05, 0x54, 0x37, 0x13, 0x52, 0x75,
                0x58, 0xb2, 0x00, 0xcf, 0x2d, 0x83, 0xb8, 0x47, 0xee, 0x1f, 0x2b, 0x8f, 0x32, 0x10,
                0x29, 0x87, 0x70, 0x81, 0x96, 0xb1, 0x3b, 0x2d, 0x47, 0x8d, 0xc8, 0xcd, 0xae, 0x26,
                0xc7,
            ],
        },
        // Test vector 2 (empty message)
        SealedBoxTestVector {
            public_key: [
                0x5b, 0x64, 0xee, 0x4f, 0x71, 0x84, 0x8d, 0x93, 0x1b, 0x9d, 0xd2, 0xe1, 0xd9, 0x5a,
                0x6d, 0x27, 0xf5, 0xa0, 0x77, 0x4a, 0xef, 0xd1, 0x32, 0xe2, 0xb7, 0xfc, 0xc3, 0xa2,
                0xae, 0xeb, 0xc8, 0x78,
            ],
            secret_key: [
                0x42, 0xdc, 0x49, 0x0e, 0x21, 0x17, 0x3b, 0x11, 0x15, 0xd8, 0x03, 0xdd, 0x0e, 0xc1,
                0x89, 0xbb, 0x73, 0xc9, 0x30, 0x05, 0x62, 0xe1, 0xcf, 0x7e, 0x37, 0x72, 0xf4, 0xa2,
                0x6a, 0x14, 0x29, 0x43,
            ],
            message: &[],
            sealed_box: &[
                0xc6, 0x57, 0x0d, 0xdb, 0x03, 0xf6, 0x8f, 0x7e, 0x02, 0xa2, 0xdb, 0x70, 0x55, 0xe0,
                0xc9, 0xa6, 0x26, 0xc9, 0xf5, 0x25, 0x08, 0x47, 0x59, 0xec, 0xc9, 0xb6, 0xfd, 0x03,
                0xe2, 0xda, 0xe3, 0x7c, 0x8b, 0x06, 0xec, 0xd2, 0x3a, 0x05, 0x46, 0x09, 0x26, 0x70,
                0xb6, 0x20, 0xc7, 0xd6, 0x26, 0x23,
            ],
        },
    ];

    #[test]
    fn test_open_sealed_box_with_test_vectors() {
        // Test all vectors from our test suite
        for (i, vector) in TEST_VECTORS.iter().enumerate() {
            // Convert test vector keys to X25519 types
            let public_key = public_key_from_bytes(&vector.public_key);
            let secret_key = secret_key_from_bytes(&vector.secret_key);

            // Try to open the sealed box
            let result = open_sealed_box(vector.sealed_box, &public_key, &secret_key);

            // Verify the result
            assert!(
                result.is_ok(),
                "Failed to open sealed box with test vector {}",
                i
            );
            assert_eq!(
                result.unwrap(),
                vector.message,
                "Decrypted message doesn't match original for test vector {}",
                i
            );
        }
    }

    #[test]
    fn test_open_sealed_box_with_wrong_key() {
        // Use the first test vector
        let vector = &TEST_VECTORS[0];

        // Use the correct public key but wrong secret key (from vector 1)
        let public_key = public_key_from_bytes(&vector.public_key);
        let wrong_secret_key = secret_key_from_bytes(&TEST_VECTORS[1].secret_key);

        // Try to open the sealed box with wrong key
        let result = open_sealed_box(vector.sealed_box, &public_key, &wrong_secret_key);

        // Verify the result is an error
        assert!(result.is_err(), "Should fail with wrong key");
    }

    #[test]
    fn test_open_sealed_box_with_corrupted_data() {
        // Use the first test vector
        let vector = &TEST_VECTORS[0];

        // Create a corrupted copy of the sealed box
        let mut corrupted_sealed_box = vector.sealed_box.to_vec();
        if corrupted_sealed_box.len() > 10 {
            let index = corrupted_sealed_box.len() / 2;
            corrupted_sealed_box[index] ^= 0x01; // Flip one bit
        }

        // Convert test vector keys to X25519 types
        let public_key = public_key_from_bytes(&vector.public_key);
        let secret_key = secret_key_from_bytes(&vector.secret_key);

        // Try to open the corrupted sealed box
        let result = open_sealed_box(&corrupted_sealed_box, &public_key, &secret_key);

        // Verify the result is an error
        assert!(result.is_err(), "Should fail with corrupted data");
    }

    #[test]
    fn test_generate_and_open() {
        // Use an existing test vector to verify we can decrypt
        let vector = &TEST_VECTORS[0];
        let vector_public_key = public_key_from_bytes(&vector.public_key);
        let vector_secret_key = secret_key_from_bytes(&vector.secret_key);

        let result = open_sealed_box(vector.sealed_box, &vector_public_key, &vector_secret_key);

        assert!(
            result.is_ok(),
            "Failed to open test vector with generated keys"
        );
        assert_eq!(result.unwrap(), vector.message, "Messages don't match");
    }

    #[test]
    fn test_seal_and_open() {
        // Generate a keypair for the recipient
        let (public_key, secret_key) = generate_keypair();

        // Create a test message
        let message = b"This is a test message for sealed box encryption";

        // Seal the message
        let sealed_box = seal(message, &public_key);

        // Verify the sealed box format
        assert!(sealed_box.len() > PUBLICKEYBYTES, "Sealed box too short");

        // Open the sealed box
        let decrypted = open_sealed_box(&sealed_box, &public_key, &secret_key)
            .expect("Failed to open sealed box");

        // Verify the decrypted message matches the original
        assert_eq!(
            decrypted, message,
            "Decrypted message doesn't match original"
        );

        // Try to open with a different keypair (should fail)
        let (wrong_public_key, wrong_secret_key) = generate_keypair();

        let result = open_sealed_box(&sealed_box, &wrong_public_key, &wrong_secret_key);
        assert!(result.is_err(), "Should fail with wrong keypair");
    }
}
