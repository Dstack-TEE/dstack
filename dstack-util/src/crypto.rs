// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use aes_gcm::{
    aead::{Aead, Nonce},
    Aes256Gcm, KeyInit,
};
use anyhow::{anyhow, Result};
use x25519_dalek::{PublicKey, StaticSecret};

pub fn dh_agree(secret: [u8; 32], their_pubkey: [u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(secret);
    let their_public = PublicKey::from(their_pubkey);
    let shared_secret = secret.diffie_hellman(&their_public);
    shared_secret.to_bytes()
}

pub fn dh_decrypt(secret: [u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>> {
    // Extract components (matching JS implementation)
    let ephemeral_pubkey = ciphertext
        .get(..32)
        .ok_or(anyhow!("Invalid ephemeral public key length"))?
        .try_into()
        .map_err(|_| anyhow!("Invalid ephemeral public key length"))?;
    let iv = &ciphertext.get(32..44).ok_or(anyhow!("Invalid IV length"))?;
    let ciphertext = &ciphertext
        .get(44..)
        .ok_or(anyhow!("Invalid ciphertext length"))?;

    // Derive shared secret using X25519
    let shared_secret = dh_agree(secret, ephemeral_pubkey);

    // Create AES-GCM cipher
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("Failed to create cipher: {}", e))?;

    // Decrypt using AES-GCM
    cipher
        .decrypt(Nonce::<Aes256Gcm>::from_slice(iv), ciphertext.as_ref())
        .map_err(|e| anyhow!("Decryption failed: {}", e))
}

/// Encrypt to `remote_public_key` in the format [`dh_decrypt`] reads:
/// ephemeral public key, IV, then the AES-GCM ciphertext.
#[cfg(test)]
pub fn dh_encrypt(remote_public_key: [u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let ephemeral_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let shared_secret = ephemeral_secret
        .diffie_hellman(&PublicKey::from(remote_public_key))
        .to_bytes();
    let cipher = Aes256Gcm::new_from_slice(&shared_secret)
        .map_err(|e| anyhow!("failed to create cipher: {e}"))?;
    let iv: [u8; 12] = rand::random();
    let ciphertext = cipher
        .encrypt(Nonce::<Aes256Gcm>::from_slice(&iv), plaintext)
        .map_err(|e| anyhow!("encryption failed: {e}"))?;
    Ok([
        PublicKey::from(&ephemeral_secret).as_bytes(),
        &iv[..],
        &ciphertext,
    ]
    .concat())
}

/// Encrypt a sealed environment with HPKE DHKEM(X25519, HKDF-SHA256) and AES-256-GCM.
pub fn sealed_env_encrypt(public_key: &[u8], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use hpke::{
        aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeS,
        Serializable,
    };
    let public_key = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow!("invalid sealed env public key"))?;
    let (enc, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &public_key,
        info,
        plaintext,
        &[],
    )
    .map_err(|e| anyhow!("sealed env encryption failed: {e}"))?;
    Ok([enc.to_bytes().as_ref(), ciphertext.as_slice()].concat())
}

/// Decrypt a sealed environment HPKE payload.
pub fn sealed_env_decrypt(secret: &[u8], info: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    use hpke::{aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, OpModeR};
    let enc = payload
        .get(..32)
        .ok_or_else(|| anyhow!("sealed env payload is missing encapsulated key"))?;
    let ciphertext = payload
        .get(32..)
        .ok_or_else(|| anyhow!("sealed env payload is missing ciphertext"))?;
    let secret = <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(secret)
        .map_err(|_| anyhow!("invalid sealed env private key"))?;
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc)
        .map_err(|_| anyhow!("invalid sealed env encapsulated key"))?;
    hpke::single_shot_open::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &secret,
        &enc,
        info,
        ciphertext,
        &[],
    )
    .map_err(|e| anyhow!("sealed env decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh_agree() {
        use rand::Rng;
        let secret = rand::thread_rng().gen::<[u8; 32]>();
        let pubkey = rand::thread_rng().gen::<[u8; 32]>();
        let shared = dh_agree(secret, pubkey);
        assert_eq!(shared.len(), 32);
        println!("secret: {:?}", hex::encode(secret));
        println!("pubkey: {:?}", hex::encode(pubkey));
        println!("shared: {:?}", hex::encode(shared));
    }

    #[test]
    fn test_dh_decrypt_invalid_input() {
        let secret = [0u8; 32];

        // Test empty input
        assert!(dh_decrypt(secret, &[]).is_err());

        // Test input too short for public key
        assert!(dh_decrypt(secret, &[0u8; 31]).is_err());

        // Test input too short for IV
        assert!(dh_decrypt(secret, &[0u8; 43]).is_err());

        // Test input with no ciphertext
        assert!(dh_decrypt(secret, &[0u8; 44]).is_err());
    }

    #[test]
    fn test_dh_decrypt() {
        let secret: [u8; 32] =
            hex::decode("7c282bf94b35dc47801dc953bfa0896fc2bd313381d3e8eca4e42f6536d2a96f")
                .unwrap()
                .try_into()
                .unwrap();
        let ciphertext = hex::decode("0bd18749612f4c8b9dd583c7d6a646b90abd34e3c731a7708d0caf9039095641e1f0948e775f0b7351788db7f246d51806954626dcccb6a60d64665ca3715c6bef75616cab476d27bba04080361200d6a58cec").unwrap();
        let decrypted = dh_decrypt(secret, &ciphertext).unwrap();
        let decrypted_str = String::from_utf8(decrypted).unwrap();
        assert_eq!(decrypted_str, "[{\"key\":\"\",\"value\":\"\"}]");
    }

    #[test]
    fn dh_encrypt_round_trips_through_dh_decrypt() {
        let secret = [7u8; 32];
        let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
        let ciphertext = dh_encrypt(public, b"env").unwrap();
        assert_eq!(dh_decrypt(secret, &ciphertext).unwrap(), b"env");
        assert!(dh_decrypt([8u8; 32], &ciphertext).is_err());
    }

    #[test]
    fn opens_sdk_sealed_envs() {
        use base64::Engine as _;
        for source in [
            include_str!("../tests/fixtures/sealed-env-python.json"),
            include_str!("../tests/fixtures/sealed-env-javascript.json"),
        ] {
            let fixture: serde_json::Value = serde_json::from_str(source).unwrap();
            let envelope = &fixture["sealed_env"];
            let decode = |name: &str| {
                base64::engine::general_purpose::STANDARD
                    .decode(envelope[name].as_str().unwrap())
                    .unwrap()
            };
            let payload = [decode("enc"), decode("ciphertext")].concat();
            let plaintext = sealed_env_decrypt(
                &hex::decode(fixture["private_key"].as_str().unwrap()).unwrap(),
                b"dstack-sealed-env-v1:3:0",
                &payload,
            )
            .unwrap();
            let decoded: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
            assert_eq!(decoded["env"], fixture["env"]);
        }
    }

    #[test]
    fn sealed_env_round_trips_and_binds_info() {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret).to_bytes();
        let info = b"dstack-sealed-env-v1:3:0";
        let payload = sealed_env_encrypt(&public, info, b"secret env").unwrap();
        assert_eq!(
            sealed_env_decrypt(&secret.to_bytes(), info, &payload).unwrap(),
            b"secret env"
        );
        assert!(
            sealed_env_decrypt(&secret.to_bytes(), b"dstack-sealed-env-v1:4:0", &payload).is_err()
        );
        let mut tampered = payload;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(sealed_env_decrypt(&secret.to_bytes(), info, &tampered).is_err());
    }
}
