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
}
