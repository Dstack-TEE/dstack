//! Key derivation functions.
use anyhow::{anyhow, Context, Result};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use ring::{
    error::Unspecified,
    hkdf::{KeyType, Okm, Prk, Salt, HKDF_SHA256},
};
use rustls_pki_types::PrivateKeyDer;

struct AnySizeKey(usize);
impl KeyType for AnySizeKey {
    fn len(&self) -> usize {
        self.0
    }
}

/// Derives a key using HKDF-SHA256.
pub fn derive_ecdsa_key(
    input_key_material: &[u8],
    context_data: &[&[u8]],
    key_size: usize,
) -> Result<Vec<u8>, Unspecified> {
    let salt = Salt::new(HKDF_SHA256, b"RATLS");
    let pseudo_rand_key: Prk = salt.extract(input_key_material);
    let output_key_material: Okm<AnySizeKey> =
        pseudo_rand_key.expand(context_data, AnySizeKey(key_size))?;
    let mut result = vec![0u8; key_size];
    output_key_material.fill(&mut result)?;
    Ok(result)
}

/// Derives a key pair from a given key pair.
pub fn derive_ecdsa_key_pair(from: &KeyPair, context_data: &[&[u8]]) -> Result<KeyPair> {
    let der_bytes = from.serialized_der();
    let sk = p256::SecretKey::from_pkcs8_der(der_bytes).context("failed to decode secret key")?;
    let sk_bytes = sk.as_scalar_primitive().to_bytes();
    derive_ecdsa_key_pair_from_bytes(&sk_bytes, context_data)
}

/// Derives a key pair from a given private key bytes.
pub fn derive_ecdsa_key_pair_from_bytes(
    sk_bytes: &[u8],
    context_data: &[&[u8]],
) -> Result<KeyPair> {
    let derived_sk_bytes =
        derive_ecdsa_key(sk_bytes, context_data, 32).or(Err(anyhow!("failed to derive key")))?;
    let derived_sk = p256::SecretKey::from_slice(&derived_sk_bytes)
        .context("failed to decode derived secret key")?;
    let derived_sk_der = derived_sk
        .to_pkcs8_der()
        .context("failed to encode derived secret key")?;
    let der = PrivateKeyDer::try_from(derived_sk_der.as_bytes())
        .map_err(|err| anyhow!("failed to decode derived secret key: {err}"))?;
    let key = KeyPair::from_der_and_sign_algo(&der, &PKCS_ECDSA_P256_SHA256)
        .context("failed to create derived key pair")?;
    Ok(key)
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derives a X25519 secret from a given key pair.
pub fn derive_dh_secret(from: &KeyPair, context_data: &[&[u8]]) -> Result<[u8; 32]> {
    let key_pair = derive_ecdsa_key_pair(from, context_data)?;
    let derived_secret = sha256(key_pair.serialized_der());
    Ok(derived_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key32() {
        let key = derive_ecdsa_key(b"input key material", &[b"context one"], 32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_derive_key256() {
        let key = derive_ecdsa_key(b"input key material", &[b"context one"], 256).unwrap();
        assert_eq!(key.len(), 256);
        assert!(key.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_derive_key_pair() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let _derived_key = derive_ecdsa_key_pair(&key, &[b"context one"]).unwrap();
    }
}
