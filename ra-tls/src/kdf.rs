// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

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
pub fn derive_key(
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

/// Derives a P-256 key pair from a given key pair.
pub fn derive_p256_key_pair(from: &KeyPair, context_data: &[&[u8]]) -> Result<KeyPair> {
    let der_bytes = from.serialized_der();
    let sk = p256::SecretKey::from_pkcs8_der(der_bytes).context("failed to decode secret key")?;
    let sk_bytes = sk.as_scalar_primitive().to_bytes();
    derive_p256_key_pair_from_bytes(&sk_bytes, context_data)
}

/// Derives a P-256 key pair from a given private key bytes.
pub fn derive_p256_key_pair_from_bytes(sk_bytes: &[u8], context_data: &[&[u8]]) -> Result<KeyPair> {
    let derived_sk_bytes =
        derive_key(sk_bytes, context_data, 32).or(Err(anyhow!("failed to derive key")))?;
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

/// Returns the canonical PKCS#8 DER encoding of a P-256 key pair.
///
/// This uses `p256::SecretKey::to_pkcs8_der()` directly instead of
/// `rcgen::KeyPair::serialized_der()` to decouple the encoding from the
/// rcgen library version. The p256 crate produces canonical ASN.1 DER which
/// is deterministic and identical to rcgen's current output.
///
/// This matters because `derive_dh_secret` hashes the PKCS#8 DER bytes
/// (including the public key) to produce a secret — a historical design
/// choice that we must preserve for backward compatibility.
fn p256_keypair_to_pkcs8_der(key_pair: &KeyPair) -> Result<Vec<u8>> {
    let sk = p256::SecretKey::from_pkcs8_der(key_pair.serialized_der())
        .context("failed to decode secret key")?;
    let pkcs8_der = sk
        .to_pkcs8_der()
        .context("failed to encode secret key to PKCS#8 DER")?;
    Ok(pkcs8_der.as_bytes().to_vec())
}

/// Derives a X25519 secret from a given key pair.
pub fn derive_dh_secret(from: &KeyPair, context_data: &[&[u8]]) -> Result<[u8; 32]> {
    let key_pair = derive_p256_key_pair(from, context_data)?;
    let derived_secret = sha256(&p256_keypair_to_pkcs8_der(&key_pair)?);
    Ok(derived_secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key32() {
        let key = derive_key(b"input key material", &[b"context one"], 32).unwrap();
        assert_eq!(key.len(), 32);
        assert!(key.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_derive_key256() {
        let key = derive_key(b"input key material", &[b"context one"], 256).unwrap();
        assert_eq!(key.len(), 256);
        assert!(key.iter().any(|&x| x != 0));
    }

    #[test]
    fn test_derive_key_pair() {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let _derived_key = derive_p256_key_pair(&key, &[b"context one"]).unwrap();
    }

    #[test]
    fn test_derive_dh_secret_stable_output() {
        // Fixed test vector generated from the original rcgen-based implementation.
        // If this test fails after a dependency upgrade, the PKCS#8 encoding has
        // changed and deployed secrets would be silently broken.
        // Do NOT update the expected value — fix the encoding instead.
        let root_der = hex::decode(
            "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02\
             01010420f57527cea4ab7ffb49af99b158cdc0e3ec06398f528349ea236b7d2a\
             fe19cec1a1440342000491f50522407ce29dce3ed7d31a15d80c1c42f13a2355\
             2d2b33a0ce09ee11e47bce95936f3e7f80d195f879e28e1b144ef37ac9ab8e36\
             a690cbf930b775897b27",
        )
        .unwrap();
        let expected_secret = "663afd58820be8ad645f9c035e93199d114ab16f738db62393bc1d7d623e8813";

        let root_key = KeyPair::from_der_and_sign_algo(
            &PrivateKeyDer::try_from(root_der.as_slice()).unwrap(),
            &PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        let context = [b"context one".as_ref(), b"context two".as_ref()];
        let secret = derive_dh_secret(&root_key, &context).unwrap();

        assert_eq!(
            hex::encode(secret),
            expected_secret,
            "derive_dh_secret output changed — this would break existing deployments"
        );
    }
}
