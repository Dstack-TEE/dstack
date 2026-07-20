// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use blake2::{
    digest::{Update, VariableOutput},
    Blake2bVar,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use xsalsa20poly1305::{aead::Aead, consts::U10, KeyInit, XSalsa20Poly1305};

use crate::error::ProviderError;

pub const PUBLIC_KEY_SIZE: usize = 32;

pub fn derive_key(sealing_key: &[u8], measurements: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    Digest::update(&mut hasher, sealing_key);
    Digest::update(&mut hasher, measurements);
    hasher.finalize().into()
}

pub fn public_key(report_data: &[u8]) -> Result<PublicKey, ProviderError> {
    let bytes: [u8; PUBLIC_KEY_SIZE] = report_data
        .get(..PUBLIC_KEY_SIZE)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ProviderError::InvalidPublicKey)?;
    Ok(PublicKey::from(bytes))
}

/// Encrypt using the libsodium sealed-box wire format so existing dstack
/// guests can continue to use `sodiumbox::open_sealed_box` unchanged.
pub fn seal(message: &[u8], recipient: &PublicKey) -> Result<Vec<u8>, ProviderError> {
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(recipient);
    if !shared_secret.was_contributory() {
        return Err(ProviderError::InvalidPublicKey);
    }
    let key = salsa20::hsalsa::<U10>(shared_secret.as_bytes().into(), &[0_u8; 16].into());
    let nonce = nonce(ephemeral_public.as_bytes(), recipient.as_bytes())?;
    let cipher = XSalsa20Poly1305::new_from_slice(&key)
        .map_err(|_| ProviderError::Crypto("invalid sealed-box key".into()))?;
    let ciphertext = cipher
        .encrypt(&nonce, message)
        .map_err(|_| ProviderError::Crypto("sealed-box encryption failed".into()))?;

    let mut sealed = Vec::with_capacity(PUBLIC_KEY_SIZE + ciphertext.len());
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

fn nonce(
    ephemeral_public: &[u8; PUBLIC_KEY_SIZE],
    recipient: &[u8; PUBLIC_KEY_SIZE],
) -> Result<xsalsa20poly1305::Nonce, ProviderError> {
    let mut hasher = Blake2bVar::new(24)
        .map_err(|_| ProviderError::Crypto("invalid sealed-box nonce size".into()))?;
    hasher.update(ephemeral_public);
    hasher.update(recipient);
    let mut bytes = [0_u8; 24];
    hasher
        .finalize_variable(&mut bytes)
        .map_err(|_| ProviderError::Crypto("sealed-box nonce derivation failed".into()))?;
    Ok(bytes.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_sha256_of_key_and_measurements() {
        assert_eq!(
            derive_key(b"sealing key", b"measurements"),
            [
                0xdc, 0x3b, 0x72, 0x62, 0x58, 0x8a, 0x75, 0x6a, 0xa3, 0xc8, 0x09, 0xce, 0xcb, 0xc1,
                0xe4, 0xa0, 0x4e, 0x1c, 0xeb, 0x47, 0x13, 0x73, 0x1e, 0xf4, 0x9c, 0xb3, 0x35, 0xfd,
                0x68, 0xd0, 0x77, 0x81,
            ]
        );
    }

    #[test]
    fn sealed_box_round_trip_matches_libsodium_format() {
        let recipient_secret = StaticSecret::from([
            0x25, 0xf4, 0x43, 0x72, 0x82, 0x0a, 0xd7, 0x3c, 0xa7, 0x9d, 0x1e, 0x33, 0xd0, 0x2c,
            0x04, 0x4c, 0x86, 0xe3, 0xe0, 0xa8, 0x79, 0xa8, 0xee, 0x9b, 0x96, 0x40, 0x45, 0x9f,
            0x9c, 0x95, 0xa8, 0xc4,
        ]);
        let recipient_public = PublicKey::from(&recipient_secret);
        let message = b"dstack local key";
        let sealed = seal(message, &recipient_public).unwrap();

        let ephemeral_public =
            PublicKey::from(<[u8; PUBLIC_KEY_SIZE]>::try_from(&sealed[..PUBLIC_KEY_SIZE]).unwrap());
        let key = salsa20::hsalsa::<U10>(
            recipient_secret
                .diffie_hellman(&ephemeral_public)
                .as_bytes()
                .into(),
            &[0_u8; 16].into(),
        );
        let nonce = nonce(ephemeral_public.as_bytes(), recipient_public.as_bytes()).unwrap();
        let cipher = XSalsa20Poly1305::new_from_slice(&key).unwrap();
        let plaintext = cipher.decrypt(&nonce, &sealed[PUBLIC_KEY_SIZE..]).unwrap();

        assert_eq!(plaintext, message);
        assert_eq!(sealed.len(), PUBLIC_KEY_SIZE + message.len() + 16);
    }

    #[test]
    fn rejects_non_contributory_public_keys() {
        let public_key = PublicKey::from([0_u8; PUBLIC_KEY_SIZE]);
        assert!(matches!(
            seal(b"secret", &public_key),
            Err(ProviderError::InvalidPublicKey)
        ));
    }
}
