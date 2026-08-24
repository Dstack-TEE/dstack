// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! The v1 application key, assembled from the shared normative primitives.
//!
//! The encodings themselves -- the salt, the context tags, the length-prefixed
//! `info` and claim, and the chain-link envelope -- live in
//! [`ra_tls::guest_api_v1`], so the agent, the verifier and the SDK share one
//! definition instead of three transcriptions of the specification prose. What
//! is left here is turning derived bytes into a usable key pair.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey;
use ra_tls::guest_api_v1::{derive_app_key, key_claim, sign_recoverable_keccak256};

pub(crate) use ra_tls::guest_api_v1::KeyAlgorithm as Algorithm;

/// An application key derived for one `(domain, algorithm)` pair.
pub(crate) struct AppKey {
    algorithm: Algorithm,
    domain: String,
    secret: [u8; 32],
    public_key: Vec<u8>,
}

impl AppKey {
    /// Derive the key for `(domain, algorithm)` from the app root key.
    ///
    /// Flat, not hierarchical: `a/b` is an opaque domain string like any other,
    /// unrelated to `a`, and no key here derives another.
    pub(crate) fn derive(app_root_key: &[u8], domain: &str, algorithm: Algorithm) -> Result<Self> {
        let secret = derive_app_key(app_root_key, domain, algorithm)?;
        let public_key = match algorithm {
            // Rejects a scalar that is zero or at least the group order. That
            // is a ~2^-128 event for one domain and the caller can just pick
            // another one, so failing is better than folding the scalar into
            // range and quietly landing two domains on one key.
            Algorithm::Secp256k1 => SigningKey::from_slice(&secret)
                .context("derived secp256k1 key is not a valid scalar")?
                .verifying_key()
                .to_sec1_bytes()
                .to_vec(),
            Algorithm::Ed25519 => Ed25519SigningKey::from_bytes(&secret)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        Ok(Self {
            algorithm,
            domain: domain.to_string(),
            secret,
            public_key,
        })
    }

    /// The raw 32-byte private key.
    pub(crate) fn secret(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    /// SEC1 compressed for secp256k1, 32 raw bytes for ed25519.
    pub(crate) fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// The app root key's signature over this key's claim: the first link of
    /// the signature chain.
    ///
    /// Takes the parsed key rather than its bytes, so the caller can share one
    /// across requests instead of re-parsing a scalar per `GetKey`.
    pub(crate) fn claim_signature(&self, app_root_key: &SigningKey) -> Result<Vec<u8>> {
        let claim = key_claim(self.algorithm, &self.domain, &self.public_key)?;
        sign_recoverable_keccak256(app_root_key, &claim)
            .map_err(|err| anyhow!("failed to sign the key claim: {err:#}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app root key `ra_tls::guest_api_v1` committed its vectors against.
    const TEST_APP_ROOT_KEY: [u8; 32] = [
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B, 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C,
        0x6D, 0x7E, 0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0x0F,
        0x1A, 0x2B,
    ];

    fn derive(domain: &str, algorithm: Algorithm) -> AppKey {
        AppKey::derive(&TEST_APP_ROOT_KEY, domain, algorithm).unwrap()
    }

    /// The public key vectors, checked through the type the handler actually
    /// uses. The private-key and encoding vectors are pinned next to the
    /// primitives in `ra_tls::guest_api_v1`.
    #[test]
    fn derives_the_committed_public_key_vectors() {
        let vectors = [
            (
                "",
                Algorithm::Secp256k1,
                "0377c7fb050db181d392266a3cee9adb2901c6d665f11bac68be5457f577ba4908",
            ),
            (
                "",
                Algorithm::Ed25519,
                "a3dc149fd5b765eab2eb7d3174fa939e39386898f10b15b7b146f6f1358ecf2a",
            ),
            (
                "wallet",
                Algorithm::Secp256k1,
                "0369cecd3c8da88730f7d45875824c3e75f63a2d3da4be42f45671954daa2abb28",
            ),
            (
                "wallet",
                Algorithm::Ed25519,
                "dade622d0fa1641e79b16e0b04e296be671f85f0aa6387b7d37e9d89f87494f5",
            ),
            (
                "a/b/c",
                Algorithm::Secp256k1,
                "02e9b1a61b6d70aa9b241753828c316bf90e33e77b2e113f9ba75a8b6dc3cde5c1",
            ),
            (
                "k\u{0}:ey",
                Algorithm::Ed25519,
                "c833107822b003ff5675b33b90b151d4315c3ab9162b17d876e8dffde41abf9b",
            ),
        ];
        for (domain, algorithm, expected) in vectors {
            assert_eq!(
                hex::encode(derive(domain, algorithm).public_key()),
                expected,
                "v1 public key vector changed for ({domain:?}, {})",
                algorithm.name()
            );
        }
    }

    #[test]
    fn the_public_key_lengths_are_the_specified_ones() {
        assert_eq!(
            derive("wallet", Algorithm::Secp256k1).public_key().len(),
            33
        );
        assert_eq!(derive("wallet", Algorithm::Ed25519).public_key().len(), 32);
    }

    #[test]
    fn the_two_algorithms_never_share_key_material() {
        for domain in ["", "wallet", "a/b/c"] {
            assert_ne!(
                derive(domain, Algorithm::Secp256k1).secret(),
                derive(domain, Algorithm::Ed25519).secret(),
                "cross-algorithm key reuse at {domain:?}"
            );
        }
    }

    #[test]
    fn the_claim_signature_verifies_under_the_app_root_key() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
        use sha3::{Digest as _, Keccak256};

        let key = derive("wallet", Algorithm::Secp256k1);
        let app_root = SigningKey::from_slice(&TEST_APP_ROOT_KEY).unwrap();
        let link = key.claim_signature(&app_root).unwrap();
        assert_eq!(link.len(), 65);

        let claim = key_claim(Algorithm::Secp256k1, "wallet", &key.public_key()).unwrap();
        let recovered = VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(&claim),
            &Signature::from_slice(&link[..64]).unwrap(),
            RecoveryId::from_byte(link[64]).unwrap(),
        )
        .unwrap();
        assert_eq!(&recovered, app_root.verifying_key());
    }
}
