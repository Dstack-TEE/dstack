// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;

use ra_tls::api_v1::sign_recoverable_keccak256;
use ra_tls::kdf;

pub(crate) fn derive_k256_key(
    parent_key: &SigningKey,
    app_id: &[u8],
) -> Result<(SigningKey, Vec<u8>)> {
    let context_data = [app_id, b"app-key"];
    let derived_key_bytes: [u8; 32] = kdf::derive_key(&parent_key.to_bytes(), &context_data, 32)?
        .try_into()
        .ok()
        .context("Invalid derived key len")?;
    let derived_signing_key = SigningKey::from_bytes(&derived_key_bytes.into())?;
    let pubkey = derived_signing_key.verifying_key();

    let signature = sign_message(
        parent_key,
        b"dstack-kms-issued",
        app_id,
        &pubkey.to_sec1_bytes(),
    )?;
    Ok((derived_signing_key, signature))
}

pub(crate) fn sign_message(
    key: &SigningKey,
    prefix: &[u8],
    appid: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    // Same 65-byte `r || s || v` envelope every dstack chain link uses; the
    // preimage is what differs between them.
    sign_recoverable_keccak256(key, &[prefix, b":", appid, message].concat())
}

/// Sign a message with a timestamp to prevent replay attacks.
/// The signature covers: prefix + ":" + appid + timestamp_be_bytes + message
pub(crate) fn sign_message_with_timestamp(
    key: &SigningKey,
    prefix: &[u8],
    appid: &[u8],
    timestamp: u64,
    message: &[u8],
) -> Result<Vec<u8>> {
    let timestamp_bytes = timestamp.to_be_bytes();
    sign_recoverable_keccak256(
        key,
        &[prefix, b":", appid, &timestamp_bytes[..], message].concat(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest as _, Keccak256};

    /// The pre-refactor envelope, reproduced verbatim from the implementation
    /// that shipped before `sign_message` moved onto the shared helper.
    ///
    /// Kept as executable code rather than prose so the compatibility claim is
    /// checked on every run: whatever KMS sends to already-deployed CVMs was
    /// produced by exactly this, and a divergence here is a divergence in
    /// issued app keys and their signatures.
    fn legacy_sign_message(
        key: &SigningKey,
        prefix: &[u8],
        appid: &[u8],
        message: &[u8],
    ) -> Vec<u8> {
        let digest = Keccak256::new_with_prefix([prefix, b":", appid, message].concat());
        let (signature, recid) = key.sign_digest_recoverable(digest).unwrap();
        let mut signature_bytes = signature.to_vec();
        signature_bytes.push(recid.to_byte());
        signature_bytes
    }

    /// The pre-refactor timestamped envelope, likewise verbatim.
    fn legacy_sign_message_with_timestamp(
        key: &SigningKey,
        prefix: &[u8],
        appid: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Vec<u8> {
        let timestamp_bytes = timestamp.to_be_bytes();
        let digest = Keccak256::new_with_prefix(
            [prefix, b":", appid, &timestamp_bytes[..], message].concat(),
        );
        let (signature, recid) = key.sign_digest_recoverable(digest).unwrap();
        let mut signature_bytes = signature.to_vec();
        signature_bytes.push(recid.to_byte());
        signature_bytes
    }

    /// Moving `sign_message` onto `ra_tls::api_v1::sign_recoverable_keccak256`
    /// must not change one byte KMS sends to an already-deployed CVM.
    ///
    /// ECDSA here is deterministic (RFC 6979), so this is an exact comparison
    /// rather than a signature check. The cases below are the two shapes KMS
    /// actually signs; broader coverage of the KMS surface belongs to the
    /// test-infrastructure effort in PR #841, not here.
    #[test]
    fn the_shared_envelope_matches_the_pre_refactor_bytes() {
        let key = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let cases: [(&[u8], &[u8], &[u8]); 4] = [
            (b"dstack-kms-issued", b"app-a", &[0x42_u8; 33]),
            (b"dstack-kms-issued", b"", &[]),
            (b"dstack-env-encrypt-pubkey", b"app-b", &[0x01_u8; 32]),
            (b"x", b"\x00\xff", &[0xde, 0xad, 0xbe, 0xef]),
        ];
        for (prefix, appid, message) in cases {
            assert_eq!(
                sign_message(&key, prefix, appid, message).unwrap(),
                legacy_sign_message(&key, prefix, appid, message),
                "envelope changed for prefix {prefix:?}"
            );
        }

        for timestamp in [0_u64, 1, 1_786_194_000, u64::MAX] {
            assert_eq!(
                sign_message_with_timestamp(&key, b"p", b"app", timestamp, b"msg").unwrap(),
                legacy_sign_message_with_timestamp(&key, b"p", b"app", timestamp, b"msg"),
                "timestamped envelope changed at {timestamp}"
            );
        }
    }

    /// Golden bytes, so the reference implementation above cannot drift along
    /// with the real one and hide a change.
    ///
    /// Captured from the pre-refactor code. Do not update these to match new
    /// output -- a mismatch means KMS would issue different key signatures than
    /// the ones deployed CVMs already hold.
    #[test]
    fn issued_app_key_signatures_match_their_golden_vectors() {
        let root = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let (derived, signature) = derive_k256_key(&root, b"app-a").unwrap();

        assert_eq!(
            hex::encode(derived.to_bytes()),
            "ed0fd39ce7c26a185f396945168972807b2f77820f14ee4bda9e1f46e8b4596d",
            "the issued app key changed"
        );
        assert_eq!(
            hex::encode(&signature),
            "e12a5f4567f6d9f80b01944dea333bbed5b418347f4260ed95e9ee198a03014e1716a40d2ed6cd367e335b33e231510aa98216e62b631f2b75c181c2f989656800",
            "the issued app key signature changed"
        );
        // ...and it is still what the pre-refactor envelope produces.
        assert_eq!(
            signature,
            legacy_sign_message(
                &root,
                b"dstack-kms-issued",
                b"app-a",
                &derived.verifying_key().to_sec1_bytes()
            )
        );
    }

    #[test]
    fn environment_public_key_signatures_bind_domain_app_key_and_timestamp() {
        let key = SigningKey::from_slice(&[7_u8; 32]).unwrap();
        let prefix = b"dstack-env-encrypt-pubkey";
        let app_id = b"app-a";
        let timestamp = 1_786_194_000;
        let public_key = [0x42_u8; 32];
        let baseline =
            sign_message_with_timestamp(&key, prefix, app_id, timestamp, &public_key).unwrap();

        assert_eq!(baseline.len(), 65);
        assert_eq!(
            baseline,
            sign_message_with_timestamp(&key, prefix, app_id, timestamp, &public_key).unwrap()
        );
        assert_ne!(
            baseline,
            sign_message_with_timestamp(&key, b"other-domain", app_id, timestamp, &public_key)
                .unwrap()
        );
        assert_ne!(
            baseline,
            sign_message_with_timestamp(&key, prefix, b"app-b", timestamp, &public_key).unwrap()
        );
        assert_ne!(
            baseline,
            sign_message_with_timestamp(&key, prefix, app_id, timestamp + 1, &public_key).unwrap()
        );
        assert_ne!(
            baseline,
            sign_message_with_timestamp(&key, prefix, app_id, timestamp, &[0x43_u8; 32]).unwrap()
        );
    }
}
