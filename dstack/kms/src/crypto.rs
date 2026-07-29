// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

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
    let digest = Keccak256::new_with_prefix([prefix, b":", appid, message].concat());
    let (signature, recid) = key.sign_digest_recoverable(digest)?;
    let mut signature_bytes = signature.to_vec();
    signature_bytes.push(recid.to_byte());
    Ok(signature_bytes)
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
    let digest =
        Keccak256::new_with_prefix([prefix, b":", appid, &timestamp_bytes[..], message].concat());
    let (signature, recid) = key.sign_digest_recoverable(digest)?;
    let mut signature_bytes = signature.to_vec();
    signature_bytes.push(recid.to_byte());
    Ok(signature_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

    fn recover(
        signature: &[u8],
        prefix: &[u8],
        app_id: &[u8],
        timestamp: Option<u64>,
        message: &[u8],
    ) -> VerifyingKey {
        let (signature, recovery_id) = signature.split_at(64);
        let signature = Signature::from_slice(signature).unwrap();
        let recovery_id = RecoveryId::from_byte(recovery_id[0]).unwrap();
        let mut payload = vec![prefix, b":", app_id];
        let timestamp_bytes;
        if let Some(timestamp) = timestamp {
            timestamp_bytes = timestamp.to_be_bytes();
            payload.push(&timestamp_bytes);
        }
        payload.push(message);
        VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(payload.concat()),
            &signature,
            recovery_id,
        )
        .unwrap()
    }

    #[test]
    fn derived_app_k256_keys_are_stable_isolated_and_root_signed() {
        let root = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let app_a = [0x21; 20];
        let app_b = [0x22; 20];
        let (key_a1, signature_a1) = derive_k256_key(&root, &app_a).unwrap();
        let (key_a2, signature_a2) = derive_k256_key(&root, &app_a).unwrap();
        let (key_b, signature_b) = derive_k256_key(&root, &app_b).unwrap();

        assert_eq!(key_a1.to_bytes(), key_a2.to_bytes());
        assert_eq!(signature_a1, signature_a2);
        assert_ne!(key_a1.to_bytes(), key_b.to_bytes());
        assert_ne!(signature_a1, signature_b);
        assert_eq!(
            recover(
                &signature_a1,
                b"dstack-kms-issued",
                &app_a,
                None,
                &key_a1.verifying_key().to_sec1_bytes(),
            ),
            *root.verifying_key(),
        );
        assert_ne!(
            recover(
                &signature_a1,
                b"dstack-kms-issued",
                &app_b,
                None,
                &key_a1.verifying_key().to_sec1_bytes(),
            ),
            *root.verifying_key(),
        );
    }

    #[test]
    fn disk_and_environment_hierarchy_has_documented_isolation_boundaries() {
        let root = [0x31; 32];
        let app_a = [0x41; 20];
        let app_b = [0x42; 20];
        let instance_a = [0x51; 32];
        let instance_b = [0x52; 32];
        let disk = |app: &[u8], instance: &[u8]| {
            kdf::derive_key(&root, &[app, instance, b"app-disk-crypt-key"], 32).unwrap()
        };
        let env = |app: &[u8]| kdf::derive_key(&root, &[app, b"env-encrypt-key"], 32).unwrap();

        assert_eq!(disk(&app_a, &instance_a), disk(&app_a, &instance_a));
        assert_ne!(disk(&app_a, &instance_a), disk(&app_b, &instance_a));
        assert_ne!(disk(&app_a, &instance_a), disk(&app_a, &instance_b));
        assert_eq!(env(&app_a), env(&app_a));
        assert_ne!(env(&app_a), env(&app_b));
        assert_eq!(env(&app_a), env(&app_a));
    }

    #[test]
    fn environment_public_key_signatures_bind_domain_app_key_and_timestamp() {
        let root = SigningKey::from_slice(&[0x61; 32]).unwrap();
        let app_id = [0x71; 20];
        let public_key = [0x81; 32];
        let legacy =
            sign_message(&root, b"dstack-env-encrypt-pubkey", &app_id, &public_key).unwrap();
        let timestamp = 1_800_000_000;
        let fresh = sign_message_with_timestamp(
            &root,
            b"dstack-env-encrypt-pubkey",
            &app_id,
            timestamp,
            &public_key,
        )
        .unwrap();

        assert_eq!(
            recover(
                &legacy,
                b"dstack-env-encrypt-pubkey",
                &app_id,
                None,
                &public_key,
            ),
            *root.verifying_key(),
        );
        assert_eq!(
            recover(
                &fresh,
                b"dstack-env-encrypt-pubkey",
                &app_id,
                Some(timestamp),
                &public_key,
            ),
            *root.verifying_key(),
        );
        assert_ne!(
            recover(
                &fresh,
                b"dstack-env-encrypt-pubkey",
                &app_id,
                Some(timestamp + 1),
                &public_key,
            ),
            *root.verifying_key(),
        );
    }
}
