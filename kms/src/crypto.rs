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
