// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! HPKE encryption for the versioned `.sealed-env` envelope.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hpke::{
    aead::AesGcm256, kdf::HkdfSha256, kem::X25519HkdfSha256, Deserializable, Kem, OpModeS,
    Serializable,
};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::json;
use sha3::{Digest, Keccak256};

/// A KMS-signed sealed environment public key, before trust verification.
#[derive(Debug, Clone)]
pub struct SealedEnvPublicKey {
    /// X25519 public key.
    pub public_key: [u8; 32],
    /// KMS root epoch that signed the key.
    pub root_epoch: u32,
    /// Application key epoch, zero for legacy keys.
    pub app_epoch: u32,
    /// Signing time in seconds since the Unix epoch.
    pub timestamp: u64,
    /// Recoverable secp256k1 signature: r || s || recovery ID (0..=3).
    pub signature: [u8; 65],
}

fn public_key_digest(app_id: &[u8; 20], key: &SealedEnvPublicKey) -> [u8; 32] {
    let mut digest = Keccak256::new()
        .chain_update(b"dstack-sealed-env-pubkey-v1:")
        .chain_update(app_id)
        .chain_update(key.root_epoch.to_be_bytes());
    digest.update(key.app_epoch.to_be_bytes());
    digest
        .chain_update(key.public_key)
        .chain_update(key.timestamp.to_be_bytes())
        .finalize()
        .into()
}

/// Recover the signer of a sealed environment public key.
///
/// Recovery alone does not establish trust or freshness; use
/// [`verify_sealed_env_public_key`] before encrypting secrets.
pub fn recover_sealed_env_public_key(
    app_id: &[u8; 20],
    key: &SealedEnvPublicKey,
) -> Result<VerifyingKey> {
    let signature = Signature::from_slice(&key.signature[..64])
        .context("invalid sealed env public key signature")?;
    let recovery_id = RecoveryId::from_byte(key.signature[64])
        .context("invalid sealed env public key recovery ID")?;
    VerifyingKey::recover_from_prehash(&public_key_digest(app_id, key), &signature, recovery_id)
        .context("failed to recover sealed env public key signer")
}

/// Verify the app binding, expected epoch, trusted epoch signer, and freshness.
///
/// `trusted_signer` must be the authenticated secp256k1 root public key for
/// `expected_epoch`. `now` is trusted Unix time in seconds. Accepts keys at most
/// 300 seconds old or 60 seconds ahead of `now`.
pub fn verify_sealed_env_public_key(
    app_id: &[u8; 20],
    key: &SealedEnvPublicKey,
    expected_epoch: u32,
    trusted_signer: &VerifyingKey,
    now: u64,
) -> Result<()> {
    verify_sealed_env_public_key_at_epochs(app_id, key, expected_epoch, 0, trusted_signer, now)
}

pub fn verify_sealed_env_public_key_at_epochs(
    app_id: &[u8; 20],
    key: &SealedEnvPublicKey,
    expected_epoch: u32,
    expected_app_epoch: u32,
    trusted_signer: &VerifyingKey,
    now: u64,
) -> Result<()> {
    if key.app_epoch != expected_app_epoch {
        bail!("sealed env public key app epoch mismatch");
    }
    if key.root_epoch != expected_epoch {
        bail!("sealed env public key root epoch mismatch");
    }
    if now.saturating_sub(key.timestamp) > 300 || key.timestamp.saturating_sub(now) > 60 {
        bail!("sealed env public key timestamp outside allowed window");
    }
    if recover_sealed_env_public_key(app_id, key)? != *trusted_signer {
        bail!("sealed env public key signer mismatch");
    }
    Ok(())
}

/// Seal environment key/value pairs to a trusted 32-byte X25519 public key.
///
/// The caller must authenticate the public key and its root epoch before calling.
/// Returns a version-1 JSON envelope using RFC 9180 base mode with
/// X25519/HKDF-SHA256/AES-256-GCM and standard Base64 encoding.
pub fn seal_env<K: AsRef<str>, V: AsRef<str>>(
    envs: &[(K, V)],
    public_key: &[u8],
    root_epoch: u32,
) -> Result<String> {
    seal_env_at_epochs(envs, public_key, root_epoch, 0)
}

pub fn seal_env_at_epochs<K: AsRef<str>, V: AsRef<str>>(
    envs: &[(K, V)],
    public_key: &[u8],
    root_epoch: u32,
    app_epoch: u32,
) -> Result<String> {
    let public_key = <X25519HkdfSha256 as Kem>::PublicKey::from_bytes(public_key)
        .map_err(|_| anyhow!("invalid sealed env public key"))?;
    let envs: Vec<_> = envs
        .iter()
        .map(|(key, value)| json!({ "key": key.as_ref(), "value": value.as_ref() }))
        .collect();
    let plaintext = serde_json::to_vec(&json!({ "env": envs }))?;
    let info = format!("dstack-sealed-env-v1:{root_epoch}:{app_epoch}");
    let (enc, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, X25519HkdfSha256>(
        &OpModeS::Base,
        &public_key,
        info.as_bytes(),
        &plaintext,
        &[],
    )
    .map_err(|err| anyhow!("sealed env encryption failed: {err}"))?;
    let envelope = json!({
        "version": 1,
        "app_epoch": app_epoch,
        "root_epoch": root_epoch,
        "enc": STANDARD.encode(enc.to_bytes()),
        "ciphertext": STANDARD.encode(ciphertext),
    });
    Ok(serde_json::to_string(&envelope)?)
}
