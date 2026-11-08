// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Environment envelope encoding and encryption for guest boot migration.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub(super) struct SealedEnv {
    pub(super) version: u32,
    pub(super) root_epoch: u32,
    pub(super) app_epoch: u32,
    #[serde(with = "serde_human_bytes::base64")]
    pub(super) enc: Vec<u8>,
    #[serde(with = "serde_human_bytes::base64")]
    pub(super) ciphertext: Vec<u8>,
}

pub(super) fn sealed_env_info_at_epochs(root: u32, app: u32) -> Vec<u8> {
    format!("dstack-sealed-env-v1:{root}:{app}").into_bytes()
}

pub(super) fn seal_env_at_epochs(
    secret: &[u8],
    epoch: u32,
    app_epoch: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let secret: [u8; 32] = secret.try_into().context("invalid sealed env key")?;
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    let payload = crate::crypto::sealed_env_encrypt(
        &public.to_bytes(),
        &sealed_env_info_at_epochs(epoch, app_epoch),
        plaintext,
    )?;
    let (enc, ciphertext) = payload.split_at(32);
    Ok(serde_json::to_vec(&SealedEnv {
        version: 1,
        root_epoch: epoch,
        app_epoch,
        enc: enc.to_vec(),
        ciphertext: ciphertext.to_vec(),
    })?)
}

pub(super) fn env_crypt_key(key: &[u8]) -> Result<[u8; 32]> {
    key.try_into()
        .ok()
        .context("encrypted env is present but the key provider gave no valid env crypt key")
}
