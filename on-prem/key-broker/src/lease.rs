// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub instance_id: String,
    pub app_id: String,
    pub slot_id: String,
    pub compose_hash: String,
    pub issued_at: u64,
    pub expires_at: u64,
    /// base64-encoded HMAC-SHA256 over the lease fields
    pub kms_sig: String,
}

impl Lease {
    pub fn sign(
        instance_id: &str,
        app_id: &str,
        slot_id: &str,
        compose_hash: &str,
        issued_at: u64,
        expires_at: u64,
        hmac_key: &[u8],
    ) -> Result<Self> {
        let mut unsigned = Self {
            instance_id: instance_id.to_string(),
            app_id: app_id.to_string(),
            slot_id: slot_id.to_string(),
            compose_hash: compose_hash.to_string(),
            issued_at,
            expires_at,
            kms_sig: String::new(),
        };
        let sig = compute_sig(&unsigned, hmac_key)?;
        unsigned.kms_sig = STANDARD.encode(sig);
        Ok(unsigned)
    }
}

fn compute_sig(lease: &Lease, key: &[u8]) -> Result<Vec<u8>> {
    let payload = format!(
        "{}:{}:{}:{}:{}:{}",
        lease.instance_id,
        lease.app_id,
        lease.slot_id,
        lease.compose_hash,
        lease.issued_at,
        lease.expires_at,
    );
    let mut mac = HmacSha256::new_from_slice(key)
        .context("failed to create HMAC key")?;
    mac.update(payload.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Load the lease HMAC key (32 bytes) from the installed keyset. Uses the
/// secp256k1 identity key (`certs/root-k256.key`, exactly 32 bytes) that
/// keyset.rs writes — the legacy `root_key.bin` no longer exists.
pub fn load_hmac_key(kms_volume: &std::path::Path) -> Result<Vec<u8>> {
    let path = kms_volume.join("certs").join("root-k256.key");
    let bytes = std::fs::read(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() < 32 {
        anyhow::bail!(
            "root-k256.key is too short ({} bytes, need at least 32)",
            bytes.len()
        );
    }
    Ok(bytes[..32].to_vec())
}
