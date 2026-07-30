// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Durable epoch-chain validation for MPC membership lifecycle changes.

use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path};

use anyhow::{ensure, Context, Result};
use fs_err as fs;
use serde::{Deserialize, Serialize};

use crate::mpc_identity::{ClusterIdentity, SignedEpochManifest};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReshareMember {
    pub node_id: String,
    pub endpoint: String,
    #[serde(with = "hex_bytes")]
    pub attestation_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ResharePlan {
    pub epoch: u64,
    #[serde(with = "hex_bytes")]
    pub previous_manifest_hash: Vec<u8>,
    pub threshold: u16,
    pub members: Vec<ReshareMember>,
}

impl ResharePlan {
    pub(crate) fn validate_subset(
        &self,
        active: &crate::mpc_identity::EpochManifest,
    ) -> Result<()> {
        ensure!(
            self.epoch == active.epoch + 1,
            "reshare epoch must advance by one"
        );
        ensure!(
            self.previous_manifest_hash == active.manifest_hash()?,
            "reshare plan does not extend the active manifest"
        );
        ensure!(
            self.threshold >= 2 && usize::from(self.threshold) <= self.members.len(),
            "invalid reshare threshold"
        );
        let mut previous: Option<&str> = None;
        for member in &self.members {
            ensure!(
                previous.is_none_or(|value| value < member.node_id.as_str()),
                "reshare members must be unique and ordered"
            );
            let active_member = active
                .members
                .iter()
                .find(|active| active.node_id == member.node_id)
                .context("joining new members requires the join protocol")?;
            ensure!(
                active_member.endpoint == member.endpoint
                    && active_member.attestation_pubkey == member.attestation_pubkey,
                "reshare member identity differs from active manifest"
            );
            previous = Some(&member.node_id);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct EpochCheckpoint {
    version: u16,
    #[serde(with = "hex_bytes")]
    provider_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex_bytes")]
    manifest_hash: Vec<u8>,
}

/// Verify a threshold-signed epoch and atomically advance the local checkpoint.
/// Epochs cannot be skipped, forked, or rolled back relative to the checkpoint.
pub(crate) fn validate_and_checkpoint(
    path: &Path,
    signed: &SignedEpochManifest,
    identity: &ClusterIdentity,
) -> Result<()> {
    ensure!(!path.as_os_str().is_empty(), "MPC checkpoint path is empty");
    let hash = signed.verify(identity)?;
    let provider_id = identity.provider_id();
    let previous = if path.exists() {
        let metadata = fs::symlink_metadata(path).context("failed to stat MPC checkpoint")?;
        ensure!(
            metadata.file_type().is_file(),
            "MPC checkpoint is not a file"
        );
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "MPC checkpoint permissions are too broad"
        );
        Some(
            serde_json::from_slice::<EpochCheckpoint>(
                &fs::read(path).context("failed to read MPC checkpoint")?,
            )
            .context("failed to parse MPC checkpoint")?,
        )
    } else {
        None
    };
    match previous {
        None => {
            ensure!(
                signed.manifest.epoch == 1,
                "first MPC epoch must be genesis epoch 1"
            );
            ensure!(
                signed.manifest.previous_manifest_hash.is_empty(),
                "genesis manifest must not have a predecessor"
            );
        }
        Some(previous) => {
            ensure!(previous.version == 1, "unsupported MPC checkpoint version");
            ensure!(
                previous.provider_id == provider_id,
                "MPC checkpoint provider mismatch"
            );
            if signed.manifest.epoch == previous.epoch {
                ensure!(
                    previous.manifest_hash == hash,
                    "conflicting manifest for active epoch"
                );
                return Ok(());
            }
            ensure!(
                signed.manifest.epoch == previous.epoch + 1,
                "MPC epoch rollback or skipped transition"
            );
            ensure!(
                signed.manifest.previous_manifest_hash == previous.manifest_hash,
                "MPC manifest does not extend the checkpointed epoch"
            );
        }
    }
    let checkpoint = EpochCheckpoint {
        version: 1,
        provider_id: provider_id.to_vec(),
        epoch: signed.manifest.epoch,
        manifest_hash: hash.to_vec(),
    };
    let encoded = serde_jcs::to_vec(&checkpoint).context("failed to encode MPC checkpoint")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("failed to create MPC checkpoint directory")?;
    }
    safe_write::safe_write(path, &encoded).context("failed to persist MPC checkpoint")?;
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .context("failed to restrict MPC checkpoint permissions")?;
    Ok(())
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        hex::decode(value.strip_prefix("0x").unwrap_or(&value)).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_identity::{EpochManifest, EpochMember};
    use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

    fn identity(key: &SigningKey) -> ClusterIdentity {
        ClusterIdentity::new(
            1,
            "cluster".into(),
            vec![2; 65],
            key.verifying_key().to_sec1_bytes().to_vec(),
            vec![3; 65],
        )
        .unwrap()
    }

    fn signed(
        key: &SigningKey,
        identity: &ClusterIdentity,
        epoch: u64,
        previous: Vec<u8>,
    ) -> SignedEpochManifest {
        let manifest = EpochManifest {
            provider_id: identity.provider_id().to_vec(),
            epoch,
            threshold: 2,
            previous_manifest_hash: previous,
            members: ["kms-1", "kms-2", "kms-3"]
                .into_iter()
                .map(|node_id| EpochMember {
                    node_id: node_id.into(),
                    endpoint: format!("https://{node_id}/prpc"),
                    attestation_pubkey: vec![4; 32],
                    share_commitment: vec![5; 33],
                })
                .collect(),
        };
        let signature: Signature = key
            .sign_prehash(&manifest.manifest_hash().unwrap())
            .unwrap();
        SignedEpochManifest {
            manifest,
            signature: signature.to_bytes().to_vec(),
        }
    }

    #[test]
    fn checkpoint_rejects_rollback_skip_and_fork() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let identity = identity(&key);
        let directory = tempfile::tempdir().unwrap();
        let checkpoint = directory.path().join("epoch.json");
        let first = signed(&key, &identity, 1, vec![]);
        validate_and_checkpoint(&checkpoint, &first, &identity).unwrap();
        validate_and_checkpoint(&checkpoint, &first, &identity).unwrap();
        let first_hash = first.manifest.manifest_hash().unwrap().to_vec();
        let second = signed(&key, &identity, 2, first_hash);
        validate_and_checkpoint(&checkpoint, &second, &identity).unwrap();
        assert!(validate_and_checkpoint(&checkpoint, &first, &identity).is_err());
        let skipped = signed(
            &key,
            &identity,
            4,
            second.manifest.manifest_hash().unwrap().to_vec(),
        );
        assert!(validate_and_checkpoint(&checkpoint, &skipped, &identity).is_err());
        let fork = signed(&key, &identity, 3, vec![9; 32]);
        assert!(validate_and_checkpoint(&checkpoint, &fork, &identity).is_err());
    }
}
