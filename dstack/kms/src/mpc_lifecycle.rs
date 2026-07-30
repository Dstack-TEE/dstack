// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Durable epoch-chain validation for MPC membership lifecycle changes.

use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use anyhow::{ensure, Context, Result};
use fs_err as fs;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    cggmp_engine::{
        load_share, share_commitment, validate_share_topology, CggmpCurve, K256KeyShare,
        P256KeyShare,
    },
    mpc_identity::{ClusterIdentity, EpochManifest, SignedEpochManifest},
};

#[derive(Clone, Debug)]
pub(crate) struct EpochPaths<'a> {
    pub manifest: &'a Path,
    pub checkpoint: &'a Path,
    pub p256_share: &'a Path,
    pub k256_share: &'a Path,
    pub derivation_share: &'a Path,
}

#[derive(Serialize, Deserialize)]
struct ActivationJournal {
    version: u16,
    signed_manifest: SignedEpochManifest,
}

pub(crate) fn pending_share_path(path: &Path, epoch: u64) -> PathBuf {
    path.with_extension(format!("epoch-{epoch}.pending"))
}

fn activation_journal_path(manifest: &Path) -> PathBuf {
    manifest.with_extension("activation-journal")
}

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
    /// Exact old-epoch threshold that deals the transition. Required when the
    /// target contains joining members; subset-only transitions may leave it
    /// empty and select a live quorum at execution time.
    #[serde(default)]
    pub dealers: Vec<String>,
    pub members: Vec<ReshareMember>,
}

const RESHARE_AUTH_DOMAIN: &[u8] = b"dstack-mpc-reshare-authorization-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SignedResharePlan {
    pub plan: ResharePlan,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

impl ResharePlan {
    pub(crate) fn validate_transition(
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
            if let Some(current) = active
                .members
                .iter()
                .find(|current| current.node_id == member.node_id)
            {
                ensure!(
                    current.endpoint == member.endpoint
                        && current.attestation_pubkey == member.attestation_pubkey,
                    "existing member identity changed during reshare"
                );
            }
            ensure!(
                !member.node_id.is_empty(),
                "reshare member node ID is empty"
            );
            ensure!(
                member.endpoint.starts_with("https://"),
                "reshare member endpoint must use HTTPS"
            );
            ensure!(
                !member.attestation_pubkey.is_empty(),
                "reshare member attestation key is empty"
            );
            previous = Some(&member.node_id);
        }
        if !self.dealers.is_empty() {
            ensure!(
                self.dealers.len() == usize::from(active.threshold),
                "reshare authorization must bind exactly the old threshold of dealers"
            );
            let indexes = self
                .dealers
                .iter()
                .map(|dealer| {
                    active
                        .members
                        .binary_search_by_key(&dealer.as_str(), |member| member.node_id.as_str())
                        .map_err(|_| anyhow::anyhow!("reshare dealer is not active"))
                })
                .collect::<Result<Vec<_>>>()?;
            ensure!(
                indexes.windows(2).all(|pair| pair[0] < pair[1]),
                "reshare dealers must be unique and in active manifest order"
            );
        }
        let has_joiner = self
            .members
            .iter()
            .any(|member| !active.contains_member(&member.node_id));
        ensure!(
            !has_joiner || !self.dealers.is_empty(),
            "join transition must bind its old-epoch dealers"
        );
        Ok(())
    }

    pub(crate) fn authorization_hash(&self) -> Result<[u8; 32]> {
        self.validate_encoding()?;
        let encoded = serde_jcs::to_vec(self)?;
        let mut hash = Sha256::new();
        hash.update((RESHARE_AUTH_DOMAIN.len() as u32).to_be_bytes());
        hash.update(RESHARE_AUTH_DOMAIN);
        hash.update((encoded.len() as u32).to_be_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }

    fn validate_encoding(&self) -> Result<()> {
        ensure!(self.epoch > 1, "reshare epoch is invalid");
        ensure!(
            self.previous_manifest_hash.len() == 32,
            "reshare predecessor hash is invalid"
        );
        ensure!(
            self.threshold >= 2 && usize::from(self.threshold) <= self.members.len(),
            "invalid reshare threshold"
        );
        Ok(())
    }

    pub(crate) fn validate_subset(
        &self,
        active: &crate::mpc_identity::EpochManifest,
    ) -> Result<()> {
        self.validate_transition(active)?;
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

impl SignedResharePlan {
    pub(crate) fn verify(&self, identity: &ClusterIdentity, active: &EpochManifest) -> Result<()> {
        self.plan.validate_transition(active)?;
        let key = VerifyingKey::from_sec1_bytes(&identity.k256_group_pubkey)
            .context("invalid reshare authorization key")?;
        let signature = Signature::from_slice(&self.signature)
            .context("invalid reshare authorization signature")?;
        key.verify_prehash(&self.plan.authorization_hash()?, &signature)
            .context("invalid threshold reshare authorization")
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

/// Seed a newly authorized joiner with the currently signed checkpoint. This
/// is only valid when the signed transition explicitly names that exact
/// manifest hash as its predecessor.
pub(crate) fn initialize_join_checkpoint(
    path: &Path,
    active: &SignedEpochManifest,
    authorization: &SignedResharePlan,
    identity: &ClusterIdentity,
) -> Result<()> {
    let hash = active.verify(identity)?;
    authorization.verify(identity, &active.manifest)?;
    ensure!(
        authorization.plan.previous_manifest_hash == hash,
        "join authorization predecessor mismatch"
    );
    if path.exists() {
        return validate_and_checkpoint(path, active, identity);
    }
    let checkpoint = EpochCheckpoint {
        version: 1,
        provider_id: identity.provider_id().to_vec(),
        epoch: active.manifest.epoch,
        manifest_hash: hash.to_vec(),
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    safe_write::safe_write(path, &serde_jcs::to_vec(&checkpoint)?)?;
    fs::set_permissions(path, Permissions::from_mode(0o600))?;
    Ok(())
}

/// Durably install a threshold-authorized next epoch. A journal is written
/// before any active file changes, so startup can finish an interrupted
/// activation instead of observing a mixed manifest/share generation.
pub(crate) fn activate_pending_epoch(
    paths: &EpochPaths<'_>,
    identity: &ClusterIdentity,
    active: &EpochManifest,
    signed: &SignedEpochManifest,
    cluster_id: &str,
    node_id: &str,
) -> Result<bool> {
    signed.verify(identity)?;
    ensure!(
        signed.manifest.epoch == active.epoch + 1,
        "activation must advance exactly one epoch"
    );
    ensure!(
        signed.manifest.previous_manifest_hash == active.manifest_hash()?,
        "activation does not extend active epoch"
    );
    let journal = ActivationJournal {
        version: 1,
        signed_manifest: signed.clone(),
    };
    let journal_path = activation_journal_path(paths.manifest);
    safe_write::safe_write(&journal_path, &serde_jcs::to_vec(&journal)?)
        .context("failed to persist MPC activation journal")?;
    fs::set_permissions(&journal_path, Permissions::from_mode(0o600))?;
    finish_activation(paths, identity, signed, cluster_id, node_id)?;
    fs::remove_file(&journal_path).context("failed to clear MPC activation journal")?;
    for path in [paths.p256_share, paths.k256_share, paths.derivation_share] {
        let pending = pending_share_path(path, signed.manifest.epoch);
        if pending.exists() {
            fs::remove_file(pending)?;
        }
    }
    Ok(signed.manifest.contains_member(node_id))
}

/// Complete a journaled activation before normal KMS state reads either the
/// manifest or shares.
pub(crate) fn recover_pending_activation(
    paths: &EpochPaths<'_>,
    identity: &ClusterIdentity,
    cluster_id: &str,
    node_id: &str,
) -> Result<bool> {
    let journal_path = activation_journal_path(paths.manifest);
    if !journal_path.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(&journal_path)?;
    ensure!(
        metadata.file_type().is_file(),
        "MPC activation journal is not a file"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "MPC activation journal permissions are too broad"
    );
    let journal: ActivationJournal = serde_json::from_slice(&fs::read(&journal_path)?)
        .context("failed to parse MPC activation journal")?;
    ensure!(
        journal.version == 1,
        "unsupported MPC activation journal version"
    );
    finish_activation(
        paths,
        identity,
        &journal.signed_manifest,
        cluster_id,
        node_id,
    )?;
    fs::remove_file(&journal_path)?;
    for path in [paths.p256_share, paths.k256_share, paths.derivation_share] {
        let pending = pending_share_path(path, journal.signed_manifest.manifest.epoch);
        if pending.exists() {
            fs::remove_file(pending)?;
        }
    }
    Ok(true)
}

fn finish_activation(
    paths: &EpochPaths<'_>,
    identity: &ClusterIdentity,
    signed: &SignedEpochManifest,
    cluster_id: &str,
    node_id: &str,
) -> Result<()> {
    signed.verify(identity)?;
    if let Some(index) = signed
        .manifest
        .members
        .iter()
        .position(|member| member.node_id == node_id)
    {
        let epoch = signed.manifest.epoch;
        let p256_pending = pending_share_path(paths.p256_share, epoch);
        let k256_pending = pending_share_path(paths.k256_share, epoch);
        let derivation_pending = pending_share_path(paths.derivation_share, epoch);
        let p256: P256KeyShare =
            load_share(&p256_pending, cluster_id, epoch, node_id, CggmpCurve::P256)?;
        let k256: K256KeyShare =
            load_share(&k256_pending, cluster_id, epoch, node_id, CggmpCurve::K256)?;
        let derivation: P256KeyShare = load_share(
            &derivation_pending,
            cluster_id,
            epoch,
            node_id,
            CggmpCurve::P256,
        )?;
        for result in [
            validate_share_topology(
                &p256,
                index,
                signed.manifest.members.len(),
                signed.manifest.threshold,
            ),
            validate_share_topology(
                &k256,
                index,
                signed.manifest.members.len(),
                signed.manifest.threshold,
            ),
            validate_share_topology(
                &derivation,
                index,
                signed.manifest.members.len(),
                signed.manifest.threshold,
            ),
        ] {
            result?;
        }
        use cggmp21::key_share::AnyKeyShare as _;
        ensure!(
            p256.shared_public_key().to_bytes(false).as_bytes() == identity.p256_group_pubkey,
            "activated P-256 group key changed"
        );
        ensure!(
            k256.shared_public_key().to_bytes(true).as_bytes() == identity.k256_group_pubkey,
            "activated K-256 group key changed"
        );
        ensure!(
            derivation.shared_public_key().to_bytes(false).as_bytes()
                == identity.derivation_group_pubkey,
            "activated derivation group key changed"
        );
        let p = p256.core.key_info.public_shares[index].to_bytes(false);
        let k = k256.core.key_info.public_shares[index].to_bytes(true);
        let d = derivation.core.key_info.public_shares[index].to_bytes(false);
        ensure!(
            signed.manifest.members[index].share_commitment
                == share_commitment(p.as_bytes(), k.as_bytes(), d.as_bytes()),
            "pending shares do not match signed manifest"
        );
        for (pending, active) in [
            (&p256_pending, paths.p256_share),
            (&k256_pending, paths.k256_share),
            (&derivation_pending, paths.derivation_share),
        ] {
            safe_write::safe_write(active, &fs::read(pending)?)?;
            fs::set_permissions(active, Permissions::from_mode(0o600))?;
        }
    }
    safe_write::safe_write(paths.manifest, &serde_jcs::to_vec(signed)?)?;
    fs::set_permissions(paths.manifest, Permissions::from_mode(0o600))?;
    validate_and_checkpoint(paths.checkpoint, signed, identity)
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

    #[test]
    fn subset_reshare_plan_rejects_unapproved_joiners() {
        let key = SigningKey::from_slice(&[7; 32]).unwrap();
        let identity = identity(&key);
        let active = signed(&key, &identity, 1, vec![]).manifest;
        let plan = ResharePlan {
            epoch: 2,
            previous_manifest_hash: active.manifest_hash().unwrap().to_vec(),
            threshold: 2,
            dealers: vec![],
            members: active.members[..2]
                .iter()
                .map(|member| ReshareMember {
                    node_id: member.node_id.clone(),
                    endpoint: member.endpoint.clone(),
                    attestation_pubkey: member.attestation_pubkey.clone(),
                })
                .collect(),
        };
        plan.validate_subset(&active).unwrap();
        let mut join = plan;
        join.members[1].node_id = "kms-new".into();
        assert!(join.validate_subset(&active).is_err());
    }

    #[test]
    fn signed_transition_authorizes_quote_bound_joiner() {
        let key = SigningKey::from_slice(&[9; 32]).unwrap();
        let identity = identity(&key);
        let active = signed(&key, &identity, 1, vec![]).manifest;
        let mut members = active
            .members
            .iter()
            .map(|member| ReshareMember {
                node_id: member.node_id.clone(),
                endpoint: member.endpoint.clone(),
                attestation_pubkey: member.attestation_pubkey.clone(),
            })
            .collect::<Vec<_>>();
        members.push(ReshareMember {
            node_id: "kms-4".into(),
            endpoint: "https://kms-4/prpc".into(),
            attestation_pubkey: vec![8; 32],
        });
        let plan = ResharePlan {
            epoch: 2,
            previous_manifest_hash: active.manifest_hash().unwrap().to_vec(),
            threshold: 3,
            dealers: active.members[..2]
                .iter()
                .map(|member| member.node_id.clone())
                .collect(),
            members,
        };
        let signature: Signature = key
            .sign_prehash(&plan.authorization_hash().unwrap())
            .unwrap();
        let signed = SignedResharePlan {
            plan,
            signature: signature.to_bytes().to_vec(),
        };
        signed.verify(&identity, &active).unwrap();
        let mut forged = signed;
        forged.plan.members.last_mut().unwrap().attestation_pubkey[0] ^= 1;
        assert!(forged.verify(&identity, &active).is_err());
    }

    #[test]
    fn startup_recovers_journaled_revocation() {
        let key = SigningKey::from_slice(&[8; 32]).unwrap();
        let identity = identity(&key);
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = directory.path().join("manifest.json");
        let checkpoint_path = directory.path().join("checkpoint.json");
        let p256 = directory.path().join("p256.share");
        let k256 = directory.path().join("k256.share");
        let derivation = directory.path().join("derivation.share");
        let paths = EpochPaths {
            manifest: &manifest_path,
            checkpoint: &checkpoint_path,
            p256_share: &p256,
            k256_share: &k256,
            derivation_share: &derivation,
        };
        let active = signed(&key, &identity, 1, vec![]);
        validate_and_checkpoint(paths.checkpoint, &active, &identity).unwrap();
        let mut next = signed(
            &key,
            &identity,
            2,
            active.manifest.manifest_hash().unwrap().to_vec(),
        );
        next.manifest.members.remove(0);
        let signature: Signature = key
            .sign_prehash(&next.manifest.manifest_hash().unwrap())
            .unwrap();
        next.signature = signature.to_bytes().to_vec();
        let journal_path = activation_journal_path(paths.manifest);
        safe_write::safe_write(
            &journal_path,
            &serde_jcs::to_vec(&ActivationJournal {
                version: 1,
                signed_manifest: next.clone(),
            })
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&journal_path, Permissions::from_mode(0o600)).unwrap();
        assert!(recover_pending_activation(&paths, &identity, "cluster", "kms-1").unwrap());
        let installed: SignedEpochManifest =
            serde_json::from_slice(&fs::read(paths.manifest).unwrap()).unwrap();
        assert_eq!(installed, next);
        assert!(!journal_path.exists());
    }
}
