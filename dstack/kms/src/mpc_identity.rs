// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Stable identities and attestation bindings for an MPC KMS cluster.
//!
//! Membership and epochs deliberately do not enter [`ClusterIdentity::provider_id`].
//! This lets a cluster reshare its keys without changing the identity pinned by apps.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ID_DOMAIN: &[u8] = b"dstack-mpc-kms-provider-id-v1";
const NODE_EVIDENCE_DOMAIN: &[u8] = b"dstack-mpc-kms-node-evidence-v1";
const MANIFEST_DOMAIN: &[u8] = b"dstack-mpc-kms-epoch-manifest-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ClusterIdentity {
    pub protocol_version: u16,
    pub cluster_id: String,
    #[serde(with = "hex_bytes")]
    pub p256_group_pubkey: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub k256_group_pubkey: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub derivation_group_pubkey: Vec<u8>,
}

impl ClusterIdentity {
    pub(crate) fn new(
        protocol_version: u16,
        cluster_id: String,
        p256_group_pubkey: Vec<u8>,
        k256_group_pubkey: Vec<u8>,
        derivation_group_pubkey: Vec<u8>,
    ) -> Result<Self> {
        ensure!(protocol_version == 1, "unsupported MPC protocol version");
        ensure!(!cluster_id.is_empty(), "MPC cluster_id must not be empty");
        ensure!(cluster_id.len() <= 128, "MPC cluster_id is too long");
        ensure!(
            !p256_group_pubkey.is_empty(),
            "missing P-256 group public key"
        );
        ensure!(
            !k256_group_pubkey.is_empty(),
            "missing K-256 group public key"
        );
        ensure!(
            !derivation_group_pubkey.is_empty(),
            "missing derivation group public key"
        );
        Ok(Self {
            protocol_version,
            cluster_id,
            p256_group_pubkey,
            k256_group_pubkey,
            derivation_group_pubkey,
        })
    }

    /// Stable key-provider ID pinned in app compose and launch measurements.
    pub(crate) fn provider_id(&self) -> [u8; 32] {
        hash_fields(
            ID_DOMAIN,
            &[
                &self.protocol_version.to_be_bytes(),
                self.cluster_id.as_bytes(),
                &self.p256_group_pubkey,
                &self.k256_group_pubkey,
                &self.derivation_group_pubkey,
            ],
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EpochMember {
    pub node_id: String,
    #[serde(with = "hex_bytes")]
    pub attestation_pubkey: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub share_commitment: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct EpochManifest {
    #[serde(with = "hex_bytes")]
    pub provider_id: Vec<u8>,
    pub epoch: u64,
    pub threshold: u16,
    #[serde(with = "hex_bytes")]
    pub previous_manifest_hash: Vec<u8>,
    pub members: Vec<EpochMember>,
}

impl EpochManifest {
    pub(crate) fn manifest_hash(&self) -> Result<[u8; 32]> {
        ensure!(self.provider_id.len() == 32, "provider_id must be 32 bytes");
        ensure!(self.epoch > 0, "epoch must be greater than zero");
        ensure!(
            self.previous_manifest_hash.is_empty() || self.previous_manifest_hash.len() == 32,
            "previous_manifest_hash must be empty or 32 bytes"
        );
        ensure!(
            self.threshold > 0 && usize::from(self.threshold) <= self.members.len(),
            "threshold must be between one and the member count"
        );
        let mut fields: Vec<Vec<u8>> = vec![
            self.provider_id.clone(),
            self.epoch.to_be_bytes().to_vec(),
            self.threshold.to_be_bytes().to_vec(),
            self.previous_manifest_hash.clone(),
        ];
        let mut previous_node_id: Option<&str> = None;
        for member in &self.members {
            ensure!(
                !member.node_id.is_empty(),
                "member node_id must not be empty"
            );
            ensure!(
                previous_node_id.is_none_or(|previous| previous < member.node_id.as_str()),
                "members must be sorted by unique node_id"
            );
            ensure!(
                !member.attestation_pubkey.is_empty(),
                "missing member attestation public key"
            );
            ensure!(
                !member.share_commitment.is_empty(),
                "missing member share commitment"
            );
            fields.push(member.node_id.as_bytes().to_vec());
            fields.push(member.attestation_pubkey.clone());
            fields.push(member.share_commitment.clone());
            previous_node_id = Some(&member.node_id);
        }
        let references: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        Ok(hash_fields(MANIFEST_DOMAIN, &references))
    }

    pub(crate) fn contains_member(&self, node_id: &str) -> bool {
        self.members
            .binary_search_by_key(&node_id, |member| member.node_id.as_str())
            .is_ok()
    }

    pub(crate) fn member_for_attestation_key(&self, public_key: &[u8]) -> Option<&EpochMember> {
        self.members
            .iter()
            .find(|member| member.attestation_pubkey == public_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct NodeEvidence {
    #[serde(with = "hex_bytes")]
    pub provider_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "hex_bytes")]
    pub manifest_hash: Vec<u8>,
    pub node_id: String,
    #[serde(with = "hex_bytes")]
    pub attestation_pubkey: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub share_commitment: Vec<u8>,
}

impl NodeEvidence {
    /// Value to place in the first 32 bytes of TDX `report_data`.
    pub(crate) fn report_data_hash(&self) -> Result<[u8; 32]> {
        ensure!(self.provider_id.len() == 32, "provider_id must be 32 bytes");
        ensure!(
            self.manifest_hash.len() == 32,
            "manifest_hash must be 32 bytes"
        );
        ensure!(!self.node_id.is_empty(), "node_id must not be empty");
        ensure!(
            !self.attestation_pubkey.is_empty(),
            "missing attestation public key"
        );
        ensure!(
            !self.share_commitment.is_empty(),
            "missing share commitment"
        );
        Ok(hash_fields(
            NODE_EVIDENCE_DOMAIN,
            &[
                &self.provider_id,
                &self.epoch.to_be_bytes(),
                &self.manifest_hash,
                self.node_id.as_bytes(),
                &self.attestation_pubkey,
                &self.share_commitment,
            ],
        ))
    }
}

pub(crate) fn decode_hex(name: &str, value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    hex::decode(value).with_context(|| format!("invalid hex in {name}"))
}

fn hash_fields(domain: &[u8], fields: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((domain.len() as u32).to_be_bytes());
    hash.update(domain);
    for field in fields {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
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

    fn identity() -> ClusterIdentity {
        ClusterIdentity::new(
            1,
            "production".into(),
            vec![2; 33],
            vec![3; 33],
            vec![4; 32],
        )
        .unwrap()
    }

    #[test]
    fn provider_id_is_deterministic_and_domain_separated() {
        let id = identity();
        assert_eq!(id.provider_id(), id.clone().provider_id());
        let mut other = id;
        other.cluster_id = "staging".into();
        assert_ne!(other.provider_id(), identity().provider_id());
    }

    #[test]
    fn node_evidence_binds_epoch_and_share_commitment() {
        let evidence = NodeEvidence {
            provider_id: identity().provider_id().to_vec(),
            epoch: 7,
            manifest_hash: vec![5; 32],
            node_id: "kms-1".into(),
            attestation_pubkey: vec![6; 32],
            share_commitment: vec![7; 33],
        };
        let hash = evidence.report_data_hash().unwrap();
        let mut next = evidence;
        next.epoch += 1;
        assert_ne!(hash, next.report_data_hash().unwrap());
    }

    #[test]
    fn manifest_hash_binds_threshold_and_requires_canonical_members() {
        let member = |node_id: &str| EpochMember {
            node_id: node_id.into(),
            attestation_pubkey: vec![6; 32],
            share_commitment: vec![7; 33],
        };
        let manifest = EpochManifest {
            provider_id: identity().provider_id().to_vec(),
            epoch: 1,
            threshold: 2,
            previous_manifest_hash: vec![],
            members: vec![member("kms-1"), member("kms-2"), member("kms-3")],
        };
        let hash = manifest.manifest_hash().unwrap();
        let mut other = manifest.clone();
        other.threshold = 3;
        assert_ne!(hash, other.manifest_hash().unwrap());
        other.members.swap(0, 1);
        assert!(other.manifest_hash().is_err());
    }
}
