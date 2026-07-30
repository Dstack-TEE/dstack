// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::mpc_identity::EpochManifest;

const REQUEST_DOMAIN: &[u8] = b"dstack-mpc-operation-v1";
const MAX_SIGN_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_OPERATION_TTL_SECS: u64 = 300;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct K256SignPayload {
    #[serde(with = "hex_bytes")]
    pub prefix: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    pub timestamp: Option<u64>,
    #[serde(with = "hex_bytes")]
    pub message: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DerivePurpose {
    DiskKey,
    EnvKey,
    AppK256,
    AppCa,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DerivePayload {
    pub purpose: DerivePurpose,
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    #[serde(default, with = "option_hex_bytes")]
    pub instance_id: Option<Vec<u8>>,
    #[serde(default)]
    pub counter: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct P256CertificatePayload {
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub tbs_der: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ManifestSignaturePayload {
    pub manifest: EpochManifest,
}

impl ManifestSignaturePayload {
    fn validate(&self) -> Result<()> {
        self.manifest.manifest_hash().map(|_| ())
    }

    pub(crate) fn digest(&self) -> Result<[u8; 32]> {
        self.manifest.manifest_hash()
    }
}

impl P256CertificatePayload {
    fn validate(&self) -> Result<()> {
        use x509_parser::{certificate::TbsCertificate, prelude::FromDer as _};
        ensure!(
            self.app_id.len() == 20,
            "certificate app_id must be 20 bytes"
        );
        ensure!(
            !self.tbs_der.is_empty() && self.tbs_der.len() <= 64 * 1024,
            "certificate TBS length is invalid"
        );
        let (remaining, _) = TbsCertificate::from_der(&self.tbs_der)
            .map_err(|error| anyhow::anyhow!("invalid certificate TBS: {error}"))?;
        ensure!(remaining.is_empty(), "certificate TBS has trailing bytes");
        Ok(())
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        Sha256::digest(&self.tbs_der).into()
    }
}

impl DerivePayload {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.app_id.len() == 20,
            "MPC derivation app_id must be 20 bytes"
        );
        ensure!(self.counter <= 16, "MPC derivation counter is too large");
        match self.purpose {
            DerivePurpose::DiskKey => ensure!(
                self.instance_id
                    .as_ref()
                    .is_some_and(|value| value.len() == 20),
                "disk-key derivation requires a 20-byte instance_id"
            ),
            _ => ensure!(
                self.instance_id.is_none(),
                "instance_id is only valid for disk-key derivation"
            ),
        }
        Ok(())
    }

    pub(crate) fn input(&self) -> Result<Vec<u8>> {
        let encoded = serde_jcs::to_vec(self).context("failed to encode derivation input")?;
        let mut input = b"dstack-mpc-derivation-v1".to_vec();
        input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        input.extend_from_slice(&encoded);
        Ok(input)
    }
}

impl K256SignPayload {
    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut digest = Keccak256::new();
        digest.update(&self.prefix);
        digest.update(b":");
        digest.update(&self.app_id);
        if let Some(timestamp) = self.timestamp {
            digest.update(timestamp.to_be_bytes());
        }
        digest.update(&self.message);
        digest.finalize().into()
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                self.prefix.as_slice(),
                b"dstack-env-encrypt-pubkey" | b"dstack-kms-issued"
            ),
            "MPC K-256 signing domain is not allowed"
        );
        ensure!(
            self.app_id.len() == 20,
            "MPC signing app_id must be 20 bytes"
        );
        ensure!(
            !self.message.is_empty() && self.message.len() <= MAX_SIGN_MESSAGE_BYTES,
            "MPC signing message length is invalid"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MpcOperationPayload {
    SignK256(K256SignPayload),
    SignManifest(ManifestSignaturePayload),
    SignP256Certificate(P256CertificatePayload),
    Derive(DerivePayload),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MpcOperation {
    #[serde(with = "hex_bytes")]
    pub session_id: Vec<u8>,
    pub epoch: u64,
    pub participants: Vec<String>,
    pub expires_at: u64,
    pub payload: MpcOperationPayload,
    #[serde(with = "hex_bytes")]
    pub request_hash: Vec<u8>,
}

#[derive(Serialize)]
struct RequestPreimage<'a> {
    #[serde(with = "hex_bytes")]
    session_id: &'a [u8],
    epoch: u64,
    participants: &'a [String],
    expires_at: u64,
    payload: &'a MpcOperationPayload,
}

impl MpcOperation {
    pub(crate) fn new_k256(
        session_id: [u8; 32],
        epoch: u64,
        participants: Vec<String>,
        expires_at: u64,
        payload: K256SignPayload,
    ) -> Result<Self> {
        let mut operation = Self {
            session_id: session_id.to_vec(),
            epoch,
            participants,
            expires_at,
            payload: MpcOperationPayload::SignK256(payload),
            request_hash: vec![],
        };
        operation.request_hash = operation.compute_request_hash()?.to_vec();
        Ok(operation)
    }

    pub(crate) fn new_derivation(
        session_id: [u8; 32],
        epoch: u64,
        participants: Vec<String>,
        expires_at: u64,
        payload: DerivePayload,
    ) -> Result<Self> {
        let mut operation = Self {
            session_id: session_id.to_vec(),
            epoch,
            participants,
            expires_at,
            payload: MpcOperationPayload::Derive(payload),
            request_hash: vec![],
        };
        operation.request_hash = operation.compute_request_hash()?.to_vec();
        Ok(operation)
    }

    pub(crate) fn new_p256_certificate(
        session_id: [u8; 32],
        epoch: u64,
        participants: Vec<String>,
        expires_at: u64,
        payload: P256CertificatePayload,
    ) -> Result<Self> {
        let mut operation = Self {
            session_id: session_id.to_vec(),
            epoch,
            participants,
            expires_at,
            payload: MpcOperationPayload::SignP256Certificate(payload),
            request_hash: vec![],
        };
        operation.request_hash = operation.compute_request_hash()?.to_vec();
        Ok(operation)
    }

    pub(crate) fn new_manifest_signature(
        session_id: [u8; 32],
        epoch: u64,
        participants: Vec<String>,
        expires_at: u64,
        payload: ManifestSignaturePayload,
    ) -> Result<Self> {
        let mut operation = Self {
            session_id: session_id.to_vec(),
            epoch,
            participants,
            expires_at,
            payload: MpcOperationPayload::SignManifest(payload),
            request_hash: vec![],
        };
        operation.request_hash = operation.compute_request_hash()?.to_vec();
        Ok(operation)
    }

    pub(crate) fn validate(&self, manifest: &EpochManifest, initiator: &str) -> Result<()> {
        ensure!(
            self.session_id.len() == 32,
            "MPC operation session ID must be 32 bytes"
        );
        ensure!(self.epoch == manifest.epoch, "MPC operation epoch mismatch");
        ensure!(
            self.participants.len() == usize::from(manifest.threshold),
            "MPC operation must use exactly threshold participants"
        );
        ensure!(
            self.participants.iter().any(|node| node == initiator),
            "MPC operation initiator is not a participant"
        );
        let indexes = self
            .participants
            .iter()
            .map(|node| {
                manifest
                    .members
                    .binary_search_by_key(&node.as_str(), |member| member.node_id.as_str())
                    .map_err(|_| anyhow::anyhow!("MPC operation contains a non-member"))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            indexes.windows(2).all(|pair| pair[0] < pair[1]),
            "MPC participants must be unique and in manifest order"
        );
        let now = unix_time()?;
        ensure!(self.expires_at >= now, "MPC operation expired");
        ensure!(
            self.expires_at - now <= MAX_OPERATION_TTL_SECS,
            "MPC operation expiration exceeds maximum TTL"
        );
        match &self.payload {
            MpcOperationPayload::SignK256(payload) => payload.validate()?,
            MpcOperationPayload::SignManifest(payload) => {
                payload.validate()?;
                ensure!(
                    payload.manifest.provider_id == manifest.provider_id,
                    "proposed manifest changes provider ID"
                );
                let genesis_self_authorization = manifest.epoch == 1
                    && manifest.previous_manifest_hash.is_empty()
                    && payload.manifest == *manifest;
                if !genesis_self_authorization {
                    ensure!(
                        payload.manifest.epoch == manifest.epoch + 1,
                        "proposed manifest must advance exactly one epoch"
                    );
                    ensure!(
                        payload.manifest.previous_manifest_hash == manifest.manifest_hash()?,
                        "proposed manifest does not extend active manifest"
                    );
                }
            }
            MpcOperationPayload::SignP256Certificate(payload) => payload.validate()?,
            MpcOperationPayload::Derive(payload) => payload.validate()?,
        }
        ensure!(
            self.request_hash == self.compute_request_hash()?,
            "MPC operation request hash mismatch"
        );
        Ok(())
    }

    pub(crate) fn compute_request_hash(&self) -> Result<[u8; 32]> {
        let encoded = serde_jcs::to_vec(&RequestPreimage {
            session_id: &self.session_id,
            epoch: self.epoch,
            participants: &self.participants,
            expires_at: self.expires_at,
            payload: &self.payload,
        })
        .context("failed to encode MPC operation")?;
        let mut digest = Sha256::new();
        digest.update((REQUEST_DOMAIN.len() as u32).to_be_bytes());
        digest.update(REQUEST_DOMAIN);
        digest.update((encoded.len() as u32).to_be_bytes());
        digest.update(encoded);
        Ok(digest.finalize().into())
    }
}

fn unix_time() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs())
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

mod option_hex_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value.as_ref().map(hex::encode).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|value| hex::decode(value.strip_prefix("0x").unwrap_or(&value)))
            .transpose()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_identity::{EpochManifest, EpochMember};

    fn manifest() -> EpochManifest {
        EpochManifest {
            provider_id: vec![1; 32],
            epoch: 3,
            threshold: 2,
            previous_manifest_hash: vec![],
            members: ["kms-1", "kms-2", "kms-3"]
                .into_iter()
                .map(|node_id| EpochMember {
                    node_id: node_id.into(),
                    endpoint: format!("https://{node_id}/prpc"),
                    attestation_pubkey: vec![2; 32],
                    share_commitment: vec![3; 33],
                })
                .collect(),
        }
    }

    #[test]
    fn operation_hash_binds_semantics_and_canonical_quorum() {
        let operation = MpcOperation::new_k256(
            [4; 32],
            3,
            vec!["kms-1".into(), "kms-2".into()],
            unix_time().unwrap() + 30,
            K256SignPayload {
                prefix: b"dstack-env-encrypt-pubkey".to_vec(),
                app_id: vec![5; 20],
                timestamp: Some(7),
                message: vec![6; 32],
            },
        )
        .unwrap();
        operation.validate(&manifest(), "kms-1").unwrap();
        let mut tampered = operation.clone();
        if let MpcOperationPayload::SignK256(payload) = &mut tampered.payload {
            payload.message[0] ^= 1;
        }
        assert!(tampered.validate(&manifest(), "kms-1").is_err());
        let mut reordered = operation;
        reordered.participants.swap(0, 1);
        reordered.request_hash = reordered.compute_request_hash().unwrap().to_vec();
        assert!(reordered.validate(&manifest(), "kms-1").is_err());
    }
}
