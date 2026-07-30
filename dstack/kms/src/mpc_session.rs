// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Authenticated message router for interactive MPC protocols.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

use crate::mpc_identity::EpochManifest;

const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MpcProtocol {
    AuxiliaryInfo,
    DkgP256,
    DkgK256,
    DkgDerivation,
    SignP256,
    SignK256,
    Derive,
    Reshare,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MpcEnvelope {
    #[serde(with = "hex_bytes")]
    pub session_id: Vec<u8>,
    pub epoch: u64,
    pub protocol: MpcProtocol,
    #[serde(with = "hex_bytes")]
    pub request_hash: Vec<u8>,
    pub sender: String,
    pub recipient: String,
    pub sequence: u64,
    pub expires_at: u64,
    #[serde(with = "hex_bytes")]
    pub payload: Vec<u8>,
    pub broadcast: bool,
}

struct Session {
    protocol: MpcProtocol,
    request_hash: Vec<u8>,
    expires_at: u64,
    last_sequence: BTreeMap<String, u64>,
    inboxes: BTreeMap<String, VecDeque<MpcEnvelope>>,
}

pub(crate) struct SessionRouter {
    manifest: EpochManifest,
    max_sessions: usize,
    max_ttl: Duration,
    sessions: Mutex<BTreeMap<Vec<u8>, Session>>,
}

impl SessionRouter {
    pub(crate) fn new(
        manifest: EpochManifest,
        max_sessions: usize,
        max_ttl: Duration,
    ) -> Result<Self> {
        manifest.manifest_hash().context("invalid epoch manifest")?;
        ensure!(max_sessions > 0, "max_sessions must be greater than zero");
        ensure!(!max_ttl.is_zero(), "max_ttl must be greater than zero");
        Ok(Self {
            manifest,
            max_sessions,
            max_ttl,
            sessions: Mutex::new(BTreeMap::new()),
        })
    }

    /// Enqueue a protocol message after binding its claimed sender to the
    /// independently authenticated RA-TLS peer identity.
    pub(crate) fn push(&self, authenticated_node_id: &str, message: MpcEnvelope) -> Result<()> {
        self.validate_envelope(authenticated_node_id, &message)?;
        let now = unix_time()?;
        let mut sessions = self.sessions.lock().expect("session mutex poisoned");
        sessions.retain(|_, session| session.expires_at >= now);
        if !sessions.contains_key(&message.session_id) && sessions.len() >= self.max_sessions {
            bail!("too many active MPC sessions");
        }
        let session = sessions
            .entry(message.session_id.clone())
            .or_insert_with(|| Session {
                protocol: message.protocol,
                request_hash: message.request_hash.clone(),
                expires_at: message.expires_at,
                last_sequence: BTreeMap::new(),
                inboxes: BTreeMap::new(),
            });
        ensure!(
            session.protocol == message.protocol,
            "session protocol changed"
        );
        ensure!(
            session.request_hash == message.request_hash,
            "session request hash changed"
        );
        ensure!(
            session.expires_at == message.expires_at,
            "session expiration changed"
        );
        let last = session
            .last_sequence
            .entry(message.sender.clone())
            .or_default();
        ensure!(
            message.sequence > *last,
            "replayed or reordered MPC message"
        );
        *last = message.sequence;
        session
            .inboxes
            .entry(message.recipient.clone())
            .or_default()
            .push_back(message);
        Ok(())
    }

    pub(crate) fn authenticated_node_id(&self, attested_public_key: &[u8]) -> Result<&str> {
        self.manifest
            .member_for_attestation_key(attested_public_key)
            .map(|member| member.node_id.as_str())
            .context("attested RA-TLS key is not an epoch member")
    }

    pub(crate) fn drain(
        &self,
        authenticated_node_id: &str,
        session_id: &[u8],
    ) -> Result<Vec<MpcEnvelope>> {
        ensure!(session_id.len() == 32, "session_id must be 32 bytes");
        ensure!(
            self.manifest.contains_member(authenticated_node_id),
            "authenticated peer is not an epoch member"
        );
        let mut sessions = self.sessions.lock().expect("session mutex poisoned");
        let Some(session) = sessions.get_mut(session_id) else {
            return Ok(vec![]);
        };
        Ok(session
            .inboxes
            .remove(authenticated_node_id)
            .unwrap_or_default()
            .into())
    }

    fn validate_envelope(&self, authenticated_node_id: &str, message: &MpcEnvelope) -> Result<()> {
        ensure!(
            message.session_id.len() == 32,
            "session_id must be 32 bytes"
        );
        ensure!(
            message.request_hash.len() == 32,
            "request_hash must be 32 bytes"
        );
        ensure!(message.epoch == self.manifest.epoch, "MPC epoch mismatch");
        ensure!(
            message.sender == authenticated_node_id,
            "MPC sender identity mismatch"
        );
        ensure!(
            self.manifest.contains_member(&message.sender),
            "sender is not an epoch member"
        );
        ensure!(
            self.manifest.contains_member(&message.recipient),
            "recipient is not an epoch member"
        );
        ensure!(
            message.sender != message.recipient,
            "sender and recipient must differ"
        );
        ensure!(!message.payload.is_empty(), "MPC payload must not be empty");
        ensure!(
            message.payload.len() <= MAX_MESSAGE_BYTES,
            "MPC payload is too large"
        );
        let now = unix_time()?;
        ensure!(message.expires_at >= now, "MPC message expired");
        ensure!(
            message.expires_at - now <= self.max_ttl.as_secs(),
            "MPC message expiration exceeds maximum TTL"
        );
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpc_identity::EpochMember;

    fn router() -> SessionRouter {
        let members = ["kms-1", "kms-2", "kms-3"]
            .into_iter()
            .map(|node_id| EpochMember {
                node_id: node_id.into(),
                endpoint: format!("https://{node_id}:8443/prpc"),
                attestation_pubkey: vec![1; 32],
                share_commitment: vec![2; 33],
            })
            .collect();
        SessionRouter::new(
            EpochManifest {
                provider_id: vec![3; 32],
                epoch: 4,
                threshold: 2,
                previous_manifest_hash: vec![],
                members,
            },
            8,
            Duration::from_secs(60),
        )
        .unwrap()
    }

    fn message() -> MpcEnvelope {
        MpcEnvelope {
            session_id: vec![4; 32],
            epoch: 4,
            protocol: MpcProtocol::SignK256,
            request_hash: vec![5; 32],
            sender: "kms-1".into(),
            recipient: "kms-2".into(),
            sequence: 1,
            expires_at: unix_time().unwrap() + 30,
            payload: vec![6],
            broadcast: false,
        }
    }

    #[test]
    fn routes_only_authenticated_epoch_members() {
        let router = router();
        router.push("kms-1", message()).unwrap();
        assert_eq!(router.drain("kms-2", &[4; 32]).unwrap(), vec![message()]);
        assert!(router.push("kms-3", message()).is_err());
    }

    #[test]
    fn rejects_replay_and_session_context_changes() {
        let router = router();
        let message = message();
        router.push("kms-1", message.clone()).unwrap();
        assert!(router.push("kms-1", message.clone()).is_err());
        let mut changed = message;
        changed.sequence = 2;
        changed.request_hash[0] ^= 1;
        assert!(router.push("kms-1", changed).is_err());
    }
}
