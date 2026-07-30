// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Drives `round-based` state machines over the attested MPC envelope layer.

use std::{collections::VecDeque, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use round_based::{
    state_machine::{ProceedResult, StateMachine},
    Incoming, MessageDestination, MessageType,
};
use serde::{de::DeserializeOwned, Serialize};

use dstack_kms_rpc::{mpc_transport_client::MpcTransportClient, MpcPushRequest};
use ra_rpc::client::{RaClient, RaClientConfig};
use ra_tls::attestation::AttestationVerifier;

use crate::{
    mpc_identity::EpochManifest,
    mpc_session::{MpcEnvelope, MpcProtocol, SessionRouter},
};

#[derive(Clone)]
pub(crate) struct DriverContext {
    pub session_id: [u8; 32],
    pub epoch: u64,
    pub protocol: MpcProtocol,
    pub request_hash: [u8; 32],
    pub local_node_id: String,
    /// Protocol index -> epoch node ID. Ordering is consensus-critical.
    pub participants: Vec<String>,
    pub expires_at: u64,
    pub poll_interval: Duration,
}

impl DriverContext {
    fn local_index(&self) -> Result<u16> {
        self.participants
            .iter()
            .position(|node| node == &self.local_node_id)
            .context("local node is not a protocol participant")?
            .try_into()
            .context("too many protocol participants")
    }
}

#[async_trait]
pub(crate) trait EnvelopeTransport: Send + Sync {
    async fn send(&self, envelope: MpcEnvelope) -> Result<()>;
    async fn receive(&self, session_id: &[u8; 32]) -> Result<Vec<MpcEnvelope>>;
}

pub(crate) struct BlockingHttpTransport {
    inner: std::sync::Arc<MpcHttpTransport>,
    runtime: tokio::runtime::Handle,
}

impl BlockingHttpTransport {
    pub(crate) fn new(
        inner: std::sync::Arc<MpcHttpTransport>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self { inner, runtime }
    }

    fn send(&self, envelope: MpcEnvelope) -> Result<()> {
        self.runtime.block_on(self.inner.send(envelope))
    }

    fn receive(&self, session_id: &[u8; 32]) -> Result<Vec<MpcEnvelope>> {
        self.runtime.block_on(self.inner.receive(session_id))
    }
}

pub(crate) struct MpcHttpTransport {
    local_node_id: String,
    local_router: std::sync::Arc<SessionRouter>,
    clients: std::collections::BTreeMap<String, MpcTransportClient<RaClient>>,
}

impl MpcHttpTransport {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        manifest: &EpochManifest,
        local_node_id: &str,
        local_router: std::sync::Arc<SessionRouter>,
        client_cert: String,
        client_key: String,
        ca_cert: String,
        attestation_verifier: std::sync::Arc<AttestationVerifier>,
    ) -> Result<Self> {
        ensure!(
            manifest.contains_member(local_node_id),
            "local MPC node is not in the epoch manifest"
        );
        let mut clients = std::collections::BTreeMap::new();
        for member in &manifest.members {
            if member.node_id == local_node_id {
                continue;
            }
            let expected_public_key = member.attestation_pubkey.clone();
            let expected_node_id = member.node_id.clone();
            let client = RaClientConfig::builder()
                .remote_uri(member.endpoint.clone())
                .tls_client_cert(client_cert.clone())
                .tls_client_key(client_key.clone())
                .tls_ca_cert(ca_cert.clone())
                .tls_built_in_root_certs(false)
                .attestation_verifier(attestation_verifier.clone())
                .cert_validator(Box::new(move |info| {
                    let info = info.context("MPC peer did not present a certificate")?;
                    ensure!(
                        info.attestation.is_some(),
                        "MPC peer certificate is not attested"
                    );
                    let (_, certificate) = x509_parser::parse_x509_certificate(&info.cert_der)
                        .context("invalid MPC peer certificate")?;
                    ensure!(
                        certificate.public_key().raw == expected_public_key,
                        "MPC peer certificate key does not match manifest member {expected_node_id}"
                    );
                    Ok(())
                }))
                .build()
                .into_client()
                .with_context(|| format!("failed to build MPC client for {}", member.node_id))?;
            clients.insert(member.node_id.clone(), MpcTransportClient::new(client));
        }
        Ok(Self {
            local_node_id: local_node_id.into(),
            local_router,
            clients,
        })
    }
}

#[async_trait]
impl EnvelopeTransport for MpcHttpTransport {
    async fn send(&self, envelope: MpcEnvelope) -> Result<()> {
        ensure!(
            envelope.sender == self.local_node_id,
            "outgoing MPC sender does not match local node"
        );
        self.clients
            .get(&envelope.recipient)
            .context("MPC recipient has no attested client")?
            .push(MpcPushRequest {
                envelope_json: serde_json::to_vec(&envelope)
                    .context("failed to encode MPC envelope")?,
            })
            .await
            .context("failed to deliver MPC envelope")
    }

    async fn receive(&self, session_id: &[u8; 32]) -> Result<Vec<MpcEnvelope>> {
        self.local_router.drain(&self.local_node_id, session_id)
    }
}

pub(crate) async fn drive_state_machine<S, T>(
    mut state: S,
    transport: &T,
    context: DriverContext,
) -> Result<S::Output>
where
    S: StateMachine,
    S::Msg: Serialize + DeserializeOwned,
    T: EnvelopeTransport,
{
    ensure!(
        context.participants.len() >= 2,
        "MPC needs at least two participants"
    );
    let local_index = context.local_index()?;
    let mut sequence = 0u64;
    let mut pending = VecDeque::new();
    loop {
        match state.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                sequence = sequence.checked_add(1).context("MPC sequence overflow")?;
                let payload = serde_json::to_vec(&outgoing.msg)
                    .context("failed to encode MPC protocol message")?;
                let (recipients, broadcast): (Vec<u16>, bool) = match outgoing.recipient {
                    MessageDestination::AllParties => (
                        (0..context.participants.len())
                            .filter(|index| *index != usize::from(local_index))
                            .map(|index| u16::try_from(index).expect("participant index overflow"))
                            .collect(),
                        true,
                    ),
                    MessageDestination::OneParty(index) => (vec![index], false),
                };
                for recipient in recipients {
                    let recipient = context
                        .participants
                        .get(usize::from(recipient))
                        .context("protocol emitted an invalid recipient index")?;
                    transport
                        .send(MpcEnvelope {
                            session_id: context.session_id.to_vec(),
                            epoch: context.epoch,
                            protocol: context.protocol,
                            request_hash: context.request_hash.to_vec(),
                            sender: context.local_node_id.clone(),
                            recipient: recipient.clone(),
                            sequence,
                            expires_at: context.expires_at,
                            payload: payload.clone(),
                            broadcast,
                        })
                        .await?;
                }
            }
            ProceedResult::NeedsOneMoreMessage => {
                while pending.is_empty() {
                    ensure_not_expired(context.expires_at)?;
                    pending.extend(transport.receive(&context.session_id).await?);
                    if pending.is_empty() {
                        tokio::time::sleep(context.poll_interval).await;
                    }
                }
                let envelope = pending.pop_front().expect("pending queue is not empty");
                ensure!(
                    envelope.recipient == context.local_node_id,
                    "misrouted MPC message"
                );
                let sender: u16 = context
                    .participants
                    .iter()
                    .position(|node| node == &envelope.sender)
                    .context("message sender is not a protocol participant")?
                    .try_into()
                    .context("sender index overflow")?;
                let incoming = Incoming {
                    id: envelope.sequence,
                    sender,
                    msg_type: if envelope.broadcast {
                        MessageType::Broadcast
                    } else {
                        MessageType::P2P
                    },
                    msg: serde_json::from_slice(&envelope.payload)
                        .context("failed to decode MPC protocol message")?,
                };
                state
                    .received_msg(incoming)
                    .map_err(|_| anyhow::anyhow!("MPC state machine rejected incoming message"))?;
            }
            ProceedResult::Yielded => tokio::task::yield_now().await,
            ProceedResult::Output(output) => return Ok(output),
            ProceedResult::Error(error) => bail!("MPC state machine failed: {error}"),
        }
    }
}

/// Executes a non-`Send` round-based state machine on a dedicated blocking
/// thread while network I/O is serviced by the Tokio runtime. CGGMP's sync
/// adapter internally uses `Rc`, so it must never be moved between threads.
pub(crate) fn drive_state_machine_blocking<S>(
    mut state: S,
    transport: &BlockingHttpTransport,
    context: DriverContext,
) -> Result<S::Output>
where
    S: StateMachine,
    S::Msg: Serialize + DeserializeOwned,
{
    ensure!(
        context.participants.len() >= 2,
        "MPC needs at least two participants"
    );
    let local_index = context.local_index()?;
    let mut sequence = 0u64;
    let mut pending = VecDeque::new();
    loop {
        match state.proceed() {
            ProceedResult::SendMsg(outgoing) => {
                sequence = sequence.checked_add(1).context("MPC sequence overflow")?;
                let payload = serde_json::to_vec(&outgoing.msg)
                    .context("failed to encode MPC protocol message")?;
                let (recipients, broadcast): (Vec<u16>, bool) = match outgoing.recipient {
                    MessageDestination::AllParties => (
                        (0..context.participants.len())
                            .filter(|index| *index != usize::from(local_index))
                            .map(|index| u16::try_from(index).expect("participant index overflow"))
                            .collect(),
                        true,
                    ),
                    MessageDestination::OneParty(index) => (vec![index], false),
                };
                for recipient in recipients {
                    let recipient = context
                        .participants
                        .get(usize::from(recipient))
                        .context("protocol emitted an invalid recipient index")?;
                    transport.send(MpcEnvelope {
                        session_id: context.session_id.to_vec(),
                        epoch: context.epoch,
                        protocol: context.protocol,
                        request_hash: context.request_hash.to_vec(),
                        sender: context.local_node_id.clone(),
                        recipient: recipient.clone(),
                        sequence,
                        expires_at: context.expires_at,
                        payload: payload.clone(),
                        broadcast,
                    })?;
                }
            }
            ProceedResult::NeedsOneMoreMessage => {
                while pending.is_empty() {
                    ensure_not_expired(context.expires_at)?;
                    pending.extend(transport.receive(&context.session_id)?);
                    if pending.is_empty() {
                        std::thread::sleep(context.poll_interval);
                    }
                }
                let envelope = pending.pop_front().expect("pending queue is not empty");
                ensure!(
                    envelope.recipient == context.local_node_id,
                    "misrouted MPC message"
                );
                let sender: u16 = context
                    .participants
                    .iter()
                    .position(|node| node == &envelope.sender)
                    .context("message sender is not a protocol participant")?
                    .try_into()
                    .context("sender index overflow")?;
                state
                    .received_msg(Incoming {
                        id: envelope.sequence,
                        sender,
                        msg_type: if envelope.broadcast {
                            MessageType::Broadcast
                        } else {
                            MessageType::P2P
                        },
                        msg: serde_json::from_slice(&envelope.payload)
                            .context("failed to decode MPC protocol message")?,
                    })
                    .map_err(|_| anyhow::anyhow!("MPC state machine rejected incoming message"))?;
            }
            ProceedResult::Yielded => std::thread::yield_now(),
            ProceedResult::Output(output) => return Ok(output),
            ProceedResult::Error(error) => bail!("MPC state machine failed: {error}"),
        }
    }
}

fn ensure_not_expired(expires_at: u64) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs();
    ensure!(now <= expires_at, "MPC session expired");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use cggmp21::{supported_curves::Secp256k1, ExecutionId};
    use rand::rngs::OsRng;

    use super::*;
    use crate::{
        cggmp_engine::{execution_id, CggmpCurve},
        mpc_identity::{EpochManifest, EpochMember},
        mpc_session::SessionRouter,
    };

    #[derive(Clone)]
    struct MemoryTransport {
        local: String,
        routers: Arc<BTreeMap<String, Arc<SessionRouter>>>,
    }

    #[async_trait]
    impl EnvelopeTransport for MemoryTransport {
        async fn send(&self, envelope: MpcEnvelope) -> Result<()> {
            self.routers
                .get(&envelope.recipient)
                .context("missing recipient router")?
                .push(&self.local, envelope)
        }

        async fn receive(&self, session_id: &[u8; 32]) -> Result<Vec<MpcEnvelope>> {
            self.routers
                .get(&self.local)
                .context("missing local router")?
                .drain(&self.local, session_id)
        }
    }

    fn manifest() -> EpochManifest {
        EpochManifest {
            provider_id: vec![3; 32],
            epoch: 1,
            threshold: 2,
            previous_manifest_hash: vec![],
            members: ["kms-1", "kms-2", "kms-3"]
                .into_iter()
                .map(|node_id| EpochMember {
                    node_id: node_id.into(),
                    endpoint: format!("https://{node_id}:8443/prpc"),
                    attestation_pubkey: vec![1; 32],
                    share_commitment: vec![2; 33],
                })
                .collect(),
        }
    }

    async fn dkg_party(
        index: u16,
        transport: MemoryTransport,
        context: DriverContext,
        eid: [u8; 32],
    ) -> Result<crate::cggmp_engine::K256IncompleteShare> {
        let mut rng = OsRng;
        let state = cggmp21::keygen::<Secp256k1>(ExecutionId::new(&eid), index, 3)
            .set_threshold(2)
            .into_state_machine(&mut rng);
        drive_state_machine(state, &transport, context)
            .await?
            .map_err(Into::into)
    }

    #[tokio::test]
    async fn drives_real_cggmp_dkg_over_authenticated_envelopes() {
        let manifest = manifest();
        let routers: Arc<BTreeMap<String, Arc<SessionRouter>>> = Arc::new(
            manifest
                .members
                .iter()
                .map(|member| {
                    (
                        member.node_id.clone(),
                        Arc::new(
                            SessionRouter::new(manifest.clone(), 8, Duration::from_secs(30))
                                .unwrap(),
                        ),
                    )
                })
                .collect(),
        );
        let participants: Vec<_> = manifest
            .members
            .iter()
            .map(|member| member.node_id.clone())
            .collect();
        let session_id = [7; 32];
        let request_hash = [8; 32];
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 20;
        let eid = execution_id("test-cluster", 1, CggmpCurve::K256, &session_id);
        let make = |index: u16| {
            let local = participants[usize::from(index)].clone();
            dkg_party(
                index,
                MemoryTransport {
                    local: local.clone(),
                    routers: routers.clone(),
                },
                DriverContext {
                    session_id,
                    epoch: 1,
                    protocol: MpcProtocol::DkgK256,
                    request_hash,
                    local_node_id: local,
                    participants: participants.clone(),
                    expires_at,
                    poll_interval: Duration::from_millis(1),
                },
                eid,
            )
        };
        let (a, b, c) = tokio::join!(make(0), make(1), make(2));
        let shares = [a.unwrap(), b.unwrap(), c.unwrap()];
        let public_key = serde_json::to_vec(&shares[0].shared_public_key()).unwrap();
        assert!(shares.iter().all(|share| {
            serde_json::to_vec(&share.shared_public_key()).unwrap() == public_key
        }));
    }
}
