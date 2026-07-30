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

use dstack_kms_rpc::{mpc_transport_client::MpcTransportClient, MpcPushRequest, MpcStartRequest};
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

pub(crate) struct BlockingTransport<T> {
    inner: std::sync::Arc<T>,
    runtime: tokio::runtime::Handle,
}

impl<T: EnvelopeTransport> BlockingTransport<T> {
    pub(crate) fn new(inner: std::sync::Arc<T>, runtime: tokio::runtime::Handle) -> Self {
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

    pub(crate) async fn start_operation(
        &self,
        node_id: &str,
        operation: &crate::mpc_operation::MpcOperation,
    ) -> Result<Vec<u8>> {
        self.clients
            .get(node_id)
            .context("MPC operation participant has no attested client")?
            .start(MpcStartRequest {
                operation_json: serde_json::to_vec(operation)
                    .context("failed to encode MPC operation")?,
            })
            .await
            .with_context(|| format!("MPC operation failed on participant {node_id}"))
            .map(|response| response.result)
    }

    pub(crate) async fn reachable_nodes(&self) -> Vec<String> {
        futures::future::join_all(self.clients.iter().map(|(node_id, client)| async move {
            tokio::time::timeout(Duration::from_secs(3), client.ping())
                .await
                .ok()
                .and_then(Result::ok)
                .map(|_| node_id.clone())
        }))
        .await
        .into_iter()
        .flatten()
        .collect()
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
pub(crate) fn drive_state_machine_blocking<S, T>(
    mut state: S,
    transport: &BlockingTransport<T>,
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

    use cggmp21::{key_share::AnyKeyShare as _, supported_curves::Secp256k1, ExecutionId};
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

    fn five_member_manifest() -> EpochManifest {
        EpochManifest {
            provider_id: vec![3; 32],
            epoch: 1,
            threshold: 3,
            previous_manifest_hash: vec![],
            members: (1..=5)
                .map(|index| EpochMember {
                    node_id: format!("kms-{index}"),
                    endpoint: format!("https://kms-{index}:8443/prpc"),
                    attestation_pubkey: vec![index as u8; 32],
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

    #[tokio::test]
    async fn drives_real_threshold_signature_over_authenticated_envelopes() {
        use cggmp21::{generic_ec::Scalar, security_level::SecurityLevel128, DataToSign};
        use k256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
        use sha2::Digest as _;

        let shares = cggmp21::trusted_dealer::builder::<Secp256k1, SecurityLevel128>(5)
            .set_threshold(Some(3))
            .generate_shares(&mut OsRng)
            .unwrap();
        let manifest = five_member_manifest();
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
        // kms-2 and kms-4 are deliberately offline.
        let participants = vec![
            "kms-1".to_string(),
            "kms-3".to_string(),
            "kms-5".to_string(),
        ];
        let session_id = [31; 32];
        let request_hash = [32; 32];
        let expires_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 30;
        let digest = [33u8; 32];
        let eid = execution_id("test-cluster", 1, CggmpCurve::K256, &session_id);
        let sign = |protocol_index: u16, keygen_index: usize| {
            let local = participants[usize::from(protocol_index)].clone();
            let transport = MemoryTransport {
                local: local.clone(),
                routers: routers.clone(),
            };
            let context = DriverContext {
                session_id,
                epoch: 1,
                protocol: MpcProtocol::SignK256,
                request_hash,
                local_node_id: local,
                participants: participants.clone(),
                expires_at,
                poll_interval: Duration::from_millis(1),
            };
            let share = shares[keygen_index].clone();
            async move {
                let mut rng = OsRng;
                let data =
                    DataToSign::from_scalar(Scalar::<Secp256k1>::from_be_bytes_mod_order(digest));
                let keygen_indexes = [0, 2, 4];
                let state = cggmp21::signing(
                    ExecutionId::new(&eid),
                    protocol_index,
                    &keygen_indexes,
                    &share,
                )
                .sign_sync(&mut rng, data);
                drive_state_machine(state, &transport, context)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };
        let (first, second, third) = tokio::join!(sign(0, 0), sign(1, 2), sign(2, 4));
        assert_eq!(first, second);
        assert_eq!(first, third);
        let mut encoded = [0u8; 64];
        first.write_to_slice(&mut encoded);
        let signature = Signature::from_slice(&encoded).unwrap();
        let public_key =
            VerifyingKey::from_sec1_bytes(shares[0].shared_public_key().to_bytes(true).as_bytes())
                .unwrap();
        public_key.verify_prehash(&digest, &signature).unwrap();

        // Reuse the curve-independent auxiliary information to exercise the
        // P-256 threshold certificate path without another safe-prime setup.
        use cggmp21::supported_curves::Secp256r1;
        let p256_cores = cggmp21::trusted_dealer::builder::<Secp256r1, SecurityLevel128>(5)
            .set_threshold(Some(3))
            .generate_core_shares(&mut OsRng)
            .unwrap();
        let p256_shares = p256_cores
            .into_iter()
            .zip(shares.iter())
            .map(|(core, share)| cggmp21::KeyShare::from_parts((core, share.aux.clone())).unwrap())
            .collect::<Vec<_>>();
        let raw_public = p256_shares[0].shared_public_key().to_bytes(false);
        const P256_SPKI_PREFIX: &[u8] = &[
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        let mut spki = P256_SPKI_PREFIX.to_vec();
        spki.extend_from_slice(raw_public.as_bytes());
        let public = ra_tls::rcgen::SubjectPublicKeyInfo::from_der(&spki).unwrap();
        let external = ra_tls::cert::prepare_external_self_signed(
            ra_tls::cert::CertRequest::builder()
                .key(&public)
                .subject("Threshold Test Root")
                .ca_level(1)
                .build(),
        )
        .unwrap();
        let p256_digest: [u8; 32] = sha2::Sha256::digest(external.tbs_der()).into();
        let p256_session = [41; 32];
        let p256_eid = execution_id("test-cluster", 1, CggmpCurve::P256, &p256_session);
        let p256_sign = |protocol_index: u16, keygen_index: usize| {
            let local = participants[usize::from(protocol_index)].clone();
            let context = DriverContext {
                session_id: p256_session,
                epoch: 1,
                protocol: MpcProtocol::SignP256,
                request_hash: [42; 32],
                local_node_id: local.clone(),
                participants: participants.clone(),
                expires_at: expires_at + 60,
                poll_interval: Duration::from_millis(1),
            };
            let transport = MemoryTransport {
                local,
                routers: routers.clone(),
            };
            let share = p256_shares[keygen_index].clone();
            async move {
                let mut rng = OsRng;
                let data = DataToSign::from_scalar(Scalar::<Secp256r1>::from_be_bytes_mod_order(
                    p256_digest,
                ));
                let state = cggmp21::signing(
                    ExecutionId::new(&p256_eid),
                    protocol_index,
                    &[0, 2, 4],
                    &share,
                )
                .sign_sync(&mut rng, data);
                drive_state_machine(state, &transport, context)
                    .await
                    .unwrap()
                    .unwrap()
            }
        };
        let (p1, p2, p3) = tokio::join!(p256_sign(0, 0), p256_sign(1, 2), p256_sign(2, 4));
        assert_eq!(p1, p2);
        assert_eq!(p1, p3);
        let mut encoded = [0u8; 64];
        p1.write_to_slice(&mut encoded);
        let pem = external.finish(&encoded).unwrap();
        let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        pem.parse_x509().unwrap().verify_signature(None).unwrap();
    }
}
