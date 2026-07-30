// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

//! Attested maintenance protocol for adding members without reconstructing a root key.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use anyhow::{ensure, Context, Result};
use async_trait::async_trait;
use cggmp21::{
    generic_ec::Scalar,
    key_share::{AnyKeyShare as _, DirtyKeyInfo, Valid},
    supported_curves::{Secp256k1, Secp256r1},
    DataToSign, ExecutionId, KeyShare,
};
use dstack_kms_rpc::{
    mpc_join_client::MpcJoinClient,
    mpc_join_server::{MpcJoinRpc, MpcJoinServer},
    MpcGenesisFinalizeRequest, MpcGenesisStartRequest, MpcGenesisStartResponse, MpcPushRequest,
};
use ra_rpc::{
    client::{RaClient, RaClientConfig},
    CallContext, RpcCall,
};
use ra_tls::{
    attestation::AttestationVerifier,
    cert::{prepare_external_certificate, CertRequest, ExternalCertificate},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    cggmp_engine::{
        execution_id, load_share, share_commitment, store_share, CggmpCurve, K256KeyShare,
        P256KeyShare,
    },
    config::KmsConfig,
    mpc_driver::{
        drive_state_machine_blocking, BlockingTransport, DriverContext, EnvelopeTransport,
    },
    mpc_identity::{ClusterIdentity, EpochManifest, EpochMember, SignedEpochManifest},
    mpc_lifecycle::{
        activate_pending_epoch, initialize_join_checkpoint, pending_share_path, EpochPaths,
        SignedResharePlan,
    },
    mpc_reshare::{self, PrivateContribution, PublicContribution},
    mpc_session::{MpcEnvelope, MpcProtocol, SessionRouter},
};

const JOIN_DOMAIN: &[u8] = b"dstack-mpc-join-operation-v1";
const JOIN_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JoinKind {
    AuxiliaryInfo,
    Reshare,
    SignManifest,
    PrepareRpcCertificate,
    SignRpcCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JoinOperation {
    #[serde(with = "hex_bytes")]
    session_id: Vec<u8>,
    kind: JoinKind,
    #[serde(with = "hex_bytes")]
    payload: Vec<u8>,
    expires_at: u64,
    #[serde(with = "hex_bytes")]
    request_hash: Vec<u8>,
}

impl JoinOperation {
    fn new(kind: JoinKind, payload: Vec<u8>) -> Result<Self> {
        let mut session = [0u8; 32];
        OsRng.fill_bytes(&mut session);
        let mut value = Self {
            session_id: session.to_vec(),
            kind,
            payload,
            expires_at: unix_time()? + JOIN_TTL.as_secs(),
            request_hash: vec![],
        };
        value.request_hash = value.hash()?.to_vec();
        Ok(value)
    }
    fn hash(&self) -> Result<[u8; 32]> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            session_id: &'a [u8],
            kind: JoinKind,
            payload: &'a [u8],
            expires_at: u64,
        }
        let encoded = serde_jcs::to_vec(&Preimage {
            session_id: &self.session_id,
            kind: self.kind,
            payload: &self.payload,
            expires_at: self.expires_at,
        })?;
        let mut hash = Sha256::new();
        hash.update(JOIN_DOMAIN);
        hash.update(encoded);
        Ok(hash.finalize().into())
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            self.session_id.len() == 32 && self.request_hash == self.hash()?,
            "invalid join operation binding"
        );
        let now = unix_time()?;
        ensure!(
            self.expires_at >= now && self.expires_at - now <= JOIN_TTL.as_secs(),
            "invalid join operation expiry"
        );
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct JoinWire {
    p256_reference: DirtyKeyInfo<Secp256r1>,
    p256_public: PublicContribution,
    p256_private: PrivateContribution,
    k256_reference: DirtyKeyInfo<Secp256k1>,
    k256_public: PublicContribution,
    k256_private: PrivateContribution,
    derivation_reference: DirtyKeyInfo<Secp256r1>,
    derivation_public: PublicContribution,
    derivation_private: PrivateContribution,
}

#[derive(Clone, Serialize, Deserialize)]
struct JoinRpcCertificatePayload {
    node_id: String,
    #[serde(with = "hex_bytes")]
    tbs_der: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
struct JoinFinalBundle {
    signed_manifest: SignedEpochManifest,
    rpc_certificates: BTreeMap<String, String>,
}

#[derive(Default)]
struct JoinArtifacts {
    aux: Option<cggmp21::key_share::AuxInfo>,
    pending: Option<(P256KeyShare, K256KeyShare, P256KeyShare)>,
}

struct JoinTransport {
    local_node_id: String,
    router: Arc<SessionRouter>,
    clients: BTreeMap<String, MpcJoinClient<RaClient>>,
}

impl JoinTransport {
    fn new(
        plan: &SignedResharePlan,
        local: &str,
        router: Arc<SessionRouter>,
        cert: String,
        key: String,
        ca: String,
        verifier: Arc<AttestationVerifier>,
    ) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for member in &plan.plan.members {
            if member.node_id == local {
                continue;
            }
            let expected = member.attestation_pubkey.clone();
            let node = member.node_id.clone();
            let client = RaClientConfig::builder()
                .remote_uri(member.endpoint.clone())
                .tls_client_cert(cert.clone())
                .tls_client_key(key.clone())
                .tls_ca_cert(ca.clone())
                .tls_built_in_root_certs(false)
                .tls_no_check(true)
                .tls_no_check_hostname(true)
                .attestation_verifier(verifier.clone())
                .cert_validator(Box::new(move |info| {
                    let info = info.context("join peer has no certificate")?;
                    ensure!(info.attestation.is_some(), "join peer is not attested");
                    let (_, certificate) = x509_parser::parse_x509_certificate(&info.cert_der)
                        .context("invalid join peer certificate")?;
                    ensure!(
                        certificate.public_key().raw == expected,
                        "wrong quote-bound key for {node}"
                    );
                    Ok(())
                }))
                .build()
                .into_client()
                .context("failed to build join client")?;
            clients.insert(member.node_id.clone(), MpcJoinClient::new(client));
        }
        Ok(Self {
            local_node_id: local.into(),
            router,
            clients,
        })
    }
    async fn start(&self, node: &str, operation: &JoinOperation) -> Result<Vec<u8>> {
        Ok(self
            .clients
            .get(node)
            .context("missing join client")?
            .start(MpcGenesisStartRequest {
                operation_json: serde_json::to_vec(operation)?,
            })
            .await?
            .result_json)
    }
    async fn ready(&self) -> Result<()> {
        let deadline = tokio::time::Instant::now() + JOIN_TTL;
        loop {
            let results =
                futures::future::join_all(self.clients.values().map(|client| client.ping())).await;
            if results.iter().all(Result::is_ok) {
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for join peers"
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[async_trait]
impl EnvelopeTransport for JoinTransport {
    async fn send(&self, envelope: MpcEnvelope) -> Result<()> {
        ensure!(envelope.sender == self.local_node_id, "wrong join sender");
        self.clients
            .get(&envelope.recipient)
            .context("missing join recipient")?
            .push(MpcPushRequest {
                envelope_json: serde_json::to_vec(&envelope)?,
            })
            .await?;
        Ok(())
    }
    async fn receive(&self, session_id: &[u8; 32]) -> Result<Vec<MpcEnvelope>> {
        self.router.drain(&self.local_node_id, session_id)
    }
}

struct JoinInner {
    config: KmsConfig,
    identity: ClusterIdentity,
    active: SignedEpochManifest,
    authorization: SignedResharePlan,
    router: Arc<SessionRouter>,
    transport: Arc<JoinTransport>,
    verifier: Arc<AttestationVerifier>,
    artifacts: Mutex<JoinArtifacts>,
    old_p256: Option<P256KeyShare>,
    old_k256: Option<K256KeyShare>,
    old_derivation: Option<P256KeyShare>,
    finalized: tokio::sync::Notify,
    is_finalized: AtomicBool,
    operations: Mutex<BTreeMap<Vec<u8>, Arc<JoinOperationRecord>>>,
}

struct JoinOperationRecord {
    operation: JoinOperation,
    result: Mutex<Option<std::result::Result<Vec<u8>, String>>>,
    finished: tokio::sync::Notify,
}

#[derive(Clone)]
pub(crate) struct JoinState(Arc<JoinInner>);

impl JoinState {
    pub(crate) fn new(config: KmsConfig) -> Result<Self> {
        let identity: ClusterIdentity =
            serde_json::from_slice(&fs_err::read(&config.mpc.identity_file)?)?;
        let active: SignedEpochManifest =
            serde_json::from_slice(&fs_err::read(&config.mpc.manifest_file)?)?;
        active.verify(&identity)?;
        let authorization: SignedResharePlan =
            serde_json::from_slice(&fs_err::read(&config.mpc.join_authorization_file)?)?;
        authorization.verify(&identity, &active.manifest)?;
        ensure!(
            authorization
                .plan
                .members
                .iter()
                .any(|member| member.node_id == config.mpc.node_id),
            "local node is absent from join target"
        );
        initialize_join_checkpoint(
            &config.mpc.checkpoint_file,
            &active,
            &authorization,
            &identity,
        )?;
        let provisional = EpochManifest {
            provider_id: identity.provider_id().to_vec(),
            epoch: authorization.plan.epoch,
            threshold: authorization.plan.threshold,
            previous_manifest_hash: authorization.plan.previous_manifest_hash.clone(),
            members: authorization
                .plan
                .members
                .iter()
                .map(|member| EpochMember {
                    node_id: member.node_id.clone(),
                    endpoint: member.endpoint.clone(),
                    attestation_pubkey: member.attestation_pubkey.clone(),
                    share_commitment: vec![1],
                })
                .collect(),
        };
        let router = Arc::new(SessionRouter::new(provisional, 32, JOIN_TTL)?);
        let verifier = Arc::new(AttestationVerifier::load(&config.attestation)?);
        let ca = fs_err::read_to_string(config.root_ca_cert())?;
        let transport = Arc::new(JoinTransport::new(
            &authorization,
            &config.mpc.node_id,
            router.clone(),
            fs_err::read_to_string(config.rpc_cert())?,
            fs_err::read_to_string(config.rpc_key())?,
            ca,
            verifier.clone(),
        )?);
        let old_index = active
            .manifest
            .members
            .iter()
            .position(|member| member.node_id == config.mpc.node_id);
        let load_old = |curve, path: &std::path::Path| -> Result<serde_json::Value> {
            match curve {
                CggmpCurve::P256 => Ok(serde_json::to_value(load_share::<P256KeyShare>(
                    path,
                    &identity.cluster_id,
                    active.manifest.epoch,
                    &config.mpc.node_id,
                    curve,
                )?)?),
                CggmpCurve::K256 => Ok(serde_json::to_value(load_share::<K256KeyShare>(
                    path,
                    &identity.cluster_id,
                    active.manifest.epoch,
                    &config.mpc.node_id,
                    curve,
                )?)?),
            }
        };
        let (old_p256, old_k256, old_derivation) = if old_index.is_some() {
            (
                Some(serde_json::from_value(load_old(
                    CggmpCurve::P256,
                    &config.mpc.p256_share_file,
                )?)?),
                Some(serde_json::from_value(load_old(
                    CggmpCurve::K256,
                    &config.mpc.k256_share_file,
                )?)?),
                Some(serde_json::from_value(load_old(
                    CggmpCurve::P256,
                    &config.mpc.derivation_share_file,
                )?)?),
            )
        } else {
            (None, None, None)
        };
        Ok(Self(Arc::new(JoinInner {
            config,
            identity,
            active,
            authorization,
            router,
            transport,
            verifier,
            artifacts: Mutex::new(JoinArtifacts::default()),
            old_p256,
            old_k256,
            old_derivation,
            finalized: tokio::sync::Notify::new(),
            is_finalized: AtomicBool::new(false),
            operations: Mutex::new(BTreeMap::new()),
        })))
    }
    pub(crate) fn verifier(&self) -> Arc<AttestationVerifier> {
        self.0.verifier.clone()
    }
    pub(crate) fn is_coordinator(&self) -> bool {
        self.0
            .authorization
            .plan
            .dealers
            .first()
            .is_some_and(|node| node == &self.0.config.mpc.node_id)
    }
    pub(crate) async fn wait_finalized(&self) {
        loop {
            let notified = self.0.finalized.notified();
            if self.0.is_finalized.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
    fn authenticated_node(&self, key: &[u8]) -> Result<&str> {
        self.0
            .authorization
            .plan
            .members
            .iter()
            .find(|member| member.attestation_pubkey == key)
            .map(|member| member.node_id.as_str())
            .context("peer is absent from authorized join")
    }

    async fn execute(&self, operation: JoinOperation, initiator: &str) -> Result<Vec<u8>> {
        operation.validate()?;
        ensure!(
            self.0
                .authorization
                .plan
                .dealers
                .first()
                .is_some_and(|node| node == initiator),
            "only authorized join coordinator may start"
        );
        let (record, owner) = {
            let mut records = self.0.operations.lock().expect("join mutex poisoned");
            if let Some(record) = records.get(&operation.request_hash) {
                ensure!(
                    record.operation == operation,
                    "conflicting join operation hash"
                );
                (record.clone(), false)
            } else {
                ensure!(records.len() < 16, "too many join operations");
                let record = Arc::new(JoinOperationRecord {
                    operation: operation.clone(),
                    result: Mutex::new(None),
                    finished: tokio::sync::Notify::new(),
                });
                records.insert(operation.request_hash.clone(), record.clone());
                (record, true)
            }
        };
        if owner {
            let result = self.execute_owned(operation).await;
            *record.result.lock().expect("join mutex poisoned") = Some(
                result
                    .as_ref()
                    .cloned()
                    .map_err(|error| format!("{error:#}")),
            );
            record.finished.notify_waiters();
            result
        } else {
            loop {
                let notified = record.finished.notified();
                if let Some(result) = record.result.lock().expect("join mutex poisoned").clone() {
                    return result.map_err(anyhow::Error::msg);
                }
                notified.await;
            }
        }
    }

    async fn execute_owned(&self, operation: JoinOperation) -> Result<Vec<u8>> {
        match operation.kind {
            JoinKind::AuxiliaryInfo => self.execute_aux(operation).await,
            JoinKind::Reshare => self.execute_reshare(operation).await,
            JoinKind::SignManifest => self.execute_sign_manifest(operation).await,
            JoinKind::PrepareRpcCertificate => self.prepare_rpc_certificate(operation),
            JoinKind::SignRpcCertificate => self.execute_sign_rpc_certificate(operation).await,
        }
    }

    async fn execute_aux(&self, operation: JoinOperation) -> Result<Vec<u8>> {
        ensure!(
            operation.payload.is_empty(),
            "auxiliary operation payload must be empty"
        );
        let members = &self.0.authorization.plan.members;
        let local_index: u16 = members
            .iter()
            .position(|member| member.node_id == self.0.config.mpc.node_id)
            .context("local target index missing")?
            .try_into()?;
        let n: u16 = members.len().try_into()?;
        let context = self.context(
            &operation,
            MpcProtocol::AuxiliaryInfo,
            members
                .iter()
                .map(|member| member.node_id.clone())
                .collect(),
        )?;
        let transport = self.0.transport.clone();
        let runtime = tokio::runtime::Handle::current();
        let eid = execution_id(
            &self.0.identity.cluster_id,
            self.0.authorization.plan.epoch,
            CggmpCurve::K256,
            operation.session_id.as_slice().try_into()?,
        );
        let aux = tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
            let state = cggmp21::aux_info_gen(ExecutionId::new(&eid), local_index, n, primes)
                .into_state_machine(&mut rng);
            drive_state_machine_blocking(
                state,
                &BlockingTransport::new(transport, runtime),
                context,
            )?
            .map_err(|error| anyhow::anyhow!("join auxiliary protocol failed: {error}"))
        })
        .await
        .context("join auxiliary worker panicked")??;
        self.0.artifacts.lock().expect("join mutex poisoned").aux = Some(aux);
        Ok(vec![])
    }

    async fn execute_reshare(&self, operation: JoinOperation) -> Result<Vec<u8>> {
        ensure!(
            operation.payload == serde_jcs::to_vec(&self.0.authorization)?,
            "wrong join authorization payload"
        );
        let plan = &self.0.authorization.plan;
        let recipient: u16 = plan
            .members
            .iter()
            .position(|member| member.node_id == self.0.config.mpc.node_id)
            .context("local target index missing")?
            .try_into()?;
        let dealer_indexes = plan
            .dealers
            .iter()
            .map(|node| {
                self.0
                    .active
                    .manifest
                    .members
                    .iter()
                    .position(|member| &member.node_id == node)
                    .context("authorized dealer is not active")?
                    .try_into()
                    .context("dealer index overflow")
            })
            .collect::<Result<Vec<u16>>>()?;
        let mut received = BTreeMap::<u16, JoinWire>::new();
        if let Some(position) = plan
            .dealers
            .iter()
            .position(|node| node == &self.0.config.mpc.node_id)
        {
            let old_index = dealer_indexes[position];
            let p = self
                .0
                .old_p256
                .as_ref()
                .context("dealer lacks old P-256 share")?;
            let k = self
                .0
                .old_k256
                .as_ref()
                .context("dealer lacks old K-256 share")?;
            let d = self
                .0
                .old_derivation
                .as_ref()
                .context("dealer lacks old derivation share")?;
            let p_core = Valid::validate(p.core.clone())
                .map_err(|error| anyhow::anyhow!("invalid old P-256 share: {error}"))?;
            let k_core = Valid::validate(k.core.clone())
                .map_err(|error| anyhow::anyhow!("invalid old K-256 share: {error}"))?;
            let d_core = Valid::validate(d.core.clone())
                .map_err(|error| anyhow::anyhow!("invalid old derivation share: {error}"))?;
            let (pp, ps) = mpc_reshare::create_contribution(
                &p_core,
                &dealer_indexes,
                plan.members.len().try_into()?,
                plan.threshold,
                &mut OsRng,
            )?;
            let (kp, ks) = mpc_reshare::create_contribution(
                &k_core,
                &dealer_indexes,
                plan.members.len().try_into()?,
                plan.threshold,
                &mut OsRng,
            )?;
            let (dp, ds) = mpc_reshare::create_contribution(
                &d_core,
                &dealer_indexes,
                plan.members.len().try_into()?,
                plan.threshold,
                &mut OsRng,
            )?;
            for (index, member) in plan.members.iter().enumerate() {
                let wire = JoinWire {
                    p256_reference: p_core.key_info.clone(),
                    p256_public: pp.clone(),
                    p256_private: ps[index].clone(),
                    k256_reference: k_core.key_info.clone(),
                    k256_public: kp.clone(),
                    k256_private: ks[index].clone(),
                    derivation_reference: d_core.key_info.clone(),
                    derivation_public: dp.clone(),
                    derivation_private: ds[index].clone(),
                };
                if index == usize::from(recipient) {
                    received.insert(old_index, wire);
                } else {
                    self.0
                        .transport
                        .send(MpcEnvelope {
                            session_id: operation.session_id.clone(),
                            epoch: plan.epoch,
                            protocol: MpcProtocol::Reshare,
                            request_hash: operation.request_hash.clone(),
                            sender: self.0.config.mpc.node_id.clone(),
                            recipient: member.node_id.clone(),
                            sequence: u64::from(old_index) + 1,
                            expires_at: operation.expires_at,
                            payload: serde_json::to_vec(&wire)?,
                            broadcast: false,
                        })
                        .await?;
                }
            }
        }
        while received.len() < dealer_indexes.len() {
            ensure!(
                unix_time()? <= operation.expires_at,
                "join resharing expired"
            );
            for envelope in self
                .0
                .transport
                .receive(operation.session_id.as_slice().try_into()?)
                .await?
            {
                let index: u16 = self
                    .0
                    .active
                    .manifest
                    .members
                    .iter()
                    .position(|member| member.node_id == envelope.sender)
                    .context("join sender is not active")?
                    .try_into()?;
                ensure!(
                    dealer_indexes.contains(&index) && !received.contains_key(&index),
                    "invalid duplicate join dealer"
                );
                received.insert(
                    index,
                    serde_json::from_slice(&envelope.payload)
                        .context("invalid join contribution")?,
                );
            }
            if received.len() < dealer_indexes.len() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        let wires = dealer_indexes
            .iter()
            .map(|index| received.get(index).expect("all join dealers received"))
            .collect::<Vec<_>>();
        for wire in &wires[1..] {
            ensure!(
                serde_jcs::to_vec(&wire.p256_reference)?
                    == serde_jcs::to_vec(&wires[0].p256_reference)?
                    && serde_jcs::to_vec(&wire.k256_reference)?
                        == serde_jcs::to_vec(&wires[0].k256_reference)?
                    && serde_jcs::to_vec(&wire.derivation_reference)?
                        == serde_jcs::to_vec(&wires[0].derivation_reference)?,
                "dealers disagree on old public topology"
            );
        }
        let combine_p = mpc_reshare::verify_and_combine_with_key_info(
            &wires[0].p256_reference,
            &dealer_indexes,
            plan.members.len().try_into()?,
            plan.threshold,
            recipient,
            &wires
                .iter()
                .map(|w| w.p256_public.clone())
                .collect::<Vec<_>>(),
            &wires
                .iter()
                .map(|w| w.p256_private.clone())
                .collect::<Vec<_>>(),
        )?;
        let combine_k = mpc_reshare::verify_and_combine_with_key_info(
            &wires[0].k256_reference,
            &dealer_indexes,
            plan.members.len().try_into()?,
            plan.threshold,
            recipient,
            &wires
                .iter()
                .map(|w| w.k256_public.clone())
                .collect::<Vec<_>>(),
            &wires
                .iter()
                .map(|w| w.k256_private.clone())
                .collect::<Vec<_>>(),
        )?;
        let combine_d = mpc_reshare::verify_and_combine_with_key_info(
            &wires[0].derivation_reference,
            &dealer_indexes,
            plan.members.len().try_into()?,
            plan.threshold,
            recipient,
            &wires
                .iter()
                .map(|w| w.derivation_public.clone())
                .collect::<Vec<_>>(),
            &wires
                .iter()
                .map(|w| w.derivation_private.clone())
                .collect::<Vec<_>>(),
        )?;
        let p_core = combine_p.into_incomplete_share_with_key_info(
            recipient,
            plan.threshold,
            &wires[0].p256_reference,
        )?;
        let k_core = combine_k.into_incomplete_share_with_key_info(
            recipient,
            plan.threshold,
            &wires[0].k256_reference,
        )?;
        let d_core = combine_d.into_incomplete_share_with_key_info(
            recipient,
            plan.threshold,
            &wires[0].derivation_reference,
        )?;
        let aux = self
            .0
            .artifacts
            .lock()
            .expect("join mutex poisoned")
            .aux
            .clone()
            .context("join auxiliary info missing")?;
        let p = KeyShare::from_parts((p_core, aux.clone()))
            .map_err(|error| anyhow::anyhow!("invalid joined P-256 share: {error}"))?;
        let k = KeyShare::from_parts((k_core, aux.clone()))
            .map_err(|error| anyhow::anyhow!("invalid joined K-256 share: {error}"))?;
        let d = KeyShare::from_parts((d_core, aux))
            .map_err(|error| anyhow::anyhow!("invalid joined derivation share: {error}"))?;
        ensure!(
            p.shared_public_key().to_bytes(false).as_bytes() == self.0.identity.p256_group_pubkey
                && k.shared_public_key().to_bytes(true).as_bytes()
                    == self.0.identity.k256_group_pubkey
                && d.shared_public_key().to_bytes(false).as_bytes()
                    == self.0.identity.derivation_group_pubkey,
            "join changed stable group identity"
        );
        let p_pub = p.core.key_info.public_shares[usize::from(recipient)].to_bytes(false);
        let k_pub = k.core.key_info.public_shares[usize::from(recipient)].to_bytes(true);
        let d_pub = d.core.key_info.public_shares[usize::from(recipient)].to_bytes(false);
        let commitment = share_commitment(p_pub.as_bytes(), k_pub.as_bytes(), d_pub.as_bytes());
        let epoch = plan.epoch;
        let node = &self.0.config.mpc.node_id;
        let cluster = &self.0.identity.cluster_id;
        store_share(
            &pending_share_path(&self.0.config.mpc.p256_share_file, epoch),
            cluster,
            epoch,
            node,
            CggmpCurve::P256,
            &p,
        )?;
        store_share(
            &pending_share_path(&self.0.config.mpc.k256_share_file, epoch),
            cluster,
            epoch,
            node,
            CggmpCurve::K256,
            &k,
        )?;
        store_share(
            &pending_share_path(&self.0.config.mpc.derivation_share_file, epoch),
            cluster,
            epoch,
            node,
            CggmpCurve::P256,
            &d,
        )?;
        self.0
            .artifacts
            .lock()
            .expect("join mutex poisoned")
            .pending = Some((p, k, d));
        Ok(commitment.to_vec())
    }

    async fn execute_sign_manifest(&self, operation: JoinOperation) -> Result<Vec<u8>> {
        ensure!(
            self.0
                .authorization
                .plan
                .dealers
                .iter()
                .any(|node| node == &self.0.config.mpc.node_id),
            "only authorized old dealers sign target manifest"
        );
        let manifest: EpochManifest =
            serde_json::from_slice(&operation.payload).context("invalid target manifest")?;
        self.validate_target_manifest(&manifest)?;
        let digest = manifest.manifest_hash()?;
        let dealers = self.0.authorization.plan.dealers.clone();
        let local: u16 = dealers
            .iter()
            .position(|node| node == &self.0.config.mpc.node_id)
            .unwrap()
            .try_into()?;
        let keygen = dealers
            .iter()
            .map(|node| {
                self.0
                    .active
                    .manifest
                    .members
                    .iter()
                    .position(|member| &member.node_id == node)
                    .context("dealer is not active")?
                    .try_into()
                    .context("dealer index overflow")
            })
            .collect::<Result<Vec<u16>>>()?;
        let share = self
            .0
            .old_k256
            .clone()
            .context("manifest signer lacks old K-256 share")?;
        let context = self.context(&operation, MpcProtocol::SignK256, dealers)?;
        let transport = self.0.transport.clone();
        let runtime = tokio::runtime::Handle::current();
        let eid = execution_id(
            &self.0.identity.cluster_id,
            self.0.active.manifest.epoch,
            CggmpCurve::K256,
            operation.session_id.as_slice().try_into()?,
        );
        tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let data =
                DataToSign::from_scalar(Scalar::<Secp256k1>::from_be_bytes_mod_order(digest));
            let state = cggmp21::signing(ExecutionId::new(&eid), local, &keygen, &share)
                .sign_sync(&mut rng, data);
            let signature = drive_state_machine_blocking(
                state,
                &BlockingTransport::new(transport, runtime),
                context,
            )??;
            let mut encoded = vec![0; cggmp21::Signature::<Secp256k1>::serialized_len()];
            signature.write_to_slice(&mut encoded);
            Ok(encoded)
        })
        .await
        .context("join manifest signing worker panicked")?
    }

    fn prepare_rpc_certificate(&self, operation: JoinOperation) -> Result<Vec<u8>> {
        ensure!(
            operation.payload.is_empty(),
            "RPC certificate preparation payload must be empty"
        );
        let key =
            ra_tls::rcgen::KeyPair::from_pem(&fs_err::read_to_string(self.0.config.rpc_key())?)?;
        let (_, current_pem) =
            x509_parser::pem::parse_x509_pem(&fs_err::read(self.0.config.rpc_cert())?)?;
        let current = current_pem.parse_x509()?;
        let attestation = ra_tls::attestation::from_cert(&current)?
            .context("join RPC certificate lacks attestation")?;
        let domain = fs_err::read_to_string(self.0.config.rpc_domain())?;
        let names = [domain.clone()];
        Ok(prepare_external_certificate(
            CertRequest::builder()
                .key(&key)
                .subject(&domain)
                .alt_names(&names)
                .special_usage("kms:rpc")
                .attestation(&attestation)
                .usage_server_auth(true)
                .usage_client_auth(true)
                .build(),
            &fs_err::read_to_string(self.0.config.root_ca_cert())?,
        )?
        .tbs_der()
        .to_vec())
    }

    fn validate_rpc_certificate_tbs(&self, payload: &JoinRpcCertificatePayload) -> Result<()> {
        use ra_tls::oids::{PHALA_RATLS_ATTESTATION, PHALA_RATLS_CERT_USAGE};
        use x509_parser::{
            certificate::TbsCertificate, der_parser::oid::Oid, prelude::FromDer as _,
        };
        let member = self
            .0
            .authorization
            .plan
            .members
            .iter()
            .find(|member| member.node_id == payload.node_id)
            .context("RPC certificate target is absent from join authorization")?;
        let (_, root_pem) =
            x509_parser::pem::parse_x509_pem(&fs_err::read(self.0.config.root_ca_cert())?)?;
        let root = root_pem.parse_x509()?;
        ensure!(
            root.public_key().subject_public_key.data.as_ref() == self.0.identity.p256_group_pubkey,
            "join RPC issuer key mismatch"
        );
        let (remaining, tbs) = TbsCertificate::from_der(&payload.tbs_der)
            .map_err(|error| anyhow::anyhow!("invalid join RPC TBS: {error}"))?;
        ensure!(
            remaining.is_empty() && tbs.issuer() == root.subject(),
            "join RPC certificate issuer mismatch"
        );
        ensure!(
            tbs.public_key().raw == member.attestation_pubkey,
            "join RPC certificate key is not quote-bound authorization key"
        );
        let usage_oid = Oid::from(PHALA_RATLS_CERT_USAGE)
            .map_err(|error| anyhow::anyhow!("invalid usage OID: {error:?}"))?;
        let usage = tbs
            .get_extension_unique(&usage_oid)?
            .context("join RPC certificate lacks usage")?;
        ensure!(
            yasna::parse_der(usage.value, |reader| reader.read_bytes())? == b"kms:rpc",
            "join RPC certificate usage mismatch"
        );
        let attestation_oid = Oid::from(PHALA_RATLS_ATTESTATION)
            .map_err(|error| anyhow::anyhow!("invalid attestation OID: {error:?}"))?;
        ensure!(
            tbs.get_extension_unique(&attestation_oid)?.is_some(),
            "join RPC certificate lacks attestation"
        );
        Ok(())
    }

    async fn execute_sign_rpc_certificate(&self, operation: JoinOperation) -> Result<Vec<u8>> {
        ensure!(
            self.0
                .authorization
                .plan
                .dealers
                .iter()
                .any(|node| node == &self.0.config.mpc.node_id),
            "only old dealers sign joined RPC certificates"
        );
        let payload: JoinRpcCertificatePayload = serde_json::from_slice(&operation.payload)?;
        self.validate_rpc_certificate_tbs(&payload)?;
        let digest: [u8; 32] = Sha256::digest(&payload.tbs_der).into();
        let dealers = self.0.authorization.plan.dealers.clone();
        let local: u16 = dealers
            .iter()
            .position(|node| node == &self.0.config.mpc.node_id)
            .unwrap()
            .try_into()?;
        let keygen = dealers
            .iter()
            .map(|node| {
                self.0
                    .active
                    .manifest
                    .members
                    .iter()
                    .position(|member| &member.node_id == node)
                    .context("dealer is not active")?
                    .try_into()
                    .context("dealer index overflow")
            })
            .collect::<Result<Vec<u16>>>()?;
        let share = self
            .0
            .old_p256
            .clone()
            .context("RPC signer lacks old P-256 share")?;
        let context = self.context(&operation, MpcProtocol::SignP256, dealers)?;
        let transport = self.0.transport.clone();
        let runtime = tokio::runtime::Handle::current();
        let eid = execution_id(
            &self.0.identity.cluster_id,
            self.0.active.manifest.epoch,
            CggmpCurve::P256,
            operation.session_id.as_slice().try_into()?,
        );
        tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let data =
                DataToSign::from_scalar(Scalar::<Secp256r1>::from_be_bytes_mod_order(digest));
            let state = cggmp21::signing(ExecutionId::new(&eid), local, &keygen, &share)
                .sign_sync(&mut rng, data);
            let signature = drive_state_machine_blocking(
                state,
                &BlockingTransport::new(transport, runtime),
                context,
            )??;
            let mut encoded = vec![0; cggmp21::Signature::<Secp256r1>::serialized_len()];
            signature.write_to_slice(&mut encoded);
            Ok(encoded)
        })
        .await
        .context("join RPC signing worker panicked")?
    }

    fn validate_target_manifest(&self, manifest: &EpochManifest) -> Result<()> {
        let plan = &self.0.authorization.plan;
        ensure!(
            manifest.provider_id == self.0.identity.provider_id()
                && manifest.epoch == plan.epoch
                && manifest.threshold == plan.threshold
                && manifest.previous_manifest_hash == plan.previous_manifest_hash,
            "target manifest differs from join authorization"
        );
        ensure!(
            manifest.members.len() == plan.members.len(),
            "target manifest member count mismatch"
        );
        for (actual, expected) in manifest.members.iter().zip(&plan.members) {
            ensure!(
                actual.node_id == expected.node_id
                    && actual.endpoint == expected.endpoint
                    && actual.attestation_pubkey == expected.attestation_pubkey
                    && actual.share_commitment.len() == 32,
                "target manifest member mismatch"
            );
        }
        let local_index = manifest
            .members
            .iter()
            .position(|member| member.node_id == self.0.config.mpc.node_id)
            .context("local member missing from target manifest")?;
        if let Some((p, k, d)) = &self
            .0
            .artifacts
            .lock()
            .expect("join mutex poisoned")
            .pending
        {
            let p = p.core.key_info.public_shares[local_index].to_bytes(false);
            let k = k.core.key_info.public_shares[local_index].to_bytes(true);
            let d = d.core.key_info.public_shares[local_index].to_bytes(false);
            ensure!(
                manifest.members[local_index].share_commitment
                    == share_commitment(p.as_bytes(), k.as_bytes(), d.as_bytes()),
                "target manifest does not bind local joined shares"
            );
        }
        Ok(())
    }

    fn context(
        &self,
        operation: &JoinOperation,
        protocol: MpcProtocol,
        participants: Vec<String>,
    ) -> Result<DriverContext> {
        Ok(DriverContext {
            session_id: operation.session_id.as_slice().try_into()?,
            epoch: self.0.authorization.plan.epoch,
            protocol,
            request_hash: operation.request_hash.as_slice().try_into()?,
            local_node_id: self.0.config.mpc.node_id.clone(),
            participants,
            expires_at: operation.expires_at,
            poll_interval: Duration::from_millis(20),
        })
    }

    pub(crate) async fn coordinate(&self) -> Result<()> {
        ensure!(self.is_coordinator(), "not authorized join coordinator");
        self.0.transport.ready().await?;
        let aux = JoinOperation::new(JoinKind::AuxiliaryInfo, vec![])?;
        self.run_targets(aux, true).await?;
        let reshare =
            JoinOperation::new(JoinKind::Reshare, serde_jcs::to_vec(&self.0.authorization)?)?;
        let commitments = self.run_targets(reshare, false).await?;
        let plan = &self.0.authorization.plan;
        let manifest = EpochManifest {
            provider_id: self.0.identity.provider_id().to_vec(),
            epoch: plan.epoch,
            threshold: plan.threshold,
            previous_manifest_hash: plan.previous_manifest_hash.clone(),
            members: plan
                .members
                .iter()
                .map(|member| EpochMember {
                    node_id: member.node_id.clone(),
                    endpoint: member.endpoint.clone(),
                    attestation_pubkey: member.attestation_pubkey.clone(),
                    share_commitment: commitments
                        .get(&member.node_id)
                        .cloned()
                        .unwrap_or_default(),
                })
                .collect(),
        };
        manifest.manifest_hash()?;
        let sign = JoinOperation::new(JoinKind::SignManifest, serde_jcs::to_vec(&manifest)?)?;
        let signatures = self.run_dealers(sign).await?;
        let first = identical(&signatures)?;
        let signed = SignedEpochManifest {
            manifest,
            signature: first.to_vec(),
        };
        signed.verify(&self.0.identity)?;
        let prepared = self
            .run_targets(
                JoinOperation::new(JoinKind::PrepareRpcCertificate, vec![])?,
                false,
            )
            .await?;
        let mut rpc_certificates = BTreeMap::new();
        for (node_id, tbs_der) in prepared {
            let payload = JoinRpcCertificatePayload {
                node_id: node_id.clone(),
                tbs_der: tbs_der.clone(),
            };
            let signatures = self
                .run_dealers(JoinOperation::new(
                    JoinKind::SignRpcCertificate,
                    serde_jcs::to_vec(&payload)?,
                )?)
                .await?;
            let signature = identical(&signatures)?;
            rpc_certificates.insert(
                node_id,
                ExternalCertificate::from_tbs_der(tbs_der)?.finish(signature)?,
            );
        }
        let bundle = JoinFinalBundle {
            signed_manifest: signed,
            rpc_certificates,
        };
        let encoded = serde_jcs::to_vec(&bundle)?;
        let calls = plan
            .members
            .iter()
            .filter(|member| member.node_id != self.0.config.mpc.node_id)
            .map(|member| async {
                self.0
                    .transport
                    .clients
                    .get(&member.node_id)
                    .context("missing join client")?
                    .finalize(MpcGenesisFinalizeRequest {
                        bundle_json: encoded.clone(),
                    })
                    .await?;
                Ok::<_, anyhow::Error>(())
            });
        for result in futures::future::join_all(calls).await {
            result?;
        }
        self.finalize(bundle)
    }

    async fn run_targets(
        &self,
        operation: JoinOperation,
        equal: bool,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let calls = self
            .0
            .authorization
            .plan
            .members
            .iter()
            .filter(|member| member.node_id != self.0.config.mpc.node_id)
            .map(|member| async {
                Ok::<_, anyhow::Error>((
                    member.node_id.clone(),
                    self.0.transport.start(&member.node_id, &operation).await?,
                ))
            });
        let local_operation = operation.clone();
        let (local, remote) = tokio::join!(
            self.execute(
                local_operation,
                self.0.authorization.plan.dealers.first().unwrap()
            ),
            futures::future::join_all(calls)
        );
        let mut out = BTreeMap::from([(self.0.config.mpc.node_id.clone(), local?)]);
        for result in remote {
            let (node, value) = result?;
            out.insert(node, value);
        }
        if equal {
            identical(&out)?;
        }
        Ok(out)
    }
    async fn run_dealers(&self, operation: JoinOperation) -> Result<BTreeMap<String, Vec<u8>>> {
        let calls = self
            .0
            .authorization
            .plan
            .dealers
            .iter()
            .filter(|node| *node != &self.0.config.mpc.node_id)
            .map(|node| async {
                Ok::<_, anyhow::Error>((
                    node.clone(),
                    self.0.transport.start(node, &operation).await?,
                ))
            });
        let local_operation = operation.clone();
        let (local, remote) = tokio::join!(
            self.execute(
                local_operation,
                self.0.authorization.plan.dealers.first().unwrap()
            ),
            futures::future::join_all(calls)
        );
        let mut out = BTreeMap::from([(self.0.config.mpc.node_id.clone(), local?)]);
        for result in remote {
            let (node, value) = result?;
            out.insert(node, value);
        }
        Ok(out)
    }
    fn finalize(&self, bundle: JoinFinalBundle) -> Result<()> {
        use ra_tls::traits::CertExt as _;
        let signed = &bundle.signed_manifest;
        self.validate_target_manifest(&signed.manifest)?;
        signed.verify(&self.0.identity)?;
        let rpc_pem = bundle
            .rpc_certificates
            .get(&self.0.config.mpc.node_id)
            .context("join bundle lacks local RPC certificate")?;
        let (_, rpc_der) = x509_parser::pem::parse_x509_pem(rpc_pem.as_bytes())?;
        let rpc = rpc_der.parse_x509()?;
        let member = signed
            .manifest
            .members
            .iter()
            .find(|member| member.node_id == self.0.config.mpc.node_id)
            .unwrap();
        ensure!(
            rpc.public_key().raw == member.attestation_pubkey
                && rpc.get_special_usage()?.as_deref() == Some("kms:rpc")
                && ra_tls::attestation::from_cert(&rpc)?.is_some(),
            "invalid joined RPC certificate identity"
        );
        let (_, root_der) =
            x509_parser::pem::parse_x509_pem(&fs_err::read(self.0.config.root_ca_cert())?)?;
        rpc.verify_signature(Some(root_der.parse_x509()?.public_key()))
            .context("invalid joined RPC certificate signature")?;
        safe_write::safe_write(self.0.config.rpc_cert(), rpc_pem.as_bytes())?;
        activate_pending_epoch(
            &EpochPaths {
                manifest: &self.0.config.mpc.manifest_file,
                checkpoint: &self.0.config.mpc.checkpoint_file,
                p256_share: &self.0.config.mpc.p256_share_file,
                k256_share: &self.0.config.mpc.k256_share_file,
                derivation_share: &self.0.config.mpc.derivation_share_file,
            },
            &self.0.identity,
            &self.0.active.manifest,
            signed,
            &self.0.identity.cluster_id,
            &self.0.config.mpc.node_id,
        )?;
        if self.0.config.mpc.join_authorization_file.exists() {
            fs_err::remove_file(&self.0.config.mpc.join_authorization_file)?;
        }
        self.0.is_finalized.store(true, Ordering::Release);
        self.0.finalized.notify_waiters();
        Ok(())
    }
}

pub(crate) struct JoinHandler {
    state: JoinState,
    peer_key: Vec<u8>,
}
impl RpcCall<JoinState> for JoinHandler {
    type PrpcService = MpcJoinServer<Self>;
    fn construct(context: CallContext<'_, JoinState>) -> Result<Self> {
        context.attestation.context("join peer must be attested")?;
        Ok(Self {
            state: context.state.clone(),
            peer_key: context.remote_public_key.context("join peer has no key")?,
        })
    }
}
impl MpcJoinRpc for JoinHandler {
    async fn ping(self) -> Result<()> {
        self.state.authenticated_node(&self.peer_key)?;
        Ok(())
    }
    async fn start(self, request: MpcGenesisStartRequest) -> Result<MpcGenesisStartResponse> {
        let initiator = self.state.authenticated_node(&self.peer_key)?.to_string();
        let operation = serde_json::from_slice(&request.operation_json)?;
        Ok(MpcGenesisStartResponse {
            result_json: self.state.execute(operation, &initiator).await?,
        })
    }
    async fn push(self, request: MpcPushRequest) -> Result<()> {
        let sender = self.state.authenticated_node(&self.peer_key)?.to_string();
        self.state
            .0
            .router
            .push(&sender, serde_json::from_slice(&request.envelope_json)?)
    }
    async fn finalize(self, request: MpcGenesisFinalizeRequest) -> Result<()> {
        let initiator = self.state.authenticated_node(&self.peer_key)?;
        ensure!(
            self.state
                .0
                .authorization
                .plan
                .dealers
                .first()
                .is_some_and(|node| node == initiator),
            "only join coordinator may finalize"
        );
        self.state
            .finalize(serde_json::from_slice(&request.bundle_json)?)
    }
}
pub(crate) fn rpc_methods() -> &'static [&'static str] {
    <MpcJoinServer<JoinHandler>>::supported_methods()
}

/// Finish an interrupted activation before startup chooses maintenance mode.
pub(crate) fn recover_if_needed(config: &KmsConfig) -> Result<bool> {
    if config.mpc.join_authorization_file.as_os_str().is_empty()
        || !config.mpc.join_authorization_file.exists()
        || !config.mpc.identity_file.exists()
    {
        return Ok(false);
    }
    let identity: ClusterIdentity =
        serde_json::from_slice(&fs_err::read(&config.mpc.identity_file)?)?;
    let recovered = crate::mpc_lifecycle::recover_pending_activation(
        &EpochPaths {
            manifest: &config.mpc.manifest_file,
            checkpoint: &config.mpc.checkpoint_file,
            p256_share: &config.mpc.p256_share_file,
            k256_share: &config.mpc.k256_share_file,
            derivation_share: &config.mpc.derivation_share_file,
        },
        &identity,
        &identity.cluster_id,
        &config.mpc.node_id,
    )?;
    let authorization: SignedResharePlan =
        serde_json::from_slice(&fs_err::read(&config.mpc.join_authorization_file)?)?;
    if config.mpc.manifest_file.exists() {
        let installed: SignedEpochManifest =
            serde_json::from_slice(&fs_err::read(&config.mpc.manifest_file)?)?;
        if installed.manifest.epoch == authorization.plan.epoch
            && installed.manifest.previous_manifest_hash
                == authorization.plan.previous_manifest_hash
        {
            installed.verify(&identity)?;
            fs_err::remove_file(&config.mpc.join_authorization_file)?;
            return Ok(true);
        }
    }
    Ok(recovered)
}
fn identical(results: &BTreeMap<String, Vec<u8>>) -> Result<&[u8]> {
    let first = results
        .values()
        .next()
        .context("join operation has no results")?;
    ensure!(
        results.values().all(|value| value == first),
        "join participants returned different results"
    );
    Ok(first)
}
fn unix_time() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(value))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let value = String::deserialize(deserializer)?;
        hex::decode(value.strip_prefix("0x").unwrap_or(&value)).map_err(serde::de::Error::custom)
    }
}
