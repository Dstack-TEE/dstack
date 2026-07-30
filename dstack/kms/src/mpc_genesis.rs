// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One-time, attested distributed genesis DKG.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use cggmp21::{
    key_share::AnyKeyShare as _,
    supported_curves::{Secp256k1, Secp256r1},
    ExecutionId, KeyShare,
};
use dstack_kms_rpc::{
    mpc_genesis_client::MpcGenesisClient,
    mpc_genesis_server::{MpcGenesisRpc, MpcGenesisServer},
    MpcGenesisFinalizeRequest, MpcGenesisStartRequest, MpcGenesisStartResponse, MpcPushRequest,
};
use ra_rpc::{
    client::{RaClient, RaClientConfig},
    CallContext, RpcCall,
};
use ra_tls::attestation::AttestationVerifier;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    cggmp_engine::{execution_id, store_share, CggmpCurve, K256KeyShare, P256KeyShare},
    config::KmsConfig,
    mpc_driver::{
        drive_state_machine_blocking, BlockingTransport, DriverContext, EnvelopeTransport,
    },
    mpc_identity::{EpochManifest, EpochMember},
    mpc_session::{MpcEnvelope, MpcProtocol, SessionRouter},
};

const GENESIS_DOMAIN: &[u8] = b"dstack-mpc-genesis-plan-v1";
const GENESIS_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GenesisMember {
    pub node_id: String,
    pub endpoint: String,
    #[serde(with = "hex_bytes")]
    pub attestation_pubkey: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct GenesisPlan {
    pub protocol_version: u16,
    pub cluster_id: String,
    pub threshold: u16,
    pub coordinator: String,
    pub members: Vec<GenesisMember>,
}

impl GenesisPlan {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.protocol_version == 1,
            "unsupported genesis protocol version"
        );
        ensure!(!self.cluster_id.is_empty(), "genesis cluster ID is empty");
        ensure!(
            self.threshold >= 2 && usize::from(self.threshold) <= self.members.len(),
            "invalid genesis threshold"
        );
        ensure!(
            self.members
                .iter()
                .any(|member| member.node_id == self.coordinator),
            "genesis coordinator is not a member"
        );
        let mut previous: Option<&str> = None;
        for member in &self.members {
            ensure!(
                previous.is_none_or(|value| value < member.node_id.as_str()),
                "genesis members must be unique and ordered"
            );
            ensure!(
                member.endpoint.starts_with("https://"),
                "genesis endpoint must use HTTPS"
            );
            ensure!(
                !member.attestation_pubkey.is_empty(),
                "missing genesis attestation key"
            );
            previous = Some(&member.node_id);
        }
        Ok(())
    }

    fn hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let encoded = serde_jcs::to_vec(self).context("failed to encode genesis plan")?;
        let mut hash = Sha256::new();
        hash.update((GENESIS_DOMAIN.len() as u32).to_be_bytes());
        hash.update(GENESIS_DOMAIN);
        hash.update((encoded.len() as u32).to_be_bytes());
        hash.update(encoded);
        Ok(hash.finalize().into())
    }

    fn provisional_manifest(&self) -> Result<EpochManifest> {
        Ok(EpochManifest {
            provider_id: self.hash()?.to_vec(),
            epoch: 1,
            threshold: self.threshold,
            previous_manifest_hash: vec![],
            members: self
                .members
                .iter()
                .map(|member| EpochMember {
                    node_id: member.node_id.clone(),
                    endpoint: member.endpoint.clone(),
                    attestation_pubkey: member.attestation_pubkey.clone(),
                    share_commitment: vec![1],
                })
                .collect(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GenesisKind {
    AuxiliaryInfo,
    DkgP256,
    DkgK256,
    DkgDerivation,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GenesisOperation {
    #[serde(with = "hex_bytes")]
    session_id: Vec<u8>,
    kind: GenesisKind,
    expires_at: u64,
    #[serde(with = "hex_bytes")]
    request_hash: Vec<u8>,
}

#[derive(Serialize)]
struct GenesisOperationPreimage<'a> {
    #[serde(with = "hex_bytes")]
    session_id: &'a [u8],
    kind: GenesisKind,
    expires_at: u64,
}

impl GenesisOperation {
    fn new(kind: GenesisKind) -> Result<Self> {
        let mut session = [0u8; 32];
        OsRng.fill_bytes(&mut session);
        let mut operation = Self {
            session_id: session.to_vec(),
            kind,
            expires_at: unix_time()?
                .checked_add(GENESIS_TTL.as_secs())
                .context("expiry overflow")?,
            request_hash: vec![],
        };
        operation.request_hash = operation.hash()?.to_vec();
        Ok(operation)
    }

    fn hash(&self) -> Result<[u8; 32]> {
        let encoded = serde_jcs::to_vec(&GenesisOperationPreimage {
            session_id: &self.session_id,
            kind: self.kind,
            expires_at: self.expires_at,
        })?;
        Ok(Sha256::digest(encoded).into())
    }

    fn validate(&self) -> Result<()> {
        ensure!(self.session_id.len() == 32, "invalid genesis session ID");
        ensure!(
            self.request_hash == self.hash()?,
            "genesis request hash mismatch"
        );
        let now = unix_time()?;
        ensure!(self.expires_at >= now, "genesis operation expired");
        ensure!(
            self.expires_at - now <= GENESIS_TTL.as_secs(),
            "genesis operation TTL too large"
        );
        Ok(())
    }
}

#[derive(Default)]
struct GenesisArtifacts {
    aux: Option<cggmp21::key_share::AuxInfo>,
    p256: Option<P256KeyShare>,
    k256: Option<K256KeyShare>,
    derivation: Option<P256KeyShare>,
}

struct GenesisTransport {
    local_node_id: String,
    local_router: Arc<SessionRouter>,
    clients: BTreeMap<String, MpcGenesisClient<RaClient>>,
}

impl GenesisTransport {
    fn new(
        plan: &GenesisPlan,
        local_node_id: &str,
        router: Arc<SessionRouter>,
        cert: String,
        key: String,
        ca: String,
        verifier: Arc<AttestationVerifier>,
    ) -> Result<Self> {
        let mut clients = BTreeMap::new();
        for member in &plan.members {
            if member.node_id == local_node_id {
                continue;
            }
            let expected_key = member.attestation_pubkey.clone();
            let node_id = member.node_id.clone();
            let client = RaClientConfig::builder()
                .remote_uri(member.endpoint.clone())
                .tls_client_cert(cert.clone())
                .tls_client_key(key.clone())
                .tls_ca_cert(ca.clone())
                .tls_built_in_root_certs(false)
                .attestation_verifier(verifier.clone())
                .cert_validator(Box::new(move |info| {
                    let info = info.context("genesis peer has no certificate")?;
                    ensure!(info.attestation.is_some(), "genesis peer is not attested");
                    let (_, certificate) = x509_parser::parse_x509_certificate(&info.cert_der)
                        .context("invalid genesis peer certificate")?;
                    ensure!(
                        certificate.public_key().raw == expected_key,
                        "wrong genesis peer key for {node_id}"
                    );
                    Ok(())
                }))
                .build()
                .into_client()
                .with_context(|| {
                    format!("failed to build genesis client for {}", member.node_id)
                })?;
            clients.insert(member.node_id.clone(), MpcGenesisClient::new(client));
        }
        Ok(Self {
            local_node_id: local_node_id.into(),
            local_router: router,
            clients,
        })
    }

    async fn start(&self, node: &str, operation: &GenesisOperation) -> Result<Vec<u8>> {
        Ok(self
            .clients
            .get(node)
            .context("missing genesis client")?
            .start(MpcGenesisStartRequest {
                operation_json: serde_json::to_vec(operation)?,
            })
            .await?
            .result_json)
    }

    async fn wait_until_ready(&self, timeout: Duration) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let probes = self.clients.iter().map(|(node, client)| async move {
                client
                    .ping()
                    .await
                    .with_context(|| format!("genesis peer {node} is unavailable"))
            });
            let results = futures::future::join_all(probes).await;
            if results.iter().all(Result::is_ok) {
                return Ok(());
            }
            ensure!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for genesis peers: {}",
                results
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| error.to_string())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
}

#[async_trait]
impl EnvelopeTransport for GenesisTransport {
    async fn send(&self, envelope: MpcEnvelope) -> Result<()> {
        ensure!(
            envelope.sender == self.local_node_id,
            "wrong genesis sender"
        );
        self.clients
            .get(&envelope.recipient)
            .context("missing genesis recipient")?
            .push(MpcPushRequest {
                envelope_json: serde_json::to_vec(&envelope)?,
            })
            .await?;
        Ok(())
    }

    async fn receive(&self, session_id: &[u8; 32]) -> Result<Vec<MpcEnvelope>> {
        self.local_router.drain(&self.local_node_id, session_id)
    }
}

struct GenesisInner {
    config: KmsConfig,
    plan: GenesisPlan,
    router: Arc<SessionRouter>,
    transport: Arc<GenesisTransport>,
    artifacts: Mutex<GenesisArtifacts>,
    verifier: Arc<AttestationVerifier>,
}

#[derive(Clone)]
pub(crate) struct GenesisState(Arc<GenesisInner>);

impl GenesisState {
    pub(crate) fn new(config: KmsConfig) -> Result<Self> {
        ensure!(
            !config.mpc.genesis_plan_file.as_os_str().is_empty(),
            "missing genesis plan file"
        );
        let plan: GenesisPlan =
            serde_json::from_slice(&fs_err::read(&config.mpc.genesis_plan_file)?)?;
        plan.validate()?;
        ensure!(
            plan.cluster_id == config.mpc.cluster_id,
            "genesis cluster ID mismatch"
        );
        ensure!(
            plan.members
                .iter()
                .any(|member| member.node_id == config.mpc.node_id),
            "local node absent from genesis plan"
        );
        let manifest = plan.provisional_manifest()?;
        let router = Arc::new(SessionRouter::new(manifest, 32, GENESIS_TTL)?);
        let verifier = Arc::new(AttestationVerifier::load(&config.attestation)?);
        let ca = fs_err::read_to_string(&config.mpc.genesis_tls_ca_cert)
            .context("failed to read genesis TLS CA")?;
        let transport = Arc::new(GenesisTransport::new(
            &plan,
            &config.mpc.node_id,
            router.clone(),
            fs_err::read_to_string(config.rpc_cert())?,
            fs_err::read_to_string(config.rpc_key())?,
            ca,
            verifier.clone(),
        )?);
        Ok(Self(Arc::new(GenesisInner {
            config,
            plan,
            router,
            transport,
            artifacts: Mutex::new(GenesisArtifacts::default()),
            verifier,
        })))
    }

    pub(crate) fn verifier(&self) -> Arc<AttestationVerifier> {
        self.0.verifier.clone()
    }

    pub(crate) fn is_coordinator(&self) -> bool {
        self.0.config.mpc.node_id == self.0.plan.coordinator
    }

    fn authenticated_node(&self, key: &[u8]) -> Result<&str> {
        self.0
            .plan
            .members
            .iter()
            .find(|member| member.attestation_pubkey == key)
            .map(|member| member.node_id.as_str())
            .context("attested peer is not in genesis plan")
    }

    async fn execute(&self, operation: GenesisOperation, initiator: &str) -> Result<Vec<u8>> {
        operation.validate()?;
        ensure!(
            initiator == self.0.plan.coordinator,
            "only genesis coordinator may start DKG"
        );
        let local_index: u16 = self
            .0
            .plan
            .members
            .iter()
            .position(|member| member.node_id == self.0.config.mpc.node_id)
            .context("local genesis index missing")?
            .try_into()?;
        let participants = self
            .0
            .plan
            .members
            .iter()
            .map(|member| member.node_id.clone())
            .collect::<Vec<_>>();
        let protocol = match operation.kind {
            GenesisKind::AuxiliaryInfo => MpcProtocol::AuxiliaryInfo,
            GenesisKind::DkgP256 => MpcProtocol::DkgP256,
            GenesisKind::DkgK256 => MpcProtocol::DkgK256,
            GenesisKind::DkgDerivation => MpcProtocol::DkgDerivation,
        };
        let context = DriverContext {
            session_id: operation.session_id.as_slice().try_into()?,
            epoch: 1,
            protocol,
            request_hash: operation.request_hash.as_slice().try_into()?,
            local_node_id: self.0.config.mpc.node_id.clone(),
            participants,
            expires_at: operation.expires_at,
            poll_interval: Duration::from_millis(20),
        };
        let transport = self.0.transport.clone();
        let runtime = tokio::runtime::Handle::current();
        let n: u16 = self.0.plan.members.len().try_into()?;
        let threshold = self.0.plan.threshold;
        let cluster = self.0.plan.cluster_id.clone();
        let nonce: [u8; 32] = operation.session_id.as_slice().try_into()?;
        match operation.kind {
            GenesisKind::AuxiliaryInfo => {
                let aux = tokio::task::spawn_blocking(move || {
                    let mut rng = OsRng;
                    let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
                    let eid = execution_id(&cluster, 1, CggmpCurve::K256, &nonce);
                    let state =
                        cggmp21::aux_info_gen(ExecutionId::new(&eid), local_index, n, primes)
                            .into_state_machine(&mut rng);
                    drive_state_machine_blocking(
                        state,
                        &BlockingTransport::new(transport, runtime),
                        context,
                    )?
                    .map_err(|error| anyhow::anyhow!("genesis auxiliary protocol failed: {error}"))
                })
                .await
                .context("auxiliary worker panicked")??;
                self.0.artifacts.lock().expect("genesis mutex poisoned").aux = Some(aux);
                Ok(vec![])
            }
            GenesisKind::DkgP256 | GenesisKind::DkgDerivation => {
                let aux = self
                    .0
                    .artifacts
                    .lock()
                    .expect("genesis mutex poisoned")
                    .aux
                    .clone()
                    .context("auxiliary info has not completed")?;
                let curve_label = if operation.kind == GenesisKind::DkgP256 {
                    CggmpCurve::P256
                } else {
                    CggmpCurve::K256
                };
                let share = tokio::task::spawn_blocking(move || {
                    let mut rng = OsRng;
                    let eid = execution_id(&cluster, 1, curve_label, &nonce);
                    let state =
                        cggmp21::keygen::<Secp256r1>(ExecutionId::new(&eid), local_index, n)
                            .set_threshold(threshold)
                            .into_state_machine(&mut rng);
                    let core = drive_state_machine_blocking(
                        state,
                        &BlockingTransport::new(transport, runtime),
                        context,
                    )??;
                    KeyShare::from_parts((core, aux)).map_err(|error| {
                        anyhow::anyhow!("failed to complete P-256 genesis share: {error}")
                    })
                })
                .await
                .context("P-256 DKG worker panicked")??;
                let public = share
                    .shared_public_key()
                    .to_bytes(false)
                    .as_bytes()
                    .to_vec();
                let mut artifacts = self.0.artifacts.lock().expect("genesis mutex poisoned");
                if operation.kind == GenesisKind::DkgP256 {
                    artifacts.p256 = Some(share);
                } else {
                    artifacts.derivation = Some(share);
                }
                Ok(public)
            }
            GenesisKind::DkgK256 => {
                let aux = self
                    .0
                    .artifacts
                    .lock()
                    .expect("genesis mutex poisoned")
                    .aux
                    .clone()
                    .context("auxiliary info has not completed")?;
                let share = tokio::task::spawn_blocking(move || {
                    let mut rng = OsRng;
                    let eid = execution_id(&cluster, 1, CggmpCurve::K256, &nonce);
                    let state =
                        cggmp21::keygen::<Secp256k1>(ExecutionId::new(&eid), local_index, n)
                            .set_threshold(threshold)
                            .into_state_machine(&mut rng);
                    let core = drive_state_machine_blocking(
                        state,
                        &BlockingTransport::new(transport, runtime),
                        context,
                    )??;
                    KeyShare::from_parts((core, aux)).map_err(|error| {
                        anyhow::anyhow!("failed to complete K-256 genesis share: {error}")
                    })
                })
                .await
                .context("K-256 DKG worker panicked")??;
                let public = share.shared_public_key().to_bytes(true).as_bytes().to_vec();
                self.0
                    .artifacts
                    .lock()
                    .expect("genesis mutex poisoned")
                    .k256 = Some(share);
                Ok(public)
            }
        }
    }

    pub(crate) async fn coordinate_dkg(&self) -> Result<()> {
        ensure!(
            self.0.config.mpc.node_id == self.0.plan.coordinator,
            "not genesis coordinator"
        );
        self.0.transport.wait_until_ready(GENESIS_TTL).await?;
        for kind in [
            GenesisKind::AuxiliaryInfo,
            GenesisKind::DkgP256,
            GenesisKind::DkgK256,
            GenesisKind::DkgDerivation,
        ] {
            let operation = GenesisOperation::new(kind)?;
            let remote = self
                .0
                .plan
                .members
                .iter()
                .filter(|member| member.node_id != self.0.config.mpc.node_id)
                .map(|member| self.0.transport.start(&member.node_id, &operation));
            let (local, remote) = tokio::join!(
                self.execute(operation.clone(), &self.0.plan.coordinator),
                futures::future::join_all(remote)
            );
            let local = local?;
            for result in remote {
                ensure!(
                    result? == local,
                    "genesis group public keys differ across nodes"
                );
            }
        }
        self.persist_shares()
    }

    fn persist_shares(&self) -> Result<()> {
        let artifacts = self.0.artifacts.lock().expect("genesis mutex poisoned");
        store_share(
            &self.0.config.mpc.p256_share_file,
            &self.0.plan.cluster_id,
            1,
            &self.0.config.mpc.node_id,
            CggmpCurve::P256,
            artifacts
                .p256
                .as_ref()
                .context("missing P-256 genesis share")?,
        )?;
        store_share(
            &self.0.config.mpc.k256_share_file,
            &self.0.plan.cluster_id,
            1,
            &self.0.config.mpc.node_id,
            CggmpCurve::K256,
            artifacts
                .k256
                .as_ref()
                .context("missing K-256 genesis share")?,
        )?;
        store_share(
            &self.0.config.mpc.derivation_share_file,
            &self.0.plan.cluster_id,
            1,
            &self.0.config.mpc.node_id,
            CggmpCurve::P256,
            artifacts
                .derivation
                .as_ref()
                .context("missing derivation genesis share")?,
        )?;
        Ok(())
    }
}

pub(crate) struct GenesisHandler {
    state: GenesisState,
    peer_key: Vec<u8>,
}

impl RpcCall<GenesisState> for GenesisHandler {
    type PrpcService = MpcGenesisServer<Self>;
    fn construct(context: CallContext<'_, GenesisState>) -> Result<Self> {
        context
            .attestation
            .context("genesis peer must be attested")?;
        Ok(Self {
            state: context.state.clone(),
            peer_key: context
                .remote_public_key
                .context("genesis peer has no key")?,
        })
    }
}

impl MpcGenesisRpc for GenesisHandler {
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
        let envelope = serde_json::from_slice(&request.envelope_json)?;
        self.state.0.router.push(&sender, envelope)
    }
    async fn finalize(self, _request: MpcGenesisFinalizeRequest) -> Result<()> {
        bail!("genesis finalization has not been authorized")
    }
}

pub(crate) fn rpc_methods() -> &'static [&'static str] {
    <MpcGenesisServer<GenesisHandler>>::supported_methods()
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
