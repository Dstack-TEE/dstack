// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! One-time, attested distributed genesis DKG.

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
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
    key_share::AnyKeyShare as _,
    supported_curves::{Secp256k1, Secp256r1},
    DataToSign, ExecutionId, KeyShare,
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
use ra_tls::{
    cert::{
        prepare_external_certificate, prepare_external_self_signed, CertRequest,
        ExternalCertificate,
    },
    rcgen::SubjectPublicKeyInfo,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    cggmp_engine::{
        execution_id, load_share, share_commitment, store_share, validate_share_topology,
        CggmpCurve, K256KeyShare, P256KeyShare,
    },
    config::KmsConfig,
    mpc_driver::{
        drive_state_machine_blocking, BlockingTransport, DriverContext, EnvelopeTransport,
    },
    mpc_identity::{ClusterIdentity, EpochManifest, EpochMember, SignedEpochManifest},
    mpc_lifecycle::validate_and_checkpoint,
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
    Commitments,
    SignRoot,
    SignManifest,
    PrepareRpcCertificate,
    SignRpcCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GenesisOperation {
    #[serde(with = "hex_bytes")]
    session_id: Vec<u8>,
    kind: GenesisKind,
    #[serde(with = "hex_bytes")]
    payload: Vec<u8>,
    expires_at: u64,
    #[serde(with = "hex_bytes")]
    request_hash: Vec<u8>,
}

#[derive(Serialize)]
struct GenesisOperationPreimage<'a> {
    #[serde(with = "hex_bytes")]
    session_id: &'a [u8],
    kind: GenesisKind,
    #[serde(with = "hex_bytes")]
    payload: &'a [u8],
    expires_at: u64,
}

impl GenesisOperation {
    fn new(kind: GenesisKind, payload: Vec<u8>) -> Result<Self> {
        let mut session = [0u8; 32];
        OsRng.fill_bytes(&mut session);
        let mut operation = Self {
            session_id: session.to_vec(),
            kind,
            payload,
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
            payload: &self.payload,
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

enum GenesisSigningShare {
    P256(P256KeyShare),
    K256(K256KeyShare),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GenesisBundle {
    identity: ClusterIdentity,
    root_ca_pem: String,
    signed_manifest: SignedEpochManifest,
    rpc_certificates: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RpcCertificateSigningPayload {
    node_id: String,
    root_ca_pem: String,
    #[serde(with = "hex_bytes")]
    tbs_der: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct GenesisJournal {
    version: u16,
    bundle: GenesisBundle,
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
    finalized: AtomicBool,
    finalized_notify: tokio::sync::Notify,
    operations: Mutex<BTreeMap<Vec<u8>, Arc<GenesisOperationRecord>>>,
}

struct GenesisOperationRecord {
    operation: GenesisOperation,
    result: Mutex<Option<std::result::Result<Vec<u8>, String>>>,
    finished: tokio::sync::Notify,
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
            finalized: AtomicBool::new(false),
            finalized_notify: tokio::sync::Notify::new(),
            operations: Mutex::new(BTreeMap::new()),
        })))
    }

    pub(crate) fn verifier(&self) -> Arc<AttestationVerifier> {
        self.0.verifier.clone()
    }

    pub(crate) fn is_coordinator(&self) -> bool {
        self.0.config.mpc.node_id == self.0.plan.coordinator
    }

    pub(crate) async fn wait_finalized(&self) {
        loop {
            let notified = self.0.finalized_notify.notified();
            if self.0.finalized.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
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

    fn identity_from_artifacts(&self) -> Result<ClusterIdentity> {
        let artifacts = self.0.artifacts.lock().expect("genesis mutex poisoned");
        ClusterIdentity::new(
            self.0.plan.protocol_version,
            self.0.plan.cluster_id.clone(),
            artifacts
                .p256
                .as_ref()
                .context("missing P-256 genesis share")?
                .shared_public_key()
                .to_bytes(false)
                .as_bytes()
                .to_vec(),
            artifacts
                .k256
                .as_ref()
                .context("missing K-256 genesis share")?
                .shared_public_key()
                .to_bytes(true)
                .as_bytes()
                .to_vec(),
            artifacts
                .derivation
                .as_ref()
                .context("missing derivation genesis share")?
                .shared_public_key()
                .to_bytes(false)
                .as_bytes()
                .to_vec(),
        )
    }

    fn validate_root_tbs(&self, tbs_der: &[u8]) -> Result<()> {
        use x509_parser::{certificate::TbsCertificate, prelude::FromDer as _};
        let (remaining, tbs) = TbsCertificate::from_der(tbs_der)
            .map_err(|error| anyhow::anyhow!("invalid genesis root TBS: {error}"))?;
        ensure!(remaining.is_empty(), "genesis root TBS has trailing bytes");
        ensure!(
            tbs.subject() == tbs.issuer(),
            "genesis root is not self-issued"
        );
        ensure!(tbs.is_ca(), "genesis root is not a CA");
        ensure!(
            tbs.signature.algorithm.to_id_string() == "1.2.840.10045.4.3.2",
            "genesis root does not use ECDSA/SHA-256"
        );
        ensure!(
            tbs.public_key().subject_public_key.data.as_ref()
                == self.identity_from_artifacts()?.p256_group_pubkey,
            "genesis root public key does not match DKG"
        );
        Ok(())
    }

    fn validate_genesis_manifest(&self, manifest: &EpochManifest) -> Result<()> {
        let identity = self.identity_from_artifacts()?;
        ensure!(
            manifest.provider_id == identity.provider_id(),
            "wrong genesis provider ID"
        );
        ensure!(
            manifest.epoch == 1 && manifest.previous_manifest_hash.is_empty(),
            "invalid genesis epoch chain"
        );
        ensure!(
            manifest.threshold == self.0.plan.threshold,
            "wrong genesis threshold"
        );
        ensure!(
            manifest.members.len() == self.0.plan.members.len(),
            "wrong genesis member count"
        );
        for (member, planned) in manifest.members.iter().zip(&self.0.plan.members) {
            ensure!(
                member.node_id == planned.node_id
                    && member.endpoint == planned.endpoint
                    && member.attestation_pubkey == planned.attestation_pubkey,
                "genesis member differs from operator plan"
            );
        }
        let local_index = self
            .0
            .plan
            .members
            .iter()
            .position(|member| member.node_id == self.0.config.mpc.node_id)
            .context("local genesis member missing")?;
        let artifacts = self.0.artifacts.lock().expect("genesis mutex poisoned");
        let expected = local_share_commitment(
            artifacts
                .p256
                .as_ref()
                .context("missing P-256 genesis share")?,
            artifacts
                .k256
                .as_ref()
                .context("missing K-256 genesis share")?,
            artifacts
                .derivation
                .as_ref()
                .context("missing derivation genesis share")?,
            local_index,
        )?;
        ensure!(
            manifest.members[local_index].share_commitment == expected,
            "wrong local genesis share commitment"
        );
        Ok(())
    }

    fn prepare_rpc_certificate(&self, root_ca_pem: &str) -> Result<Vec<u8>> {
        let key =
            ra_tls::rcgen::KeyPair::from_pem(&fs_err::read_to_string(self.0.config.rpc_key())?)
                .context("invalid genesis RPC key")?;
        let (_, current_pem) =
            x509_parser::pem::parse_x509_pem(&fs_err::read(self.0.config.rpc_cert())?)?;
        let current = current_pem.parse_x509()?;
        let attestation = ra_tls::attestation::from_cert(&current)?
            .context("genesis RPC certificate lacks attestation")?;
        let domain = fs_err::read_to_string(self.0.config.rpc_domain())?;
        let names = [domain.clone()];
        let external = prepare_external_certificate(
            CertRequest::builder()
                .key(&key)
                .subject(&domain)
                .alt_names(&names)
                .special_usage("kms:rpc")
                .attestation(&attestation)
                .usage_server_auth(true)
                .usage_client_auth(true)
                .build(),
            root_ca_pem,
        )?;
        Ok(external.tbs_der().to_vec())
    }

    async fn validate_rpc_certificate_tbs(
        &self,
        payload: &RpcCertificateSigningPayload,
    ) -> Result<()> {
        use ra_tls::oids::{PHALA_RATLS_ATTESTATION, PHALA_RATLS_CERT_USAGE};
        use x509_parser::{
            certificate::TbsCertificate, der_parser::oid::Oid, prelude::FromDer as _,
        };
        let member = self
            .0
            .plan
            .members
            .iter()
            .find(|member| member.node_id == payload.node_id)
            .context("RPC certificate target is not in genesis plan")?;
        let (_, root_pem) = x509_parser::pem::parse_x509_pem(payload.root_ca_pem.as_bytes())?;
        let root = root_pem.parse_x509()?;
        root.verify_signature(None)
            .context("invalid threshold root certificate")?;
        ensure!(
            root.public_key().subject_public_key.data.as_ref()
                == self.identity_from_artifacts()?.p256_group_pubkey,
            "RPC certificate root differs from DKG"
        );
        let (remaining, tbs) = TbsCertificate::from_der(&payload.tbs_der)
            .map_err(|error| anyhow::anyhow!("invalid RPC certificate TBS: {error}"))?;
        ensure!(
            remaining.is_empty(),
            "RPC certificate TBS has trailing bytes"
        );
        ensure!(
            tbs.issuer() == root.subject(),
            "RPC certificate has wrong issuer"
        );
        ensure!(
            tbs.public_key().raw == member.attestation_pubkey,
            "RPC certificate key differs from quote-bound genesis key"
        );
        ensure!(
            tbs.signature.algorithm.to_id_string() == "1.2.840.10045.4.3.2",
            "RPC certificate does not use ECDSA/SHA-256"
        );
        let usage_oid = Oid::from(PHALA_RATLS_CERT_USAGE)
            .map_err(|error| anyhow::anyhow!("invalid usage OID: {error:?}"))?;
        let usage = tbs
            .get_extension_unique(&usage_oid)?
            .context("RPC certificate lacks usage")?;
        ensure!(
            yasna::parse_der(usage.value, |reader| reader.read_bytes())? == b"kms:rpc",
            "wrong RPC certificate usage"
        );
        let attestation_oid = Oid::from(PHALA_RATLS_ATTESTATION)
            .map_err(|error| anyhow::anyhow!("invalid attestation OID: {error:?}"))?;
        let extension = tbs
            .get_extension_unique(&attestation_oid)?
            .context("RPC certificate lacks attestation")?;
        let encoded = yasna::parse_der(extension.value, |reader| reader.read_bytes())?;
        let attestation = ra_tls::attestation::VersionedAttestation::from_bytes(&encoded)
            .context("invalid RPC certificate attestation")?;
        let public_key = tbs.public_key().raw.to_vec();
        attestation
            .into_v1()
            .verify_with_ra_pubkey(&public_key, &self.0.verifier)
            .await
            .context("RPC certificate attestation is not bound to its key")?;
        Ok(())
    }

    async fn execute(&self, operation: GenesisOperation, initiator: &str) -> Result<Vec<u8>> {
        operation.validate()?;
        ensure!(
            initiator == self.0.plan.coordinator,
            "only genesis coordinator may start DKG"
        );
        let (record, owner) = {
            let mut operations = self.0.operations.lock().expect("genesis mutex poisoned");
            if let Some(record) = operations.get(&operation.request_hash) {
                ensure!(
                    record.operation == operation,
                    "conflicting genesis operation hash"
                );
                (record.clone(), false)
            } else {
                ensure!(operations.len() < 256, "too many genesis operations");
                let record = Arc::new(GenesisOperationRecord {
                    operation: operation.clone(),
                    result: Mutex::new(None),
                    finished: tokio::sync::Notify::new(),
                });
                operations.insert(operation.request_hash.clone(), record.clone());
                (record, true)
            }
        };
        if owner {
            let result = self.execute_owned(operation).await;
            *record.result.lock().expect("genesis mutex poisoned") = Some(
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
                if let Some(result) = record
                    .result
                    .lock()
                    .expect("genesis mutex poisoned")
                    .clone()
                {
                    return result.map_err(anyhow::Error::msg);
                }
                notified.await;
            }
        }
    }

    async fn execute_owned(&self, operation: GenesisOperation) -> Result<Vec<u8>> {
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
            GenesisKind::Commitments => MpcProtocol::SignK256,
            GenesisKind::SignRoot => MpcProtocol::SignP256,
            GenesisKind::SignManifest => MpcProtocol::SignK256,
            GenesisKind::PrepareRpcCertificate | GenesisKind::SignRpcCertificate => {
                MpcProtocol::SignP256
            }
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
            GenesisKind::Commitments => {
                let artifacts = self.0.artifacts.lock().expect("genesis mutex poisoned");
                let p256 = artifacts
                    .p256
                    .as_ref()
                    .context("missing P-256 genesis share")?;
                let k256 = artifacts
                    .k256
                    .as_ref()
                    .context("missing K-256 genesis share")?;
                let derivation = artifacts
                    .derivation
                    .as_ref()
                    .context("missing derivation genesis share")?;
                Ok(
                    local_share_commitment(p256, k256, derivation, usize::from(local_index))?
                        .to_vec(),
                )
            }
            GenesisKind::PrepareRpcCertificate => {
                let root_ca_pem = std::str::from_utf8(&operation.payload)
                    .context("invalid genesis root PEM payload")?;
                self.prepare_rpc_certificate(root_ca_pem)
            }
            GenesisKind::SignRoot | GenesisKind::SignManifest | GenesisKind::SignRpcCertificate => {
                ensure!(
                    operation.payload.len() <= 64 * 1024,
                    "genesis signing payload is too large"
                );
                let digest: [u8; 32] = match operation.kind {
                    GenesisKind::SignRoot => {
                        self.validate_root_tbs(&operation.payload)?;
                        Sha256::digest(&operation.payload).into()
                    }
                    GenesisKind::SignManifest => {
                        let manifest: EpochManifest = serde_json::from_slice(&operation.payload)
                            .context("invalid genesis manifest")?;
                        self.validate_genesis_manifest(&manifest)?;
                        manifest.manifest_hash()?
                    }
                    GenesisKind::SignRpcCertificate => {
                        let payload: RpcCertificateSigningPayload =
                            serde_json::from_slice(&operation.payload)
                                .context("invalid RPC certificate signing payload")?;
                        self.validate_rpc_certificate_tbs(&payload).await?;
                        Sha256::digest(&payload.tbs_der).into()
                    }
                    _ => unreachable!(),
                };
                let keygen_indexes = (0..n).collect::<Vec<_>>();
                let local_protocol_index = local_index;
                let (curve, share) = {
                    let artifacts = self.0.artifacts.lock().expect("genesis mutex poisoned");
                    match operation.kind {
                        GenesisKind::SignRoot | GenesisKind::SignRpcCertificate => (
                            CggmpCurve::P256,
                            GenesisSigningShare::P256(
                                artifacts
                                    .p256
                                    .clone()
                                    .context("missing P-256 genesis share")?,
                            ),
                        ),
                        GenesisKind::SignManifest => (
                            CggmpCurve::K256,
                            GenesisSigningShare::K256(
                                artifacts
                                    .k256
                                    .clone()
                                    .context("missing K-256 genesis share")?,
                            ),
                        ),
                        _ => unreachable!(),
                    }
                };
                tokio::task::spawn_blocking(move || {
                    let mut rng = OsRng;
                    let eid = execution_id(&cluster, 1, curve, &nonce);
                    match share {
                        GenesisSigningShare::P256(share) => {
                            let data = DataToSign::from_scalar(
                                Scalar::<Secp256r1>::from_be_bytes_mod_order(digest),
                            );
                            let state = cggmp21::signing(
                                ExecutionId::new(&eid),
                                local_protocol_index,
                                &keygen_indexes,
                                &share,
                            )
                            .sign_sync(&mut rng, data);
                            let signature = drive_state_machine_blocking(
                                state,
                                &BlockingTransport::new(transport, runtime),
                                context,
                            )??;
                            let mut encoded =
                                vec![0; cggmp21::Signature::<Secp256r1>::serialized_len()];
                            signature.write_to_slice(&mut encoded);
                            Ok(encoded)
                        }
                        GenesisSigningShare::K256(share) => {
                            let data = DataToSign::from_scalar(
                                Scalar::<Secp256k1>::from_be_bytes_mod_order(digest),
                            );
                            let state = cggmp21::signing(
                                ExecutionId::new(&eid),
                                local_protocol_index,
                                &keygen_indexes,
                                &share,
                            )
                            .sign_sync(&mut rng, data);
                            let signature = drive_state_machine_blocking(
                                state,
                                &BlockingTransport::new(transport, runtime),
                                context,
                            )??;
                            let mut encoded =
                                vec![0; cggmp21::Signature::<Secp256k1>::serialized_len()];
                            signature.write_to_slice(&mut encoded);
                            Ok(encoded)
                        }
                    }
                })
                .await
                .context("genesis signing worker panicked")?
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
            let results = self
                .coordinate_operation(GenesisOperation::new(kind, vec![])?)
                .await?;
            let first = results
                .values()
                .next()
                .context("genesis has no participants")?;
            ensure!(
                results.values().all(|value| value == first),
                "genesis group public keys differ across nodes"
            );
        }
        let commitments = self
            .coordinate_operation(GenesisOperation::new(GenesisKind::Commitments, vec![])?)
            .await?;
        let identity = self.identity_from_artifacts()?;
        let manifest = EpochManifest {
            provider_id: identity.provider_id().to_vec(),
            epoch: 1,
            threshold: self.0.plan.threshold,
            previous_manifest_hash: vec![],
            members: self
                .0
                .plan
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

        let public_key = p256_subject_public_key(&identity.p256_group_pubkey)?;
        let external_root = prepare_external_self_signed(
            CertRequest::builder()
                .key(&public_key)
                .org_name("Dstack")
                .subject("Dstack Threshold Root CA")
                .ca_level(1)
                .build(),
        )?;
        let root_signatures = self
            .coordinate_operation(GenesisOperation::new(
                GenesisKind::SignRoot,
                external_root.tbs_der().to_vec(),
            )?)
            .await?;
        let root_signature = identical_result(&root_signatures, "root signatures")?;
        let root_ca_pem = external_root.finish(root_signature)?;

        let prepared_rpc_certificates = self
            .coordinate_operation(GenesisOperation::new(
                GenesisKind::PrepareRpcCertificate,
                root_ca_pem.as_bytes().to_vec(),
            )?)
            .await?;
        let mut rpc_certificates = BTreeMap::new();
        for (node_id, tbs_der) in prepared_rpc_certificates {
            let payload = RpcCertificateSigningPayload {
                node_id: node_id.clone(),
                root_ca_pem: root_ca_pem.clone(),
                tbs_der: tbs_der.clone(),
            };
            let signatures = self
                .coordinate_operation(GenesisOperation::new(
                    GenesisKind::SignRpcCertificate,
                    serde_jcs::to_vec(&payload)?,
                )?)
                .await?;
            let signature = identical_result(&signatures, "RPC certificate signatures")?;
            let certificate = ExternalCertificate::from_tbs_der(tbs_der)?.finish(signature)?;
            rpc_certificates.insert(node_id, certificate);
        }

        let manifest_json = serde_jcs::to_vec(&manifest)?;
        let manifest_signatures = self
            .coordinate_operation(GenesisOperation::new(
                GenesisKind::SignManifest,
                manifest_json,
            )?)
            .await?;
        let signature = identical_result(&manifest_signatures, "manifest signatures")?.to_vec();
        let bundle = GenesisBundle {
            identity,
            root_ca_pem,
            signed_manifest: SignedEpochManifest {
                manifest,
                signature,
            },
            rpc_certificates,
        };
        let bundle_json = serde_jcs::to_vec(&bundle)?;
        let finalizations = self
            .0
            .plan
            .members
            .iter()
            .filter(|member| member.node_id != self.0.config.mpc.node_id)
            .map(|member| async {
                self.0
                    .transport
                    .clients
                    .get(&member.node_id)
                    .context("missing genesis client")?
                    .finalize(MpcGenesisFinalizeRequest {
                        bundle_json: bundle_json.clone(),
                    })
                    .await
                    .with_context(|| format!("failed to finalize genesis peer {}", member.node_id))
            });
        for result in futures::future::join_all(finalizations).await {
            result?;
        }
        self.finalize_bundle(bundle)
    }

    async fn coordinate_operation(
        &self,
        operation: GenesisOperation,
    ) -> Result<BTreeMap<String, Vec<u8>>> {
        let remote = self
            .0
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
            self.execute(local_operation, &self.0.plan.coordinator),
            futures::future::join_all(remote),
        );
        let mut results = BTreeMap::new();
        results.insert(self.0.config.mpc.node_id.clone(), local?);
        for result in remote {
            let (node, value) = result?;
            results.insert(node, value);
        }
        Ok(results)
    }

    fn finalize_bundle(&self, bundle: GenesisBundle) -> Result<()> {
        ensure!(
            bundle.identity == self.identity_from_artifacts()?,
            "genesis identity differs from local DKG"
        );
        bundle.signed_manifest.verify(&bundle.identity)?;
        self.validate_genesis_manifest(&bundle.signed_manifest.manifest)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(bundle.root_ca_pem.as_bytes())
            .context("invalid genesis root PEM")?;
        let certificate = pem
            .parse_x509()
            .context("invalid genesis root certificate")?;
        ensure!(
            certificate.subject() == certificate.issuer(),
            "genesis root is not self-signed"
        );
        ensure!(
            certificate.public_key().subject_public_key.data.as_ref()
                == bundle.identity.p256_group_pubkey,
            "wrong genesis root public key"
        );
        certificate
            .verify_signature(None)
            .context("invalid genesis root threshold signature")?;
        let journal_path = genesis_journal_path(&self.0.config);
        safe_write::safe_write(
            &journal_path,
            &serde_jcs::to_vec(&GenesisJournal {
                version: 1,
                bundle: bundle.clone(),
            })?,
        )?;
        fs_err::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o600))?;
        self.persist_shares()?;
        persist_bundle_files(&self.0.config, &bundle)?;
        fs_err::remove_file(journal_path)?;
        self.0.finalized.store(true, Ordering::Release);
        self.0.finalized_notify.notify_waiters();
        Ok(())
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
    async fn finalize(self, request: MpcGenesisFinalizeRequest) -> Result<()> {
        let initiator = self.state.authenticated_node(&self.peer_key)?;
        ensure!(
            initiator == self.state.0.plan.coordinator,
            "only genesis coordinator may finalize"
        );
        let bundle =
            serde_json::from_slice(&request.bundle_json).context("invalid genesis bundle")?;
        self.state.finalize_bundle(bundle)
    }
}

pub(crate) fn rpc_methods() -> &'static [&'static str] {
    <MpcGenesisServer<GenesisHandler>>::supported_methods()
}

fn genesis_journal_path(config: &KmsConfig) -> std::path::PathBuf {
    config.mpc.identity_file.with_extension("genesis-journal")
}

fn persist_bundle_files(config: &KmsConfig, bundle: &GenesisBundle) -> Result<()> {
    use ra_tls::traits::CertExt as _;
    ensure!(
        !config.mpc.identity_file.as_os_str().is_empty(),
        "missing MPC identity file"
    );
    let rpc_pem = bundle
        .rpc_certificates
        .get(&config.mpc.node_id)
        .context("genesis bundle lacks local RPC certificate")?;
    let (_, rpc_der) = x509_parser::pem::parse_x509_pem(rpc_pem.as_bytes())?;
    let rpc = rpc_der.parse_x509()?;
    let member = bundle
        .signed_manifest
        .manifest
        .members
        .iter()
        .find(|member| member.node_id == config.mpc.node_id)
        .context("local node absent from genesis manifest")?;
    ensure!(
        rpc.public_key().raw == member.attestation_pubkey,
        "genesis RPC certificate key mismatch"
    );
    ensure!(
        rpc.get_special_usage()?.as_deref() == Some("kms:rpc"),
        "genesis RPC certificate usage mismatch"
    );
    ensure!(
        ra_tls::attestation::from_cert(&rpc)?.is_some(),
        "genesis RPC certificate lacks attestation"
    );
    let (_, root_der) = x509_parser::pem::parse_x509_pem(bundle.root_ca_pem.as_bytes())?;
    let root = root_der.parse_x509()?;
    rpc.verify_signature(Some(root.public_key()))
        .context("invalid threshold RPC certificate signature")?;
    ensure!(
        !config.mpc.manifest_file.as_os_str().is_empty(),
        "missing MPC manifest file"
    );
    safe_write::safe_write(
        &config.mpc.identity_file,
        &serde_jcs::to_vec(&bundle.identity)?,
    )?;
    safe_write::safe_write(config.root_ca_cert(), bundle.root_ca_pem.as_bytes())?;
    safe_write::safe_write(config.rpc_cert(), rpc_pem.as_bytes())?;
    // A directory converted from legacy mode must not retain exportable root
    // keys after MPC genesis has established the threshold identity.
    for legacy_secret in [config.root_ca_key(), config.k256_key()] {
        if legacy_secret.exists() {
            fs_err::remove_file(legacy_secret)?;
        }
    }
    safe_write::safe_write(
        &config.mpc.manifest_file,
        &serde_jcs::to_vec(&bundle.signed_manifest)?,
    )?;
    validate_and_checkpoint(
        &config.mpc.checkpoint_file,
        &bundle.signed_manifest,
        &bundle.identity,
    )
}

/// Finish a crash-interrupted genesis commit before startup decides whether
/// to enter genesis or normal mode.
pub(crate) fn recover_if_needed(config: &KmsConfig) -> Result<bool> {
    if config.mpc.identity_file.as_os_str().is_empty() {
        return Ok(false);
    }
    let journal_path = genesis_journal_path(config);
    if !journal_path.exists() {
        return Ok(false);
    }
    let metadata = fs_err::symlink_metadata(&journal_path)?;
    ensure!(
        metadata.file_type().is_file(),
        "MPC genesis journal is not a file"
    );
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "MPC genesis journal permissions are too broad"
    );
    let journal: GenesisJournal = serde_json::from_slice(&fs_err::read(&journal_path)?)
        .context("failed to parse MPC genesis journal")?;
    ensure!(
        journal.version == 1,
        "unsupported MPC genesis journal version"
    );
    let bundle = journal.bundle;
    bundle.signed_manifest.verify(&bundle.identity)?;
    ensure!(
        bundle.signed_manifest.manifest.epoch == 1,
        "genesis journal contains a non-genesis epoch"
    );
    let (_, pem) = x509_parser::pem::parse_x509_pem(bundle.root_ca_pem.as_bytes())?;
    let certificate = pem.parse_x509()?;
    ensure!(
        certificate.public_key().subject_public_key.data.as_ref()
            == bundle.identity.p256_group_pubkey,
        "genesis journal root key mismatch"
    );
    certificate
        .verify_signature(None)
        .context("invalid journaled genesis root signature")?;
    let manifest = &bundle.signed_manifest.manifest;
    let index = manifest
        .members
        .iter()
        .position(|member| member.node_id == config.mpc.node_id)
        .context("local member absent from journaled genesis")?;
    let p: P256KeyShare = load_share(
        &config.mpc.p256_share_file,
        &bundle.identity.cluster_id,
        1,
        &config.mpc.node_id,
        CggmpCurve::P256,
    )?;
    let k: K256KeyShare = load_share(
        &config.mpc.k256_share_file,
        &bundle.identity.cluster_id,
        1,
        &config.mpc.node_id,
        CggmpCurve::K256,
    )?;
    let d: P256KeyShare = load_share(
        &config.mpc.derivation_share_file,
        &bundle.identity.cluster_id,
        1,
        &config.mpc.node_id,
        CggmpCurve::P256,
    )?;
    validate_share_topology(&p, index, manifest.members.len(), manifest.threshold)?;
    validate_share_topology(&k, index, manifest.members.len(), manifest.threshold)?;
    validate_share_topology(&d, index, manifest.members.len(), manifest.threshold)?;
    ensure!(
        p.shared_public_key().to_bytes(false).as_bytes() == bundle.identity.p256_group_pubkey
            && k.shared_public_key().to_bytes(true).as_bytes() == bundle.identity.k256_group_pubkey
            && d.shared_public_key().to_bytes(false).as_bytes()
                == bundle.identity.derivation_group_pubkey,
        "journaled genesis shares changed stable identity"
    );
    let pp = p.core.key_info.public_shares[index].to_bytes(false);
    let kp = k.core.key_info.public_shares[index].to_bytes(true);
    let dp = d.core.key_info.public_shares[index].to_bytes(false);
    ensure!(
        manifest.members[index].share_commitment
            == share_commitment(pp.as_bytes(), kp.as_bytes(), dp.as_bytes()),
        "journaled genesis shares do not match manifest"
    );
    persist_bundle_files(config, &bundle)?;
    fs_err::remove_file(journal_path)?;
    Ok(true)
}

fn unix_time() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn local_share_commitment(
    p256: &P256KeyShare,
    k256: &K256KeyShare,
    derivation: &P256KeyShare,
    index: usize,
) -> Result<[u8; 32]> {
    let p256 = p256
        .core
        .key_info
        .public_shares
        .get(index)
        .context("missing P-256 public share")?
        .to_bytes(false);
    let k256 = k256
        .core
        .key_info
        .public_shares
        .get(index)
        .context("missing K-256 public share")?
        .to_bytes(true);
    let derivation = derivation
        .core
        .key_info
        .public_shares
        .get(index)
        .context("missing derivation public share")?
        .to_bytes(false);
    Ok(share_commitment(
        p256.as_bytes(),
        k256.as_bytes(),
        derivation.as_bytes(),
    ))
}

fn identical_result<'a>(results: &'a BTreeMap<String, Vec<u8>>, label: &str) -> Result<&'a [u8]> {
    let first = results
        .values()
        .next()
        .context("genesis operation has no results")?;
    ensure!(
        results.values().all(|value| value == first),
        "genesis {label} differ across nodes"
    );
    Ok(first)
}

fn p256_subject_public_key(raw: &[u8]) -> Result<SubjectPublicKeyInfo> {
    ensure!(
        raw.len() == 65 && raw[0] == 4,
        "invalid P-256 genesis public key"
    );
    // SubjectPublicKeyInfo for id-ecPublicKey / prime256v1 followed by the
    // uncompressed SEC1 point.
    const PREFIX: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    let mut der = PREFIX.to_vec();
    der.extend_from_slice(raw);
    SubjectPublicKeyInfo::from_der(&der).context("failed to construct genesis root public key")
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
