// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Root-key operation boundary.
//!
//! The public KMS service must only depend on this interface. The local
//! implementation preserves the legacy behavior; the MPC implementation can
//! replace it without making root key material available to request handlers.

use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use cggmp21::key_share::AnyKeyShare as _;
use cggmp21::{
    generic_ec::Scalar,
    supported_curves::{Secp256k1, Secp256r1},
    DataToSign, ExecutionId,
};
use futures::future::join_all;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use ra_tls::{
    cert::{prepare_external_certificate, CaCert, CertRequest},
    kdf,
};
use rand::{rngs::OsRng, RngCore};

use crate::{
    cggmp_engine::{execution_id, load_share, CggmpCurve, K256KeyShare, P256KeyShare},
    crypto::{derive_k256_key, sign_message, sign_message_with_timestamp},
    mpc_driver::{
        drive_state_machine_blocking, BlockingHttpTransport, DriverContext, MpcHttpTransport,
    },
    mpc_identity::EpochManifest,
    mpc_operation::{
        DerivePayload, DerivePurpose, K256SignPayload, MpcOperation, MpcOperationPayload,
        P256CertificatePayload,
    },
    mpc_session::{MpcProtocol, SessionRouter},
    threshold_prf::{self, PrfPartial},
};

pub(crate) struct DerivedAppKeys {
    pub disk_key: [u8; 32],
    pub env_key: [u8; 32],
    pub k256_key: Vec<u8>,
    pub k256_signature: Vec<u8>,
}

#[async_trait]
pub(crate) trait KeyBackend: Send + Sync {
    async fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys>;
    async fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]>;
    async fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>>;
    async fn sign_k256_timestamped(
        &self,
        prefix: &[u8],
        app_id: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Result<Vec<u8>>;
    fn k256_public_key(&self) -> Vec<u8>;
    fn p256_public_key(&self) -> Vec<u8>;
    fn derivation_public_key(&self) -> Vec<u8>;
    fn root_ca_cert(&self) -> &str;
    async fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert>;
    async fn run_mpc_operation(
        &self,
        operation: crate::mpc_operation::MpcOperation,
        initiator: &str,
    ) -> Result<Vec<u8>>;
    /// Legacy KMS-to-KMS migration. MPC backends must reject this operation.
    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)>;
}

pub(crate) struct LocalKeyBackend {
    root_ca: CaCert,
    k256_key: SigningKey,
}

impl LocalKeyBackend {
    pub(crate) fn from_pem_and_bytes(
        root_ca_cert: String,
        root_ca_key: String,
        k256_key: &[u8],
    ) -> Result<Self> {
        Ok(Self {
            root_ca: CaCert::new(root_ca_cert, root_ca_key).context("invalid root CA")?,
            k256_key: SigningKey::from_slice(k256_key).context("invalid K-256 root key")?,
        })
    }
}

#[async_trait]
impl KeyBackend for LocalKeyBackend {
    async fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys> {
        let disk_key = kdf::derive_dh_secret(
            &self.root_ca.key,
            &[app_id, instance_id, b"app-disk-crypt-key"],
        )?;
        let env_key = self.derive_env_key(app_id).await?;
        let (k256_key, k256_signature) = derive_k256_key(&self.k256_key, app_id)?;
        Ok(DerivedAppKeys {
            disk_key,
            env_key,
            k256_key: k256_key.to_bytes().to_vec(),
            k256_signature,
        })
    }

    async fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]> {
        kdf::derive_dh_secret(&self.root_ca.key, &[app_id, b"env-encrypt-key"])
    }

    async fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        sign_message(&self.k256_key, prefix, app_id, message)
    }

    async fn sign_k256_timestamped(
        &self,
        prefix: &[u8],
        app_id: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        sign_message_with_timestamp(&self.k256_key, prefix, app_id, timestamp, message)
    }

    fn k256_public_key(&self) -> Vec<u8> {
        self.k256_key.verifying_key().to_sec1_bytes().to_vec()
    }

    fn p256_public_key(&self) -> Vec<u8> {
        self.root_ca.key.public_key_raw().to_vec()
    }

    fn derivation_public_key(&self) -> Vec<u8> {
        self.p256_public_key()
    }

    fn root_ca_cert(&self) -> &str {
        &self.root_ca.pem_cert
    }

    async fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert> {
        let app_key = kdf::derive_p256_key_pair(&self.root_ca.key, &[app_id, b"app-ca"])?;
        let request = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        let certificate = self
            .root_ca
            .sign(request)
            .context("failed to sign app CA")?;
        Ok(CaCert::from_parts(app_key, certificate))
    }

    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)> {
        Ok((
            self.root_ca.key.serialize_pem(),
            self.k256_key.to_bytes().to_vec(),
        ))
    }

    async fn run_mpc_operation(
        &self,
        _operation: crate::mpc_operation::MpcOperation,
        _initiator: &str,
    ) -> Result<Vec<u8>> {
        bail!("MPC operations are unavailable on the local key backend")
    }
}

/// MPC backend containing only validated threshold shares. No complete root
/// private key is loaded or reconstructed by this backend.
pub(crate) struct MpcKeyBackend {
    root_ca_cert: String,
    p256_share: P256KeyShare,
    k256_share: K256KeyShare,
    derivation_share: P256KeyShare,
    transport: Arc<MpcHttpTransport>,
    manifest: EpochManifest,
    cluster_id: String,
    node_id: String,
    operations: Mutex<BTreeMap<Vec<u8>, Arc<OperationRecord>>>,
}

struct OperationRecord {
    request_hash: Vec<u8>,
    initiator: String,
    expires_at: u64,
    result: Mutex<Option<Result<Vec<u8>, String>>>,
    finished: tokio::sync::Notify,
}

impl MpcKeyBackend {
    pub(crate) fn load(
        root_ca_cert: String,
        cluster_id: &str,
        epoch: u64,
        node_id: &str,
        p256_share_file: &std::path::Path,
        k256_share_file: &std::path::Path,
        derivation_share_file: &std::path::Path,
        manifest: &EpochManifest,
        router: std::sync::Arc<SessionRouter>,
        rpc_cert: String,
        rpc_key: String,
        attestation_verifier: std::sync::Arc<ra_tls::attestation::AttestationVerifier>,
    ) -> Result<Self> {
        let transport = MpcHttpTransport::new(
            manifest,
            node_id,
            router,
            rpc_cert,
            rpc_key,
            root_ca_cert.clone(),
            attestation_verifier,
        )?;
        Ok(Self {
            root_ca_cert,
            p256_share: load_share(
                p256_share_file,
                cluster_id,
                epoch,
                node_id,
                CggmpCurve::P256,
            )?,
            k256_share: load_share(
                k256_share_file,
                cluster_id,
                epoch,
                node_id,
                CggmpCurve::K256,
            )?,
            derivation_share: load_share(
                derivation_share_file,
                cluster_id,
                epoch,
                node_id,
                CggmpCurve::P256,
            )?,
            transport: Arc::new(transport),
            manifest: manifest.clone(),
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
            operations: Mutex::new(BTreeMap::new()),
        })
    }

    fn participants(&self) -> Result<Vec<String>> {
        let threshold = usize::from(self.manifest.threshold);
        let mut selected: Vec<_> = self
            .manifest
            .members
            .iter()
            .filter(|member| member.node_id == self.node_id)
            .map(|member| member.node_id.clone())
            .collect();
        selected.extend(
            self.manifest
                .members
                .iter()
                .filter(|member| member.node_id != self.node_id)
                .take(threshold.saturating_sub(1))
                .map(|member| member.node_id.clone()),
        );
        selected.sort_by_key(|node| {
            self.manifest
                .members
                .iter()
                .position(|member| &member.node_id == node)
                .expect("selected manifest member")
        });
        ensure!(selected.len() == threshold, "not enough MPC members");
        Ok(selected)
    }

    async fn coordinate_k256(&self, payload: K256SignPayload) -> Result<Vec<u8>> {
        let mut session_id = [0u8; 32];
        OsRng.fill_bytes(&mut session_id);
        let operation = MpcOperation::new_k256(
            session_id,
            self.manifest.epoch,
            self.participants()?,
            unix_time()?
                .checked_add(60)
                .context("MPC expiry overflow")?,
            payload,
        )?;
        operation.validate(&self.manifest, &self.node_id)?;

        let remote = operation
            .participants
            .iter()
            .filter(|node| *node != &self.node_id)
            .map(|node| self.transport.start_operation(node, &operation));
        let (local, remote) = tokio::join!(
            self.run_mpc_operation(operation.clone(), &self.node_id),
            join_all(remote)
        );
        let local = local?;
        for result in remote {
            ensure!(
                result? == local,
                "MPC participants returned different signatures"
            );
        }
        self.add_recovery_id(&operation, local)
    }

    async fn derive(&self, payload: DerivePayload) -> Result<[u8; 32]> {
        let mut session_id = [0u8; 32];
        OsRng.fill_bytes(&mut session_id);
        let operation = MpcOperation::new_derivation(
            session_id,
            self.manifest.epoch,
            self.participants()?,
            unix_time()?
                .checked_add(60)
                .context("MPC expiry overflow")?,
            payload.clone(),
        )?;
        operation.validate(&self.manifest, &self.node_id)?;
        let remote = operation
            .participants
            .iter()
            .filter(|node| *node != &self.node_id)
            .map(|node| async {
                (
                    node.clone(),
                    self.transport.start_operation(node, &operation).await,
                )
            });
        let (local, remote) = tokio::join!(
            self.run_mpc_operation(operation.clone(), &self.node_id),
            join_all(remote)
        );
        let mut results = vec![(self.node_id.clone(), local?)];
        for (node, result) in remote {
            results.push((node, result?));
        }
        let input = payload.input()?;
        let request_hash: [u8; 32] = operation.request_hash.as_slice().try_into()?;
        let mut evaluations = Vec::with_capacity(results.len());
        for (node, encoded) in results {
            let expected_index = self
                .manifest
                .members
                .iter()
                .position(|member| member.node_id == node)
                .context("derivation responder is not in manifest")?;
            let partial: PrfPartial =
                serde_json::from_slice(&encoded).context("invalid threshold derivation partial")?;
            ensure!(
                usize::from(partial.keygen_index) == expected_index,
                "threshold derivation partial has wrong signer index"
            );
            let public_share = self
                .derivation_share
                .core
                .key_info
                .public_shares
                .get(expected_index)
                .context("missing derivation public share")?
                .to_bytes(false);
            evaluations.push((
                partial.keygen_index,
                threshold_prf::verify(&partial, public_share.as_bytes(), &input, &request_hash)?,
            ));
        }
        threshold_prf::combine(evaluations, &input)
    }

    async fn sign_p256_certificate(&self, payload: P256CertificatePayload) -> Result<Vec<u8>> {
        self.validate_p256_certificate(&payload)?;
        let mut session_id = [0u8; 32];
        OsRng.fill_bytes(&mut session_id);
        let operation = MpcOperation::new_p256_certificate(
            session_id,
            self.manifest.epoch,
            self.participants()?,
            unix_time()?
                .checked_add(60)
                .context("MPC expiry overflow")?,
            payload,
        )?;
        operation.validate(&self.manifest, &self.node_id)?;
        let remote = operation
            .participants
            .iter()
            .filter(|node| *node != &self.node_id)
            .map(|node| self.transport.start_operation(node, &operation));
        let (local, remote) = tokio::join!(
            self.run_mpc_operation(operation.clone(), &self.node_id),
            join_all(remote)
        );
        let local = local?;
        ensure!(
            local.len() == 64,
            "invalid threshold P-256 signature length"
        );
        for result in remote {
            ensure!(
                result? == local,
                "MPC participants returned different P-256 signatures"
            );
        }
        Ok(local)
    }

    fn validate_p256_certificate(&self, payload: &P256CertificatePayload) -> Result<()> {
        use ra_tls::oids::{PHALA_RATLS_APP_ID, PHALA_RATLS_CERT_USAGE};
        use x509_parser::{
            certificate::TbsCertificate,
            der_parser::oid::Oid,
            prelude::{FromDer as _, ParsedExtension},
        };
        let (_, root_pem) = x509_parser::pem::parse_x509_pem(self.root_ca_cert.as_bytes())
            .context("invalid root CA PEM")?;
        let root = root_pem
            .parse_x509()
            .context("invalid root CA certificate")?;
        let (remaining, tbs) = TbsCertificate::from_der(&payload.tbs_der)
            .map_err(|error| anyhow::anyhow!("invalid certificate TBS: {error}"))?;
        ensure!(remaining.is_empty(), "certificate TBS has trailing bytes");
        ensure!(
            tbs.issuer() == root.subject(),
            "certificate issuer is not the root CA"
        );
        ensure!(
            tbs.signature.algorithm.to_id_string() == "1.2.840.10045.4.3.2",
            "certificate does not use ECDSA-with-SHA256"
        );
        let constraints = tbs
            .basic_constraints()
            .context("invalid certificate basic constraints")?
            .context("app CA certificate lacks basic constraints")?;
        ensure!(
            constraints.value.ca && constraints.value.path_len_constraint == Some(0),
            "app CA certificate has invalid CA constraints"
        );
        let app_oid = Oid::from(PHALA_RATLS_APP_ID)
            .map_err(|error| anyhow::anyhow!("invalid app ID OID: {error:?}"))?;
        let app_extension = tbs
            .get_extension_unique(&app_oid)
            .context("duplicate app ID extension")?
            .context("app CA certificate lacks app ID")?;
        let app_id = yasna::parse_der(app_extension.value, |reader| reader.read_bytes())
            .context("invalid app ID extension")?;
        ensure!(app_id == payload.app_id, "certificate app ID mismatch");
        let usage_oid = Oid::from(PHALA_RATLS_CERT_USAGE)
            .map_err(|error| anyhow::anyhow!("invalid usage OID: {error:?}"))?;
        let usage_extension = tbs
            .get_extension_unique(&usage_oid)
            .context("duplicate certificate usage extension")?
            .context("app CA certificate lacks usage extension")?;
        let usage = yasna::parse_der(usage_extension.value, |reader| reader.read_bytes())
            .context("invalid certificate usage extension")?;
        ensure!(usage == b"app:ca", "certificate usage is not app:ca");
        ensure!(
            matches!(
                tbs.public_key().parsed(),
                Ok(x509_parser::public_key::PublicKey::EC(_))
            ),
            "app CA public key is not an EC key"
        );
        // Force duplicate/invalid key-usage extensions to fail parsing as well.
        let usage = tbs.key_usage().context("invalid key usage extension")?;
        ensure!(
            usage.is_some_and(|usage| usage.value.key_cert_sign() && usage.value.crl_sign()),
            "app CA certificate lacks certificate-signing key usage"
        );
        for extension in tbs.extensions() {
            if matches!(
                extension.parsed_extension(),
                ParsedExtension::ParseError { .. }
            ) {
                bail!("app CA certificate contains a malformed extension")
            }
        }
        Ok(())
    }

    fn add_recovery_id(&self, operation: &MpcOperation, signature: Vec<u8>) -> Result<Vec<u8>> {
        ensure!(signature.len() == 64, "invalid MPC K-256 signature length");
        let signature = K256Signature::from_slice(&signature).context("invalid MPC signature")?;
        let public_key = VerifyingKey::from_sec1_bytes(&self.k256_public_key())
            .context("invalid MPC group public key")?;
        let digest = match &operation.payload {
            MpcOperationPayload::SignK256(payload) => payload.digest(),
            MpcOperationPayload::SignP256Certificate(_) => {
                bail!("P-256 certificate result does not have a recovery ID")
            }
            MpcOperationPayload::Derive(_) => bail!("derivation result is not a signature"),
        };
        for recovery_id in 0u8..4 {
            let recovery_id = RecoveryId::try_from(recovery_id).context("invalid recovery ID")?;
            if VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
                .is_ok_and(|recovered| recovered == public_key)
            {
                let mut encoded = signature.to_bytes().to_vec();
                encoded.push(recovery_id.to_byte());
                return Ok(encoded);
            }
        }
        bail!("MPC signature cannot be recovered to the group public key")
    }

    async fn execute_once(&self, operation: MpcOperation, initiator: &str) -> Result<Vec<u8>> {
        let (record, owner) = {
            let now = unix_time()?;
            let mut operations = self.operations.lock().expect("operation mutex poisoned");
            operations.retain(|_, record| record.expires_at >= now);
            if let Some(record) = operations.get(&operation.session_id) {
                ensure!(
                    record.request_hash == operation.request_hash && record.initiator == initiator,
                    "MPC session ID was reused with different operation context"
                );
                (record.clone(), false)
            } else {
                let record = Arc::new(OperationRecord {
                    request_hash: operation.request_hash.clone(),
                    initiator: initiator.into(),
                    expires_at: operation.expires_at,
                    result: Mutex::new(None),
                    finished: tokio::sync::Notify::new(),
                });
                operations.insert(operation.session_id.clone(), record.clone());
                (record, true)
            }
        };
        if owner {
            let result = self.execute_operation(operation).await;
            *record
                .result
                .lock()
                .expect("operation result mutex poisoned") = Some(
                result
                    .as_ref()
                    .map(|value| value.clone())
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
                    .expect("operation result mutex poisoned")
                    .clone()
                {
                    return result.map_err(anyhow::Error::msg);
                }
                notified.await;
            }
        }
    }

    async fn execute_operation(&self, operation: MpcOperation) -> Result<Vec<u8>> {
        match &operation.payload {
            MpcOperationPayload::SignK256(_) => self.execute_k256(operation).await,
            MpcOperationPayload::SignP256Certificate(payload) => {
                self.validate_p256_certificate(payload)?;
                self.execute_p256(operation).await
            }
            MpcOperationPayload::Derive(payload) => {
                let input = payload.input()?;
                let own_index = self
                    .manifest
                    .members
                    .iter()
                    .position(|member| member.node_id == self.node_id)
                    .context("local node is not in manifest")?;
                ensure!(
                    usize::from(self.derivation_share.core.i) == own_index,
                    "derivation share index does not match manifest ordering"
                );
                let secret_scalar: &Scalar<Secp256r1> = self.derivation_share.core.x.as_ref();
                let secret: [u8; 32] = secret_scalar
                    .to_be_bytes()
                    .as_bytes()
                    .try_into()
                    .context("invalid derivation secret share length")?;
                let public = self
                    .derivation_share
                    .core
                    .key_info
                    .public_shares
                    .get(own_index)
                    .context("missing local derivation public share")?
                    .to_bytes(false);
                let request_hash: [u8; 32] = operation.request_hash.as_slice().try_into()?;
                let partial = threshold_prf::evaluate(
                    own_index
                        .try_into()
                        .context("derivation share index overflow")?,
                    &secret,
                    public.as_bytes(),
                    &input,
                    &request_hash,
                    &mut OsRng,
                )?;
                serde_json::to_vec(&partial).context("failed to encode derivation partial")
            }
        }
    }

    async fn execute_k256(&self, operation: MpcOperation) -> Result<Vec<u8>> {
        let MpcOperationPayload::SignK256(payload) = &operation.payload else {
            bail!("K-256 executor received a different MPC operation")
        };
        let digest = payload.digest();
        let local_protocol_index: u16 = operation
            .participants
            .iter()
            .position(|node| node == &self.node_id)
            .context("local node is not an MPC participant")?
            .try_into()
            .context("MPC participant index overflow")?;
        let keygen_indexes = operation
            .participants
            .iter()
            .map(|node| {
                self.manifest
                    .members
                    .iter()
                    .position(|member| &member.node_id == node)
                    .context("MPC participant is not in manifest")?
                    .try_into()
                    .context("MPC keygen index overflow")
            })
            .collect::<Result<Vec<u16>>>()?;
        let own_keygen_index = self
            .manifest
            .members
            .iter()
            .position(|member| member.node_id == self.node_id)
            .context("local node is not in manifest")?;
        ensure!(
            usize::from(self.k256_share.core.i) == own_keygen_index,
            "K-256 share index does not match manifest ordering"
        );

        let eid = execution_id(
            &self.cluster_id,
            operation.epoch,
            CggmpCurve::K256,
            operation
                .session_id
                .as_slice()
                .try_into()
                .context("invalid MPC session ID")?,
        );
        let context = DriverContext {
            session_id: operation.session_id.as_slice().try_into()?,
            epoch: operation.epoch,
            protocol: MpcProtocol::SignK256,
            request_hash: operation.request_hash.as_slice().try_into()?,
            local_node_id: self.node_id.clone(),
            participants: operation.participants.clone(),
            expires_at: operation.expires_at,
            poll_interval: Duration::from_millis(10),
        };
        let share = self.k256_share.clone();
        let transport = self.transport.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let data =
                DataToSign::from_scalar(Scalar::<Secp256k1>::from_be_bytes_mod_order(digest));
            let state = cggmp21::signing(
                ExecutionId::new(&eid),
                local_protocol_index,
                &keygen_indexes,
                &share,
            )
            .sign_sync(&mut rng, data);
            let signature = drive_state_machine_blocking(
                state,
                &BlockingHttpTransport::new(transport, runtime),
                context,
            )??;
            let mut encoded = vec![0u8; cggmp21::Signature::<Secp256k1>::serialized_len()];
            signature.write_to_slice(&mut encoded);
            Ok(encoded)
        })
        .await
        .context("MPC signing worker panicked")?
    }

    async fn execute_p256(&self, operation: MpcOperation) -> Result<Vec<u8>> {
        let MpcOperationPayload::SignP256Certificate(payload) = &operation.payload else {
            bail!("P-256 executor received a different MPC operation")
        };
        let digest = payload.digest();
        let local_protocol_index: u16 = operation
            .participants
            .iter()
            .position(|node| node == &self.node_id)
            .context("local node is not an MPC participant")?
            .try_into()
            .context("MPC participant index overflow")?;
        let keygen_indexes = operation
            .participants
            .iter()
            .map(|node| {
                self.manifest
                    .members
                    .iter()
                    .position(|member| &member.node_id == node)
                    .context("MPC participant is not in manifest")?
                    .try_into()
                    .context("MPC keygen index overflow")
            })
            .collect::<Result<Vec<u16>>>()?;
        let own_keygen_index = self
            .manifest
            .members
            .iter()
            .position(|member| member.node_id == self.node_id)
            .context("local node is not in manifest")?;
        ensure!(
            usize::from(self.p256_share.core.i) == own_keygen_index,
            "P-256 share index does not match manifest ordering"
        );
        let eid = execution_id(
            &self.cluster_id,
            operation.epoch,
            CggmpCurve::P256,
            operation.session_id.as_slice().try_into()?,
        );
        let context = DriverContext {
            session_id: operation.session_id.as_slice().try_into()?,
            epoch: operation.epoch,
            protocol: MpcProtocol::SignP256,
            request_hash: operation.request_hash.as_slice().try_into()?,
            local_node_id: self.node_id.clone(),
            participants: operation.participants.clone(),
            expires_at: operation.expires_at,
            poll_interval: Duration::from_millis(10),
        };
        let share = self.p256_share.clone();
        let transport = self.transport.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut rng = OsRng;
            let data =
                DataToSign::from_scalar(Scalar::<Secp256r1>::from_be_bytes_mod_order(digest));
            let state = cggmp21::signing(
                ExecutionId::new(&eid),
                local_protocol_index,
                &keygen_indexes,
                &share,
            )
            .sign_sync(&mut rng, data);
            let signature = drive_state_machine_blocking(
                state,
                &BlockingHttpTransport::new(transport, runtime),
                context,
            )??;
            let mut encoded = vec![0u8; cggmp21::Signature::<Secp256r1>::serialized_len()];
            signature.write_to_slice(&mut encoded);
            Ok(encoded)
        })
        .await
        .context("MPC P-256 signing worker panicked")?
    }
}

fn unix_time() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs())
}

#[async_trait]
impl KeyBackend for MpcKeyBackend {
    async fn derive_app_keys(&self, app_id: &[u8], instance_id: &[u8]) -> Result<DerivedAppKeys> {
        let disk_key = self
            .derive(DerivePayload {
                purpose: DerivePurpose::DiskKey,
                app_id: app_id.to_vec(),
                instance_id: Some(instance_id.to_vec()),
            })
            .await?;
        let env_key = self.derive_env_key(app_id).await?;
        let app_seed = self
            .derive(DerivePayload {
                purpose: DerivePurpose::AppK256,
                app_id: app_id.to_vec(),
                instance_id: None,
            })
            .await?;
        let k256_key = SigningKey::from_slice(&app_seed)
            .context("threshold derivation produced an invalid K-256 key")?;
        let public_key = k256_key.verifying_key().to_sec1_bytes();
        let k256_signature = self
            .sign_k256(b"dstack-kms-issued", app_id, &public_key)
            .await?;
        Ok(DerivedAppKeys {
            disk_key,
            env_key,
            k256_key: k256_key.to_bytes().to_vec(),
            k256_signature,
        })
    }

    async fn derive_env_key(&self, app_id: &[u8]) -> Result<[u8; 32]> {
        self.derive(DerivePayload {
            purpose: DerivePurpose::EnvKey,
            app_id: app_id.to_vec(),
            instance_id: None,
        })
        .await
    }

    async fn sign_k256(&self, prefix: &[u8], app_id: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        self.coordinate_k256(K256SignPayload {
            prefix: prefix.to_vec(),
            app_id: app_id.to_vec(),
            timestamp: None,
            message: message.to_vec(),
        })
        .await
    }

    async fn sign_k256_timestamped(
        &self,
        prefix: &[u8],
        app_id: &[u8],
        timestamp: u64,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        self.coordinate_k256(K256SignPayload {
            prefix: prefix.to_vec(),
            app_id: app_id.to_vec(),
            timestamp: Some(timestamp),
            message: message.to_vec(),
        })
        .await
    }

    fn k256_public_key(&self) -> Vec<u8> {
        self.k256_share
            .shared_public_key()
            .to_bytes(true)
            .as_bytes()
            .to_vec()
    }

    fn p256_public_key(&self) -> Vec<u8> {
        self.p256_share
            .shared_public_key()
            .to_bytes(false)
            .as_bytes()
            .to_vec()
    }

    fn derivation_public_key(&self) -> Vec<u8> {
        self.derivation_share
            .shared_public_key()
            .to_bytes(false)
            .as_bytes()
            .to_vec()
    }

    fn root_ca_cert(&self) -> &str {
        &self.root_ca_cert
    }

    async fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert> {
        let seed = self
            .derive(DerivePayload {
                purpose: DerivePurpose::AppCa,
                app_id: app_id.to_vec(),
                instance_id: None,
            })
            .await?;
        let app_key = kdf::derive_p256_key_pair_from_bytes(&seed, &[app_id, b"app-ca"])?;
        let request = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        let external = prepare_external_certificate(request, &self.root_ca_cert)
            .context("failed to prepare threshold-signed app CA")?;
        let signature = self
            .sign_p256_certificate(P256CertificatePayload {
                app_id: app_id.to_vec(),
                tbs_der: external.tbs_der().to_vec(),
            })
            .await?;
        let certificate = external.finish(&signature)?;
        CaCert::new(certificate, app_key.serialize_pem())
            .context("failed to construct threshold-signed app CA")
    }

    async fn run_mpc_operation(&self, operation: MpcOperation, initiator: &str) -> Result<Vec<u8>> {
        operation.validate(&self.manifest, initiator)?;
        self.execute_once(operation, initiator).await
    }

    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)> {
        bail!("MPC root shares cannot be exported as root keys")
    }
}
