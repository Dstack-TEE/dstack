// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Root-key operation boundary.
//!
//! The public KMS service must only depend on this interface. The local
//! implementation preserves the legacy behavior; the MPC implementation can
//! replace it without making root key material available to request handlers.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use cggmp21::key_share::AnyKeyShare as _;
use cggmp21::{generic_ec::Scalar, supported_curves::Secp256k1, DataToSign, ExecutionId};
use futures::future::join_all;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use ra_tls::{
    cert::{CaCert, CertRequest},
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
    mpc_operation::{K256SignPayload, MpcOperation, MpcOperationPayload},
    mpc_session::{MpcProtocol, SessionRouter},
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
    transport: Arc<MpcHttpTransport>,
    manifest: EpochManifest,
    cluster_id: String,
    node_id: String,
}

impl MpcKeyBackend {
    pub(crate) fn load(
        root_ca_cert: String,
        cluster_id: &str,
        epoch: u64,
        node_id: &str,
        p256_share_file: &std::path::Path,
        k256_share_file: &std::path::Path,
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
            transport: Arc::new(transport),
            manifest: manifest.clone(),
            cluster_id: cluster_id.into(),
            node_id: node_id.into(),
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

    fn add_recovery_id(&self, operation: &MpcOperation, signature: Vec<u8>) -> Result<Vec<u8>> {
        ensure!(signature.len() == 64, "invalid MPC K-256 signature length");
        let signature = K256Signature::from_slice(&signature).context("invalid MPC signature")?;
        let public_key = VerifyingKey::from_sec1_bytes(&self.k256_public_key())
            .context("invalid MPC group public key")?;
        let digest = match &operation.payload {
            MpcOperationPayload::SignK256(payload) => payload.digest(),
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
}

fn unix_time() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system time before UNIX epoch")?
        .as_secs())
}

#[async_trait]
impl KeyBackend for MpcKeyBackend {
    async fn derive_app_keys(&self, _app_id: &[u8], _instance_id: &[u8]) -> Result<DerivedAppKeys> {
        bail!("MPC derivation protocol is unavailable")
    }

    async fn derive_env_key(&self, _app_id: &[u8]) -> Result<[u8; 32]> {
        bail!("MPC derivation protocol is unavailable")
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

    fn root_ca_cert(&self) -> &str {
        &self.root_ca_cert
    }

    async fn derive_app_ca(&self, _app_id: &[u8]) -> Result<CaCert> {
        bail!("legacy app CA derivation is unavailable in MPC mode")
    }

    async fn run_mpc_operation(&self, operation: MpcOperation, initiator: &str) -> Result<Vec<u8>> {
        operation.validate(&self.manifest, initiator)?;
        let MpcOperationPayload::SignK256(payload) = &operation.payload;
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
                &BlockingHttpTransport::new(transport, tokio::runtime::Handle::current()),
                context,
            )??;
            let mut encoded = vec![0u8; cggmp21::Signature::<Secp256k1>::serialized_len()];
            signature.write_to_slice(&mut encoded);
            Ok(encoded)
        })
        .await
        .context("MPC signing worker panicked")?
    }

    async fn export_root_keys(&self) -> Result<(String, Vec<u8>)> {
        bail!("MPC root shares cannot be exported as root keys")
    }
}
