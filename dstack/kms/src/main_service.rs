// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use dstack_kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, GetAppKeyRequest, GetKmsKeyRequest, GetMetaResponse,
    GetTempCaCertResponse, KmsKeyResponse, KmsKeys, PublicKeyResponse, SignCertRequest,
    SignCertResponse,
};
use dstack_verifier::{CvmVerifier, VerificationDetails};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use moka::future::Cache;
use ra_rpc::{CallContext, RpcCall};
use ra_tls::{
    attestation::{resolve_vm_config, AttestationVerifier, TeeVariant, VerifiedAttestation},
    cert::{CaCert, CertRequest, CertSigningRequestV1, CertSigningRequestV2, Csr},
    kdf,
    rcgen::KeyPair,
};
use scale::Decode;
use tracing::warn;
use upgrade_authority::{
    build_boot_info, ensure_app_id_len, local_kms_boot_info, AuthorizationResult, BootInfo,
    GetInfoResponse, Operation, RootEpochRegistry,
};

use crate::{
    config::{KmsConfig, RootKeyPaths},
    crypto::{derive_k256_key, sign_message, sign_message_with_timestamp},
};

pub(crate) mod amd_attest;
pub(crate) mod upgrade_authority;

/// How long the auth API's info and this KMS's own authorization are reused.
///
/// `GetMeta` and `GetAppEnvEncryptPubKey` need no client certificate, and each
/// would otherwise cost the auth API a round of chain RPC calls. Concurrent callers share one
/// in-flight request. App authorization is never cached.
const AUTH_API_CACHE_TTL: Duration = Duration::from_secs(1);

/// How long this KMS's own verified boot info is reused.
///
/// Its measurements do not change while the KMS runs, but the TCB status and advisories do when
/// the platform's collateral is updated, and the auth API judges them on every self check.
const SELF_BOOT_INFO_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Clone)]
pub struct KmsState {
    inner: Arc<KmsStateInner>,
}

impl std::ops::Deref for KmsState {
    type Target = KmsStateInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// The root key pair of one epoch.
struct RootKeys {
    ca: CaCert,
    k256: SigningKey,
}

impl RootKeys {
    fn load(paths: &RootKeyPaths) -> Result<Self> {
        let ca = CaCert::load(&paths.ca_cert, &paths.ca_key)
            .context("failed to load root CA certificate")?;
        let key_bytes = fs::read(&paths.k256_key).context("failed to read ECDSA root key")?;
        let k256 = SigningKey::from_slice(&key_bytes).context("failed to load ECDSA root key")?;
        Ok(Self { ca, k256 })
    }
}

/// The root keys of epochs 0..=latest this KMS holds, and their chain hashes.
pub(crate) struct Keyring {
    roots: Vec<RootKeys>,
    chain_hashes: Vec<[u8; 32]>,
}

impl Keyring {
    pub(crate) fn load(config: &KmsConfig) -> Result<Self> {
        let latest = read_root_epoch(config)?;
        let roots = (0..=latest)
            .map(|epoch| {
                RootKeys::load(&config.root_key_paths(epoch, latest))
                    .with_context(|| format!("failed to load root keys of epoch {epoch}"))
            })
            .collect::<Result<Vec<_>>>()?;
        let chain_hashes = root_chain_hashes(roots.iter().map(|root| (&root.ca.key, &root.k256)));
        Ok(Self {
            roots,
            chain_hashes,
        })
    }

    pub(crate) fn latest(&self) -> u32 {
        self.roots.len() as u32 - 1
    }

    pub(crate) fn servable_epoch(&self, registry: RootEpochRegistry) -> Result<u32> {
        servable_epoch(&self.chain_hashes, registry)
    }
}

/// Chain hashes of the root keys of epochs 0, 1, ...
pub(crate) fn root_chain_hashes<'a>(
    roots: impl Iterator<Item = (&'a KeyPair, &'a SigningKey)>,
) -> Vec<[u8; 32]> {
    let pubkeys: Vec<_> = roots
        .map(|(ca, k256)| {
            (
                ca.public_key_der(),
                k256.verifying_key().to_sec1_bytes().to_vec(),
            )
        })
        .collect();
    dstack_types::root_epoch::chain_hashes(pubkeys.iter().map(|(ca, k256)| (&ca[..], &k256[..])))
}

/// The epoch a keyring with `chain_hashes` serves under `registry`: the
/// current epoch, which the keyring must hold with a matching chain hash. A
/// keyring nobody registered is servable only at epoch 0, as before root
/// epochs existed.
pub(crate) fn servable_epoch(
    chain_hashes: &[[u8; 32]],
    registry: RootEpochRegistry,
) -> Result<u32> {
    let latest = chain_hashes.len() as u32 - 1;
    let current = match registry {
        RootEpochRegistry::Unchecked => return Ok(latest),
        RootEpochRegistry::Empty if latest == 0 => return Ok(0),
        RootEpochRegistry::Empty => {
            bail!("the keyring holds root epoch {latest}, but no root epoch is registered")
        }
        RootEpochRegistry::Current(current) => current,
    };
    match chain_hashes.get(current.epoch as usize) {
        Some(hash) if *hash == current.chain_hash => Ok(current.epoch),
        Some(_) => bail!(
            "the root keys up to epoch {} are not the registered ones",
            current.epoch
        ),
        None => bail!(
            "root epoch {} is current, but the keyring holds only up to {latest}",
            current.epoch
        ),
    }
}

pub struct KmsStateInner {
    config: KmsConfig,
    keyring: Keyring,
    temp_ca: CaCert,
    /// The CA of the running TLS listener, independent of key selection.
    rpc_ca_pubkey: Vec<u8>,
    restart: tokio::sync::Notify,
    verifier: CvmVerifier,
    attestation_verifier: Arc<AttestationVerifier>,
    self_boot_info: Cache<(), BootInfo>,
    self_allowed: Cache<Operation, AuthorizationResult>,
    auth_api_info: Cache<(), GetInfoResponse>,
    metrics: KmsMetrics,
}

#[derive(Default)]
pub(crate) struct KmsMetrics {
    attestation_requests_total: AtomicU64,
    attestation_failures_total: AtomicU64,
}

impl KmsMetrics {
    pub(crate) fn record_attestation_request(&self, failed: bool) {
        self.attestation_requests_total
            .fetch_add(1, Ordering::Relaxed);
        if failed {
            self.attestation_failures_total
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn render_prometheus(&self) -> String {
        let attestation_requests_total = self.attestation_requests_total.load(Ordering::Relaxed);
        let attestation_failures_total = self.attestation_failures_total.load(Ordering::Relaxed);

        format!(
            "# HELP dstack_kms_attestation_requests_total Total number of KMS attestation requests.\n\
             # TYPE dstack_kms_attestation_requests_total counter\n\
             dstack_kms_attestation_requests_total {attestation_requests_total}\n\
             # HELP dstack_kms_attestation_failures_total Total number of failed KMS attestation requests.\n\
             # TYPE dstack_kms_attestation_failures_total counter\n\
             dstack_kms_attestation_failures_total {attestation_failures_total}\n"
        )
    }
}

fn short_lived_cache<K, V>(capacity: u64) -> Cache<K, V>
where
    K: Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::builder()
        .max_capacity(capacity)
        .time_to_live(AUTH_API_CACHE_TTL)
        .build()
}

impl KmsState {
    /// clear cached image and measurement material for the given hashes. Used by
    /// the admin `ClearImageCache` RPC; authorization is enforced by the admin
    /// listener's HTTP authenticator, not here.
    pub(crate) fn clear_image_cache(&self, image_hash: &str, config_hash: &str) -> Result<()> {
        self.verifier.clear_cache(image_hash, config_hash)
    }

    pub fn new(config: KmsConfig, keyring: Keyring, rpc_ca_cert: String) -> Result<Self> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(rpc_ca_cert.as_bytes())
            .context("invalid RPC CA certificate")?;
        let rpc_ca_pubkey = pem
            .parse_x509()
            .context("invalid RPC CA certificate")?
            .public_key()
            .raw
            .to_vec();
        let attestation_verifier = Arc::new(
            AttestationVerifier::load(&config.attestation)
                .context("failed to load attestation verifier")?,
        );
        let verifier = CvmVerifier::new(
            config.image.cache_dir.display().to_string(),
            config.image.download_url.clone(),
            config.image.download_timeout,
            attestation_verifier.clone(),
        );
        if !config.enforce_self_authorization {
            warn!(
                "self-authorization is disabled; trusted RPCs will not be gated by KMS self-attestation - do not use in production TEE deployments"
            );
        }
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                temp_ca: crate::onboard_service::ensure_temp_ca(&config)?,
                config,
                keyring,
                rpc_ca_pubkey,
                restart: tokio::sync::Notify::new(),
                verifier,
                attestation_verifier,
                self_boot_info: Cache::builder()
                    .max_capacity(1)
                    .time_to_live(SELF_BOOT_INFO_TTL)
                    .build(),
                self_allowed: short_lived_cache(4),
                auth_api_info: short_lived_cache(1),
                metrics: KmsMetrics::default(),
            }),
        })
    }

    pub(crate) fn metrics(&self) -> &KmsMetrics {
        &self.inner.metrics
    }

    pub(crate) fn attestation_verifier(&self) -> Arc<AttestationVerifier> {
        self.inner.attestation_verifier.clone()
    }

    fn epoch_root(&self, epoch: u32) -> Result<&RootKeys> {
        self.keyring
            .roots
            .get(epoch as usize)
            .with_context(|| format!("root epoch {epoch} is not held by this KMS"))
    }

    pub async fn restart_requested(&self) {
        self.restart.notified().await
    }

    async fn current_epoch_from_info(&self) -> Result<u32> {
        let info = self
            .auth_api_info
            .try_get_with((), self.config.auth_api.get_info())
            .await
            .map_err(|err| anyhow!("{err:#}"))?;
        self.keyring.servable_epoch(info.root_epochs)
    }

    /// Resolve this request from its authorization result; no serving epoch is cached.
    fn authorized_epoch(
        &self,
        result: &AuthorizationResult,
        requested: Option<u32>,
    ) -> Result<u32> {
        if result.current_app_epoch != 0 {
            bail!("this KMS does not support nonzero app epochs");
        }
        let current = if self.config.auth_api.is_dev() {
            self.keyring.latest()
        } else {
            let current = result
                .current_root()?
                .context("Root epoch not registered")?;
            self.keyring
                .servable_epoch(RootEpochRegistry::Current(current))?
        };
        if !result.is_allowed {
            bail!("Authorization denied: {}", result.rejection_reason);
        }
        let epoch = requested.unwrap_or(current);
        if epoch > current {
            bail!("root epoch {epoch} is not active; the current one is {current}");
        }
        self.epoch_root(epoch)?;
        Ok(epoch)
    }

    /// Keep the running TLS issuer consistent with default key responses until reload.
    fn ensure_rpc_ca(&self, current_epoch: u32) -> Result<()> {
        if self.epoch_root(current_epoch)?.ca.key.public_key_der() != self.rpc_ca_pubkey {
            self.restart.notify_one();
            bail!("the RPC root CA changed; retry after the TLS certificate is refreshed");
        }
        Ok(())
    }
}

/// Wait for the registered current roots to issue the RPC certificate at startup.
/// An epoch-0 keyring may start while the info endpoint is unreachable, but
/// key release still requires an authorization result with registered roots.
pub(crate) async fn wait_for_servable_epoch(config: &KmsConfig, keyring: &Keyring) -> u32 {
    const RETRY: Duration = Duration::from_secs(10);
    loop {
        let result = match config.auth_api.get_info().await {
            Ok(info) => keyring.servable_epoch(info.root_epochs),
            Err(err) if keyring.latest() == 0 => {
                warn!("skipping the root epoch check: {err:#}");
                return 0;
            }
            Err(err) => Err(err.context("failed to read the current root epoch")),
        };
        match result {
            Ok(epoch) => return epoch,
            Err(err) => {
                warn!("not serving yet: {err:#}; retrying in {}s", RETRY.as_secs());
                tokio::time::sleep(RETRY).await;
            }
        }
    }
}

struct AppKeys {
    disk_crypt_key: Vec<u8>,
    env_crypt_key: Vec<u8>,
    k256_key: Vec<u8>,
    k256_signature: Vec<u8>,
}

fn derive_app_keys(root: &RootKeys, app_id: &[u8], instance_id: &[u8]) -> Result<AppKeys> {
    let disk_crypt_key =
        kdf::derive_dh_secret(&root.ca.key, &[app_id, instance_id, b"app-disk-crypt-key"])
            .context("Failed to derive app disk key")?;
    let env_crypt_key = kdf::derive_dh_secret(&root.ca.key, &[app_id, b"env-encrypt-key"])
        .context("Failed to derive env encrypt key")?;
    let env_crypt_key = x25519_dalek::StaticSecret::from(env_crypt_key).to_bytes();
    let (k256_key, k256_signature) =
        derive_k256_key(&root.k256, app_id).context("Failed to derive app ecdsa key")?;
    Ok(AppKeys {
        disk_crypt_key: disk_crypt_key.to_vec(),
        env_crypt_key: env_crypt_key.to_vec(),
        k256_key: k256_key.to_bytes().to_vec(),
        k256_signature,
    })
}

pub(crate) fn read_root_epoch(config: &KmsConfig) -> Result<u32> {
    match fs::read_to_string(config.root_epoch()) {
        Ok(epoch) => epoch.trim().parse().context("invalid root epoch file"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => Err(err).context("failed to read root epoch file"),
    }
}

pub struct RpcHandler {
    state: KmsState,
    attestation: Option<VerifiedAttestation>,
}

impl RpcHandler {
    pub(crate) fn from_context(context: CallContext<'_, KmsState>) -> Self {
        Self {
            state: context.state.clone(),
            attestation: context.attestation,
        }
    }

    pub(crate) async fn handover_keys(self, request: GetKmsKeyRequest) -> Result<KmsKeyResponse> {
        self.ensure_self_allowed(Operation::KmsExportKeys)
            .await
            .context("KMS self authorization failed")?;
        let info = self.ensure_kms_allowed(&request.vm_config).await?;
        ensure_key_release_allowed(&info, (&self.state.config).into())?;
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.temp_ca.key.serialize_pem(),
            keys: self
                .state
                .keyring
                .roots
                .iter()
                .map(|root| KmsKeys {
                    ca_key: root.ca.key.serialize_pem(),
                    k256_key: root.k256.to_bytes().to_vec(),
                })
                .collect(),
        })
    }
}

struct BootConfig {
    boot_info: BootInfo,
    gateway_app_id: String,
    root_epoch: u32,
}

pub(crate) fn build_boot_info_for_attestation(
    att: &VerifiedAttestation,
    use_boottime_mr: bool,
    vm_config_str: &str,
) -> Result<BootInfo> {
    let boot_info = if att.report.amd_snp_report().is_some() {
        amd_attest::build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
            att,
            resolve_vm_config(vm_config_str, &att.config)?,
        )?
    } else {
        build_boot_info(att, use_boottime_mr, vm_config_str)?
    };
    ensure_app_id_len(&boot_info.app_id)?;
    Ok(boot_info)
}

/// The per-platform local key-release opt-ins, read from `KmsConfig`.
///
/// Carried as a named struct rather than positional bools so that adding a
/// platform does not silently reorder an existing call site.
#[derive(Debug, Clone, Copy, Default)]
struct KeyReleasePolicy {
    snp: bool,
    aws_nitro_tpm: bool,
    nitro_enclave: bool,
}

impl From<&KmsConfig> for KeyReleasePolicy {
    fn from(config: &KmsConfig) -> Self {
        Self {
            snp: config.sev_snp_key_release,
            aws_nitro_tpm: config.aws_nitro_tpm_key_release,
            nitro_enclave: config.nitro_enclave_key_release,
        }
    }
}

fn ensure_key_release_allowed(boot_info: &BootInfo, policy: KeyReleasePolicy) -> Result<()> {
    match boot_info.tee_variant {
        TeeVariant::DstackAmdSevSnp if !policy.snp => {
            bail!("amd sev-snp key release is not enabled")
        }
        TeeVariant::DstackAwsNitroTpm if !policy.aws_nitro_tpm => {
            bail!("aws nitro-tpm key release is not enabled")
        }
        TeeVariant::DstackNitroEnclave if !policy.nitro_enclave => {
            bail!("aws nitro enclave key release is not enabled")
        }
        _ => Ok(()),
    }
}

impl RpcHandler {
    async fn ensure_self_allowed(&self, operation: Operation) -> Result<u32> {
        if !self.state.config.enforce_self_authorization {
            let epoch = self.state.current_epoch_from_info().await?;
            self.state.ensure_rpc_ca(epoch)?;
            return Ok(epoch);
        }
        let boot_info = self
            .state
            .self_boot_info
            .try_get_with((), local_kms_boot_info(&self.state.attestation_verifier))
            .await
            .map_err(|err| anyhow!("{err:#}"))
            .context("Failed to load cached self boot info")?;
        let response = self
            .state
            .self_allowed
            .try_get_with(operation, async {
                let response = self
                    .state
                    .config
                    .auth_api
                    .authorize_kms(&boot_info, operation, None)
                    .await
                    .context("Failed to call self KMS auth check")?;
                let epoch = self.state.authorized_epoch(&response, None)?;
                self.state.ensure_rpc_ca(epoch)?;
                Ok::<_, anyhow::Error>(response)
            })
            .await
            .map_err(|err| anyhow!("{err:#}"))?;
        let epoch = self.state.authorized_epoch(&response, None)?;
        Ok(epoch)
    }

    fn ensure_attested(&self) -> Result<&VerifiedAttestation> {
        let Some(attestation) = &self.attestation else {
            bail!("No attestation provided");
        };
        Ok(attestation)
    }

    async fn ensure_kms_allowed(&self, vm_config: &str) -> Result<BootInfo> {
        let att = self.ensure_attested()?;
        let boot_info = build_boot_info_for_attestation(att, false, vm_config)?;
        let response = self
            .state
            .config
            .auth_api
            .authorize_kms(&boot_info, Operation::KmsImportKeys, None)
            .await?;
        self.state.authorized_epoch(&response, None)?;
        self.ensure_attestation_policy(att, vm_config, &boot_info, &response)
            .await?;
        Ok(boot_info)
    }

    async fn ensure_app_boot_allowed(
        &self,
        vm_config: &str,
        requested_root_epoch: Option<u32>,
    ) -> Result<BootConfig> {
        let att = self.ensure_attested()?;
        let boot_info = build_boot_info_for_attestation(att, false, vm_config)?;
        self.ensure_app_attestation_allowed(
            att,
            boot_info,
            vm_config,
            Operation::AppGetKey,
            requested_root_epoch,
        )
        .await
    }

    async fn ensure_app_attestation_allowed(
        &self,
        att: &VerifiedAttestation,
        boot_info: BootInfo,
        vm_config: &str,
        operation: Operation,
        requested_root_epoch: Option<u32>,
    ) -> Result<BootConfig> {
        let response = self
            .state
            .config
            .auth_api
            .authorize_app(&boot_info, operation, requested_root_epoch)
            .await?;
        let root_epoch = self
            .state
            .authorized_epoch(&response, requested_root_epoch)?;
        self.ensure_attestation_policy(att, vm_config, &boot_info, &response)
            .await?;
        Ok(BootConfig {
            boot_info,
            gateway_app_id: response.gateway_app_id,
            root_epoch,
        })
    }

    async fn ensure_attestation_policy(
        &self,
        att: &VerifiedAttestation,
        vm_config: &str,
        boot_info: &BootInfo,
        response: &AuthorizationResult,
    ) -> Result<()> {
        let current_epoch = if self.state.config.auth_api.is_dev() {
            self.state.keyring.latest()
        } else {
            response.current_root_epoch
        };
        self.state.ensure_rpc_ca(current_epoch)?;
        // SNP rootfs/app/config binding is handled by the SNP launch-measurement
        // helper above. The legacy OS-image verifier is TDX-oriented and still
        // rejects SNP quotes; keep SNP on the explicit fail-closed helper path.
        if boot_info.tee_variant != TeeVariant::DstackAmdSevSnp {
            self.state
                .verifier
                .verify_os_image_hash(vm_config.into(), att, &mut VerificationDetails::default())
                .await
                .context("Failed to verify os image hash")?;
        }
        Ok(())
    }

    fn derive_app_ca(&self, app_id: &[u8], root: &RootKeys) -> Result<CaCert> {
        let context_data = vec![app_id, b"app-ca"];
        let app_key = kdf::derive_p256_key_pair(&root.ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let req = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        let app_ca = root.ca.sign(req).context("Failed to sign App CA")?;
        Ok(CaCert::from_parts(app_key, app_ca))
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self, request: GetAppKeyRequest) -> Result<AppKeyResponse> {
        if request.api_version > 1 {
            bail!("Unsupported API version: {}", request.api_version);
        }
        self.ensure_self_allowed(Operation::KmsServe)
            .await
            .context("KMS self authorization failed")?;
        let BootConfig {
            boot_info,
            gateway_app_id,
            root_epoch,
        } = self
            .ensure_app_boot_allowed(&request.vm_config, request.root_epoch)
            .await
            .context("App not allowed")?;
        ensure_key_release_allowed(&boot_info, (&self.state.config).into())?;
        let root = self.state.epoch_root(root_epoch)?;
        let keys = derive_app_keys(root, &boot_info.app_id, &boot_info.instance_id)?;

        Ok(AppKeyResponse {
            ca_cert: root.ca.pem_cert.clone(),
            disk_crypt_key: keys.disk_crypt_key,
            env_crypt_key: keys.env_crypt_key,
            k256_key: keys.k256_key,
            k256_signature: keys.k256_signature,
            tproxy_app_id: gateway_app_id.clone(),
            gateway_app_id,
            os_image_hash: boot_info.os_image_hash,
            root_epoch,
        })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let epoch = self
            .ensure_self_allowed(Operation::KmsServe)
            .await
            .context("KMS self authorization failed")?;
        let root = self.state.epoch_root(epoch)?;
        ensure_app_id_len(&request.app_id)?;
        let secret = kdf::derive_dh_secret(
            &root.ca.key,
            &[&request.app_id[..], "env-encrypt-key".as_bytes()],
        )
        .context("Failed to derive env encrypt key")?;
        let secret = x25519_dalek::StaticSecret::from(secret);
        let pubkey = x25519_dalek::PublicKey::from(&secret);

        let public_key = pubkey.to_bytes().to_vec();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("System time before UNIX epoch")?
            .as_secs();

        // Legacy signature (without timestamp) for backward compatibility
        let signature = sign_message(
            &root.k256,
            b"dstack-env-encrypt-pubkey",
            &request.app_id,
            &public_key,
        )
        .context("Failed to sign the public key")?;

        // New signature with timestamp to prevent replay attacks
        let signature_v1 = sign_message_with_timestamp(
            &root.k256,
            b"dstack-env-encrypt-pubkey",
            &request.app_id,
            timestamp,
            &public_key,
        )
        .context("Failed to sign the public key with timestamp")?;

        Ok(PublicKeyResponse {
            public_key,
            signature,
            timestamp,
            signature_v1,
        })
    }

    async fn get_meta(self) -> Result<GetMetaResponse> {
        let bootstrap_info = fs::read_to_string(self.state.config.bootstrap_info())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok());
        let info = self
            .state
            .auth_api_info
            .try_get_with((), self.state.config.auth_api.get_info())
            .await
            .map_err(|err| anyhow!("{err:#}"))?;
        let epoch = self.state.keyring.servable_epoch(info.root_epochs)?;
        let root = self.state.epoch_root(epoch)?;
        Ok(GetMetaResponse {
            ca_cert: root.ca.pem_cert.clone(),
            allow_any_upgrade: self.state.inner.config.auth_api.is_dev(),
            k256_pubkey: root.k256.verifying_key().to_sec1_bytes().to_vec(),
            bootstrap_info,
            is_dev: self.state.config.auth_api.is_dev(),
            kms_contract_address: info.kms_contract_address,
            chain_id: info.chain_id,
            gateway_app_id: info.gateway_app_id,
            app_auth_implementation: info.app_implementation,
            os_image_verification: Some(true),
        })
    }

    async fn get_kms_key(self, request: GetKmsKeyRequest) -> Result<KmsKeyResponse> {
        if !self.state.config.onboard.public_key_handover {
            bail!("public KMS key handover is disabled; use the admin listener");
        }
        self.handover_keys(request).await
    }

    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        let epoch = self.ensure_self_allowed(Operation::KmsServe).await?;
        if self.state.config.enforce_self_authorization {
            let boot_info = self
                .state
                .self_boot_info
                .get(&())
                .await
                .context("missing authorized KMS boot info")?;
            ensure_key_release_allowed(&boot_info, (&self.state.config).into())?;
        }
        Ok(GetTempCaCertResponse {
            temp_ca_cert: self.state.temp_ca.pem_cert.clone(),
            temp_ca_key: self.state.temp_ca.key.serialize_pem(),
            ca_cert: self.state.epoch_root(epoch)?.ca.pem_cert.clone(),
        })
    }

    async fn sign_cert(self, request: SignCertRequest) -> Result<SignCertResponse> {
        self.ensure_self_allowed(Operation::KmsServe)
            .await
            .context("KMS self authorization failed")?;
        let csr = match request.api_version {
            1 => {
                let csr = CertSigningRequestV1::decode(&mut &request.csr[..])
                    .context("Failed to parse csr")?;
                csr.verify(&request.signature)
                    .context("Failed to verify csr signature")?;
                csr.try_into().context("Failed to upgrade csr v1 to v2")?
            }
            2 => {
                let csr = CertSigningRequestV2::decode(&mut &request.csr[..])
                    .context("Failed to parse csr")?;
                csr.verify(&request.signature)
                    .context("Failed to verify csr signature")?;
                csr
            }
            _ => bail!("Unsupported API version: {}", request.api_version),
        };
        let attestation = csr
            .attestation
            .clone()
            .into_v1()
            .verify_with_ra_pubkey(&csr.pubkey, &self.state.attestation_verifier)
            .await
            .context("Quote verification failed")?;
        let boot_info = build_boot_info_for_attestation(&attestation, true, &request.vm_config)?;
        let app_info = self
            .ensure_app_attestation_allowed(
                &attestation,
                boot_info,
                &request.vm_config,
                Operation::AppGetCert,
                None,
            )
            .await?;
        ensure_key_release_allowed(&app_info.boot_info, (&self.state.config).into())?;
        let root = self.state.epoch_root(app_info.root_epoch)?;
        let app_ca = self.derive_app_ca(&app_info.boot_info.app_id, root)?;
        // Stamp the identity verified above, not the requester's own claims.
        // Runtime measurements (`false`) are what certificates have always carried.
        let cert_app_info = attestation
            .decode_app_info_ex(false, &request.vm_config)
            .context("Failed to decode the verified app info")?;
        let cert = app_ca
            .sign_csr(&csr, Some(&cert_app_info), "app:custom")
            .context("Failed to sign certificate")?;
        Ok(SignCertResponse {
            certificate_chain: vec![
                cert.pem(),
                app_ca.pem_cert.clone(),
                root.ca.pem_cert.clone(),
            ],
        })
    }
}

impl RpcCall<KmsState> for RpcHandler {
    type PrpcService = KmsServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        Ok(RpcHandler::from_context(context))
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <KmsServer<RpcHandler>>::supported_methods()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_service::amd_attest::{
        compute_expected_measurement, MeasurementInput, OvmfSectionParam,
    };
    use cc_eventlog::RuntimeEvent;
    use sha2::{Digest, Sha256, Sha384};
    use std::{path::Path, time::Duration};

    const SNP_ENABLED: KeyReleasePolicy = KeyReleasePolicy {
        snp: true,
        aws_nitro_tpm: false,
        nitro_enclave: false,
    };
    const NITRO_ENCLAVE_ENABLED: KeyReleasePolicy = KeyReleasePolicy {
        snp: false,
        aws_nitro_tpm: false,
        nitro_enclave: true,
    };

    use std::collections::BTreeMap;

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn valid_snp_measurement_input() -> MeasurementInput {
        let rootfs_hash = hex_of(0x33, 32);
        MeasurementInput {
            base_cmdline: format!("console=ttyS0 dstack.rootfs_hash={rootfs_hash}"),
            ovmf_hash: hex_of(0x44, 48),
            kernel_hash: hex_of(0x55, 32),
            initrd_hash: hex_of(0x66, 32),
            sev_hashes_table_gpa: 0x80_1000,
            sev_es_reset_eip: 0xffff_fff0,
            vcpus: 2,
            vcpu_type: Some("epyc-v4".to_string()),
            guest_features: 1,
            ovmf_sections: vec![
                OvmfSectionParam {
                    gpa: 0x100000,
                    size: 0x2000,
                    section_type: 1,
                },
                OvmfSectionParam {
                    gpa: 0x80_0000,
                    size: 0x1000,
                    section_type: 0x10,
                },
                OvmfSectionParam {
                    gpa: 0x81_0000,
                    size: 0x1000,
                    section_type: 2,
                },
                OvmfSectionParam {
                    gpa: 0x82_0000,
                    size: 0x1000,
                    section_type: 3,
                },
            ],
        }
    }

    fn valid_snp_mr_config() -> dstack_types::mr_config::MrConfigV3 {
        dstack_types::mr_config::MrConfigV3::new(
            vec![0x11; 20],
            vec![0x22; 32],
            None,
            dstack_types::KeyProviderKind::None,
            Vec::new(),
            vec![0x99; 20],
        )
    }

    fn verified_snp_attestation(measurement: [u8; 48], chip_id: [u8; 64]) -> VerifiedAttestation {
        let mr_config = valid_snp_mr_config();
        verified_snp_attestation_with_config(measurement, chip_id, String::new(), &mr_config)
    }

    fn verified_snp_attestation_with_config(
        measurement: [u8; 48],
        chip_id: [u8; 64],
        config: String,
        mr_config: &dstack_types::mr_config::MrConfigV3,
    ) -> VerifiedAttestation {
        VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAmdSevSnp(
                ra_tls::attestation::SnpQuote {
                    report: Vec::new(),
                    cert_chain: Vec::new(),
                    mr_config: mr_config.to_canonical_json(),
                },
            ),
            runtime_events: Vec::new(),
            report_data: [0x42; 64],
            config,
            report: ra_tls::attestation::DstackVerifiedReport::DstackAmdSevSnp(
                dstack_attest::amd_sev_snp::VerifiedAmdSnpReport {
                    measurement,
                    report_data: [0x42; 64],
                    host_data: mr_config.to_snp_host_data(),
                    chip_id,
                    tcb_info: dstack_attest::amd_sev_snp::AmdSnpTcbInfo::default(),
                    advisory_ids: Vec::new(),
                },
            ),
        }
    }

    fn snp_measurement_document(
        input: &MeasurementInput,
    ) -> dstack_mr::sev::SnpMeasurementDocument {
        let measurement = dstack_mr::sev::sev_os_image_measurement_from_input(input)
            .unwrap()
            .to_cbor_vec();
        let sha256sum = format!(
            "{}  {}\n",
            hex::encode(sha2::Sha256::digest(&measurement)),
            dstack_types::SNP_MEASUREMENT_FILENAME
        )
        .into_bytes();
        dstack_mr::sev::SnpMeasurementDocument {
            checksum_file: sha256sum,
            measurement,
            vcpus: input.vcpus,
            vcpu_type: input.vcpu_type.clone(),
            guest_features: input.guest_features,
        }
    }

    fn snp_vm_config(
        input: &MeasurementInput,
        mr_config: &dstack_types::mr_config::MrConfigV3,
    ) -> String {
        let document = snp_measurement_document(input);
        serde_json::json!({
            "os_image_hash": hex::encode(dstack_types::image_hash_from_sha256sum(&document.checksum_file)),
            "sev_snp_measurement": serde_json::to_string(&document).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string()
    }

    fn sha256_chunks(chunks: &[&[u8]]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        for chunk in chunks {
            hasher.update(chunk);
        }
        hasher.finalize().to_vec()
    }

    fn replay_runtime_events_sha384(events: &[RuntimeEvent]) -> Vec<u8> {
        let mut pcr = [0u8; 48];
        for event in events {
            let mut hasher = Sha384::new();
            hasher.update(pcr);
            hasher.update(event.sha384_digest());
            pcr = hasher.finalize().into();
            if event.event == "system-ready" {
                break;
            }
        }
        pcr.to_vec()
    }

    fn aws_nitro_tpm_boot_pcrs(pcr4_byte: u8) -> BTreeMap<u16, Vec<u8>> {
        BTreeMap::from([
            (4, vec![pcr4_byte; 48]),
            (7, vec![0x77; 48]),
            (12, vec![0x12; 48]),
        ])
    }

    fn aws_nitro_tpm_os_image_hash(pcrs: &BTreeMap<u16, Vec<u8>>) -> Vec<u8> {
        sha256_chunks(&[&pcrs[&4], &pcrs[&7], &pcrs[&12]])
    }

    fn expected_aws_nitro_tpm_mr_system(
        pcrs: &BTreeMap<u16, Vec<u8>>,
        key_provider_info: &[u8],
    ) -> Vec<u8> {
        let mr_key_provider = sha256_chunks(&[key_provider_info]);
        sha256_chunks(&[&pcrs[&4], &pcrs[&7], &pcrs[&12], &mr_key_provider])
    }

    fn expected_aws_nitro_tpm_mr_aggregated(
        pcrs: &BTreeMap<u16, Vec<u8>>,
        runtime_events: &[RuntimeEvent],
    ) -> Vec<u8> {
        let launch_pcr = replay_runtime_events_sha384(runtime_events);
        sha256_chunks(&[&pcrs[&4], &pcrs[&7], &pcrs[&12], &launch_pcr])
    }

    fn runtime_event(event: &str, payload: Vec<u8>) -> RuntimeEvent {
        RuntimeEvent::new(event.to_string(), payload, Default::default())
    }

    fn verified_aws_nitro_tpm_attestation(
        compose_hash: Vec<u8>,
        pcr4_byte: u8,
    ) -> (VerifiedAttestation, String, Vec<u8>, Vec<u8>) {
        let key_provider_info = aws_nitro_tpm_key_provider_info();
        let runtime_events = aws_nitro_tpm_runtime_events(compose_hash, &key_provider_info);
        verified_aws_nitro_tpm_attestation_with_events(runtime_events, pcr4_byte, key_provider_info)
    }

    fn aws_nitro_tpm_key_provider_info() -> Vec<u8> {
        br#"{"name":"tpm","id":"aws-test"}"#.to_vec()
    }

    fn aws_nitro_tpm_runtime_events(
        compose_hash: Vec<u8>,
        key_provider_info: &[u8],
    ) -> Vec<RuntimeEvent> {
        vec![
            runtime_event("system-preparing", Vec::new()),
            runtime_event("app-id", vec![0x11; 20]),
            runtime_event("compose-hash", compose_hash),
            runtime_event("instance-id", vec![0x33; 20]),
            runtime_event("boot-mr-done", Vec::new()),
            runtime_event("key-provider", key_provider_info.to_vec()),
            runtime_event("storage-fs", vec![0x44; 32]),
            runtime_event("system-ready", Vec::new()),
        ]
    }

    fn verified_aws_nitro_tpm_attestation_with_events(
        runtime_events: Vec<RuntimeEvent>,
        pcr4_byte: u8,
        key_provider_info: Vec<u8>,
    ) -> (VerifiedAttestation, String, Vec<u8>, Vec<u8>) {
        let mut pcrs = aws_nitro_tpm_boot_pcrs(pcr4_byte);
        pcrs.insert(14, replay_runtime_events_sha384(&runtime_events));
        let os_image_hash = aws_nitro_tpm_os_image_hash(&pcrs);
        let vm_config = serde_json::json!({
            "os_image_hash": hex::encode(&os_image_hash),
        })
        .to_string();

        let attestation = VerifiedAttestation {
            quote: ra_tls::attestation::AttestationQuote::DstackAwsNitroTpm(
                ra_tls::attestation::DstackAwsNitroTpmQuote {
                    attestation_doc: Vec::new(),
                },
            ),
            runtime_events,
            report_data: [0x42; 64],
            config: String::new(),
            report: ra_tls::attestation::DstackVerifiedReport::DstackAwsNitroTpm(
                ra_tls::attestation::AwsNitroTpmVerifiedReport {
                    module_id: "i-aws-nitrotpm-test".to_string(),
                    pcrs,
                    public_key: Some(vec![0x55; 32]),
                    user_data: vec![0x42; 64],
                    nonce: Some(vec![0x66; 32]),
                    timestamp: 1,
                },
            ),
        };
        (attestation, vm_config, os_image_hash, key_provider_info)
    }

    fn verified_aws_nitro_tpm_pcrs(att: &VerifiedAttestation) -> &BTreeMap<u16, Vec<u8>> {
        match &att.report {
            ra_tls::attestation::DstackVerifiedReport::DstackAwsNitroTpm(report) => &report.pcrs,
            _ => panic!("expected AWS NitroTPM report"),
        }
    }

    fn verified_aws_nitro_tpm_pcrs_mut(
        att: &mut VerifiedAttestation,
    ) -> &mut BTreeMap<u16, Vec<u8>> {
        match &mut att.report {
            ra_tls::attestation::DstackVerifiedReport::DstackAwsNitroTpm(report) => {
                &mut report.pcrs
            }
            _ => panic!("expected AWS NitroTPM report"),
        }
    }

    #[test]
    fn build_boot_info_for_attestation_binds_aws_nitro_tpm_app_measurement() {
        let (attestation, vm_config, os_image_hash, key_provider_info) =
            verified_aws_nitro_tpm_attestation(vec![0x22; 32], 0x04);
        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("aws nitrotpm attestation should produce KMS boot info");
        let pcrs = verified_aws_nitro_tpm_pcrs(&attestation);

        assert_eq!(boot_info.tee_variant, TeeVariant::DstackAwsNitroTpm);
        assert_eq!(boot_info.tcb_status, "UpToDate");
        assert!(boot_info.advisory_ids.is_empty());
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
        assert_eq!(boot_info.compose_hash, vec![0x22; 32]);
        assert_eq!(boot_info.instance_id, vec![0x33; 20]);
        assert_eq!(boot_info.key_provider_info, key_provider_info);
        assert_eq!(boot_info.os_image_hash, os_image_hash);
        assert_eq!(
            boot_info.mr_system,
            expected_aws_nitro_tpm_mr_system(pcrs, &boot_info.key_provider_info)
        );
        assert_eq!(
            boot_info.mr_aggregated,
            expected_aws_nitro_tpm_mr_aggregated(pcrs, &attestation.runtime_events)
        );

        let (changed_app_attestation, changed_app_vm_config, _, _) =
            verified_aws_nitro_tpm_attestation(vec![0x23; 32], 0x04);
        let changed_app_boot_info = build_boot_info_for_attestation(
            &changed_app_attestation,
            false,
            &changed_app_vm_config,
        )
        .expect("changed app identity should still decode");
        assert_eq!(boot_info.mr_system, changed_app_boot_info.mr_system);
        assert_ne!(boot_info.compose_hash, changed_app_boot_info.compose_hash);
        assert_ne!(boot_info.mr_aggregated, changed_app_boot_info.mr_aggregated);

        let (changed_boot_attestation, changed_boot_vm_config, _, _) =
            verified_aws_nitro_tpm_attestation(vec![0x22; 32], 0x05);
        let changed_boot_info = build_boot_info_for_attestation(
            &changed_boot_attestation,
            false,
            &changed_boot_vm_config,
        )
        .expect("changed verified boot PCRs should still decode");
        assert_ne!(boot_info.mr_system, changed_boot_info.mr_system);
        assert_ne!(boot_info.mr_aggregated, changed_boot_info.mr_aggregated);
    }

    #[test]
    fn aws_nitro_tpm_key_release_requires_explicit_enablement() {
        let (attestation, vm_config, _, _) =
            verified_aws_nitro_tpm_attestation(vec![0x22; 32], 0x04);
        let mut boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("aws nitrotpm attestation should produce KMS boot info");

        // disabled (the default) fails closed for the new AWS NitroTPM mode
        let err = ensure_key_release_allowed(&boot_info, KeyReleasePolicy::default()).unwrap_err();
        assert!(err.to_string().contains("not enabled"));
        // explicitly enabled permits it
        ensure_key_release_allowed(
            &boot_info,
            KeyReleasePolicy {
                aws_nitro_tpm: true,
                ..Default::default()
            },
        )
        .unwrap();

        // A TDX boot info is unaffected by the AWS gate even when it is disabled.
        boot_info.tee_variant = TeeVariant::DstackTdx;
        ensure_key_release_allowed(&boot_info, KeyReleasePolicy::default()).unwrap();
    }

    #[test]
    fn build_boot_info_for_attestation_binds_aws_nitro_tpm_pcr12() {
        let (mut attestation, vm_config, _, _) =
            verified_aws_nitro_tpm_attestation(vec![0x22; 32], 0x04);
        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("base aws nitrotpm boot info should decode");

        verified_aws_nitro_tpm_pcrs_mut(&mut attestation).insert(12, vec![0x99; 48]);
        let changed_pcr12_boot_info =
            build_boot_info_for_attestation(&attestation, false, &vm_config)
                .expect("changed PCR12 should still decode into a different boot identity");
        assert_ne!(boot_info.mr_system, changed_pcr12_boot_info.mr_system);
        assert_ne!(
            boot_info.mr_aggregated,
            changed_pcr12_boot_info.mr_aggregated
        );

        verified_aws_nitro_tpm_pcrs_mut(&mut attestation).remove(&12);
        let err = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect_err("missing PCR12 must be rejected");
        assert!(
            format!("{err:#}").contains("PCR 12 not found"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn build_boot_info_for_attestation_rejects_reordered_aws_nitro_tpm_events() {
        let key_provider_info = aws_nitro_tpm_key_provider_info();
        let events = aws_nitro_tpm_runtime_events(vec![0x22; 32], &key_provider_info);
        let (mut attestation, vm_config, _, _) =
            verified_aws_nitro_tpm_attestation_with_events(events.clone(), 0x04, key_provider_info);

        attestation.runtime_events = events.clone();
        attestation.runtime_events.swap(2, 3);
        let err = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect_err("runtime event reordering must be rejected");
        assert!(
            format!("{err:#}").contains("PCR14 mismatch"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn build_boot_info_for_attestation_rejects_aws_nitro_tpm_missing_pcr14() {
        let (mut attestation, vm_config, _, _) =
            verified_aws_nitro_tpm_attestation(vec![0x22; 32], 0x04);
        verified_aws_nitro_tpm_pcrs_mut(&mut attestation).remove(&14);

        let err = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect_err("missing PCR14 must be rejected");

        assert!(format!("{err:#}").contains("PCR 14 not found"));
    }

    #[test]
    fn build_boot_info_for_attestation_accepts_aws_nitro_tpm_boottime_mr_for_runtime_quote() {
        // Regression: SignCert authorizes with use_boottime_mr=true, but the app
        // submits a full runtime quote whose PCR14 covers the whole event log.
        // Decode must bind the full replay to the quoted register and then take
        // the boot-mr-done snapshot for the MR, instead of rejecting the runtime
        // quote with "PCR14 mismatch".
        let (attestation, vm_config, _, _) =
            verified_aws_nitro_tpm_attestation(vec![0x22; 32], 0x04);

        let runtime = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("runtime-mr decode should succeed");
        let boottime = build_boot_info_for_attestation(&attestation, true, &vm_config)
            .expect("boottime-mr decode of a full runtime quote must not fail");

        // App identity is snapshot-independent.
        assert_eq!(runtime.app_id, boottime.app_id);
        assert_eq!(runtime.compose_hash, boottime.compose_hash);
        // The boot-time snapshot truncates the launch log at boot-mr-done, so
        // its aggregated MR differs from the full runtime MR.
        assert_ne!(runtime.mr_aggregated, boottime.mr_aggregated);
    }

    #[test]
    fn build_boot_info_for_attestation_accepts_snp_vm_config_path() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = snp_vm_config(&input, &mr_config);

        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("snp attestation should build boot info through vm_config path");

        assert_eq!(boot_info.tee_variant, TeeVariant::DstackAmdSevSnp);
        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(
            boot_info.device_id,
            sha2::Sha256::digest([0xab; 64]).to_vec()
        );
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
    }

    #[test]
    fn build_boot_info_for_attestation_uses_embedded_snp_vm_config_when_external_is_empty() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let embedded_config = snp_vm_config(&input, &mr_config);
        let attestation = verified_snp_attestation_with_config(
            measurement,
            [0xab; 64],
            embedded_config,
            &mr_config,
        );

        let boot_info = build_boot_info_for_attestation(&attestation, false, "")
            .expect("snp local KMS attestation should use embedded vm_config");

        assert_eq!(boot_info.tee_variant, TeeVariant::DstackAmdSevSnp);
        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
    }

    #[test]
    fn build_boot_info_for_attestation_rejects_a_vm_config_differing_from_the_attested_one() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let vm_config = snp_vm_config(&input, &mr_config);
        let attestation = verified_snp_attestation_with_config(
            measurement,
            [0xab; 64],
            vm_config.clone(),
            &mr_config,
        );
        let mut request: serde_json::Value = serde_json::from_str(&vm_config).unwrap();
        request["cpu_count"] = 8.into();

        let err = build_boot_info_for_attestation(&attestation, false, &request.to_string())
            .expect_err("a vm_config differing from the attested one must be rejected");
        assert!(format!("{err:#}").contains("does not match the config carried"));
        build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("an identical copy is accepted");
    }

    #[test]
    fn build_boot_info_for_attestation_accepts_self_contained_snp_input_without_config() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = snp_vm_config(&input, &mr_config);

        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("self-contained SNP vm_config should not require KMS-local sev_snp config");
        assert_eq!(boot_info.tee_variant, TeeVariant::DstackAmdSevSnp);
        assert_eq!(
            boot_info.device_id,
            sha2::Sha256::digest([0xab; 64]).to_vec()
        );
    }

    #[test]
    fn build_boot_info_for_attestation_rejects_snp_mr_config_without_app_id() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mut mr_config = valid_snp_mr_config();
        mr_config.app_id = None;
        let attestation = verified_snp_attestation_with_config(
            measurement,
            [0xab; 64],
            String::new(),
            &mr_config,
        );
        let vm_config = snp_vm_config(&input, &mr_config);
        let err = build_boot_info_for_attestation(&attestation, false, &vm_config).unwrap_err();
        assert_eq!(err.to_string(), "app_id must be 20 bytes");
    }

    fn snp_boot_info() -> BootInfo {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = snp_vm_config(&input, &mr_config);
        build_boot_info_for_attestation(&attestation, false, &vm_config).unwrap()
    }

    #[test]
    fn snp_key_release_requires_explicit_enablement() {
        let boot_info = snp_boot_info();

        let err = ensure_key_release_allowed(&boot_info, KeyReleasePolicy::default())
            .expect_err("snp boot info must not be key-release enabled by default");
        assert!(
            err.to_string()
                .contains("amd sev-snp key release is not enabled"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn snp_key_release_accepts_auth_approved_boot_info_when_enabled() {
        let boot_info = snp_boot_info();

        ensure_key_release_allowed(&boot_info, SNP_ENABLED)
            .expect("explicitly enabled SNP key release should allow auth-approved boot info");
    }

    #[test]
    fn snp_key_release_leaves_tcb_and_advisory_policy_to_auth_api() {
        let mut boot_info = snp_boot_info();

        boot_info.tcb_status = "OutOfDate".to_string();
        boot_info.advisory_ids.push("SNP-TEST-ADVISORY".to_string());
        ensure_key_release_allowed(&boot_info, SNP_ENABLED)
            .expect("TCB/advisory policy should be decided by the auth API, not this local gate");
    }

    #[test]
    fn nitro_enclave_key_release_requires_explicit_enablement() {
        let mut boot_info = snp_boot_info();
        boot_info.tee_variant = TeeVariant::DstackNitroEnclave;

        // disabled (the default) fails closed
        let err = ensure_key_release_allowed(&boot_info, KeyReleasePolicy::default())
            .expect_err("nitro enclave boot info must not be key-release enabled by default");
        assert!(
            err.to_string()
                .contains("aws nitro enclave key release is not enabled"),
            "unexpected error: {err:?}"
        );

        // explicitly enabled permits it
        ensure_key_release_allowed(&boot_info, NITRO_ENCLAVE_ENABLED)
            .expect("explicitly enabled nitro enclave key release should allow the boot info");
    }

    #[test]
    fn key_release_gates_do_not_leak_across_platforms() {
        let mut boot_info = snp_boot_info();

        // Enabling one platform must not enable another.
        boot_info.tee_variant = TeeVariant::DstackNitroEnclave;
        ensure_key_release_allowed(&boot_info, SNP_ENABLED)
            .expect_err("the SNP opt-in must not release keys to a nitro enclave");
        boot_info.tee_variant = TeeVariant::DstackAmdSevSnp;
        ensure_key_release_allowed(&boot_info, NITRO_ENCLAVE_ENABLED)
            .expect_err("the nitro enclave opt-in must not release keys to an SNP guest");

        // TDX and GCP TDX have no local gate and are unaffected by all of them.
        for variant in [TeeVariant::DstackTdx, TeeVariant::DstackGcpTdx] {
            boot_info.tee_variant = variant;
            ensure_key_release_allowed(&boot_info, KeyReleasePolicy::default())
                .expect("TDX key release has no local opt-in gate");
        }
    }

    /// An auth API that counts requests and answers them all at once, so a
    /// test can tell how many upstream calls a burst of concurrent RPCs cost.
    fn serve_concurrent_auth_api(
        body: &'static str,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                counter.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut chunk = [0u8; 4096];
                    let _ = stream.read(&mut chunk);
                    // Hold the response long enough that a burst of callers is
                    // genuinely in flight together rather than serialized.
                    std::thread::sleep(Duration::from_millis(200));
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        (format!("http://{address}"), requests)
    }

    /// A `KmsState` backed by freshly generated root material in `cert_dir`,
    /// with its auth API pointed at `webhook_url`.
    fn kms_state(cert_dir: &Path, webhook_url: &str) -> KmsState {
        use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
        use rocket::figment::{
            providers::{Format, Toml},
            Figment,
        };

        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack KMS CA")
            .ca_level(1)
            .key(&ca_key)
            .build()
            .self_signed()
            .unwrap();
        fs::write(cert_dir.join("root-ca.key"), ca_key.serialize_pem()).unwrap();
        fs::write(cert_dir.join("root-ca.crt"), ca_cert.pem()).unwrap();
        fs::write(
            cert_dir.join("root-k256.key"),
            SigningKey::random(&mut rand::rngs::OsRng).to_bytes(),
        )
        .unwrap();

        let overrides = format!(
            r#"
            [core]
            cert_dir = "{}"
            attest_rpc_cert = false
            enforce_self_authorization = false

            [core.image]
            cache_dir = "{}"

            [core.auth_api]
            type = "webhook"

            [core.auth_api.webhook]
            url = "{webhook_url}"
            "#,
            cert_dir.display(),
            cert_dir.display(),
        );
        let config: KmsConfig = Figment::from(rocket::Config::default())
            .merge(Toml::string(crate::config::DEFAULT_CONFIG))
            .merge(Toml::string(&overrides))
            .focus("core")
            .extract()
            .unwrap();
        let keyring = Keyring::load(&config).unwrap();
        KmsState::new(config, keyring, ca_cert.pem()).unwrap()
    }

    #[rocket::async_test]
    async fn authorization_selects_epochs_without_a_serving_epoch_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let initial = kms_state(dir.path(), "http://127.0.0.1:1");
        let mut keyring = Keyring::load(&initial.config).unwrap();
        let key = KeyPair::generate_for(&ra_tls::rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertRequest::builder()
            .key(&key)
            .subject("Root epoch 1")
            .ca_level(1)
            .build()
            .self_signed()
            .unwrap();
        keyring.roots.push(RootKeys {
            ca: CaCert::from_parts(key, cert),
            k256: SigningKey::random(&mut rand::rngs::OsRng),
        });
        keyring.chain_hashes =
            root_chain_hashes(keyring.roots.iter().map(|root| (&root.ca.key, &root.k256)));
        let state = KmsState::new(
            initial.config.clone(),
            keyring,
            initial.keyring.roots[0].ca.pem_cert.clone(),
        )
        .unwrap();
        let result = |epoch: u32| AuthorizationResult {
            is_allowed: true,
            rejection_reason: String::new(),
            gateway_app_id: String::new(),
            current_root_epoch: epoch,
            current_app_epoch: 0,
            current_root_epoch_hash: hex::encode(state.keyring.chain_hashes[epoch as usize]),
        };
        assert_eq!(state.authorized_epoch(&result(0), None).unwrap(), 0);
        assert!(state.authorized_epoch(&result(0), Some(1)).is_err());
        assert_eq!(state.authorized_epoch(&result(1), None).unwrap(), 1);
        assert_eq!(state.authorized_epoch(&result(1), Some(0)).unwrap(), 0);
        assert_eq!(state.authorized_epoch(&result(1), Some(1)).unwrap(), 1);
        assert!(state.authorized_epoch(&result(1), Some(u32::MAX)).is_err());
        // Key selection already follows epoch 1; only the TLS listener needs refreshing.
        assert!(state.ensure_rpc_ca(1).is_err());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), state.restart_requested())
                .await
                .is_ok()
        );
        assert_eq!(state.rpc_ca_pubkey, initial.rpc_ca_pubkey);

        let mut rejected = result(1);
        rejected.is_allowed = false;
        rejected.rejection_reason = "Policy denied".into();
        assert!(state.authorized_epoch(&rejected, Some(0)).is_err());
        rejected.is_allowed = true;
        for hash in [
            "invalid".into(),
            hex::encode([0; 32]),
            hex::encode([0x55; 32]),
        ] {
            rejected.current_root_epoch_hash = hash;
            assert!(state.authorized_epoch(&rejected, None).is_err());
        }
        let mut missing = result(1);
        missing.current_root_epoch = u32::MAX;
        assert!(state.authorized_epoch(&missing, Some(0)).is_err());
        assert!(state.epoch_root(u32::MAX).is_err());
    }

    const AUTH_API_INFO: &str = r#"{"status":"ok","kmsContractAddr":"0xkms","ethRpcUrl":"https://rpc.example","gatewayAppId":"0xgateway","chainId":1,"appImplementation":"0ximpl"}"#;

    #[rocket::async_test]
    async fn self_authorization_cache_cannot_authorize_a_different_operation() {
        use upgrade_authority::tests::{boot_info, serve};
        let dir = tempfile::tempdir().unwrap();
        let initial = kms_state(dir.path(), "http://127.0.0.1:1");
        let response = |allowed| {
            serde_json::json!({
                "isAllowed": allowed, "rejectionReason": "export denied", "gatewayAppId": "",
                "currentRootEpoch": 0, "currentAppEpoch": 0,
                "currentRootEpochHash": hex::encode(initial.keyring.chain_hashes[0]),
            })
            .to_string()
        };
        let (url, server) = serve(vec![response(true), response(false)]);
        let mut config = initial.config.clone();
        config.enforce_self_authorization = true;
        config.auth_api = upgrade_authority::tests::webhook(url);
        let keyring = Keyring::load(&config).unwrap();
        let state = KmsState::new(
            config,
            keyring,
            initial.epoch_root(0).unwrap().ca.pem_cert.clone(),
        )
        .unwrap();
        state.self_boot_info.insert((), boot_info(1)).await;
        let handler = RpcHandler {
            state,
            attestation: None,
        };
        assert_eq!(
            handler
                .ensure_self_allowed(Operation::KmsServe)
                .await
                .unwrap(),
            0
        );
        assert!(handler
            .ensure_self_allowed(Operation::KmsExportKeys)
            .await
            .is_err());
        assert_eq!(
            handler
                .ensure_self_allowed(Operation::KmsServe)
                .await
                .unwrap(),
            0
        );
        let requests = server.join().unwrap();
        assert_eq!(requests[0].1["operation"], "kms_serve");
        assert_eq!(requests[1].1["operation"], "kms_export_keys");
    }

    #[rocket::async_test]
    async fn legacy_temp_ca_rpc_returns_a_separate_ca_and_the_served_root() {
        assert!(dstack_kms_rpc::kms_server::KMSMethod::from_str("GetTempCaCert").is_some());
        let dir = tempfile::tempdir().unwrap();
        let (url, _) = serve_concurrent_auth_api(AUTH_API_INFO);
        let state = kms_state(dir.path(), &url);
        let response = RpcHandler {
            state: state.clone(),
            attestation: None,
        }
        .get_temp_ca_cert()
        .await
        .unwrap();
        let temp_ca = CaCert::new(response.temp_ca_cert, response.temp_ca_key).unwrap();
        assert_ne!(temp_ca.key.public_key_der(), state.rpc_ca_pubkey);
        assert_eq!(response.ca_cert, state.epoch_root(0).unwrap().ca.pem_cert);
    }

    #[rocket::async_test]
    async fn concurrent_get_meta_calls_share_one_auth_api_request() {
        let dir = tempfile::tempdir().unwrap();
        let (url, upstream_requests) = serve_concurrent_auth_api(AUTH_API_INFO);
        let state = kms_state(dir.path(), &url);

        let burst: Vec<_> = (0..24)
            .map(|_| {
                let state = state.clone();
                rocket::tokio::spawn(async move {
                    RpcHandler {
                        state,
                        attestation: None,
                    }
                    .get_meta()
                    .await
                })
            })
            .collect();
        for handle in burst {
            let meta = handle.await.unwrap().unwrap();
            assert_eq!(meta.chain_id, Some(1));
            assert_eq!(meta.gateway_app_id.as_deref(), Some("0xgateway"));
        }
        assert_eq!(
            upstream_requests.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }
}
