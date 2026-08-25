// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cert_client::CertRequestClient;
use dstack_attest::default_verifier;
use dstack_guest_agent_rpc::v0::{
    dstack_guest_server::{DstackGuestRpc, DstackGuestServer},
    tappd_server::{TappdRpc, TappdServer},
    worker_server::{WorkerRpc, WorkerServer},
    AppInfo, AttestResponse, DeriveK256KeyResponse, DeriveKeyArgs, EmitEventArgs,
    GetAttestationForAppKeyRequest, GetKeyArgs, GetKeyResponse, GetQuoteResponse, GetTlsKeyArgs,
    GetTlsKeyResponse, RawQuoteArgs, SignRequest, SignResponse, TdxQuoteArgs, TdxQuoteResponse,
    VerifyRequest, VerifyResponse, WorkerVersion,
};
use dstack_types::{AppKeys, SysConfig};
use ed25519_dalek::ed25519::signature::hazmat::{PrehashSigner, PrehashVerifier};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use or_panic::ResultOrPanic;
use ra_rpc::{CallContext, RpcCall};
use ra_tls::{
    api_v1::sign_recoverable_keccak256,
    attestation::{
        QuoteContentType, TdxAttestationExt, VersionedAttestation, DEFAULT_HASH_ALGORITHM,
    },
    cert::{CertConfigV2, CertSigningRequestV2, Csr},
    kdf::{derive_key, derive_p256_key_pair_from_bytes},
};
use rcgen::KeyPair;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;

use tracing::error;

use crate::{
    backend::{PlatformBackend, RealPlatform},
    config::Config,
};

/// How long a failed identity decode is left alone before another call is
/// allowed to touch the platform again.
///
/// The cache makes the happy path free, but nothing caches a failure, and the
/// retry path is reachable from `/prpc/v1/Info` -- anonymous, publicly
/// reachable, and one hardware quote plus an event-log replay per attempt,
/// under the global quote lock. Retrying per call would hand any caller that
/// can route to the CVM exactly the lever the cache exists to remove, for as
/// long as the platform stays broken. A floor of half a minute bounds that to
/// one attempt per interval while still letting a platform that was only
/// momentarily unable to attest recover on its own.
const IDENTITY_RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// Decode the immutable identity fields out of a boot attestation.
///
/// Costs a quote and an event-log replay, which is why its result is cached for
/// the life of the process.
fn decode_identity(inner: &AppStateInner) -> Result<AppIdentity> {
    let attestation = inner.info_attestation()?.into_v1();
    let app_info = attestation
        .decode_app_info(false)
        .context("failed to decode app info")?;
    Ok(AppIdentity {
        app_id: app_info.app_id,
        instance_id: app_info.instance_id,
        device_id: app_info.device_id,
        mr_aggregated: app_info.mr_aggregated.to_vec(),
        os_image_hash: app_info.os_image_hash,
        compose_hash: app_info.compose_hash,
        key_provider_info: String::from_utf8(app_info.key_provider_info).unwrap_or_default(),
    })
}

fn read_dmi_file(name: &str) -> String {
    fs::read_to_string(format!("/sys/class/dmi/id/{name}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: Config,
    keys: AppKeys,
    vm_config: String,
    cert_client: CertRequestClient,
    demo_cert: RwLock<String>,
    platform: Arc<dyn PlatformBackend>,
    /// Present only when the app opted into health gating; see `health`.
    health: Option<Arc<crate::health::HealthMonitor>>,
    /// Serialises on-demand GPU attestation.
    gpu_attestor: crate::gpu_attest::GpuAttestor,
    /// The app root key, parsed once.
    ///
    /// `None` when the key provider handed us something that is not a valid
    /// secp256k1 scalar. Kept non-fatal so this cannot turn a boot problem into
    /// a boot failure -- the RPCs that need it report it per call, as they did
    /// when each parsed the key itself.
    app_root_signing_key: Option<SigningKey>,
    /// Identity as decoded from the boot attestation. See [`AppIdentity`].
    identity: RwLock<Option<Arc<AppIdentity>>>,
    /// When the last identity decode failed, so the retry can be throttled.
    /// See [`IDENTITY_RETRY_INTERVAL`]. Separate from the cache above because
    /// it is written only on the degraded path, and read only when the cache
    /// is empty.
    identity_last_failure: Mutex<Option<Instant>>,
    /// `sys_vendor` and `product_name`, read once. Neither changes while the
    /// VM is running.
    cloud_vendor: String,
    cloud_product: String,
}

/// The identity fields v1 `Info` reports, decoded once.
///
/// Every one of these is fixed for the life of the VM: they come out of the
/// launch measurements. Recomputing them per call meant generating a fresh
/// hardware quote and replaying the RTMR event log under the global quote lock
/// on every `Info` -- including anonymous calls to the public `/prpc/v1/Info`,
/// which let any caller that can route to the CVM monopolise that lock and
/// starve the attestation path the agent actually needs.
#[derive(Debug)]
pub(crate) struct AppIdentity {
    pub(crate) app_id: Vec<u8>,
    pub(crate) instance_id: Vec<u8>,
    pub(crate) device_id: Vec<u8>,
    pub(crate) mr_aggregated: Vec<u8>,
    pub(crate) os_image_hash: Vec<u8>,
    pub(crate) compose_hash: Vec<u8>,
    pub(crate) key_provider_info: String,
}

impl AppStateInner {
    fn info_attestation(&self) -> Result<VersionedAttestation> {
        self.platform.attestation_for_info()
    }

    async fn issue_cert(&self, key: &KeyPair, config: CertConfigV2) -> Result<Vec<String>> {
        let pubkey = key.public_key_der();
        let attestation = self
            .platform
            .certificate_attestation(&pubkey)
            .context("Failed to get certificate attestation")?;
        let csr = CertSigningRequestV2 {
            confirm: "please sign cert:".to_string(),
            pubkey,
            config,
            attestation,
        };
        let signature = csr.signed_by(key).context("Failed to sign the CSR")?;
        self.cert_client
            .sign_csr(&csr, &signature)
            .await
            .context("Failed to sign the CSR")
    }

    async fn request_demo_cert(&self) -> Result<String> {
        let key = KeyPair::generate().context("Failed to generate demo key")?;
        let demo_cert = self
            .issue_cert(
                &key,
                CertConfigV2 {
                    org_name: None,
                    subject: "demo-cert".to_string(),
                    subject_alt_names: vec![],
                    usage_server_auth: false,
                    usage_client_auth: true,
                    ext_quote: true,
                    ext_app_info: false,
                    not_after: None,
                    not_before: None,
                },
            )
            .await
            .context("Failed to get app cert")?
            .join("\n");
        Ok(demo_cert)
    }
}

impl AppState {
    fn maybe_request_demo_cert(&self) {
        let state = self.inner.clone();
        if !state
            .demo_cert
            .read()
            .or_panic("lock shoud never fail")
            .is_empty()
        {
            return;
        }
        tokio::spawn(async move {
            match state.request_demo_cert().await {
                Ok(demo_cert) => {
                    *state.demo_cert.write().or_panic("lock shoud never fail") = demo_cert;
                }
                Err(e) => {
                    error!("Failed to request demo cert: {e}");
                }
            }
        });
    }

    pub async fn new_with_platform(
        config: Config,
        platform: Arc<dyn PlatformBackend>,
    ) -> Result<Self> {
        let keys: AppKeys = serde_json::from_str(&fs::read_to_string(&config.keys_file)?)
            .context("Failed to parse app keys")?;
        let sys_config: SysConfig =
            serde_json::from_str(&fs::read_to_string(&config.sys_config_file)?)
                .context("Failed to parse VM config")?;
        let collateral_urls = sys_config.collateral_urls();
        let gpu_attestor = crate::gpu_attest::GpuAttestor::new();
        let vm_config = sys_config.vm_config;
        // Same trust anchor decision as dstack-util: never host-supplied, and
        // development roots only when this guest published them itself.
        let verifier = Arc::new(default_verifier(&collateral_urls)?);
        let cert_client = CertRequestClient::create(&keys, verifier, vm_config.clone())
            .await
            .context("Failed to create cert signer")?;
        // Only run the refresh loop when the app asked the gateway to gate on
        // its health. Nothing polls an app that did not, so recomputing a
        // verdict nobody reads would be pure cost inside the CVM.
        let health = config
            .app_compose
            .requirements
            .as_ref()
            .filter(|requirements| requirements.health_check)
            .map(|requirements| {
                crate::health::HealthMonitor::spawn(
                    requirements.health_status_file.clone(),
                    config.app_compose.runner.clone(),
                )
            });
        // Parsed once, and non-fatally: an unusable app root key is reported by
        // the RPCs that need one, not by refusing to start.
        let app_root_signing_key = match SigningKey::from_slice(&keys.k256_key) {
            Ok(key) => Some(key),
            Err(err) => {
                error!("the app root k256 key did not parse: {err:?}");
                None
            }
        };
        let me = Self {
            inner: Arc::new(AppStateInner {
                config,
                keys,
                cert_client,
                demo_cert: RwLock::new(String::new()),
                vm_config,
                platform,
                health,
                gpu_attestor,
                app_root_signing_key,
                identity: RwLock::new(None),
                identity_last_failure: Mutex::new(None),
                cloud_vendor: read_dmi_file("sys_vendor"),
                cloud_product: read_dmi_file("product_name"),
            }),
        };
        // Decode identity now so no request has to. Non-fatal: a platform that
        // cannot attest at this instant would otherwise take the whole agent
        // down, and `identity()` retries on demand. A failure here counts as
        // the first attempt and arms the retry throttle, so the boot attempt
        // and a request-driven one are on the same budget.
        if let Err(err) = me.identity() {
            error!("failed to decode app identity at startup: {err:?}");
        }
        me.maybe_request_demo_cert();
        Ok(me)
    }

    pub async fn new(config: Config) -> Result<Self> {
        Self::new_with_platform(config, Arc::new(RealPlatform)).await
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }

    pub(crate) fn health(&self) -> Option<&crate::health::HealthMonitor> {
        self.inner.health.as_deref()
    }

    pub(crate) fn quote_response(&self, report_data: [u8; 64]) -> Result<GetQuoteResponse> {
        self.inner
            .platform
            .quote_response(report_data, &self.inner.vm_config)
    }

    pub(crate) fn attest_cvm(&self, report_data: [u8; 64]) -> Result<Vec<u8>> {
        self.inner.platform.attest_cvm(report_data)?.to_bytes()
    }

    /// The application's root secp256k1 key, the root of every derived key and
    /// the signer of the first link of every signature chain.
    pub(crate) fn app_root_k256_key(&self) -> &[u8] {
        &self.inner.keys.k256_key
    }

    /// The same key, parsed. Shared rather than re-parsed per request.
    pub(crate) fn app_root_signing_key(&self) -> Result<&SigningKey> {
        let Some(key) = self.inner.app_root_signing_key.as_ref() else {
            anyhow::bail!("the app root k256 key is not a valid secp256k1 scalar");
        };
        Ok(key)
    }

    /// The KMS root key's signature over the app root public key: the second
    /// link of every signature chain, produced outside this agent and passed
    /// through byte-for-byte on both API surfaces.
    pub(crate) fn kms_k256_signature(&self) -> &[u8] {
        &self.inner.keys.k256_signature
    }

    pub(crate) fn cloud_vendor(&self) -> &str {
        &self.inner.cloud_vendor
    }

    pub(crate) fn cloud_product(&self) -> &str {
        &self.inner.cloud_product
    }

    /// The decoded identity, computed at most once on success.
    ///
    /// Populated at construction; the decode below only runs when that attempt
    /// failed, so a platform that could not attest at boot still answers later
    /// rather than staying broken for the life of the process. It runs at most
    /// once per [`IDENTITY_RETRY_INTERVAL`], because the callers reaching it
    /// include anonymous ones. Within the window the caller is told the
    /// identity is unavailable and when the next attempt is, and the platform
    /// is not touched at all.
    pub(crate) fn identity(&self) -> Result<Arc<AppIdentity>> {
        if let Some(identity) = self
            .inner
            .identity
            .read()
            .or_panic("lock should never fail")
            .as_ref()
        {
            return Ok(identity.clone());
        }
        // Two callers arriving together on a cold cache may both attempt once.
        // That is the same race the cache has always had, and one extra quote
        // is not worth holding a lock across the decode for.
        if let Some(failed_at) = *self
            .inner
            .identity_last_failure
            .lock()
            .or_panic("lock should never fail")
        {
            let elapsed = failed_at.elapsed();
            if elapsed < IDENTITY_RETRY_INTERVAL {
                let retry_in = (IDENTITY_RETRY_INTERVAL - elapsed).as_secs() + 1;
                anyhow::bail!(
                    "the app identity is unavailable: decoding it failed and the next attempt is at most {retry_in}s away"
                );
            }
        }
        // Blocking, and deliberately left on the executor: the throttle above
        // caps this at one quote per interval for the whole process, which is
        // far short of what would justify a `spawn_blocking` hop and making
        // every caller of `identity()` async to reach it.
        let identity = match decode_identity(&self.inner) {
            Ok(identity) => Arc::new(identity),
            Err(err) => {
                *self
                    .inner
                    .identity_last_failure
                    .lock()
                    .or_panic("lock should never fail") = Some(Instant::now());
                return Err(err);
            }
        };
        *self
            .inner
            .identity
            .write()
            .or_panic("lock should never fail") = Some(identity.clone());
        Ok(identity)
    }

    /// The VM's hardware configuration, as the VMM produced it.
    pub(crate) fn vm_config(&self) -> &str {
        &self.inner.vm_config
    }

    pub(crate) fn gpu_attestor(&self) -> &crate::gpu_attest::GpuAttestor {
        &self.inner.gpu_attestor
    }

    pub(crate) async fn issue_cert(
        &self,
        key: &KeyPair,
        config: CertConfigV2,
    ) -> Result<Vec<String>> {
        self.inner.issue_cert(key, config).await
    }
}

/// Generate the fresh P-256 key that backs a certificate the agent issues.
///
/// Random, not derived: the certificate is minted per call, so there is
/// nothing for a stable key to buy, and a key nobody can re-derive is a
/// smaller thing to hold.
///
/// The `Failed to ...` contexts are the v0.5.11 strings verbatim. They are what
/// a frozen-surface caller sees, so they keep their original capitalisation
/// rather than following the lowercase house rule.
fn generate_cert_key() -> Result<KeyPair> {
    let mut seed = [0u8; 32];
    SystemRandom::new()
        .fill(&mut seed)
        .context("Failed to generate secure seed")?;
    derive_p256_key_pair_from_bytes(&seed, &[]).context("Failed to derive key")
}

/// The certificate request fields both surfaces take.
///
/// The two wire messages are different types with identical fields, so this is
/// where they meet. Without it the shared body is copied per surface and the
/// copies drift.
pub(crate) struct CertRequestFields {
    pub(crate) subject: String,
    pub(crate) alt_names: Vec<String>,
    pub(crate) usage_ra_tls: bool,
    pub(crate) usage_server_auth: bool,
    pub(crate) usage_client_auth: bool,
    pub(crate) with_app_info: bool,
    pub(crate) not_before: Option<u64>,
    pub(crate) not_after: Option<u64>,
}

/// A freshly issued certificate and the key that backs it.
pub(crate) struct IssuedCert {
    pub(crate) key: String,
    pub(crate) certificate_chain: Vec<String>,
}

/// Validate, generate a key, build the CSR, and get it signed.
///
/// The whole body of the frozen `GetTlsKey` and of v1's `IssueCert`: they
/// differ only in which message type carries the fields in and the result out.
pub(crate) async fn issue_cert_for_request(
    state: &AppState,
    request: CertRequestFields,
) -> Result<IssuedCert> {
    validate_cert_validity(request.not_before, request.not_after)?;
    let key = generate_cert_key()?;
    let config = CertConfigV2 {
        org_name: None,
        subject: request.subject,
        subject_alt_names: request.alt_names,
        usage_server_auth: request.usage_server_auth,
        usage_client_auth: request.usage_client_auth,
        ext_quote: request.usage_ra_tls,
        ext_app_info: request.with_app_info,
        not_after: request.not_after,
        not_before: request.not_before,
    };
    let certificate_chain = state.issue_cert(&key, config).await?;
    Ok(IssuedCert {
        key: key.serialize_pem(),
        certificate_chain,
    })
}

pub struct InternalRpcHandler {
    state: AppState,
}

impl InternalRpcHandler {
    /// Only the router constructs this in a running agent; the v1 tests build
    /// one directly to assert the unversioned surface still answers as it did.
    #[cfg(test)]
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

pub async fn get_info(state: &AppState, external: bool) -> Result<AppInfo> {
    let hide_tcb_info = external && !state.config().app_compose.public_tcbinfo;
    let versioned_attestation = state.inner.info_attestation()?;
    let attestation = versioned_attestation.into_v1();
    let app_info = attestation
        .decode_app_info(false)
        .context("Failed to decode app info")?;
    let event_log = attestation.tdx_event_log().unwrap_or_default();
    let tcb_info = if hide_tcb_info {
        "".to_string()
    } else {
        let app_compose = state.config().app_compose.raw.clone();
        let td_report = match attestation.td10_report() {
            Some(report) => json!({
                "mrtd": hex::encode(report.mr_td),
                "rtmr0": hex::encode(report.rt_mr0),
                "rtmr1": hex::encode(report.rt_mr1),
                "rtmr2": hex::encode(report.rt_mr2),
                "rtmr3": hex::encode(report.rt_mr3),
            }),
            None => json!({}),
        };
        serde_json::to_string_pretty(&json!({
            "mrtd": td_report["mrtd"],
            "rtmr0": td_report["rtmr0"],
            "rtmr1": td_report["rtmr1"],
            "rtmr2": td_report["rtmr2"],
            "rtmr3": td_report["rtmr3"],
            "mr_aggregated": hex::encode(app_info.mr_aggregated),
            "os_image_hash": hex::encode(&app_info.os_image_hash),
            "compose_hash": hex::encode(&app_info.compose_hash),
            "device_id": hex::encode(&app_info.device_id),
            "event_log": event_log,
            "app_compose": app_compose,
        }))
        .unwrap_or_default()
    };
    let vm_config = if hide_tcb_info {
        "".to_string()
    } else {
        state.inner.vm_config.clone()
    };
    state.maybe_request_demo_cert();
    Ok(AppInfo {
        app_name: state.config().app_compose.name.clone(),
        app_id: app_info.app_id,
        instance_id: app_info.instance_id,
        device_id: app_info.device_id,
        mr_aggregated: app_info.mr_aggregated.to_vec(),
        os_image_hash: app_info.os_image_hash.clone(),
        key_provider_info: String::from_utf8(app_info.key_provider_info).unwrap_or_default(),
        compose_hash: app_info.compose_hash.clone(),
        app_cert: state
            .inner
            .demo_cert
            .read()
            .or_panic("lock should not fail")
            .clone(),
        tcb_info,
        vm_config,
        cloud_vendor: read_dmi_file("sys_vendor"),
        cloud_product: read_dmi_file("product_name"),
    })
}

pub(crate) fn validate_cert_validity(
    not_before: Option<u64>,
    not_after: Option<u64>,
) -> Result<()> {
    if let (Some(not_before), Some(not_after)) = (not_before, not_after) {
        if not_before >= not_after {
            anyhow::bail!("not_before must be earlier than not_after");
        }
    }
    Ok(())
}

impl DstackGuestRpc for InternalRpcHandler {
    async fn get_tls_key(self, request: GetTlsKeyArgs) -> anyhow::Result<GetTlsKeyResponse> {
        let issued = issue_cert_for_request(
            &self.state,
            CertRequestFields {
                subject: request.subject,
                alt_names: request.alt_names,
                usage_ra_tls: request.usage_ra_tls,
                usage_server_auth: request.usage_server_auth,
                usage_client_auth: request.usage_client_auth,
                with_app_info: request.with_app_info,
                not_before: request.not_before,
                not_after: request.not_after,
            },
        )
        .await?;
        Ok(GetTlsKeyResponse {
            key: issued.key,
            certificate_chain: issued.certificate_chain,
        })
    }

    async fn get_key(self, request: GetKeyArgs) -> Result<GetKeyResponse> {
        let k256_app_key = &self.state.inner.keys.k256_key;

        let algorithm = normalize_algorithm(&request.algorithm);
        let (key, pubkey_hex) = match algorithm {
            "ed25519" => {
                let derived_key = derive_key(k256_app_key, &[request.path.as_bytes()], 32)
                    .context("Failed to derive ed25519 key")?;
                let signing_key = Ed25519SigningKey::from_bytes(
                    &derived_key
                        .as_slice()
                        .try_into()
                        .or(Err(anyhow::anyhow!("Invalid key length")))?,
                );
                let pubkey_hex = hex::encode(signing_key.verifying_key().as_bytes());
                (derived_key, pubkey_hex)
            }
            "secp256k1" | "" => {
                let derived_key = derive_key(k256_app_key, &[request.path.as_bytes()], 32)
                    .context("Failed to derive k256 key")?;

                let signing_key =
                    SigningKey::from_slice(&derived_key).context("Failed to parse k256 key")?;
                let pubkey_hex = hex::encode(signing_key.verifying_key().to_sec1_bytes());
                (derived_key, pubkey_hex)
            }
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };

        let msg_to_sign = format!("{}:{}", request.purpose, pubkey_hex);
        let app_signing_key =
            SigningKey::from_slice(k256_app_key).context("Failed to parse app k256 key")?;
        // The shared 65-byte `r || s || v` envelope. Byte-identical to the copy
        // this replaced -- `get_key_pins_the_frozen_chain_link` is the vector
        // that says so, and it exists for exactly this de-duplication.
        let signature = sign_recoverable_keccak256(&app_signing_key, msg_to_sign.as_bytes())?;

        Ok(GetKeyResponse {
            key,
            signature_chain: vec![signature, self.state.inner.keys.k256_signature.clone()],
        })
    }

    async fn get_quote(self, request: RawQuoteArgs) -> Result<GetQuoteResponse> {
        let report_data = pad64(&request.report_data).context("Report data is too long")?;
        self.state.quote_response(report_data)
    }

    /// Always fails. See the RPC's doc comment in agent_rpc.proto: the method
    /// exists so a pre-0.6 client learns why its events stopped being recorded,
    /// instead of the bare `Service not found` a deleted method would answer
    /// with, which says nothing about the removal.
    async fn emit_event(self, _request: EmitEventArgs) -> Result<()> {
        anyhow::bail!(
            "EmitEvent was removed in dstack 0.6.0; runtime RTMR3 events are system-owned and cannot be extended by apps"
        )
    }

    async fn info(self) -> Result<AppInfo> {
        get_info(&self.state, false).await
    }

    async fn sign(self, request: SignRequest) -> Result<SignResponse> {
        let algorithm = normalize_algorithm(&request.algorithm);
        // Use the base algorithm for key derivation (e.g. secp256k1_prehashed -> secp256k1)
        let key_algorithm = match algorithm {
            "secp256k1_prehashed" => "secp256k1",
            other => other,
        };
        let key_response = self
            .get_key(GetKeyArgs {
                path: "vms".to_string(),
                purpose: "signing".to_string(),
                algorithm: key_algorithm.to_string(),
            })
            .await?;
        let (signature, public_key) = match algorithm {
            "ed25519" => {
                let key_bytes: [u8; 32] = key_response
                    .key
                    .try_into()
                    .ok()
                    .context("Key is incorrect")?;
                let signing_key = Ed25519SigningKey::from_bytes(&key_bytes);
                let signature = signing_key.sign(&request.data);
                let public_key = signing_key.verifying_key().to_bytes().to_vec();
                (signature.to_bytes().to_vec(), public_key)
            }
            "secp256k1" => {
                let signing_key = SigningKey::from_slice(&key_response.key)
                    .context("Failed to parse secp256k1 key")?;
                let signature: k256::ecdsa::Signature = signing_key.sign(&request.data);
                let public_key = signing_key.verifying_key().to_sec1_bytes().to_vec();
                (signature.to_bytes().to_vec(), public_key)
            }
            "secp256k1_prehashed" => {
                if request.data.len() != 32 {
                    return Err(anyhow::anyhow!(
                        "Pre-hashed signing requires a 32-byte digest, but received {} bytes",
                        request.data.len()
                    ));
                }
                let signing_key = SigningKey::from_slice(&key_response.key)
                    .context("Failed to parse secp256k1 key")?;
                let signature: k256::ecdsa::Signature = signing_key.sign_prehash(&request.data)?;
                let public_key = signing_key.verifying_key().to_sec1_bytes().to_vec();
                (signature.to_bytes().to_vec(), public_key)
            }
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };
        Ok(SignResponse {
            signature: signature.clone(),
            signature_chain: vec![
                signature,
                key_response.signature_chain[0].clone(),
                key_response.signature_chain[1].clone(),
            ],
            public_key,
        })
    }

    /// Deprecated, kept for 0.5.x clients only. See the RPC's doc comment in
    /// agent_rpc.proto.
    ///
    /// k256 rejects a non-canonical (high-S) signature, so a malleated copy of a
    /// valid signature does not verify. Keep it that way: 0.5.x answered the
    /// same, and callers may be treating this answer as a uniqueness check.
    ///
    /// The rejection is in the verification, not in the parsing -- `from_slice`
    /// only rejects an `r` or `s` outside `1..n`, and a malleated `s` is still
    /// in range. So a caller sees HTTP 200 with `valid: false`, not the 400 a
    /// parse failure would produce. Same security answer, different status
    /// code, and the status code is the part a client branches on.
    async fn verify(self, request: VerifyRequest) -> Result<VerifyResponse> {
        let algorithm = normalize_algorithm(&request.algorithm);
        let valid = match algorithm {
            "ed25519" => {
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                    &request
                        .public_key
                        .as_slice()
                        .try_into()
                        .ok()
                        .context("invalid public key")?,
                )?;
                let signature = ed25519_dalek::Signature::from_slice(&request.signature)?;
                verifying_key.verify(&request.data, &signature).is_ok()
            }
            "secp256k1" => {
                let verifying_key =
                    k256::ecdsa::VerifyingKey::from_sec1_bytes(&request.public_key)?;
                let signature = k256::ecdsa::Signature::from_slice(&request.signature)?;
                verifying_key.verify(&request.data, &signature).is_ok()
            }
            "secp256k1_prehashed" => {
                let verifying_key =
                    k256::ecdsa::VerifyingKey::from_sec1_bytes(&request.public_key)?;
                let signature = k256::ecdsa::Signature::from_slice(&request.signature)?;
                verifying_key
                    .verify_prehash(&request.data, &signature)
                    .is_ok()
            }
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };
        Ok(VerifyResponse { valid })
    }

    async fn attest(self, request: RawQuoteArgs) -> Result<AttestResponse> {
        let report_data = pad64(&request.report_data).context("Report data is too long")?;
        Ok(AttestResponse {
            attestation: self.state.attest_cvm(report_data)?,
        })
    }

    async fn version(self) -> Result<WorkerVersion> {
        Ok(WorkerVersion {
            version: crate::CARGO_PKG_VERSION.to_string(),
            rev: crate::GIT_REV.to_string(),
        })
    }
}

/// Normalize algorithm name to canonical form.
/// Accepts "k256" as an alias for "secp256k1".
fn normalize_algorithm(algorithm: &str) -> &str {
    match algorithm {
        "k256" => "secp256k1",
        other => other,
    }
}

pub(crate) fn pad64(data: &[u8]) -> Option<[u8; 64]> {
    if data.len() > 64 {
        return None;
    }
    let mut padded = [0u8; 64];
    padded[..data.len()].copy_from_slice(data);
    Some(padded)
}

impl RpcCall<AppState> for InternalRpcHandler {
    type PrpcService = DstackGuestServer<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(InternalRpcHandler {
            state: context.state.clone(),
        })
    }
}

pub struct InternalRpcHandlerV0 {
    state: AppState,
}

impl TappdRpc for InternalRpcHandlerV0 {
    async fn derive_key(self, request: DeriveKeyArgs) -> anyhow::Result<GetTlsKeyResponse> {
        let mut mbuf = [0u8; 32];
        let seed = if request.random_seed {
            SystemRandom::new()
                .fill(&mut mbuf)
                .context("Failed to generate secure seed")?;
            &mbuf[..]
        } else {
            &self.state.inner.keys.k256_key
        };
        let derived_key = derive_p256_key_pair_from_bytes(seed, &[request.path.as_bytes()])
            .context("Failed to derive key")?;
        let config = CertConfigV2 {
            org_name: None,
            subject: request.subject,
            subject_alt_names: request.alt_names,
            usage_server_auth: request.usage_server_auth,
            usage_client_auth: request.usage_client_auth,
            ext_quote: request.usage_ra_tls,
            ext_app_info: false,
            not_before: None,
            not_after: None,
        };
        let certificate_chain = self.state.inner.issue_cert(&derived_key, config).await?;
        Ok(GetTlsKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain,
        })
    }

    async fn derive_k256_key(self, request: GetKeyArgs) -> Result<DeriveK256KeyResponse> {
        let res = InternalRpcHandler { state: self.state }
            .get_key(request)
            .await?;
        Ok(DeriveK256KeyResponse {
            k256_key: res.key,
            k256_signature_chain: res.signature_chain,
        })
    }

    async fn tdx_quote(self, request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let hash_algorithm = if request.hash_algorithm.is_empty() {
            DEFAULT_HASH_ALGORITHM
        } else {
            &request.hash_algorithm
        };
        let content_type = if request.prefix.is_empty() {
            QuoteContentType::AppData
        } else {
            QuoteContentType::Custom(&request.prefix)
        };
        let prefix = if hash_algorithm == "raw" {
            "".into()
        } else {
            content_type.tag().to_string()
        };
        let report_data =
            content_type.to_report_data_with_hash(&request.report_data, &request.hash_algorithm)?;
        let response = self.state.quote_response(report_data)?;
        Ok(TdxQuoteResponse {
            quote: response.quote,
            event_log: response.event_log,
            hash_algorithm: hash_algorithm.to_string(),
            prefix,
        })
    }

    async fn raw_quote(self, request: RawQuoteArgs) -> Result<TdxQuoteResponse> {
        self.tdx_quote(TdxQuoteArgs {
            report_data: request.report_data,
            hash_algorithm: "raw".to_string(),
            prefix: "".to_string(),
        })
        .await
    }

    async fn info(self) -> Result<AppInfo> {
        get_info(&self.state, false).await
    }

    async fn version(self) -> Result<WorkerVersion> {
        Ok(WorkerVersion {
            version: crate::CARGO_PKG_VERSION.to_string(),
            rev: crate::GIT_REV.to_string(),
        })
    }
}

impl RpcCall<AppState> for InternalRpcHandlerV0 {
    type PrpcService = TappdServer<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(InternalRpcHandlerV0 {
            state: context.state.clone(),
        })
    }
}

pub struct ExternalRpcHandler {
    state: AppState,
}

impl ExternalRpcHandler {
    pub(crate) fn new(state: AppState) -> Self {
        Self { state }
    }
}

impl WorkerRpc for ExternalRpcHandler {
    async fn info(self) -> Result<AppInfo> {
        get_info(&self.state, true).await
    }

    async fn version(self) -> Result<WorkerVersion> {
        Ok(WorkerVersion {
            version: crate::CARGO_PKG_VERSION.to_string(),
            rev: crate::GIT_REV.to_string(),
        })
    }

    /// Legacy and frozen at the v0.5.11 shape. See the RPC's doc comment in
    /// agent_rpc.proto.
    ///
    /// Returns a `GetQuoteResponse`, which only Intel TDX can fill, so this
    /// fails on every other platform exactly as `GetQuote` does. v1 ships no
    /// counterpart that lifts the limitation: a v1 application attests its own
    /// key instead -- derive it at `/v1/GetKey`, commit the public key into
    /// `report_data`, call `/v1/Attest`, and serve the result to relying
    /// parties. See the `Worker` service comment in agent_rpc_v1.proto.
    ///
    /// The report data comes from `app_key_report_data`, which commits to the
    /// key `Sign` derives -- same path, purpose and base algorithm -- so the
    /// attested public key is the one that actually signs.
    async fn get_attestation_for_app_key(
        self,
        request: GetAttestationForAppKeyRequest,
    ) -> Result<GetQuoteResponse> {
        let report_data = self.app_key_report_data(&request.algorithm).await?;
        self.state.quote_response(report_data)
    }
}

impl ExternalRpcHandler {
    /// Derive the app key for `algorithm` and build the DIP-1 report data that
    /// commits to its public key.
    ///
    /// The caller cannot compute this itself -- it does not know the public key
    /// until the key is derived here -- which is why attesting an app key needs
    /// its own method instead of the caller-supplied report data `GetQuote`
    /// and `Attest` take.
    pub(crate) async fn app_key_report_data(&self, algorithm: &str) -> Result<[u8; 64]> {
        let algorithm = normalize_algorithm(algorithm);
        // Prehashing is a signing mode, not a key type: the same secp256k1 key
        // signs both ways, so derive it under the base name. `Sign` does the
        // same, and without this the prehashed name reaches `get_key` verbatim
        // and comes back "Unsupported algorithm".
        let key_algorithm = match algorithm {
            "secp256k1_prehashed" => "secp256k1",
            other => other,
        };
        let key_response = InternalRpcHandler {
            state: self.state.clone(),
        }
        .get_key(GetKeyArgs {
            path: "vms".to_string(),
            purpose: "signing".to_string(),
            algorithm: key_algorithm.to_string(),
        })
        .await?;

        let (prefix, pubkey) = match algorithm {
            "ed25519" => {
                let key_bytes: [u8; 32] = key_response
                    .key
                    .try_into()
                    .ok()
                    .context("Key is incorrect")?;
                let key = Ed25519SigningKey::from_bytes(&key_bytes);
                ("dip1::ed25519-pk:", key.verifying_key().to_bytes().to_vec())
            }
            "secp256k1" | "secp256k1_prehashed" => {
                let key = SigningKey::from_slice(&key_response.key)
                    .context("Failed to parse secp256k1 key")?;
                (
                    "dip1::secp256k1c-pk:",
                    key.verifying_key().to_sec1_bytes().to_vec(),
                )
            }
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };

        let report_string = format!("{prefix}{}", URL_SAFE_NO_PAD.encode(pubkey));
        let bytes = report_string.as_bytes();
        let mut report_data = [0u8; 64];
        // A longer public key encoding than the 64 bytes of report data would
        // otherwise truncate into a valid-looking commitment to a different key.
        if bytes.len() > report_data.len() {
            anyhow::bail!("report data for {algorithm} does not fit in 64 bytes");
        }
        report_data[..bytes.len()].copy_from_slice(bytes);
        Ok(report_data)
    }
}

impl RpcCall<AppState> for ExternalRpcHandler {
    type PrpcService = WorkerServer<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(ExternalRpcHandler {
            state: context.state.clone(),
        })
    }
}

#[cfg(test)]
// `pub(crate)` so the v1 handler's tests can build a state from the same
// fixture. Two fixtures would let the two surfaces be tested against different
// app root keys, which is exactly what the cross-version key assertions check.
pub(crate) mod tests {
    use super::*;
    use crate::{
        backend::PlatformBackend,
        config::{AppComposeWrapper, Config},
    };
    use dstack_attest::attestation::AttestationVerifier;
    use dstack_guest_agent_rpc::v0::{GetAttestationForAppKeyRequest, SignRequest};
    use dstack_types::{AppCompose, AppKeys, EventLogVersion, KeyProvider};
    use ed25519_dalek::ed25519::signature::hazmat::PrehashVerifier;
    use ed25519_dalek::{
        Signature as Ed25519Signature, Verifier, VerifyingKey as Ed25519VerifyingKey,
    };
    use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
    use ra_tls::attestation::{AttestationV1, PlatformEvidence, VersionedAttestation};
    use sha2::{Digest as _, Sha256};
    use std::collections::HashSet;
    use std::convert::TryFrom;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn extract_pubkey_from_report_data(report_data: &[u8], prefix: &str) -> Result<Vec<u8>> {
        let end = report_data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(report_data.len());
        let report_str = std::str::from_utf8(&report_data[..end])?;

        if let Some(base64_pk) = report_str.strip_prefix(prefix) {
            URL_SAFE_NO_PAD
                .decode(base64_pk)
                .context("Failed to decode base64")
        } else {
            Err(anyhow::anyhow!("Prefix not found in report data"))
        }
    }

    pub(crate) async fn setup_test_state() -> (AppState, tempfile::NamedTempFile) {
        setup_test_state_with_platform(None).await
    }

    /// How many times the fixture platform was asked to attest for `Info`, and
    /// whether it should refuse. Counting the calls is the only way to see the
    /// identity throttle work: what it changes is how often the platform is
    /// touched, not what any single call returns.
    #[derive(Default)]
    struct InfoAttestationProbe {
        calls: AtomicUsize,
        failing: AtomicBool,
    }

    impl InfoAttestationProbe {
        fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                failing: AtomicBool::new(true),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::Relaxed)
        }

        fn set_failing(&self, failing: bool) {
            self.failing.store(failing, Ordering::Relaxed);
        }
    }

    /// The fixture state, built against a platform the probe watches.
    async fn setup_test_state_with_probe(
        probe: Arc<InfoAttestationProbe>,
    ) -> (AppState, tempfile::NamedTempFile) {
        build_test_state(None, |_| {}, probe).await
    }

    /// The same state with the app having opted into publishing its TCB info,
    /// which is what unlocks the document fields on the external surface.
    pub(crate) async fn setup_test_state_with_public_tcbinfo() -> (AppState, tempfile::NamedTempFile)
    {
        build_test_state(
            None,
            |config| {
                config.app_compose.app_compose.public_tcbinfo = true;
                config.app_compose.raw = r#"{"name":"test"}"#.to_string();
            },
            Arc::default(),
        )
        .await
    }

    /// The same state, with the fixture's platform evidence swapped out.
    /// `None` keeps the fixture's Intel TDX evidence.
    pub(crate) async fn setup_test_state_with_platform(
        platform: Option<PlatformEvidence>,
    ) -> (AppState, tempfile::NamedTempFile) {
        build_test_state(platform, |_| {}, Arc::default()).await
    }

    /// The one fixture body. `configure` adjusts the app config before the
    /// state is built, which is cheaper and clearer than rebuilding an
    /// already-shared `Arc` afterwards.
    async fn build_test_state(
        platform: Option<PlatformEvidence>,
        configure: impl FnOnce(&mut Config),
        probe: Arc<InfoAttestationProbe>,
    ) -> (AppState, tempfile::NamedTempFile) {
        let mut temp_attestation_file = tempfile::NamedTempFile::new().unwrap();

        let attestation = include_bytes!("../fixtures/attestation.bin");
        temp_attestation_file.write_all(attestation).unwrap();
        temp_attestation_file.flush().unwrap();

        let dummy_appcompose = AppCompose {
            manifest_version: "2".to_string(),
            name: String::new(),
            features: Vec::new(),
            runner: String::new(),
            snapshotter: None,
            docker_compose_file: None,
            init_script: Vec::new(),
            public_logs: false,
            public_sysinfo: false,
            public_tcbinfo: false,
            kms_enabled: false,
            gateway_enabled: false,
            local_key_provider_enabled: false,
            key_provider: None,
            key_provider_id: Vec::new(),
            allowed_envs: Vec::new(),
            no_instance_id: false,
            secure_time: false,
            storage_fs: None,
            swap_size: 0,
            event_log_version: EventLogVersion::V1,
            port_policy: Default::default(),
            requirements: None,
            verity_volumes: Vec::new(),
        };

        let dummy_appcompose_wrapper = AppComposeWrapper {
            app_compose: dummy_appcompose,
            raw: String::new(),
        };

        let mut dummy_config = Config {
            keys_file: String::new(),
            app_compose: dummy_appcompose_wrapper,
            sys_config_file: String::new().into(),
            data_disks: HashSet::new(),
        };
        configure(&mut dummy_config);

        const DUMMY_PEM_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCSeV81CKVqILf/
bk+OarAkZeph4ggb1d9Qt4bzJjVNsowpc/iWbacO6dHvrjXrqNdK7WEHDuxYlQCS
xppINUCKyCoelAt2OJuUonLHtT3s41pGM0k69fcUb420fhKqNAHIaCCc38vOFDZ7
aqLUGNDooc7bXgZxHUJHmq9QneeB74Ia+6TzA2KKXMu4ixvZWvrgRt64XKyL3+4J
sQ6QqSgopGeyTv0blxFxF6X8UTUO/nZPnqf7BN9GnkJtHglb0TLI1H7BYvFmnpjT
8yfjmdbRxvnczvRJuKCzTq9ePEvhRrwAzqQk3Ide0/KWdIiu2nrrfO/Imvia1DNp
GgJsV0L7AgMBAAECggEARUbTcV1kAwRzkgOF7CloouZzCxWhWSz4AJC06oadOmDi
qu53WgqFs2eCjBZ82TdTkFQiiniT7zeV/FWjfdh17M3MIgdKPoF6kDufBvahUcuc
FEzIa3MPB+LVBlOEl2yelT8ugZPVrGPh+tBOL/uGvyhckmNvr4szoHM4TOxKJSk/
njFbJcoX3UmampyxSa6MMSGaxM2pdziTujoj5+sJ/a0x/wwIih/XEZSWgLzDjGZS
qaKmldjD0SRJQrZ1LTjjguKtkbOwKa2dtNOoHBkAtHyI+vWOLXNzZisXMazpmHNT
mE2X6oQFcAXI7HHuHzkLaLpEdqlHA16nwFPNF0LzAQKBgQDLaE1eZnutK+nxHpUq
cb3vMGN8dPxCrQJz/fvEb6lP93RCWBZbGen2gLGvFKyFwPcD/OR0HfBnFRjHIy25
V4ta+iubQM3GFO2FOp9SwequCPY2H6YXah4LyXrCIw4Pv3x/I2bpbLOlltmMT5PS
qPV86dH546kxOsJS6VhMCcQXAQKBgQC4WJu9VTBPfKf8JL8f7b/K0+MBN3OBkhsN
V6nCR8JizAa1hxmxpMaeq7PqlGpJhQKinBblR314Cpqqrt7AL005gCxD0ddBM9Ib
/7HafmLrAuhEDxnYx/QAyprTOsqjLS8Vd+eaA0nGF68R1LLHLxfXfhiuAjMwScCs
afCrbdG1+wKBgAyZ3ZEnkCneOpPxbRRAD6AtwzwGk0oeJbTB20MEF90YW19wzZG/
PTtEJb3O7hErLyJUHGMFJ8t7BxnvF/oPblaogOMRVK4cxconI4+g68T0USxxMXzp
2gqo5K36NfjLyA6oRsvXLBnqCngixembBfpDEfsFG4otNbSlOA8d28QBAoGBAKdG
YCtxPaEi8BtwDK2gQsR9eCMGeh08wqdcwIG2M8EKeZwGt13mswQPsfZOLhQASd/b
2zq5oDRpCueOPjoNsflXQNNZegWETEdzwaMNxByUSsZXHZED/3koX00EsBNZULwe
TV4HVc4Wd5mqc38iUHQNy78559ENW3QXvXcQ85Y5AoGBAIQlSbNRupo/5ATwJW0e
bggPyacIhS9GrsgP9qz9p8xxNSfcyAFRGiXnlGoiRbNchbUiZPRjoJ08lOHGxVQw
O17ivI85heZnG+i5Yz0ZolMd8fbc4h78oA9FnJQJV5AeTDqTxf528A2jyWCAmu11
Sv2zO+vcYHN7bT2UTCEWkeAw
-----END PRIVATE KEY-----
"#;

        const DUMMY_PEM_CERT: &str = r#"-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUYRX7SNHsL6EGSy0ACQzjX4cfaw0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI1MTAwOTEyNDMyN1oXDTI2MTAw
OTEyNDMyN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAknlfNQilaiC3/25PjmqwJGXqYeIIG9XfULeG8yY1TbKM
KXP4lm2nDunR764166jXSu1hBw7sWJUAksaaSDVAisgqHpQLdjiblKJyx7U97ONa
RjNJOvX3FG+NtH4SqjQByGggnN/LzhQ2e2qi1BjQ6KHO214GcR1CR5qvUJ3nge+C
Gvuk8wNiilzLuIsb2Vr64EbeuFysi9/uCbEOkKkoKKRnsk79G5cRcRel/FE1Dv52
T56n+wTfRp5CbR4JW9EyyNR+wWLxZp6Y0/Mn45nW0cb53M70Sbigs06vXjxL4Ua8
AM6kJNyHXtPylnSIrtp663zvyJr4mtQzaRoCbFdC+wIDAQABo1MwUTAdBgNVHQ4E
FgQUsnBjoCWFH3il0MvjO9p0o/vcACgwHwYDVR0jBBgwFoAUsnBjoCWFH3il0Mvj
O9p0o/vcACgwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAj9rI
cHDTj9LhD2Nca/Mj2dNwUa1Fq81I5EF3GWi6mosTT4hfQupUC1i/6UE6ubLHRUGr
J3JnHBG8hUCddx5VxLncDmYP/4LHVEue/XdCURgY+K2WxQnUPDzZV2mXJXUzp8si
6xzFyiPyf4qsQaoRQnpOmyUXvBwtdf3M28EA/pTBBDZ4pZJ1QaSTlT7fpDgK2e6L
arBh7HebdS9UBaWLtYBMsRWRK5qpOQnLiy8H6J93/W6i4X3DSxeZXeYiMSO/jsJ8
5XxL9zqOVjsw9Bxr79zCe7JF6fp6r3miUndMHQch/WXOY07lxH00cEqYo+2/Vk5D
pNs85uhOZE8z2jr8Pg==
-----END CERTIFICATE-----
"#;

        const DUMMY_K256_KEY: [u8; 32] = [
            0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B, 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B,
            0x5C, 0x6D, 0x7E, 0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B, 0x7C, 0x8D,
            0x9E, 0x0F, 0x1A, 0x2B,
        ];

        let dummy_keys = AppKeys {
            disk_crypt_key: Vec::new(),
            env_crypt_key: Vec::new(),
            k256_key: DUMMY_K256_KEY.to_vec(),
            k256_signature: Vec::new(),
            gateway_app_id: String::new(),
            ca_cert: DUMMY_PEM_CERT.to_string(),
            key_provider: KeyProvider::None {
                key: DUMMY_PEM_KEY.to_string(),
            },
        };

        let verifier = Arc::new(AttestationVerifier::new_prod(None).unwrap());
        let dummy_cert_client = CertRequestClient::create(&dummy_keys, verifier, String::new())
            .await
            .expect("Failed to create CertRequestClient");

        struct TestSimulatorPlatform {
            attestation: VersionedAttestation,
            probe: Arc<InfoAttestationProbe>,
        }

        fn patch_report_data(
            attestation: &VersionedAttestation,
            report_data: [u8; 64],
        ) -> AttestationV1 {
            attestation.clone().into_v1().with_report_data(report_data)
        }

        impl PlatformBackend for TestSimulatorPlatform {
            fn attestation_for_info(&self) -> Result<VersionedAttestation> {
                self.probe.calls.fetch_add(1, Ordering::Relaxed);
                if self.probe.failing.load(Ordering::Relaxed) {
                    anyhow::bail!("the platform cannot attest right now");
                }
                Ok(self.attestation.clone())
            }

            fn certificate_attestation(&self, pubkey: &[u8]) -> Result<VersionedAttestation> {
                let report_data =
                    ra_tls::attestation::QuoteContentType::RaTlsCert.to_report_data(pubkey);
                let attestation = patch_report_data(&self.attestation, report_data);
                Ok(VersionedAttestation::V1 { attestation })
            }

            fn quote_response(
                &self,
                report_data: [u8; 64],
                vm_config: &str,
            ) -> Result<GetQuoteResponse> {
                let attestation = patch_report_data(&self.attestation, report_data);
                let Some(quote) = attestation.platform.tdx_quote().map(ToOwned::to_owned) else {
                    return Err(anyhow::anyhow!(
                        "GetQuote is Intel TDX only, use Attest on this platform"
                    ));
                };
                Ok(GetQuoteResponse {
                    quote,
                    event_log: serde_json::to_string(
                        attestation.tdx_event_log().unwrap_or_default(),
                    )
                    .unwrap_or_default(),
                    report_data: report_data.to_vec(),
                    vm_config: vm_config.to_string(),
                })
            }

            fn attest_cvm(&self, report_data: [u8; 64]) -> Result<VersionedAttestation> {
                let attestation = patch_report_data(&self.attestation, report_data);
                Ok(VersionedAttestation::V1 { attestation })
            }
        }

        let inner = AppStateInner {
            config: dummy_config,
            keys: dummy_keys,
            vm_config: String::new(),
            cert_client: dummy_cert_client,
            demo_cert: RwLock::new(String::new()),
            platform: Arc::new(TestSimulatorPlatform {
                attestation: {
                    let fixture = VersionedAttestation::from_bytes(
                        &std::fs::read(temp_attestation_file.path()).unwrap(),
                    )
                    .unwrap();
                    match platform {
                        None => fixture,
                        Some(evidence) => {
                            let mut attestation = fixture.into_v1();
                            attestation.platform = evidence;
                            VersionedAttestation::V1 { attestation }
                        }
                    }
                },
                probe,
            }),
            health: None,
            // Pinned to a path that cannot exist, so no test ever spawns a
            // real collection against a host GPU and every test sees the
            // same "this image cannot attest a GPU" answer.
            gpu_attestor: crate::gpu_attest::GpuAttestor::with_nvattest_path(
                "/nonexistent/nvattest",
            ),
            app_root_signing_key: SigningKey::from_slice(&DUMMY_K256_KEY).ok(),
            identity: RwLock::new(None),
            identity_last_failure: Mutex::new(None),
            // Read the same way production does, so a test comparing v1 `Info`
            // against v0 `get_info` compares like with like.
            cloud_vendor: read_dmi_file("sys_vendor"),
            cloud_product: read_dmi_file("product_name"),
        };

        (
            AppState {
                inner: Arc::new(inner),
            },
            temp_attestation_file,
        )
    }

    #[tokio::test]
    async fn test_sign_ed25519_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for ed25519";
        let request = SignRequest {
            algorithm: "ed25519".to_string(),
            data: data_to_sign.to_vec(),
        };

        let response = handler.sign(request).await.unwrap();

        let report_data = ExternalRpcHandler::new(state)
            .app_key_report_data("ed25519")
            .await
            .unwrap();
        let pk_bytes = extract_pubkey_from_report_data(&report_data, "dip1::ed25519-pk:").unwrap();

        let public_key = Ed25519VerifyingKey::try_from(pk_bytes.as_slice()).unwrap();
        let signature = Ed25519Signature::try_from(response.signature.as_slice()).unwrap();
        assert!(public_key.verify(data_to_sign, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_sign_secp256k1_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for secp256k1";
        let request = SignRequest {
            algorithm: "secp256k1".to_string(),
            data: data_to_sign.to_vec(),
        };

        let response = handler.sign(request).await.unwrap();

        let report_data = ExternalRpcHandler::new(state)
            .app_key_report_data("secp256k1")
            .await
            .unwrap();
        let pk_bytes =
            extract_pubkey_from_report_data(&report_data, "dip1::secp256k1c-pk:").unwrap();

        let public_key = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
        let signature = K256Signature::try_from(response.signature.as_slice()).unwrap();
        assert!(public_key.verify(data_to_sign, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_sign_secp256k1_prehashed_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for secp256k1 prehashed";

        let digest = Sha256::digest(data_to_sign);

        let request = SignRequest {
            algorithm: "secp256k1_prehashed".to_string(),
            data: digest.to_vec(),
        };

        let response = handler.sign(request).await.unwrap();

        let report_data = ExternalRpcHandler::new(state)
            .app_key_report_data("secp256k1")
            .await
            .unwrap();
        let pk_bytes =
            extract_pubkey_from_report_data(&report_data, "dip1::secp256k1c-pk:").unwrap();

        let public_key = VerifyingKey::from_sec1_bytes(&pk_bytes).unwrap();
        let signature = K256Signature::try_from(response.signature.as_slice()).unwrap();
        assert!(public_key
            .verify_prehash(digest.as_slice(), &signature)
            .is_ok());
    }

    #[tokio::test]
    async fn test_sign_secp256k1_prehashed_invalid_length_fails() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };

        // digest with an invalid length
        let invalid_digest = vec![0; 31];

        let request = SignRequest {
            algorithm: "secp256k1_prehashed".to_string(),
            data: invalid_digest,
        };

        let response = handler.sign(request).await;
        assert!(response.is_err());
        assert!(response
            .unwrap_err()
            .to_string()
            .contains("requires a 32-byte digest"));
    }

    #[tokio::test]
    async fn test_sign_unsupported_algorithm_fails() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler { state };
        let request = SignRequest {
            algorithm: "rsa".to_string(), // Unsupported algorithm
            data: b"test message".to_vec(),
        };

        let result = handler.sign(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }

    const ED25519_REPORT_DATA: &str =
        "dip1::ed25519-pk:5Pbre1Amf1hrp2V2bbfKlIfxpQb2pJAmrgmhxgVoG9s\0\0\0\0";
    const SECP256K1_REPORT_DATA: &str =
        "dip1::secp256k1c-pk:A6t_JdVkVdMAocH3f1f20WGT6JzdntxcXimUtEax8zc9";

    /// The DIP-1 report data the frozen `Worker.GetAttestationForAppKey`
    /// commits to, wrapped in a TDX quote. Pinned so the commitment format a
    /// relying party parses cannot drift; v1 has no counterpart method, so
    /// this is the only surface these bytes appear on.
    #[tokio::test]
    async fn app_key_report_data_matches_its_vectors() {
        let (state, _guard) = setup_test_state().await;
        for (algorithm, expected) in [
            ("ed25519", ED25519_REPORT_DATA),
            ("secp256k1", SECP256K1_REPORT_DATA),
        ] {
            let report_data = ExternalRpcHandler::new(state.clone())
                .app_key_report_data(algorithm)
                .await
                .unwrap();
            assert_eq!(expected.as_bytes(), report_data.as_slice(), "{algorithm}");
        }
    }

    /// Prehashing changes how a key signs, not which key it is, so it must
    /// commit to the same public key as the plain name.
    #[tokio::test]
    async fn app_key_report_data_accepts_secp256k1_prehashed() {
        let (state, _guard) = setup_test_state().await;
        let prehashed = ExternalRpcHandler::new(state.clone())
            .app_key_report_data("secp256k1_prehashed")
            .await
            .expect("secp256k1_prehashed must be accepted");
        let plain = ExternalRpcHandler::new(state)
            .app_key_report_data("secp256k1")
            .await
            .unwrap();
        assert_eq!(prehashed, plain);
    }

    #[tokio::test]
    async fn app_key_report_data_rejects_an_unsupported_algorithm() {
        let (state, _guard) = setup_test_state().await;
        let result = ExternalRpcHandler::new(state)
            .app_key_report_data("ecdsa")
            .await;
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }

    /// The frozen method returns a `GetQuoteResponse`, which only Intel TDX can
    /// fill. That limitation is why v1 replaced the method with the
    /// attest-your-own-key flow rather than porting it, so it has to stay
    /// observable here.
    #[tokio::test]
    async fn get_attestation_for_app_key_is_tdx_only() {
        let (state, _guard) = setup_test_state_with_platform(Some(PlatformEvidence::SevSnp {
            report: vec![0u8; 1184],
            cert_chain: Vec::new(),
            mr_config: String::new(),
        }))
        .await;

        let err = ExternalRpcHandler::new(state)
            .get_attestation_for_app_key(GetAttestationForAppKeyRequest {
                algorithm: "ed25519".to_string(),
            })
            .await
            .expect_err("the frozen method cannot answer without a TDX quote");
        assert!(
            err.to_string().contains("Intel TDX only"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn get_attestation_for_app_key_answers_on_tdx() {
        let (state, _guard) = setup_test_state().await;
        let response = ExternalRpcHandler::new(state)
            .get_attestation_for_app_key(GetAttestationForAppKeyRequest {
                algorithm: "ed25519".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(ED25519_REPORT_DATA.as_bytes(), response.report_data);
        assert!(!response.quote.is_empty());
    }

    /// The frozen v0 signature chain, pinned byte for byte.
    ///
    /// Added when the keccak256 -> recoverable-sign -> `r || s || v` envelope
    /// was de-duplicated into `ra_tls::api_v1`: without a vector here,
    /// nothing would have caught the shared helper disagreeing with the copy it
    /// replaced. RFC 6979 makes the signature deterministic, so this is exact.
    #[tokio::test]
    async fn get_key_pins_the_frozen_chain_link() {
        let (state, _guard) = setup_test_state().await;
        let response = InternalRpcHandler::new(state)
            .get_key(GetKeyArgs {
                path: "test".to_string(),
                purpose: "signing".to_string(),
                algorithm: "secp256k1".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(
            hex::encode(&response.signature_chain[0]),
            "c8a3dcf06c4e95bd78a5d7a1c8fcff171fc5848cfae804c6fc11bda4dc5d4062379995390843827444992c4c0e4bac70f0f878e01b9fc8b98cd7126fe5a3876b01"
        );
    }

    #[test]
    fn test_normalize_algorithm() {
        assert_eq!(normalize_algorithm("k256"), "secp256k1");
        assert_eq!(normalize_algorithm("secp256k1"), "secp256k1");
        assert_eq!(normalize_algorithm("ed25519"), "ed25519");
        assert_eq!(normalize_algorithm(""), "");
        assert_eq!(normalize_algorithm("unknown"), "unknown");
    }

    #[tokio::test]
    async fn test_get_key_k256_alias() {
        let (state, _guard) = setup_test_state().await;
        let handler_k256 = InternalRpcHandler {
            state: state.clone(),
        };
        let handler_secp = InternalRpcHandler {
            state: state.clone(),
        };

        let req_k256 = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "k256".to_string(),
        };
        let req_secp = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "secp256k1".to_string(),
        };

        let resp_k256 = handler_k256.get_key(req_k256).await.unwrap();
        let resp_secp = handler_secp.get_key(req_secp).await.unwrap();

        // k256 alias should produce the same key as secp256k1
        assert_eq!(resp_k256.key, resp_secp.key);
    }

    #[tokio::test]
    async fn test_get_key_secp256k1_prehashed_rejected() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler { state };

        let request = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "secp256k1_prehashed".to_string(),
        };

        let result = handler.get_key(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }

    #[tokio::test]
    async fn test_get_key_ed25519_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler { state };

        let request = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "ed25519".to_string(),
        };

        let response = handler.get_key(request).await.unwrap();
        assert!(!response.key.is_empty());
        assert_eq!(response.signature_chain.len(), 2);
    }

    #[tokio::test]
    async fn test_get_key_default_algorithm() {
        let (state, _guard) = setup_test_state().await;
        let handler_default = InternalRpcHandler {
            state: state.clone(),
        };
        let handler_secp = InternalRpcHandler {
            state: state.clone(),
        };

        let req_default = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "".to_string(),
        };
        let req_secp = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "secp256k1".to_string(),
        };

        let resp_default = handler_default.get_key(req_default).await.unwrap();
        let resp_secp = handler_secp.get_key(req_secp).await.unwrap();

        // Empty algorithm should default to secp256k1
        assert_eq!(resp_default.key, resp_secp.key);
    }

    #[test]
    fn test_tls_certificate_validity_order() {
        assert!(validate_cert_validity(None, None).is_ok());
        assert!(validate_cert_validity(Some(10), Some(11)).is_ok());
        assert_eq!(
            validate_cert_validity(Some(11), Some(11))
                .unwrap_err()
                .to_string(),
            "not_before must be earlier than not_after"
        );
        assert!(validate_cert_validity(Some(12), Some(11)).is_err());
    }

    #[tokio::test]
    async fn test_get_key_unsupported_algorithm_fails() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler { state };

        let request = GetKeyArgs {
            path: "test".to_string(),
            purpose: "signing".to_string(),
            algorithm: "rsa".to_string(),
        };

        let result = handler.get_key(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }

    #[tokio::test]
    async fn test_version() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler { state };

        let response = handler.version().await.unwrap();
        assert!(!response.version.is_empty());
    }

    #[tokio::test]
    async fn test_tdx_quote_reports_effective_prefix() {
        let (state, _guard) = setup_test_state().await;

        let default = InternalRpcHandlerV0 {
            state: state.clone(),
        }
        .tdx_quote(TdxQuoteArgs {
            report_data: b"test".to_vec(),
            hash_algorithm: "sha512".to_string(),
            prefix: "".to_string(),
        })
        .await
        .unwrap();
        assert_eq!(default.prefix, "app-data");

        let custom = InternalRpcHandlerV0 { state }
            .tdx_quote(TdxQuoteArgs {
                report_data: b"test".to_vec(),
                hash_algorithm: "sha512".to_string(),
                prefix: "custom-domain".to_string(),
            })
            .await
            .unwrap();
        assert_eq!(custom.prefix, "custom-domain");
    }

    #[tokio::test]
    async fn test_sign_k256_alias() {
        let (state, _guard) = setup_test_state().await;
        let handler_k256 = InternalRpcHandler {
            state: state.clone(),
        };
        let handler_secp = InternalRpcHandler {
            state: state.clone(),
        };

        let data = b"test message".to_vec();

        let req_k256 = SignRequest {
            algorithm: "k256".to_string(),
            data: data.clone(),
        };
        let req_secp = SignRequest {
            algorithm: "secp256k1".to_string(),
            data: data.clone(),
        };

        let resp_k256 = handler_k256.sign(req_k256).await.unwrap();
        let resp_secp = handler_secp.sign(req_secp).await.unwrap();

        // k256 alias should produce the same public key as secp256k1
        assert_eq!(resp_k256.public_key, resp_secp.public_key);
    }

    /// Sign with `algorithm`, then verify the result through the legacy Verify
    /// RPC -- the round trip a 0.5.x SDK performs.
    async fn sign_then_verify(
        algorithm: &str,
        data: Vec<u8>,
    ) -> (AppState, tempfile::NamedTempFile, SignResponse) {
        let (state, guard) = setup_test_state().await;
        let signed = InternalRpcHandler {
            state: state.clone(),
        }
        .sign(SignRequest {
            algorithm: algorithm.to_string(),
            data: data.clone(),
        })
        .await
        .unwrap();

        let verified = InternalRpcHandler {
            state: state.clone(),
        }
        .verify(VerifyRequest {
            algorithm: algorithm.to_string(),
            data,
            signature: signed.signature.clone(),
            public_key: signed.public_key.clone(),
        })
        .await
        .unwrap();
        assert!(verified.valid);

        (state, guard, signed)
    }

    #[tokio::test]
    async fn verify_accepts_an_ed25519_signature_from_sign() {
        sign_then_verify("ed25519", b"test message for ed25519".to_vec()).await;
    }

    #[tokio::test]
    async fn verify_accepts_a_secp256k1_signature_from_sign() {
        sign_then_verify("secp256k1", b"test message for secp256k1".to_vec()).await;
    }

    #[tokio::test]
    async fn verify_accepts_a_secp256k1_prehashed_signature_from_sign() {
        let digest = Sha256::digest(b"test message for secp256k1 prehashed");
        sign_then_verify("secp256k1_prehashed", digest.to_vec()).await;
    }

    #[tokio::test]
    async fn verify_rejects_tampered_data() {
        let (state, _guard, signed) =
            sign_then_verify("ed25519", b"original message".to_vec()).await;

        let response = InternalRpcHandler { state }
            .verify(VerifyRequest {
                algorithm: "ed25519".to_string(),
                data: b"tampered message".to_vec(),
                signature: signed.signature,
                public_key: signed.public_key,
            })
            .await
            .unwrap();

        assert!(!response.valid);
    }

    /// A malleated (high-S) signature must not verify, and must come back as a
    /// verdict rather than as an error.
    ///
    /// Both halves matter. k256 rejects high-S inside the verification, not in
    /// `from_slice`, so the caller sees HTTP 200 with `valid: false` -- not the
    /// 400 a parse failure would produce, and the status code is the part a
    /// 0.5.x client branches on. A k256 upgrade that moved the check into
    /// parsing would keep the security answer and silently change the status,
    /// which is what `.expect()` below is here to catch.
    #[tokio::test]
    async fn verify_rejects_a_malleated_secp256k1_signature() {
        let data = b"test message for secp256k1".to_vec();
        let (state, _guard, signed) = sign_then_verify("secp256k1", data.clone()).await;

        // `sign` emits low-S, so negating `s` yields the other encoding of the
        // same signature -- the one an unnormalised verifier would also accept.
        let signature = K256Signature::from_slice(&signed.signature).unwrap();
        let malleated = K256Signature::from_scalars(signature.r(), -signature.s()).unwrap();
        // `normalize_s` is `Some` only for a high-S signature, so this asserts
        // the malleation is real and is exactly the twin of what just verified.
        assert_eq!(malleated.normalize_s().as_ref(), Some(&signature));

        let response = InternalRpcHandler { state }
            .verify(VerifyRequest {
                algorithm: "secp256k1".to_string(),
                data,
                signature: malleated.to_vec(),
                public_key: signed.public_key,
            })
            .await
            .expect("a malleated signature is a verdict, not an error");

        assert!(!response.valid);
    }

    #[tokio::test]
    async fn verify_unsupported_algorithm_fails() {
        let (state, _guard) = setup_test_state().await;
        let result = InternalRpcHandler { state }
            .verify(VerifyRequest {
                algorithm: "rsa".to_string(),
                data: b"test message".to_vec(),
                signature: vec![0; 64],
                public_key: vec![0; 32],
            })
            .await;

        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }

    #[tokio::test]
    async fn emit_event_reports_its_removal() {
        let (state, _guard) = setup_test_state().await;
        let result = InternalRpcHandler { state }
            .emit_event(EmitEventArgs {
                event: "test-event".to_string(),
                payload: b"payload".to_vec(),
            })
            .await;

        let err = result.unwrap_err().to_string();
        assert!(err.contains("removed in dstack 0.6.0"), "{err}");
    }

    /// A failed decode must be as cheap to repeat as a cached success is.
    /// `identity()` is reached from the anonymous `/prpc/v1/Info`, and each
    /// attempt is a hardware quote plus an RTMR replay under the global quote
    /// lock -- retrying per call would give a caller on a broken platform the
    /// very lever the cache exists to take away.
    #[tokio::test]
    async fn a_failed_identity_decode_is_not_retried_within_the_throttle_window() {
        let probe = Arc::new(InfoAttestationProbe::failing());
        let (state, _guard) = setup_test_state_with_probe(probe.clone()).await;

        let err = state
            .identity()
            .expect_err("the platform refuses to attest");
        assert!(err.to_string().contains("cannot attest"), "{err}");
        assert_eq!(probe.calls(), 1);

        for _ in 0..8 {
            let err = state.identity().expect_err("still throttled");
            assert!(
                err.to_string().contains("the app identity is unavailable"),
                "{err}"
            );
        }
        assert_eq!(
            probe.calls(),
            1,
            "the platform was asked again inside the throttle window"
        );
    }

    /// The throttle bounds the retry rate; it must not turn a transient failure
    /// into a permanent one. Once the window has passed the next call attests
    /// again, and a success from then on is cached like any other.
    #[tokio::test]
    async fn the_identity_decode_is_retried_once_the_throttle_window_has_passed() {
        let probe = Arc::new(InfoAttestationProbe::failing());
        let (state, _guard) = setup_test_state_with_probe(probe.clone()).await;
        state
            .identity()
            .expect_err("the platform refuses to attest");

        // Age the recorded failure rather than sleeping out the interval.
        *state
            .inner
            .identity_last_failure
            .lock()
            .expect("lock should never fail") = Some(
            Instant::now()
                .checked_sub(IDENTITY_RETRY_INTERVAL)
                .expect("the monotonic clock is older than the throttle window"),
        );
        probe.set_failing(false);

        let identity = state.identity().expect("the platform recovered");
        assert_eq!(probe.calls(), 2);

        let again = state.identity().expect("a decoded identity is cached");
        assert!(Arc::ptr_eq(&identity, &again));
        assert_eq!(
            probe.calls(),
            2,
            "a success must be cached, not re-decoded per call"
        );
    }
}
