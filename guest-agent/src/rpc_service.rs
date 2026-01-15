// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cc_eventlog::tdx::read_event_log;
use cert_client::CertRequestClient;
use dstack_attest::emit_runtime_event;
use dstack_guest_agent_rpc::{
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
use ed25519_dalek::{
    Signer as Ed25519Signer, SigningKey as Ed25519SigningKey, Verifier as Ed25519Verifier,
};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use or_panic::ResultOrPanic;
use ra_rpc::{Attestation, CallContext, RpcCall};
use ra_tls::{
    attestation::{QuoteContentType, VersionedAttestation, DEFAULT_HASH_ALGORITHM},
    cert::CertConfig,
    kdf::{derive_ecdsa_key, derive_ecdsa_key_pair_from_bytes},
};
use rcgen::KeyPair;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use sha3::{Digest, Keccak256};
use tracing::error;

use crate::config::Config;

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
}

impl AppStateInner {
    fn simulator_attestation(&self) -> Result<Option<VersionedAttestation>> {
        if !self.config.simulator.enabled {
            return Ok(None);
        }
        let attestation_bytes = fs::read(&self.config.simulator.attestation_file)
            .context("Failed to read simulator attestation file")?;
        let attestation = VersionedAttestation::from_scale(&attestation_bytes)
            .context("Failed to decode simulator attestation")?;
        Ok(Some(attestation))
    }

    async fn request_demo_cert(&self) -> Result<String> {
        let key = KeyPair::generate().context("Failed to generate demo key")?;
        let attestation_override = self.simulator_attestation()?;
        let demo_cert = self
            .cert_client
            .request_cert(
                &key,
                CertConfig {
                    org_name: None,
                    subject: "demo-cert".to_string(),
                    subject_alt_names: vec![],
                    usage_server_auth: false,
                    usage_client_auth: true,
                    ext_quote: true,
                },
                attestation_override,
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

    pub async fn new(config: Config) -> Result<Self> {
        let keys: AppKeys = serde_json::from_str(&fs::read_to_string(&config.keys_file)?)
            .context("Failed to parse app keys")?;
        let sys_config: SysConfig =
            serde_json::from_str(&fs::read_to_string(&config.sys_config_file)?)
                .context("Failed to parse VM config")?;
        let vm_config = sys_config.vm_config;
        let cert_client =
            CertRequestClient::create(&keys, config.pccs_url.as_deref(), vm_config.clone())
                .await
                .context("Failed to create cert signer")?;
        let me = Self {
            inner: Arc::new(AppStateInner {
                config,
                keys,
                cert_client,
                demo_cert: RwLock::new(String::new()),
                vm_config,
            }),
        };
        me.maybe_request_demo_cert();
        Ok(me)
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }
}

pub struct InternalRpcHandler {
    state: AppState,
}

pub async fn get_info(state: &AppState, external: bool) -> Result<AppInfo> {
    let hide_tcb_info = external && !state.config().app_compose.public_tcbinfo;
    let attestation = if let Some(attestation) = state.inner.simulator_attestation()? {
        attestation.into_inner()
    } else {
        let Ok(attestation) = Attestation::local() else {
            return Ok(AppInfo::default());
        };
        attestation
    };
    let app_info = attestation
        .decode_app_info(false)
        .context("Failed to decode app info")?;
    let event_log = attestation
        .tdx_quote()
        .map(|q| &q.event_log[..])
        .unwrap_or_default();
    let tcb_info = if hide_tcb_info {
        "".to_string()
    } else {
        let app_compose = state.config().app_compose.raw.clone();
        let td_report = match attestation.get_td10_report() {
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

impl DstackGuestRpc for InternalRpcHandler {
    async fn get_tls_key(self, request: GetTlsKeyArgs) -> anyhow::Result<GetTlsKeyResponse> {
        let mut seed = [0u8; 32];
        SystemRandom::new()
            .fill(&mut seed)
            .context("Failed to generate secure seed")?;
        let derived_key =
            derive_ecdsa_key_pair_from_bytes(&seed, &[]).context("Failed to derive key")?;
        let config = CertConfig {
            org_name: None,
            subject: request.subject,
            subject_alt_names: request.alt_names,
            usage_server_auth: request.usage_server_auth,
            usage_client_auth: request.usage_client_auth,
            ext_quote: request.usage_ra_tls,
        };
        let attestation_override = self
            .state
            .inner
            .simulator_attestation()
            .context("Failed to load simulator attestation")?;
        let certificate_chain = self
            .state
            .inner
            .cert_client
            .request_cert(&derived_key, config, attestation_override)
            .await
            .context("Failed to sign the CSR")?;
        Ok(GetTlsKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain,
        })
    }

    async fn get_key(self, request: GetKeyArgs) -> Result<GetKeyResponse> {
        let k256_app_key = &self.state.inner.keys.k256_key;

        let (key, pubkey_hex) = match request.algorithm.as_str() {
            "ed25519" => {
                let derived_key = derive_ecdsa_key(k256_app_key, &[request.path.as_bytes()], 32)
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
            "secp256k1" | "secp256k1_prehashed" | "" => {
                let derived_key = derive_ecdsa_key(k256_app_key, &[request.path.as_bytes()], 32)
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
        let digest = Keccak256::new_with_prefix(msg_to_sign);
        let (signature, recid) = app_signing_key.sign_digest_recoverable(digest)?;
        let mut signature = signature.to_vec();
        signature.push(recid.to_byte());

        Ok(GetKeyResponse {
            key,
            signature_chain: vec![signature, self.state.inner.keys.k256_signature.clone()],
        })
    }

    async fn get_quote(self, request: RawQuoteArgs) -> Result<GetQuoteResponse> {
        let report_data = pad64(&request.report_data).context("Report data is too long")?;
        if self.state.config().simulator.enabled {
            return simulate_quote(
                self.state.config(),
                report_data,
                &self.state.inner.vm_config,
            );
        }
        let attestation = Attestation::quote(&report_data).context("Failed to get quote")?;
        let tdx_quote = attestation.get_tdx_quote_bytes();
        let tdx_event_log = attestation.get_tdx_event_log_string();
        Ok(GetQuoteResponse {
            quote: tdx_quote.unwrap_or_default(),
            event_log: tdx_event_log.unwrap_or_default(),
            report_data: report_data.to_vec(),
            vm_config: self.state.inner.vm_config.clone(),
        })
    }

    async fn emit_event(self, request: EmitEventArgs) -> Result<()> {
        if self.state.config().simulator.enabled {
            return Ok(());
        }
        emit_runtime_event(&request.event, &request.payload)
    }

    async fn info(self) -> Result<AppInfo> {
        get_info(&self.state, false).await
    }

    async fn sign(self, request: SignRequest) -> Result<SignResponse> {
        let key_response = self
            .get_key(GetKeyArgs {
                path: "vms".to_string(),
                purpose: "signing".to_string(),
                algorithm: request.algorithm.clone(),
            })
            .await?;
        let (signature, public_key) = match request.algorithm.as_str() {
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

    async fn verify(self, request: VerifyRequest) -> Result<VerifyResponse> {
        let valid = match request.algorithm.as_str() {
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
        if let Some(attestation) = self.state.inner.simulator_attestation()? {
            return Ok(AttestResponse {
                attestation: attestation.to_scale(),
            });
        }
        let attestation = Attestation::quote(&report_data).context("Failed to get attestation")?;
        Ok(AttestResponse {
            attestation: attestation.into_versioned().to_scale(),
        })
    }
}

fn pad64(data: &[u8]) -> Option<[u8; 64]> {
    if data.len() > 64 {
        return None;
    }
    let mut padded = [0u8; 64];
    padded[..data.len()].copy_from_slice(data);
    Some(padded)
}

fn simulate_quote(
    config: &Config,
    report_data: [u8; 64],
    vm_config: &str,
) -> Result<GetQuoteResponse> {
    let attestation_bytes = fs::read(&config.simulator.attestation_file)
        .context("Failed to read simulator attestation file")?;
    let VersionedAttestation::V0 { attestation } =
        VersionedAttestation::from_scale(&attestation_bytes)
            .context("Failed to decode simulator attestation")?;
    let mut attestation = attestation;
    let Some(quote) = attestation.tdx_quote_mut() else {
        return Err(anyhow::anyhow!("Quote not found"));
    };

    quote.quote[568..632].copy_from_slice(&report_data);
    Ok(GetQuoteResponse {
        quote: quote.quote.to_vec(),
        event_log: serde_json::to_string(&quote.event_log)
            .context("Failed to serialize event log")?,
        report_data: report_data.to_vec(),
        vm_config: vm_config.to_string(),
    })
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
        let derived_key = derive_ecdsa_key_pair_from_bytes(seed, &[request.path.as_bytes()])
            .context("Failed to derive key")?;
        let config = CertConfig {
            org_name: None,
            subject: request.subject,
            subject_alt_names: request.alt_names,
            usage_server_auth: request.usage_server_auth,
            usage_client_auth: request.usage_client_auth,
            ext_quote: request.usage_ra_tls,
        };
        let attestation_override = self
            .state
            .inner
            .simulator_attestation()
            .context("Failed to load simulator attestation")?;
        let certificate_chain = self
            .state
            .inner
            .cert_client
            .request_cert(&derived_key, config, attestation_override)
            .await
            .context("Failed to sign the CSR")?;
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
        let prefix = if hash_algorithm == "raw" {
            "".into()
        } else {
            QuoteContentType::AppData.tag().to_string()
        };
        let content_type = if request.prefix.is_empty() {
            QuoteContentType::AppData
        } else {
            QuoteContentType::Custom(&request.prefix)
        };
        let report_data =
            content_type.to_report_data_with_hash(&request.report_data, &request.hash_algorithm)?;
        if self.state.config().simulator.enabled {
            let response = simulate_quote(
                self.state.config(),
                report_data,
                &self.state.inner.vm_config,
            )?;
            return Ok(TdxQuoteResponse {
                quote: response.quote,
                event_log: response.event_log,
                hash_algorithm: hash_algorithm.to_string(),
                prefix,
            });
        }
        let event_log = read_event_log().context("Failed to decode event log")?;
        let event_log =
            serde_json::to_string(&event_log).context("Failed to serialize event log")?;
        let quote = tdx_attest::get_quote(&report_data).context("Failed to get quote")?;
        Ok(TdxQuoteResponse {
            quote,
            event_log,
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
            version: env!("CARGO_PKG_VERSION").to_string(),
            rev: super::GIT_REV.to_string(),
        })
    }

    async fn get_attestation_for_app_key(
        self,
        request: GetAttestationForAppKeyRequest,
    ) -> Result<GetQuoteResponse> {
        let key_response = InternalRpcHandler {
            state: self.state.clone(),
        }
        .get_key(GetKeyArgs {
            path: "vms".to_string(),
            purpose: "signing".to_string(),
            algorithm: request.algorithm.clone(),
        })
        .await?;

        match request.algorithm.as_str() {
            "ed25519" => {
                let key_bytes: [u8; 32] = key_response
                    .key
                    .try_into()
                    .ok()
                    .context("Key is incorrect")?;
                let ed25519_key = Ed25519SigningKey::from_bytes(&key_bytes);
                let ed25519_pubkey = ed25519_key.verifying_key().to_bytes();

                let mut ed25519_report_data = [0u8; 64];
                let ed25519_b64 = URL_SAFE_NO_PAD.encode(ed25519_pubkey);
                let ed25519_report_string = format!("dip1::ed25519-pk:{}", ed25519_b64);
                let ed_bytes = ed25519_report_string.as_bytes();
                ed25519_report_data[..ed_bytes.len()].copy_from_slice(ed_bytes);

                if self.state.config().simulator.enabled {
                    Ok(simulate_quote(
                        self.state.config(),
                        ed25519_report_data,
                        &self.state.inner.vm_config,
                    )?)
                } else {
                    let ed25519_quote = tdx_attest::get_quote(&ed25519_report_data)
                        .context("Failed to get ed25519 quote")?;
                    let event_log = serde_json::to_string(
                        &read_event_log().context("Failed to read event log")?,
                    )?;
                    Ok(GetQuoteResponse {
                        quote: ed25519_quote,
                        event_log: event_log.clone(),
                        report_data: ed25519_report_data.to_vec(),
                        vm_config: self.state.inner.vm_config.clone(),
                    })
                }
            }
            "secp256k1" | "secp256k1_prehashed" => {
                let secp256k1_key = SigningKey::from_slice(&key_response.key)
                    .context("Failed to parse secp256k1 key")?;
                let secp256k1_pubkey = secp256k1_key.verifying_key().to_sec1_bytes();

                let mut secp256k1_report_data = [0u8; 64];
                let secp256k1_b64 = URL_SAFE_NO_PAD.encode(secp256k1_pubkey);
                let secp256k1_report_string = format!("dip1::secp256k1c-pk:{}", secp256k1_b64);
                let secp_bytes = secp256k1_report_string.as_bytes();
                secp256k1_report_data[..secp_bytes.len()].copy_from_slice(secp_bytes);

                if self.state.config().simulator.enabled {
                    Ok(simulate_quote(
                        self.state.config(),
                        secp256k1_report_data,
                        &self.state.inner.vm_config,
                    )?)
                } else {
                    let secp256k1_quote = tdx_attest::get_quote(&secp256k1_report_data)
                        .context("Failed to get secp256k1 quote")?;
                    let event_log = serde_json::to_string(
                        &read_event_log().context("Failed to read event log")?,
                    )?;

                    Ok(GetQuoteResponse {
                        quote: secp256k1_quote,
                        event_log,
                        report_data: secp256k1_report_data.to_vec(),
                        vm_config: self.state.inner.vm_config.clone(),
                    })
                }
            }
            _ => Err(anyhow::anyhow!("Unsupported algorithm")),
        }
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
mod tests {
    use super::*;
    use crate::config::{AppComposeWrapper, Config, Simulator};
    use dstack_guest_agent_rpc::{GetAttestationForAppKeyRequest, SignRequest};
    use dstack_types::{AppCompose, AppKeys, KeyProvider};
    use ed25519_dalek::ed25519::signature::hazmat::PrehashVerifier;
    use ed25519_dalek::{
        Signature as Ed25519Signature, Verifier, VerifyingKey as Ed25519VerifyingKey,
    };
    use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
    use sha2::Sha256;
    use std::collections::HashSet;
    use std::convert::TryFrom;
    use std::io::Write;

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

    async fn setup_test_state() -> (AppState, tempfile::NamedTempFile) {
        let mut temp_attestation_file = tempfile::NamedTempFile::new().unwrap();

        let attestation = include_bytes!("../fixtures/attestation.bin");
        temp_attestation_file.write_all(attestation).unwrap();
        temp_attestation_file.flush().unwrap();

        let dummy_simulator = Simulator {
            enabled: true,
            attestation_file: temp_attestation_file.path().to_str().unwrap().to_string(),
        };

        let dummy_appcompose = AppCompose {
            manifest_version: 0,
            name: String::new(),
            features: Vec::new(),
            runner: String::new(),
            docker_compose_file: None,
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
        };

        let dummy_appcompose_wrapper = AppComposeWrapper {
            app_compose: dummy_appcompose,
            raw: String::new(),
        };

        let dummy_config = Config {
            keys_file: String::new(),
            app_compose: dummy_appcompose_wrapper,
            sys_config_file: String::new().into(),
            pccs_url: None,
            simulator: dummy_simulator,
            data_disks: HashSet::new(),
        };

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

        let dummy_cert_client = CertRequestClient::create(&dummy_keys, None, String::new())
            .await
            .expect("Failed to create CertRequestClient");

        let inner = AppStateInner {
            config: dummy_config,
            keys: dummy_keys,
            vm_config: String::new(),
            cert_client: dummy_cert_client,
            demo_cert: RwLock::new(String::new()),
        };

        (
            AppState {
                inner: Arc::new(inner),
            },
            temp_attestation_file,
        )
    }

    #[tokio::test]
    async fn test_verify_ed25519_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for ed25519";
        let sign_request = SignRequest {
            algorithm: "ed25519".to_string(),
            data: data_to_sign.to_vec(),
        };

        let sign_response = handler.sign(sign_request).await.unwrap();

        let verify_request = VerifyRequest {
            algorithm: "ed25519".to_string(),
            data: data_to_sign.to_vec(),
            signature: sign_response.signature,
            public_key: sign_response.public_key,
        };
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let verify_response = handler.verify(verify_request).await.unwrap();
        assert!(verify_response.valid);
    }

    #[tokio::test]
    async fn test_verify_secp256k1_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for secp256k1";
        let sign_request = SignRequest {
            algorithm: "secp256k1".to_string(),
            data: data_to_sign.to_vec(),
        };

        let sign_response = handler.sign(sign_request).await.unwrap();

        let verify_request = VerifyRequest {
            algorithm: "secp256k1".to_string(),
            data: data_to_sign.to_vec(),
            signature: sign_response.signature,
            public_key: sign_response.public_key,
        };
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let verify_response = handler.verify(verify_request).await.unwrap();
        assert!(verify_response.valid);
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

        let attestation_response = ExternalRpcHandler::new(state)
            .get_attestation_for_app_key(GetAttestationForAppKeyRequest {
                algorithm: "ed25519".to_string(),
            })
            .await
            .unwrap();

        let pk_bytes =
            extract_pubkey_from_report_data(&attestation_response.report_data, "dip1::ed25519-pk:")
                .unwrap();

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

        let attestation_response = ExternalRpcHandler::new(state)
            .get_attestation_for_app_key(GetAttestationForAppKeyRequest {
                algorithm: "secp256k1".to_string(),
            })
            .await
            .unwrap();

        let pk_bytes = extract_pubkey_from_report_data(
            &attestation_response.report_data,
            "dip1::secp256k1c-pk:",
        )
        .unwrap();

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

        let attestation_response = ExternalRpcHandler::new(state)
            .get_attestation_for_app_key(GetAttestationForAppKeyRequest {
                algorithm: "secp256k1".to_string(),
            })
            .await
            .unwrap();

        let pk_bytes = extract_pubkey_from_report_data(
            &attestation_response.report_data,
            "dip1::secp256k1c-pk:",
        )
        .unwrap();

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

    #[tokio::test]
    async fn test_get_attestation_for_app_key_ed25519_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = ExternalRpcHandler::new(state.clone());
        let request = GetAttestationForAppKeyRequest {
            algorithm: "ed25519".to_string(),
        };

        let response = handler.get_attestation_for_app_key(request).await.unwrap();

        const EXPECTED_REPORT_DATA: &str =
            "dip1::ed25519-pk:5Pbre1Amf1hrp2V2bbfKlIfxpQb2pJAmrgmhxgVoG9s\0\0\0\0";
        assert_eq!(EXPECTED_REPORT_DATA.as_bytes(), response.report_data);
    }

    #[tokio::test]
    async fn test_get_attestation_for_app_key_secp256k1_success() {
        let (state, _guard) = setup_test_state().await;
        let handler = ExternalRpcHandler::new(state.clone());
        let request = GetAttestationForAppKeyRequest {
            algorithm: "secp256k1".to_string(),
        };

        let response = handler.get_attestation_for_app_key(request).await.unwrap();

        const EXPECTED_REPORT_DATA: &str =
            "dip1::secp256k1c-pk:A6t_JdVkVdMAocH3f1f20WGT6JzdntxcXimUtEax8zc9";
        assert_eq!(EXPECTED_REPORT_DATA.as_bytes(), response.report_data);
    }

    #[tokio::test]
    async fn test_get_attestation_for_app_key_unsupported_algorithm_fails() {
        let (state, _guard) = setup_test_state().await;
        let handler = ExternalRpcHandler::new(state);
        let request = GetAttestationForAppKeyRequest {
            algorithm: "ecdsa".to_string(), // Unsupported algorithm
        };

        let result = handler.get_attestation_for_app_key(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }
}
