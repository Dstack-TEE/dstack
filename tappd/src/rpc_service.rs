use std::sync::Arc;

use anyhow::{Context, Result};
use cert_client::CertRequestClient;
use dstack_types::AppKeys;
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{Attestation, CallContext, RpcCall};
use ra_tls::{
    attestation::{QuoteContentType, DEFAULT_HASH_ALGORITHM},
    cert::CertConfig,
    kdf::{derive_ecdsa_key, derive_ecdsa_key_pair_from_bytes},
};
use rcgen::KeyPair;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use sha3::{Digest, Keccak256};
use tappd_rpc::{
    tappd_server::{TappdRpc, TappdServer},
    worker_server::{WorkerRpc, WorkerServer},
    DeriveK256KeyArgs, DeriveK256KeyResponse, DeriveKeyArgs, DeriveKeyResponse, RawQuoteArgs,
    TdxQuoteArgs, TdxQuoteResponse, WorkerInfo, WorkerVersion,
};
use tdx_attest::eventlog::read_event_logs;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: Config,
    keys: AppKeys,
    cert_client: CertRequestClient,
    demo_cert: String,
}

impl AppState {
    pub async fn new(config: Config) -> Result<Self> {
        let keys: AppKeys = serde_json::from_str(&fs::read_to_string(&config.keys_file)?)
            .context("Failed to parse app keys")?;
        let cert_client = CertRequestClient::create(&keys, config.pccs_url.as_deref())
            .await
            .context("Failed to create cert signer")?;
        let key = KeyPair::generate().context("Failed to generate demo key")?;
        let demo_cert = cert_client
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
            )
            .await
            .context("Failed to get app cert")?
            .join("\n");
        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                keys,
                cert_client,
                demo_cert,
            }),
        })
    }

    pub fn config(&self) -> &Config {
        &self.inner.config
    }
}

pub struct InternalRpcHandler {
    state: AppState,
}

impl InternalRpcHandler {}

impl TappdRpc for InternalRpcHandler {
    async fn derive_key(self, request: DeriveKeyArgs) -> anyhow::Result<DeriveKeyResponse> {
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
        let certificate_chain = self
            .state
            .inner
            .cert_client
            .request_cert(&derived_key, config)
            .await
            .context("Failed to sign the CSR")?;
        Ok(DeriveKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain,
        })
    }

    async fn derive_k256_key(self, request: DeriveK256KeyArgs) -> Result<DeriveK256KeyResponse> {
        let k256_app_key = &self.state.inner.keys.k256_key;
        let derived_k256_key = derive_ecdsa_key(k256_app_key, &[request.path.as_bytes()], 32)
            .context("Failed to derive k256 key")?;
        let derived_k256_key =
            SigningKey::from_slice(&derived_k256_key).context("Failed to parse k256 key")?;
        let derived_k256_pubkey = derived_k256_key.verifying_key();
        let msg_to_sign = format!(
            "{}:{}",
            request.purpose,
            hex::encode(derived_k256_pubkey.to_sec1_bytes())
        );
        let digest = Keccak256::new_with_prefix(msg_to_sign);
        let (signature, recid) = derived_k256_key.sign_digest_recoverable(digest)?;
        let mut signature = signature.to_vec();
        signature.push(recid.to_byte());

        Ok(DeriveK256KeyResponse {
            k256_key: derived_k256_key.to_bytes().to_vec(),
            k256_signature_chain: vec![signature, self.state.inner.keys.k256_signature.clone()],
        })
    }

    async fn tdx_quote(self, request: TdxQuoteArgs) -> Result<TdxQuoteResponse> {
        let content_type = if request.prefix.is_empty() {
            QuoteContentType::AppData
        } else {
            QuoteContentType::Custom(&request.prefix)
        };
        let report_data =
            content_type.to_report_data_with_hash(&request.report_data, &request.hash_algorithm)?;
        let event_log = read_event_logs().context("Failed to decode event log")?;
        let event_log =
            serde_json::to_string(&event_log).context("Failed to serialize event log")?;
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;
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

    async fn info(self) -> Result<WorkerInfo> {
        ExternalRpcHandler { state: self.state }.info().await
    }
}

impl RpcCall<AppState> for InternalRpcHandler {
    type PrpcService = TappdServer<Self>;

    fn construct(context: CallContext<'_, AppState>) -> Result<Self> {
        Ok(InternalRpcHandler {
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
    async fn info(self) -> Result<WorkerInfo> {
        let response = InternalRpcHandler {
            state: self.state.clone(),
        }
        .raw_quote(RawQuoteArgs {
            report_data: [0; 64].to_vec(),
        })
        .await;
        let Ok(response) = response else {
            return Ok(WorkerInfo::default());
        };
        let Ok(attestation) = Attestation::new(response.quote, response.event_log.into()) else {
            return Ok(WorkerInfo::default());
        };
        let app_info = attestation
            .decode_app_info(false)
            .context("Failed to decode app info")?;
        let event_log = &attestation.event_log;
        let app_compose = fs::read_to_string(&self.state.config().compose_file).unwrap_or_default();
        let tcb_info = serde_json::to_string_pretty(&json!({
            "mrtd": hex::encode(app_info.mrtd),
            "rtmr0": hex::encode(app_info.rtmr0),
            "rtmr1": hex::encode(app_info.rtmr1),
            "rtmr2": hex::encode(app_info.rtmr2),
            "rtmr3": hex::encode(app_info.rtmr3),
            "mr_aggregated": hex::encode(app_info.mr_aggregated),
            "mr_image": hex::encode(app_info.mr_image),
            "mr_key_provider": hex::encode(app_info.mr_key_provider),
            "compose_hash": hex::encode(&app_info.compose_hash),
            "device_id": hex::encode(&app_info.device_id),
            "event_log": event_log,
            "app_compose": app_compose,
        }))
        .unwrap_or_default();
        Ok(WorkerInfo {
            app_name: self.state.config().app_name.clone(),
            app_id: app_info.app_id,
            instance_id: app_info.instance_id,
            device_id: app_info.device_id,
            mr_aggregated: app_info.mr_aggregated.to_vec(),
            mr_image: app_info.mr_image.to_vec(),
            mr_key_provider: app_info.mr_key_provider.to_vec(),
            key_provider_info: String::from_utf8(app_info.key_provider_info).unwrap_or_default(),
            compose_hash: app_info.compose_hash.clone(),
            app_cert: self.state.inner.demo_cert.clone(),
            tcb_info,
            public_logs: self.state.config().public_logs,
            public_sysinfo: self.state.config().public_sysinfo,
        })
    }

    async fn version(self) -> Result<WorkerVersion> {
        Ok(WorkerVersion {
            version: env!("CARGO_PKG_VERSION").to_string(),
            rev: super::GIT_REV.to_string(),
        })
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
