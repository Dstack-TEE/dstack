// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{Context, Result};
use cert_client::CertRequestClient;
use dstack_guest_agent_rpc::{
    dstack_guest_server::{DstackGuestRpc, DstackGuestServer},
    tappd_server::{TappdRpc, TappdServer},
    worker_server::{WorkerRpc, WorkerServer},
    AppInfo, DeriveK256KeyResponse, DeriveKeyArgs, EmitEventArgs, GetAttestationRequest,
    GetKeyArgs, GetKeyResponse, GetQuoteResponse, GetTlsKeyArgs, GetTlsKeyResponse, RawQuoteArgs,
    SignRequest, SignResponse, TdxQuoteArgs, TdxQuoteResponse, WorkerVersion,
};
use dstack_types::{AppKeys, SysConfig};
use ed25519_dalek::{Signer as Ed25519Signer, SigningKey as Ed25519SigningKey};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{Attestation, CallContext, RpcCall};
use ra_tls::{
    attestation::{QuoteContentType, DEFAULT_HASH_ALGORITHM},
    cert::CertConfig,
    kdf::{derive_ecdsa_key, derive_ecdsa_key_pair_from_bytes},
};
use rand::rngs::OsRng;
use rcgen::KeyPair;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use sha3::{Digest, Keccak256};
use tdx_attest::eventlog::read_event_logs;

use crate::config::Config;

#[derive(Clone)]
pub struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    config: Config,
    keys: AppKeys,
    vm_config: String,
    cert_client: CertRequestClient,
    demo_cert: String,
    ed25519_key: Ed25519SigningKey,
    secp256k1_key: SigningKey,
    ed25519_attestation: GetQuoteResponse,
    secp256k1_attestation: GetQuoteResponse,
}

impl AppState {
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
                config.simulator.enabled,
            )
            .await
            .context("Failed to get app cert")?
            .join("\n");

        let mut csprng = OsRng;
        let ed25519_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let secp256k1_key = SigningKey::random(&mut csprng);

        let ed25519_pubkey = ed25519_key.verifying_key().to_bytes();
        let secp256k1_pubkey = secp256k1_key.verifying_key().to_sec1_bytes();

        let mut ed25519_report_data = [0u8; 64];
        ed25519_report_data[..ed25519_pubkey.len()].copy_from_slice(&ed25519_pubkey);

        let mut secp256k1_report_data = [0u8; 64];
        secp256k1_report_data[..secp256k1_pubkey.len()].copy_from_slice(&secp256k1_pubkey);
        let (ed25519_attestation, secp256k1_attestation) = if config.simulator.enabled {
            (
                simulate_quote(&config, ed25519_report_data, &vm_config)?,
                simulate_quote(&config, secp256k1_report_data, &vm_config)?,
            )
        } else {
            let (ed25519_quote, secp256k1_quote) = (
                tdx_attest::get_quote(&ed25519_report_data, None)
                    .context("Failed to get ed25519 quote")?
                    .1,
                tdx_attest::get_quote(&secp256k1_report_data, None)
                    .context("Failed to get secp256k1 quote")?
                    .1,
            );
            let event_log =
                serde_json::to_string(&read_event_logs().context("Failed to read event log")?)?;
            (
                GetQuoteResponse {
                    quote: ed25519_quote,
                    event_log: event_log.clone(),
                    report_data: ed25519_report_data.to_vec(),
                    vm_config: vm_config.clone(),
                },
                GetQuoteResponse {
                    quote: secp256k1_quote,
                    event_log,
                    report_data: secp256k1_report_data.to_vec(),
                    vm_config: vm_config.clone(),
                },
            )
        };

        Ok(Self {
            inner: Arc::new(AppStateInner {
                config,
                keys,
                cert_client,
                demo_cert,
                vm_config,
                ed25519_key,
                secp256k1_key,
                ed25519_attestation,
                secp256k1_attestation,
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

pub async fn get_info(state: &AppState, external: bool) -> Result<AppInfo> {
    let hide_tcb_info = external && !state.config().app_compose.public_tcbinfo;
    let response = InternalRpcHandler {
        state: state.clone(),
    }
    .get_quote(RawQuoteArgs {
        report_data: [0; 64].to_vec(),
    })
    .await;
    let Ok(response) = response else {
        return Ok(AppInfo::default());
    };
    let Ok(attestation) = Attestation::new(response.quote, response.event_log.into()) else {
        return Ok(AppInfo::default());
    };
    let app_info = attestation
        .decode_app_info(false)
        .context("Failed to decode app info")?;
    let event_log = &attestation.event_log;
    let tcb_info = if hide_tcb_info {
        "".to_string()
    } else {
        let app_compose = state.config().app_compose.raw.clone();
        serde_json::to_string_pretty(&json!({
            "mrtd": hex::encode(app_info.mrtd),
            "rtmr0": hex::encode(app_info.rtmr0),
            "rtmr1": hex::encode(app_info.rtmr1),
            "rtmr2": hex::encode(app_info.rtmr2),
            "rtmr3": hex::encode(app_info.rtmr3),
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
    Ok(AppInfo {
        app_name: state.config().app_compose.name.clone(),
        app_id: app_info.app_id,
        instance_id: app_info.instance_id,
        device_id: app_info.device_id,
        mr_aggregated: app_info.mr_aggregated.to_vec(),
        os_image_hash: app_info.os_image_hash.clone(),
        key_provider_info: String::from_utf8(app_info.key_provider_info).unwrap_or_default(),
        compose_hash: app_info.compose_hash.clone(),
        app_cert: state.inner.demo_cert.clone(),
        tcb_info,
        vm_config,
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
        let certificate_chain = self
            .state
            .inner
            .cert_client
            .request_cert(&derived_key, config, self.state.config().simulator.enabled)
            .await
            .context("Failed to sign the CSR")?;
        Ok(GetTlsKeyResponse {
            key: derived_key.serialize_pem(),
            certificate_chain,
        })
    }

    async fn get_key(self, request: GetKeyArgs) -> Result<GetKeyResponse> {
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
        let app_signing_key =
            SigningKey::from_slice(k256_app_key).context("Failed to parse app k256 key")?;
        let digest = Keccak256::new_with_prefix(msg_to_sign);
        let (signature, recid) = app_signing_key.sign_digest_recoverable(digest)?;
        let mut signature = signature.to_vec();
        signature.push(recid.to_byte());

        Ok(GetKeyResponse {
            key: derived_k256_key.to_bytes().to_vec(),
            signature_chain: vec![signature, self.state.inner.keys.k256_signature.clone()],
        })
    }

    async fn get_quote(self, request: RawQuoteArgs) -> Result<GetQuoteResponse> {
        fn pad64(data: &[u8]) -> Option<[u8; 64]> {
            if data.len() > 64 {
                return None;
            }
            let mut padded = [0u8; 64];
            padded[..data.len()].copy_from_slice(data);
            Some(padded)
        }
        let report_data = pad64(&request.report_data).context("Report data is too long")?;
        if self.state.config().simulator.enabled {
            return simulate_quote(
                self.state.config(),
                report_data,
                &self.state.inner.vm_config,
            );
        }
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;
        let event_log = read_event_logs().context("Failed to decode event log")?;
        let event_log =
            serde_json::to_string(&event_log).context("Failed to serialize event log")?;

        Ok(GetQuoteResponse {
            quote,
            event_log,
            report_data: report_data.to_vec(),
            vm_config: self.state.inner.vm_config.clone(),
        })
    }

    async fn emit_event(self, request: EmitEventArgs) -> Result<()> {
        if self.state.config().simulator.enabled {
            return Ok(());
        }
        tdx_attest::extend_rtmr3(&request.event, &request.payload)
    }

    async fn info(self) -> Result<AppInfo> {
        get_info(&self.state, false).await
    }

    async fn sign(self, request: SignRequest) -> Result<SignResponse> {
        let signature = match request.algorithm.as_str() {
            "ed25519" => {
                let signature = self.state.inner.ed25519_key.sign(&request.data);
                signature.to_bytes().to_vec()
            }
            "secp256k1" => {
                let signature: k256::ecdsa::Signature =
                    self.state.inner.secp256k1_key.sign(&request.data);
                signature.to_bytes().to_vec()
            }
            _ => return Err(anyhow::anyhow!("Unsupported algorithm")),
        };
        Ok(SignResponse { signature })
    }
}

fn simulate_quote(
    config: &Config,
    report_data: [u8; 64],
    vm_config: &str,
) -> Result<GetQuoteResponse> {
    let quote_file =
        fs::read_to_string(&config.simulator.quote_file).context("Failed to read quote file")?;
    let mut quote = hex::decode(quote_file.trim()).context("Failed to decode quote")?;
    let event_log = fs::read_to_string(&config.simulator.event_log_file)
        .context("Failed to read event log file")?;
    if quote.len() < 632 {
        return Err(anyhow::anyhow!("Quote is too short"));
    }
    quote[568..632].copy_from_slice(&report_data);
    Ok(GetQuoteResponse {
        quote,
        event_log,
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
        let certificate_chain = self
            .state
            .inner
            .cert_client
            .request_cert(&derived_key, config, self.state.config().simulator.enabled)
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
        let event_log = read_event_logs().context("Failed to decode event log")?;
        let event_log =
            serde_json::to_string(&event_log).context("Failed to serialize event log")?;
        let (_, quote) =
            tdx_attest::get_quote(&report_data, None).context("Failed to get quote")?;
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

    async fn get_attestation(self, request: GetAttestationRequest) -> Result<GetQuoteResponse> {
        match request.algorithm.as_str() {
            "ed25519" => Ok(self.state.inner.ed25519_attestation.clone()),
            "secp256k1" => Ok(self.state.inner.secp256k1_attestation.clone()),
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
    use dstack_guest_agent_rpc::{GetAttestationRequest, SignRequest};
    use dstack_types::{AppCompose, AppKeys, DockerConfig, KeyProvider};
    use ed25519_dalek::{Signature as Ed25519Signature, Verifier};
    use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
    use std::collections::HashSet;
    use std::convert::TryFrom;

    async fn setup_test_state() -> AppState {
        let mut csprng = OsRng;
        let ed25519_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let secp256k1_key = SigningKey::random(&mut csprng);

        let ed25519_attestation = GetQuoteResponse {
            quote: b"dummy_ed25519_quote".to_vec(),
            event_log: "dummy_ed25519_event_log".to_string(),
            report_data: vec![1; 64],
            vm_config: String::new(),
        };
        let secp256k1_attestation = GetQuoteResponse {
            quote: b"dummy_secp256k1_quote".to_vec(),
            event_log: "dummy_secp256k1_event_log".to_string(),
            report_data: vec![2; 64],
            vm_config: String::new(),
        };

        let dummy_simulator = Simulator {
            enabled: false,
            quote_file: String::new(),
            event_log_file: String::new(),
        };

        let dummy_docker_config = DockerConfig {
            registry: None,
            username: None,
            token_key: None,
        };

        let dummy_appcompose = AppCompose {
            manifest_version: 0,
            name: String::new(),
            features: Vec::new(),
            runner: String::new(),
            docker_compose_file: None,
            docker_config: dummy_docker_config,
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

        let dummy_keys = AppKeys {
            disk_crypt_key: Vec::new(),
            env_crypt_key: Vec::new(),
            k256_key: Vec::new(),
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
            demo_cert: String::new(),
            ed25519_key,
            secp256k1_key,
            ed25519_attestation,
            secp256k1_attestation,
        };

        AppState {
            inner: Arc::new(inner),
        }
    }

    #[tokio::test]
    async fn test_sign_ed25519_success() {
        let state = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for ed25519";
        let request = SignRequest {
            algorithm: "ed25519".to_string(),
            data: data_to_sign.to_vec(),
        };

        let response = handler.sign(request).await.unwrap();

        let public_key = state.inner.ed25519_key.verifying_key();
        let signature_bytes: [u8; 64] = response
            .signature
            .try_into()
            .expect("Signature length is incorrect");
        let signature = Ed25519Signature::from_bytes(&signature_bytes);
        assert!(public_key.verify(data_to_sign, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_sign_secp256k1_success() {
        let state = setup_test_state().await;
        let handler = InternalRpcHandler {
            state: state.clone(),
        };
        let data_to_sign = b"test message for secp256k1";
        let request = SignRequest {
            algorithm: "secp256k1".to_string(),
            data: data_to_sign.to_vec(),
        };

        let response = handler.sign(request).await.unwrap();

        let public_key = VerifyingKey::from(&state.inner.secp256k1_key);
        let signature = K256Signature::try_from(response.signature.as_slice()).unwrap();
        assert!(public_key.verify(data_to_sign, &signature).is_ok());
    }

    #[tokio::test]
    async fn test_sign_unsupported_algorithm_fails() {
        let state = setup_test_state().await;
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
    async fn test_get_attestation_ed25519_success() {
        let state = setup_test_state().await;
        let handler = ExternalRpcHandler::new(state.clone());
        let request = GetAttestationRequest {
            algorithm: "ed25519".to_string(),
        };

        let response = handler.get_attestation(request).await.unwrap();

        assert_eq!(response, state.inner.ed25519_attestation);
    }

    #[tokio::test]
    async fn test_get_attestation_secp256k1_success() {
        let state = setup_test_state().await;
        let handler = ExternalRpcHandler::new(state.clone());
        let request = GetAttestationRequest {
            algorithm: "secp256k1".to_string(),
        };

        let response = handler.get_attestation(request).await.unwrap();

        assert_eq!(response, state.inner.secp256k1_attestation);
    }

    #[tokio::test]
    async fn test_get_attestation_unsupported_algorithm_fails() {
        let state = setup_test_state().await;
        let handler = ExternalRpcHandler::new(state);
        let request = GetAttestationRequest {
            algorithm: "ecdsa".to_string(), // Unsupported algorithm
        };

        let result = handler.get_attestation(request).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Unsupported algorithm");
    }
}
