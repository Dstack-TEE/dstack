// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    kms_client::KmsClient,
    onboard_server::{OnboardRpc, OnboardServer},
    AttestationInfoResponse, BootstrapRequest, BootstrapResponse, GetKmsKeyRequest, OnboardRequest,
    OnboardResponse,
};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{
    client::{CertInfo, RaClient, RaClientConfig},
    CallContext, RpcCall,
};
use ra_tls::{
    attestation::{PlatformEvidence, QuoteContentType, VerifiedAttestation, VersionedAttestation},
    cert::{CaCert, CertRequest},
    rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256},
};
use safe_write::safe_write;

use crate::{
    config::KmsConfig,
    main_service::upgrade_authority::{
        app_attest, dstack_client, ensure_kms_allowed, ensure_self_kms_allowed, pad64,
    },
};

#[derive(Clone)]
pub struct OnboardState {
    config: KmsConfig,
}

impl OnboardState {
    pub fn new(config: KmsConfig) -> Self {
        Self { config }
    }
}

pub struct OnboardHandler {
    state: OnboardState,
}

impl RpcCall<OnboardState> for OnboardHandler {
    type PrpcService = OnboardServer<Self>;

    fn construct(context: CallContext<'_, OnboardState>) -> Result<Self> {
        Ok(OnboardHandler {
            state: context.state.clone(),
        })
    }
}

impl OnboardRpc for OnboardHandler {
    async fn bootstrap(self, request: BootstrapRequest) -> Result<BootstrapResponse> {
        ensure_self_kms_allowed(&self.state.config)
            .await
            .context("KMS is not allowed to bootstrap")?;
        let keys = Keys::generate(&request.domain)
            .await
            .context("Failed to generate keys")?;

        let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        let ca_pubkey = keys.ca_key.public_key_der();
        let attestation = attest_keys(&ca_pubkey, &k256_pubkey).await?;

        let cfg = &self.state.config;
        let response = BootstrapResponse {
            ca_pubkey,
            k256_pubkey,
            attestation,
        };
        // Store the bootstrap info
        safe_write(cfg.bootstrap_info(), serde_json::to_vec(&response)?)?;
        keys.store(cfg)?;
        Ok(response)
    }

    async fn onboard(self, request: OnboardRequest) -> Result<OnboardResponse> {
        let source_url = request.source_url.trim_end_matches('/').to_string();
        let source_url = if source_url.ends_with("/prpc") {
            source_url
        } else {
            format!("{source_url}/prpc")
        };
        let keys = Keys::onboard(
            &self.state.config,
            &source_url,
            &request.domain,
            self.state.config.pccs_url.clone(),
        )
        .await
        .context("Failed to onboard")?;
        let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        keys.store(&self.state.config)
            .context("Failed to store keys")?;
        Ok(OnboardResponse { k256_pubkey })
    }

    async fn get_attestation_info(self) -> Result<AttestationInfoResponse> {
        let pccs_url = self.state.config.pccs_url.clone();

        // Get attestation from guest agent
        let report_data = pad64([0u8; 32]);
        let response = app_attest(report_data)
            .await
            .context("Failed to get attestation")?;

        // Decode and verify the attestation to get real device ID
        let attestation = VersionedAttestation::from_bytes(&response.attestation)
            .context("Failed to decode attestation")?;
        let attestation_mode = match &attestation.clone().into_v1().platform {
            PlatformEvidence::Tdx { .. } => "dstack-tdx",
            PlatformEvidence::GcpTdx => "dstack-gcp-tdx",
            PlatformEvidence::NitroEnclave => "dstack-nitro-enclave",
        }
        .to_string();
        let verified = attestation
            .into_v1()
            .verify(pccs_url.as_deref())
            .await
            .context("Failed to verify attestation")?;

        // Get vm_config from guest agent
        let info = dstack_client()
            .info()
            .await
            .context("Failed to get VM info")?;

        // Decode app info to get device_id, mr_aggregated, os_image_hash, mr_system
        let app_info = verified
            .decode_app_info_ex(false, &info.vm_config)
            .context("Failed to decode app info")?;

        let (eth_rpc_url, kms_contract_address) = match self.state.config.auth_api.get_info().await
        {
            Ok(info) => (
                info.eth_rpc_url.unwrap_or_default(),
                info.kms_contract_address.unwrap_or_default(),
            ),
            Err(err) => {
                tracing::warn!("failed to get auth api info: {err}");
                (String::new(), String::new())
            }
        };

        Ok(AttestationInfoResponse {
            device_id: app_info.device_id,
            mr_aggregated: app_info.mr_aggregated.to_vec(),
            os_image_hash: app_info.os_image_hash,
            attestation_mode,
            site_name: self.state.config.site_name.clone(),
            eth_rpc_url,
            kms_contract_address,
        })
    }

    async fn finish(self) -> anyhow::Result<()> {
        std::process::exit(0);
    }
}

struct Keys {
    k256_key: SigningKey,
    tmp_ca_key: KeyPair,
    tmp_ca_cert: Certificate,
    ca_key: KeyPair,
    ca_cert: Certificate,
    rpc_key: KeyPair,
    rpc_cert: Certificate,
    rpc_domain: String,
}

impl Keys {
    async fn generate(domain: &str) -> Result<Self> {
        let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let k256_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self::from_keys(tmp_ca_key, ca_key, rpc_key, k256_key, domain).await
    }

    async fn from_keys(
        tmp_ca_key: KeyPair,
        ca_key: KeyPair,
        rpc_key: KeyPair,
        k256_key: SigningKey,
        domain: &str,
    ) -> Result<Self> {
        let tmp_ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack Client Temp CA")
            .ca_level(0)
            .key(&tmp_ca_key)
            .build()
            .self_signed()?;

        // Create self-signed KMS cert
        let ca_cert = CertRequest::builder()
            .org_name("Dstack")
            .subject("Dstack KMS CA")
            .ca_level(1)
            .key(&ca_key)
            .build()
            .self_signed()?;
        let pubkey = rpc_key.public_key_der();
        let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
        let response = app_attest(report_data.to_vec())
            .await
            .context("Failed to get quote")?;
        let attestation = VersionedAttestation::from_bytes(&response.attestation)
            .context("Invalid attestation")?;

        // Sign WWW server cert with KMS cert
        let rpc_cert = CertRequest::builder()
            .subject(domain)
            .alt_names(&[domain.to_string()])
            .special_usage("kms:rpc")
            .maybe_attestation(Some(&attestation))
            .key(&rpc_key)
            .build()
            .signed_by(&ca_cert, &ca_key)?;
        Ok(Keys {
            k256_key,
            tmp_ca_key,
            tmp_ca_cert,
            ca_key,
            ca_cert,
            rpc_key,
            rpc_cert,
            rpc_domain: domain.to_string(),
        })
    }

    async fn onboard(
        cfg: &KmsConfig,
        other_kms_url: &str,
        domain: &str,
        pccs_url: Option<String>,
    ) -> Result<Self> {
        let attestation_slot = Arc::new(Mutex::new(None::<VerifiedAttestation>));
        let attestation_slot_out = attestation_slot.clone();
        let client = RaClientConfig::builder()
            .tls_no_check(true)
            .remote_uri(other_kms_url.to_string())
            .cert_validator(Box::new(move |info: Option<CertInfo>| {
                let Some(info) = info else {
                    bail!("Source KMS did not present a TLS certificate");
                };
                let Some(attestation) = info.attestation else {
                    bail!("Source KMS certificate does not contain attestation");
                };
                let mut slot = attestation_slot_out
                    .lock()
                    .map_err(|_| anyhow::anyhow!("source attestation mutex poisoned"))?;
                *slot = Some(attestation);
                Ok(())
            }))
            .maybe_pccs_url(pccs_url.clone())
            .build()
            .into_client()?;
        let mut kms_client = KmsClient::new(client);

        let tmp_ca = kms_client.get_temp_ca_cert().await?;
        let (ra_cert, ra_key) = gen_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key).await?;
        let ra_client = RaClient::new_mtls(other_kms_url.into(), ra_cert, ra_key, pccs_url)
            .context("Failed to create client")?;
        kms_client = KmsClient::new(ra_client);
        let source_attestation = attestation_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("source attestation mutex poisoned"))?
            .clone()
            .context("Missing source KMS attestation")?;
        ensure_kms_allowed(cfg, &source_attestation)
            .await
            .context("Source KMS is not allowed for onboarding")?;

        let info = dstack_client().info().await.context("Failed to get info")?;
        let keys_res = kms_client
            .get_kms_key(GetKmsKeyRequest {
                vm_config: info.vm_config,
            })
            .await?;
        if keys_res.keys.len() != 1 {
            return Err(anyhow::anyhow!("Invalid keys"));
        }
        let keys = keys_res.keys[0].clone();
        let tmp_ca_key_pem = keys_res.temp_ca_key;
        let root_ca_key_pem = keys.ca_key;
        let root_k256_key = keys.k256_key;

        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::from_pem(&root_ca_key_pem).context("Failed to parse CA key")?;
        let tmp_ca_key =
            KeyPair::from_pem(&tmp_ca_key_pem).context("Failed to parse tmp CA key")?;
        let ecdsa_key =
            SigningKey::from_slice(&root_k256_key).context("Failed to parse ECDSA key")?;
        Self::from_keys(tmp_ca_key, ca_key, rpc_key, ecdsa_key, domain).await
    }

    fn store(&self, cfg: &KmsConfig) -> Result<()> {
        self.store_keys(cfg)?;
        self.store_certs(cfg)?;
        safe_write(cfg.rpc_domain(), self.rpc_domain.as_bytes())?;
        Ok(())
    }

    fn store_keys(&self, cfg: &KmsConfig) -> Result<()> {
        safe_write(cfg.tmp_ca_key(), self.tmp_ca_key.serialize_pem())?;
        safe_write(cfg.root_ca_key(), self.ca_key.serialize_pem())?;
        safe_write(cfg.rpc_key(), self.rpc_key.serialize_pem())?;
        safe_write(cfg.k256_key(), self.k256_key.to_bytes())?;
        Ok(())
    }

    fn store_certs(&self, cfg: &KmsConfig) -> Result<()> {
        safe_write(cfg.tmp_ca_cert(), self.tmp_ca_cert.pem())?;
        safe_write(cfg.root_ca_cert(), self.ca_cert.pem())?;
        safe_write(cfg.rpc_cert(), self.rpc_cert.pem())?;
        Ok(())
    }
}

pub(crate) async fn update_certs(cfg: &KmsConfig) -> Result<()> {
    // Read existing keys
    let tmp_ca_key = KeyPair::from_pem(&fs::read_to_string(cfg.tmp_ca_key())?)?;
    let ca_key = KeyPair::from_pem(&fs::read_to_string(cfg.root_ca_key())?)?;
    let rpc_key = KeyPair::from_pem(&fs::read_to_string(cfg.rpc_key())?)?;

    // Read k256 key
    let k256_key_bytes = fs::read(cfg.k256_key())?;
    let k256_key = SigningKey::from_slice(&k256_key_bytes)?;

    let domain = if cfg.onboard.auto_bootstrap_domain.is_empty() {
        fs::read_to_string(cfg.rpc_domain())?
    } else {
        cfg.onboard.auto_bootstrap_domain.clone()
    };
    let domain = domain.trim();

    // Regenerate certificates using existing keys
    let keys = Keys::from_keys(tmp_ca_key, ca_key, rpc_key, k256_key, domain)
        .await
        .context("Failed to regenerate certificates")?;

    // Write the new certificates to files
    keys.store_certs(cfg)?;

    Ok(())
}

pub(crate) async fn bootstrap_keys(cfg: &KmsConfig) -> Result<()> {
    ensure_self_kms_allowed(cfg)
        .await
        .context("KMS is not allowed to auto-bootstrap")?;
    let keys = Keys::generate(&cfg.onboard.auto_bootstrap_domain)
        .await
        .context("Failed to generate keys")?;
    keys.store(cfg)?;
    Ok(())
}

async fn attest_keys(p256_pubkey: &[u8], k256_pubkey: &[u8]) -> Result<Vec<u8>> {
    let p256_hex = hex::encode(p256_pubkey);
    let k256_hex = hex::encode(k256_pubkey);
    let content_to_quote = format!("dstack-kms-genereted-keys-v1:{p256_hex};{k256_hex};");
    let hash = keccak256(content_to_quote.as_bytes());
    let report_data = pad64(hash);
    let res = app_attest(report_data).await?;
    Ok(res.attestation)
}

fn keccak256(msg: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(msg);
    hasher.finalize().into()
}

async fn gen_ra_cert(ca_cert_pem: String, ca_key_pem: String) -> Result<(String, String)> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let ca = CaCert::new(ca_cert_pem, ca_key_pem)?;
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let response = app_attest(report_data.to_vec())
        .await
        .context("Failed to get quote")?;
    let attestation =
        VersionedAttestation::from_bytes(&response.attestation).context("Invalid attestation")?;
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .attestation(&attestation)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}
