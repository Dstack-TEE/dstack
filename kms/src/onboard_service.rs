// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use dstack_guest_agent_rpc::{
    dstack_guest_client::DstackGuestClient, AttestResponse, RawQuoteArgs,
};
use dstack_kms_rpc::{
    kms_client::KmsClient,
    onboard_server::{OnboardRpc, OnboardServer},
    BootstrapRequest, BootstrapResponse, GetKmsKeyRequest, OnboardRequest, OnboardResponse,
};
use fs_err as fs;
use http_client::prpc::PrpcClient;
use k256::ecdsa::SigningKey;
use ra_rpc::{client::RaClient, CallContext, RpcCall};
use ra_tls::{
    attestation::{QuoteContentType, VersionedAttestation},
    cert::{CaCert, CertRequest},
    rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256},
};
use safe_write::safe_write;

use crate::ckd::{
    derive_root_key_from_mpc, g1_to_near_format, generate_ephemeral_keypair, MpcConfig,
};
use crate::config::{AuthApi, KmsConfig};
use crate::near_kms_client::{load_or_generate_near_signer, NearKmsClient};
use dcap_qvl::collateral;
use near_api::NetworkConfig;
use ra_tls::kdf;
use serde_json::json;

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
        let quote_enabled = self.state.config.onboard.quote_enabled;

        // Check if we're using NEAR auth API
        let use_near_mpc = matches!(&self.state.config.auth_api, AuthApi::Near { .. });

        let keys = if use_near_mpc {
            // Attempt MPC key derivation if config is available
            match try_derive_keys_from_mpc(&self.state.config, &request.domain, quote_enabled).await
            {
                Ok(Some(keys)) => {
                    tracing::info!("✅ Successfully derived keys from NEAR MPC network");
                    keys
                }
                Ok(None) => {
                    tracing::warn!("MPC config incomplete, falling back to local key generation");
                    Keys::generate(&request.domain, quote_enabled)
                        .await
                        .context("Failed to generate keys")?
                }
                Err(e) => {
                    tracing::warn!(
                        "MPC key derivation failed: {}, falling back to local generation",
                        e
                    );
                    Keys::generate(&request.domain, quote_enabled)
                        .await
                        .context("Failed to generate keys")?
                }
            }
        } else {
            // Ethereum/Base/Phala: Generate keys locally
            Keys::generate(&request.domain, quote_enabled)
                .await
                .context("Failed to generate keys")?
        };

        let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        let ca_pubkey = keys.ca_key.public_key_der();
        let attestation = if quote_enabled {
            Some(attest_keys(&ca_pubkey, &k256_pubkey).await?)
        } else {
            None
        };

        let cfg = &self.state.config;
        let response = BootstrapResponse {
            ca_pubkey,
            k256_pubkey,
            attestation: attestation.unwrap_or_default(),
        };
        // Store the bootstrap info
        safe_write(cfg.bootstrap_info(), serde_json::to_vec(&response)?)?;
        keys.store(cfg)?;
        Ok(response)
    }

    async fn onboard(self, request: OnboardRequest) -> Result<OnboardResponse> {
        let keys = Keys::onboard(
            &request.source_url,
            &request.domain,
            self.state.config.onboard.quote_enabled,
            self.state.config.pccs_url.clone(),
        )
        .await
        .context("Failed to onboard")?;
        keys.store(&self.state.config)
            .context("Failed to store keys")?;
        Ok(OnboardResponse {})
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
    async fn generate(domain: &str, quote_enabled: bool) -> Result<Self> {
        let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let k256_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self::from_keys(tmp_ca_key, ca_key, rpc_key, k256_key, domain, quote_enabled).await
    }

    /// Create Keys from MPC-derived root key
    /// The root_key is a 32-byte key derived from MPC
    async fn from_mpc_root_key(
        root_key: [u8; 32],
        domain: &str,
        quote_enabled: bool,
    ) -> Result<Self> {
        // Derive CA key from root key using deterministic key derivation
        let ca_key = kdf::derive_ecdsa_key_pair_from_bytes(&root_key, &[b"ca-key"])
            .context("Failed to derive CA key from MPC root key")?;

        // Derive tmp CA key from root key
        let tmp_ca_key = kdf::derive_ecdsa_key_pair_from_bytes(&root_key, &[b"tmp-ca-key"])
            .context("Failed to derive tmp CA key from MPC root key")?;

        // Derive RPC key from root key
        let rpc_key = kdf::derive_ecdsa_key_pair_from_bytes(&root_key, &[b"rpc-key"])
            .context("Failed to derive RPC key from MPC root key")?;

        // Use root key directly as K256 key (it's already 32 bytes)
        let k256_key = SigningKey::from_bytes(&root_key.into())
            .context("Failed to create K256 key from root key")?;

        Self::from_keys(tmp_ca_key, ca_key, rpc_key, k256_key, domain, quote_enabled).await
    }

    async fn from_keys(
        tmp_ca_key: KeyPair,
        ca_key: KeyPair,
        rpc_key: KeyPair,
        k256_key: SigningKey,
        domain: &str,
        quote_enabled: bool,
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
        let attestation = if quote_enabled {
            let pubkey = rpc_key.public_key_der();
            let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
            let response = app_attest(report_data.to_vec())
                .await
                .context("Failed to get quote")?;
            let attestation = VersionedAttestation::from_scale(&response.attestation)
                .context("Invalid attestation")?;
            Some(attestation)
        } else {
            None
        };

        // Sign WWW server cert with KMS cert
        let rpc_cert = CertRequest::builder()
            .subject(domain)
            .alt_names(&[domain.to_string()])
            .special_usage("kms:rpc")
            .maybe_attestation(attestation.as_ref())
            .key(&rpc_key)
            .build()
            .signed_by(&ca_cert, &ca_key)?;

        Ok(Self {
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
        other_kms_url: &str,
        domain: &str,
        quote_enabled: bool,
        pccs_url: Option<String>,
    ) -> Result<Self> {
        let kms_client = RaClient::new(other_kms_url.into(), true)?;
        let mut kms_client = KmsClient::new(kms_client);

        if quote_enabled {
            let tmp_ca = kms_client.get_temp_ca_cert().await?;
            let (ra_cert, ra_key) = gen_ra_cert(tmp_ca.temp_ca_cert, tmp_ca.temp_ca_key).await?;
            let ra_client = RaClient::new_mtls(other_kms_url.into(), ra_cert, ra_key, pccs_url)
                .context("Failed to create client")?;
            kms_client = KmsClient::new(ra_client);
        }

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
        Self::from_keys(
            tmp_ca_key,
            ca_key,
            rpc_key,
            ecdsa_key,
            domain,
            quote_enabled,
        )
        .await
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
    let keys = Keys::from_keys(
        tmp_ca_key,
        ca_key,
        rpc_key,
        k256_key,
        domain,
        cfg.onboard.quote_enabled,
    )
    .await
    .context("Failed to regenerate certificates")?;

    // Write the new certificates to files
    keys.store_certs(cfg)?;

    Ok(())
}

pub(crate) async fn bootstrap_keys(cfg: &KmsConfig) -> Result<()> {
    // Check if we're using NEAR auth API
    let use_near_mpc = matches!(&cfg.auth_api, AuthApi::Near { .. });

    let keys = if use_near_mpc {
        // Attempt MPC key derivation
        match try_derive_keys_from_mpc(
            cfg,
            &cfg.onboard.auto_bootstrap_domain,
            cfg.onboard.quote_enabled,
        )
        .await
        {
            Ok(Some(keys)) => {
                tracing::info!("✅ Successfully derived keys from NEAR MPC network");
                keys
            }
            Ok(None) => {
                tracing::warn!("MPC config incomplete, falling back to local key generation");
                Keys::generate(
                    &cfg.onboard.auto_bootstrap_domain,
                    cfg.onboard.quote_enabled,
                )
                .await
                .context("Failed to generate keys")?
            }
            Err(e) => {
                tracing::warn!(
                    "MPC key derivation failed: {}, falling back to local generation",
                    e
                );
                Keys::generate(
                    &cfg.onboard.auto_bootstrap_domain,
                    cfg.onboard.quote_enabled,
                )
                .await
                .context("Failed to generate keys")?
            }
        }
    } else {
        // Ethereum/Base/Phala: Generate keys locally
        Keys::generate(
            &cfg.onboard.auto_bootstrap_domain,
            cfg.onboard.quote_enabled,
        )
        .await
        .context("Failed to generate keys")?
    };

    keys.store(cfg)?;
    Ok(())
}

/// Attempt to derive keys from NEAR MPC network
/// Returns Ok(Some(keys)) if successful, Ok(None) if config is incomplete, Err if derivation failed
async fn try_derive_keys_from_mpc(
    cfg: &KmsConfig,
    domain: &str,
    quote_enabled: bool,
) -> Result<Option<Keys>> {
    let AuthApi::Near { near } = &cfg.auth_api else {
        return Ok(None);
    };

    let rpc_url = near
        .rpc_url
        .as_deref()
        .unwrap_or("https://free.rpc.fastnear.com")
        .to_string();

    // Check if MPC configuration is complete
    let mpc_contract_id = match &near.mpc_contract_id {
        Some(id) => id.clone(),
        None => {
            tracing::debug!("MPC contract ID not configured, skipping MPC derivation");
            return Ok(None);
        }
    };
    let kms_contract_id = &near.contract_id;
    let mpc_domain_id = near.mpc_domain_id;

    let network_id = near.network_id.as_deref().unwrap_or("testnet");
    let network_config = NetworkConfig::from_rpc_url(network_id, &rpc_url);

    // Load or generate NEAR signer (implicit account)
    let signer = load_or_generate_near_signer(cfg)?;
    let signer = match signer {
        Some(s) => s,
        None => {
            tracing::warn!("Failed to load or generate NEAR signer, cannot call KMS contract");
            return Ok(None);
        }
    };

    tracing::info!("Attempting MPC key derivation from NEAR network...");
    tracing::info!("  Network ID: {}", network_id);
    tracing::info!("  RPC URL: {}", rpc_url);
    tracing::info!("  MPC Contract: {}", mpc_contract_id);
    tracing::info!("  KMS Contract: {}", kms_contract_id);
    tracing::info!("  Domain ID: {}", mpc_domain_id);
    tracing::info!("  Signer Account ID: {}", signer.account_id);

    let kms_client = NearKmsClient::new(network_config, mpc_contract_id.clone(), kms_contract_id.clone(), Some(signer))?;

    let mpc_public_key = kms_client.get_mpc_public_key(mpc_domain_id).await?;

    tracing::info!(
        "✅ Fetched MPC public key from contract: {}",
        mpc_public_key
    );

    // Generate ephemeral BLS12-381 G1 keypair
    let (ephemeral_private_key, ephemeral_public_key) = generate_ephemeral_keypair();
    let worker_public_key = g1_to_near_format(ephemeral_public_key)
        .context("Failed to convert ephemeral public key to NEAR format")?;

    tracing::debug!("Generated ephemeral BLS12-381 keypair");

    // Create MPC config
    let mpc_config = MpcConfig {
        mpc_contract_id: mpc_contract_id.clone(),
        mpc_domain_id,
        mpc_public_key: mpc_public_key.clone(),
        kms_contract_id: kms_contract_id.clone(),
        near_rpc_url: rpc_url.to_string(),
    };

    // Get TDX attestation (quote, collateral, tcb_info) for KMS contract
    // The KMS contract's request_kms_root_key() requires attestation verification
    let (quote_hex, collateral_json, tcb_info_json) = if quote_enabled {
        // Generate a quote with the worker public key as report_data
        let worker_pubkey_bytes = ephemeral_public_key.to_compressed();
        let mut report_data = vec![0u8; 64];
        // Put worker public key in report_data (first 48 bytes for BLS12-381 G1)
        if worker_pubkey_bytes.len() <= 48 {
            report_data[..worker_pubkey_bytes.len()].copy_from_slice(&worker_pubkey_bytes);
        } else {
            // Hash if too long
            use sha2::{Digest, Sha256};
            let hash = Sha256::digest(&worker_pubkey_bytes);
            report_data[..32].copy_from_slice(&hash);
        }

        let attest_response = app_attest(report_data)
            .await
            .context("Failed to get TDX quote for MPC request")?;

        let attestation = VersionedAttestation::from_scale(&attest_response.attestation)
            .context("Failed to parse attestation")?;

        // Get quote bytes
        let quote_bytes = attestation
            .tdx_quote()
            .and_then(|q| Some(q.quote.clone()))
            .context("Failed to get TDX quote bytes")?;
        let quote_hex = hex::encode(&quote_bytes);

        // Get collateral and tcb_info
        let pccs_url = cfg.pccs_url.as_deref();
        let verified_report = collateral::get_collateral_and_verify(&quote_bytes, pccs_url)
            .await
            .context("Failed to get collateral and verify quote")?;

        let collateral_json = serde_json::to_string(&verified_report.collateral)
            .context("Failed to serialize collateral")?;

        // Get TCB info from verified report
        let td_report = verified_report
            .report
            .as_td10()
            .context("Failed to get TD10 report")?;

        let tcb_info_json = serde_json::to_string(&json!({
            "mrtd": hex::encode(td_report.mr_td),
            "rtmr0": hex::encode(td_report.rt_mr0),
            "rtmr1": hex::encode(td_report.rt_mr1),
            "rtmr2": hex::encode(td_report.rt_mr2),
            "rtmr3": hex::encode(td_report.rt_mr3),
        }))
        .context("Failed to serialize TCB info")?;

        (quote_hex, collateral_json, tcb_info_json)
    } else {
        anyhow::bail!("Quote must be enabled for NEAR MPC key derivation (attestation required)");
    };

    // Request root key from KMS contract (which will verify attestation and call MPC)
    tracing::info!("Calling KMS contract's request_kms_root_key() with attestation...");
    let mpc_response = kms_client
        .request_kms_root_key(
            &quote_hex,
            &collateral_json,
            &tcb_info_json,
            &worker_public_key,
        )
        .await
        .context("Failed to request root key from KMS contract")?;

    tracing::info!("Received MPC response (big_y, big_c)");

    // Derive root key from MPC response
    let root_key = derive_root_key_from_mpc(
        &mpc_response,
        ephemeral_private_key,
        &mpc_config,
        kms_contract_id,
    )
    .context("Failed to derive root key from MPC response")?;

    tracing::info!("✅ Successfully derived 32-byte root key from MPC");

    // Convert root key to Keys structure
    let keys = Keys::from_mpc_root_key(root_key, domain, quote_enabled)
        .await
        .context("Failed to create keys from MPC root key")?;

    Ok(Some(keys))
}

fn dstack_client() -> DstackGuestClient<PrpcClient> {
    let address = dstack_types::dstack_agent_address();
    let http_client = PrpcClient::new(address);
    DstackGuestClient::new(http_client)
}

async fn app_attest(report_data: Vec<u8>) -> Result<AttestResponse> {
    dstack_client().attest(RawQuoteArgs { report_data }).await
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

fn pad64(hash: [u8; 32]) -> Vec<u8> {
    let mut padded = Vec::with_capacity(64);
    padded.extend_from_slice(&hash);
    padded.resize(64, 0);
    padded
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
        VersionedAttestation::from_scale(&response.attestation).context("Invalid attestation")?;
    let req = CertRequest::builder()
        .subject("RA-TLS TEMP Cert")
        .attestation(&attestation)
        .key(&key)
        .build();
    let cert = ca.sign(req).context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}
