// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, sync::Arc};

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, ClearImageCacheRequest, GetAppKeyRequest, GetKmsKeyRequest,
    GetMetaResponse, GetTempCaCertResponse, KmsKeyResponse, KmsKeys, PublicKeyResponse,
    SignCertRequest, SignCertResponse,
};
use dstack_verifier::{CvmVerifier, VerificationDetails};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{CallContext, RpcCall};
use ra_tls::{
    attestation::VerifiedAttestation,
    cert::{CaCert, CertRequest, CertSigningRequestV1, CertSigningRequestV2, Csr},
    kdf,
};
use scale::Decode;
use sha2::Digest;
use tracing::info;
use upgrade_authority::BootInfo;

use crate::{
    config::KmsConfig,
    crypto::{derive_k256_key, sign_message, sign_message_with_timestamp},
    near_kms_client,
};

mod upgrade_authority;

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

pub struct KmsStateInner {
    config: KmsConfig,
    root_ca: CaCert,
    k256_key: SigningKey,
    temp_ca_cert: String,
    temp_ca_key: String,
    verifier: CvmVerifier,
    /// NEAR signer for MPC key derivation (generated automatically as implicit account)
    near_signer: Option<near_crypto::InMemorySigner>,
}

impl KmsState {
    pub fn new(config: KmsConfig) -> Result<Self> {
        let root_ca = CaCert::load(config.root_ca_cert(), config.root_ca_key())
            .context("Failed to load root CA certificate")?;
        let key_bytes = fs::read(config.k256_key()).context("Failed to read ECDSA root key")?;
        let k256_key =
            SigningKey::from_slice(&key_bytes).context("Failed to load ECDSA root key")?;
        let temp_ca_key =
            fs::read_to_string(config.tmp_ca_key()).context("Faeild to read temp ca key")?;
        let temp_ca_cert =
            fs::read_to_string(config.tmp_ca_cert()).context("Faeild to read temp ca cert")?;
        let verifier = CvmVerifier::new(
            config.image.cache_dir.display().to_string(),
            config.image.download_url.clone(),
            config.image.download_timeout,
            config.pccs_url.clone(),
        );

        // Load or generate NEAR implicit account signer if using NEAR auth
        let near_signer = near_kms_client::load_or_generate_near_signer(&config)?;

        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca,
                k256_key,
                temp_ca_cert,
                temp_ca_key,
                verifier,
                near_signer,
            }),
        })
    }

    /// Get NEAR signer account ID (implicit account)
    pub fn near_signer_account_id(&self) -> Option<String> {
        self.near_signer.as_ref().map(|s| s.account_id.to_string())
    }
}

pub struct RpcHandler {
    state: KmsState,
    attestation: Option<VerifiedAttestation>,
}

struct BootConfig {
    boot_info: BootInfo,
    gateway_app_id: String,
}

impl RpcHandler {
    fn ensure_attested(&self) -> Result<&VerifiedAttestation> {
        let Some(attestation) = &self.attestation else {
            bail!("No attestation provided");
        };
        Ok(attestation)
    }

    async fn ensure_kms_allowed(&self, vm_config: &str) -> Result<BootInfo> {
        let att = self.ensure_attested()?;
        self.ensure_app_attestation_allowed(att, true, false, vm_config)
            .await
            .map(|c| c.boot_info)
    }

    async fn ensure_app_boot_allowed(&self, vm_config: &str) -> Result<BootConfig> {
        let att = self.ensure_attested()?;
        self.ensure_app_attestation_allowed(att, false, false, vm_config)
            .await
    }

    fn image_cache_dir(&self) -> PathBuf {
        self.state.config.image.cache_dir.join("images")
    }

    fn remove_cache(&self, parent_dir: &PathBuf, sub_dir: &str) -> Result<()> {
        if sub_dir.is_empty() {
            return Ok(());
        }
        if sub_dir == "all" {
            fs::remove_dir_all(parent_dir)?;
        } else {
            let path = parent_dir.join(sub_dir);
            if path.is_dir() {
                fs::remove_dir_all(path)?;
            } else {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    fn ensure_admin(&self, token: &str) -> Result<()> {
        let token_hash = sha2::Sha256::new_with_prefix(token).finalize();
        if token_hash.as_slice() != self.state.config.admin_token_hash.as_slice() {
            bail!("Invalid token");
        }
        Ok(())
    }

    async fn verify_os_image_hash(
        &self,
        vm_config: String,
        report: &VerifiedAttestation,
    ) -> Result<()> {
        if !self.state.config.image.verify {
            info!("Image verification is disabled");
            return Ok(());
        }
        let mut detail = VerificationDetails::default();
        self.state
            .verifier
            .verify_os_image_hash(vm_config, report, false, &mut detail)
            .await
            .context("Failed to verify os image hash")?;
        Ok(())
    }

    async fn ensure_app_attestation_allowed(
        &self,
        att: &VerifiedAttestation,
        is_kms: bool,
        use_boottime_mr: bool,
        vm_config_str: &str,
    ) -> Result<BootConfig> {
        let tcb_status;
        let advisory_ids;
        match att.report.tdx_report() {
            Some(report) => {
                tcb_status = report.status.clone();
                advisory_ids = report.advisory_ids.clone();
            }
            None => {
                tcb_status = "".to_string();
                advisory_ids = Vec::new();
            }
        };
        let app_info = att.decode_app_info_ex(use_boottime_mr, vm_config_str)?;
        let boot_info = BootInfo {
            attestation_mode: att.quote.mode(),
            mr_aggregated: app_info.mr_aggregated.to_vec(),
            os_image_hash: app_info.os_image_hash,
            mr_system: app_info.mr_system.to_vec(),
            app_id: app_info.app_id,
            compose_hash: app_info.compose_hash,
            instance_id: app_info.instance_id,
            device_id: app_info.device_id,
            key_provider_info: app_info.key_provider_info,
            tcb_status,
            advisory_ids,
        };
        let response = self
            .state
            .config
            .auth_api
            .is_app_allowed(&boot_info, is_kms)
            .await?;
        if !response.is_allowed {
            bail!("Boot denied: {}", response.reason);
        }
        self.verify_os_image_hash(vm_config_str.into(), att)
            .await
            .context("Failed to verify os image hash")?;
        Ok(BootConfig {
            boot_info,
            gateway_app_id: response.gateway_app_id,
        })
    }

    fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert> {
        let context_data = vec![app_id, b"app-ca"];
        let app_key = kdf::derive_ecdsa_key_pair(&self.state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let req = CertRequest::builder()
            .key(&app_key)
            .org_name("Dstack")
            .subject("Dstack App CA")
            .ca_level(0)
            .app_id(app_id)
            .special_usage("app:ca")
            .build();
        let app_ca = self
            .state
            .root_ca
            .sign(req)
            .context("Failed to sign App CA")?;
        Ok(CaCert::from_parts(app_key, app_ca))
    }
}

impl KmsRpc for RpcHandler {
    async fn get_app_key(self, request: GetAppKeyRequest) -> Result<AppKeyResponse> {
        if request.api_version > 1 {
            bail!("Unsupported API version: {}", request.api_version);
        }
        let BootConfig {
            boot_info,
            gateway_app_id,
        } = self
            .ensure_app_boot_allowed(&request.vm_config)
            .await
            .context("App not allowed")?;
        let app_id = boot_info.app_id;
        let instance_id = boot_info.instance_id;

        let context_data = vec![&app_id[..], &instance_id[..], b"app-disk-crypt-key"];
        let app_disk_key = kdf::derive_dh_secret(&self.state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;
        let env_crypt_key = {
            let secret =
                kdf::derive_dh_secret(&self.state.root_ca.key, &[&app_id[..], b"env-encrypt-key"])
                    .context("Failed to derive env encrypt key")?;
            let secret = x25519_dalek::StaticSecret::from(secret);
            secret.to_bytes()
        };

        let (k256_key, k256_signature) = {
            let (k256_app_key, signature) = derive_k256_key(&self.state.k256_key, &app_id)
                .context("Failed to derive app ecdsa key")?;
            (k256_app_key.to_bytes().to_vec(), signature)
        };

        Ok(AppKeyResponse {
            ca_cert: self.state.root_ca.pem_cert.clone(),
            disk_crypt_key: app_disk_key.to_vec(),
            env_crypt_key: env_crypt_key.to_vec(),
            k256_key,
            k256_signature,
            tproxy_app_id: gateway_app_id.clone(),
            gateway_app_id,
            os_image_hash: boot_info.os_image_hash,
        })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        let secret = kdf::derive_dh_secret(
            &self.state.root_ca.key,
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
            &self.state.k256_key,
            b"dstack-env-encrypt-pubkey",
            &request.app_id,
            &public_key,
        )
        .context("Failed to sign the public key")?;

        // New signature with timestamp to prevent replay attacks
        let signature_v1 = sign_message_with_timestamp(
            &self.state.k256_key,
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
        let info = self.state.config.auth_api.get_info().await?;
        Ok(GetMetaResponse {
            ca_cert: self.state.inner.root_ca.pem_cert.clone(),
            allow_any_upgrade: self.state.inner.config.auth_api.is_dev(),
            k256_pubkey: self
                .state
                .inner
                .k256_key
                .verifying_key()
                .to_sec1_bytes()
                .to_vec(),
            bootstrap_info,
            is_dev: self.state.config.auth_api.is_dev(),
            kms_contract_address: info.kms_contract_address,
            chain_id: info.chain_id,
            gateway_app_id: info.gateway_app_id,
            app_auth_implementation: info.app_implementation,
            near_signer_account_id: self.state.near_signer_account_id(),
        })
    }

    async fn get_kms_key(self, request: GetKmsKeyRequest) -> Result<KmsKeyResponse> {
        if self.state.config.onboard.quote_enabled {
            let _info = self.ensure_kms_allowed(&request.vm_config).await?;
        }
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            keys: vec![KmsKeys {
                ca_key: self.state.inner.root_ca.key.serialize_pem(),
                k256_key: self.state.inner.k256_key.to_bytes().to_vec(),
            }],
        })
    }

    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        Ok(GetTempCaCertResponse {
            temp_ca_cert: self.state.inner.temp_ca_cert.clone(),
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            ca_cert: self.state.inner.root_ca.pem_cert.clone(),
        })
    }

    async fn sign_cert(self, request: SignCertRequest) -> Result<SignCertResponse> {
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
            .into_inner()
            .verify_with_ra_pubkey(&csr.pubkey, self.state.config.pccs_url.as_deref())
            .await
            .context("Quote verification failed")?;
        let app_info = self
            .ensure_app_attestation_allowed(&attestation, false, true, &request.vm_config)
            .await?;
        let app_ca = self.derive_app_ca(&app_info.boot_info.app_id)?;
        let cert = app_ca
            .sign_csr(&csr, Some(&app_info.boot_info.app_id), "app:custom")
            .context("Failed to sign certificate")?;
        Ok(SignCertResponse {
            certificate_chain: vec![
                cert.pem(),
                app_ca.pem_cert.clone(),
                self.state.root_ca.pem_cert.clone(),
            ],
        })
    }

    async fn clear_image_cache(self, request: ClearImageCacheRequest) -> Result<()> {
        self.ensure_admin(&request.token)?;
        self.remove_cache(&self.image_cache_dir(), &request.image_hash)
            .context("Failed to clear image cache")?;
        // Clear measurement cache (now handled by verifier's cache in measurements/ dir)
        let mr_cache_dir = self.state.config.image.cache_dir.join("measurements");
        self.remove_cache(&mr_cache_dir, &request.config_hash)
            .context("Failed to clear measurement cache")?;
        Ok(())
    }
}

impl RpcCall<KmsState> for RpcHandler {
    type PrpcService = KmsServer<Self>;

    fn construct(context: CallContext<'_, KmsState>) -> Result<Self> {
        Ok(RpcHandler {
            state: context.state.clone(),
            attestation: context.attestation,
        })
    }
}

pub fn rpc_methods() -> &'static [&'static str] {
    <KmsServer<RpcHandler>>::supported_methods()
}
