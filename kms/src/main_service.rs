// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

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
    attestation::{AttestationMode, VerifiedAttestation},
    cert::{CaCert, CertRequest, CertSigningRequestV1, CertSigningRequestV2, Csr},
    kdf,
};
use scale::Decode;
use sha2::Digest;
use tokio::sync::OnceCell;
use tracing::{info, warn};
use upgrade_authority::{build_boot_info, ensure_app_id_len, local_kms_boot_info, BootInfo};

use crate::{
    config::{KmsConfig, SevSnpKeyReleaseConfig},
    crypto::{derive_k256_key, sign_message, sign_message_with_timestamp},
};

pub(crate) mod amd_attest;
pub(crate) mod upgrade_authority;

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
    self_boot_info: OnceCell<BootInfo>,
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
        if !config.enforce_self_authorization {
            warn!(
                "self-authorization is disabled; trusted RPCs will not be gated by KMS self-attestation - do not use in production TEE deployments"
            );
        }
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca,
                k256_key,
                temp_ca_cert,
                temp_ca_key,
                verifier,
                self_boot_info: OnceCell::new(),
                metrics: KmsMetrics::default(),
            }),
        })
    }

    pub(crate) fn metrics(&self) -> &KmsMetrics {
        &self.inner.metrics
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

pub(crate) fn build_boot_info_for_attestation(
    att: &VerifiedAttestation,
    use_boottime_mr: bool,
    vm_config_str: &str,
) -> Result<BootInfo> {
    if att.report.amd_snp_report().is_some() {
        let vm_config_str = if vm_config_str.is_empty() {
            att.config.as_str()
        } else {
            vm_config_str
        };
        return amd_attest::build_amd_snp_boot_info_from_verified_attestation_and_vm_config(
            att,
            vm_config_str,
        );
    }
    build_boot_info(att, use_boottime_mr, vm_config_str)
}

fn ensure_snp_key_release_allowed(
    boot_info: &BootInfo,
    policy: &SevSnpKeyReleaseConfig,
) -> Result<()> {
    if boot_info.attestation_mode != AttestationMode::DstackAmdSevSnp {
        return Ok(());
    }
    if !policy.enabled {
        bail!("amd sev-snp key release is not enabled");
    }
    Ok(())
}

fn ensure_self_key_release_allowed(
    self_boot_info: Option<&BootInfo>,
    policy: &SevSnpKeyReleaseConfig,
) -> Result<()> {
    if let Some(boot_info) = self_boot_info {
        ensure_snp_key_release_allowed(boot_info, policy)?;
    }
    Ok(())
}

impl RpcHandler {
    async fn ensure_self_allowed(&self) -> Result<Option<&BootInfo>> {
        if !self.state.config.enforce_self_authorization {
            return Ok(None);
        }
        let boot_info = self
            .state
            .self_boot_info
            .get_or_try_init(|| local_kms_boot_info(self.state.config.pccs_url.as_deref()))
            .await
            .context("Failed to load cached self boot info")?;
        let response = self
            .state
            .config
            .auth_api
            .is_app_allowed(boot_info, true)
            .await
            .context("Failed to call self KMS auth check")?;
        if !response.is_allowed {
            bail!("KMS is not allowed: {}", response.reason);
        }
        Ok(Some(boot_info))
    }

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

    fn remove_cache(&self, parent_dir: &Path, sub_dir: &str) -> Result<()> {
        if sub_dir.is_empty() {
            return Ok(());
        }

        if sub_dir == "all" {
            fs::remove_dir_all(parent_dir)?;
            return Ok(());
        }

        if !sub_dir.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("Invalid cache key");
        }

        let path = parent_dir.join(sub_dir);

        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else if path.is_file() {
            fs::remove_file(path)?;
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
        let boot_info = build_boot_info_for_attestation(att, use_boottime_mr, vm_config_str)?;
        let response = self
            .state
            .config
            .auth_api
            .is_app_allowed(&boot_info, is_kms)
            .await?;
        if !response.is_allowed {
            bail!("Boot denied: {}", response.reason);
        }
        // SNP rootfs/app/config binding is handled by the SNP launch-measurement
        // helper above. The legacy OS-image verifier is TDX-oriented and still
        // rejects SNP quotes; keep SNP on the explicit fail-closed helper path.
        if boot_info.attestation_mode != AttestationMode::DstackAmdSevSnp {
            self.verify_os_image_hash(vm_config_str.into(), att)
                .await
                .context("Failed to verify os image hash")?;
        }
        Ok(BootConfig {
            boot_info,
            gateway_app_id: response.gateway_app_id,
        })
    }

    fn derive_app_ca(&self, app_id: &[u8]) -> Result<CaCert> {
        let context_data = vec![app_id, b"app-ca"];
        let app_key = kdf::derive_p256_key_pair(&self.state.root_ca.key, &context_data)
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
        self.ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
        let BootConfig {
            boot_info,
            gateway_app_id,
        } = self
            .ensure_app_boot_allowed(&request.vm_config)
            .await
            .context("App not allowed")?;
        ensure_snp_key_release_allowed(&boot_info, &self.state.config.sev_snp_key_release)?;
        let app_id = boot_info.app_id;
        let instance_id = boot_info.instance_id;
        let os_image_hash = boot_info.os_image_hash;

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
            os_image_hash,
        })
    }

    async fn get_app_env_encrypt_pub_key(self, request: AppId) -> Result<PublicKeyResponse> {
        self.ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
        ensure_app_id_len(&request.app_id)?;
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
        })
    }

    async fn get_kms_key(self, request: GetKmsKeyRequest) -> Result<KmsKeyResponse> {
        self.ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
        let info = self.ensure_kms_allowed(&request.vm_config).await?;
        ensure_snp_key_release_allowed(&info, &self.state.config.sev_snp_key_release)?;
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            keys: vec![KmsKeys {
                ca_key: self.state.inner.root_ca.key.serialize_pem(),
                k256_key: self.state.inner.k256_key.to_bytes().to_vec(),
            }],
        })
    }

    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        let self_boot_info = self
            .ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
        ensure_self_key_release_allowed(self_boot_info, &self.state.config.sev_snp_key_release)?;
        Ok(GetTempCaCertResponse {
            temp_ca_cert: self.state.inner.temp_ca_cert.clone(),
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            ca_cert: self.state.inner.root_ca.pem_cert.clone(),
        })
    }

    async fn sign_cert(self, request: SignCertRequest) -> Result<SignCertResponse> {
        self.ensure_self_allowed()
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
            .verify_with_ra_pubkey(&csr.pubkey, self.state.config.pccs_url.as_deref())
            .await
            .context("Quote verification failed")?;
        let app_info = self
            .ensure_app_attestation_allowed(&attestation, false, true, &request.vm_config)
            .await?;
        ensure_snp_key_release_allowed(
            &app_info.boot_info,
            &self.state.config.sev_snp_key_release,
        )?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_service::amd_attest::{
        compute_expected_measurement, MeasurementInput, OvmfSectionParam,
    };

    fn hex_of(byte: u8, len: usize) -> String {
        hex::encode(vec![byte; len])
    }

    fn valid_snp_measurement_input() -> MeasurementInput {
        MeasurementInput {
            app_id: hex_of(0x11, 20),
            compose_hash: hex_of(0x22, 32),
            rootfs_hash: hex_of(0x33, 32),
            base_cmdline: None,
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

    #[test]
    fn build_boot_info_for_attestation_accepts_snp_vm_config_path() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = serde_json::json!({
            "sev_snp_measurement": serde_json::to_string(&input).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string();

        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("snp attestation should build boot info through vm_config path");

        assert_eq!(boot_info.attestation_mode, AttestationMode::DstackAmdSevSnp);
        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(boot_info.device_id, vec![0xab; 64]);
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
    }

    #[test]
    fn build_boot_info_for_attestation_uses_embedded_snp_vm_config_when_external_is_empty() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let embedded_config = serde_json::json!({
            "sev_snp_measurement": serde_json::to_string(&input).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string();
        let attestation = verified_snp_attestation_with_config(
            measurement,
            [0xab; 64],
            embedded_config,
            &mr_config,
        );

        let boot_info = build_boot_info_for_attestation(&attestation, false, "")
            .expect("snp local KMS attestation should use embedded vm_config");

        assert_eq!(boot_info.attestation_mode, AttestationMode::DstackAmdSevSnp);
        assert_eq!(boot_info.mr_aggregated.len(), 32);
        assert_eq!(boot_info.app_id, vec![0x11; 20]);
    }

    #[test]
    fn build_boot_info_for_attestation_accepts_self_contained_snp_input_without_config() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = serde_json::json!({
            "sev_snp_measurement": serde_json::to_string(&input).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string();

        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("self-contained SNP vm_config should not require KMS-local sev_snp config");
        assert_eq!(boot_info.attestation_mode, AttestationMode::DstackAmdSevSnp);
        assert_eq!(boot_info.device_id, vec![0xab; 64]);
    }

    fn snp_boot_info() -> BootInfo {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = serde_json::json!({
            "sev_snp_measurement": serde_json::to_string(&input).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string();
        build_boot_info_for_attestation(&attestation, false, &vm_config).unwrap()
    }

    #[test]
    fn snp_key_release_requires_explicit_enablement() {
        let boot_info = snp_boot_info();
        let policy = SevSnpKeyReleaseConfig::default();

        let err = ensure_snp_key_release_allowed(&boot_info, &policy)
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
        let policy = SevSnpKeyReleaseConfig {
            enabled: true,
            ..Default::default()
        };

        ensure_snp_key_release_allowed(&boot_info, &policy)
            .expect("explicitly enabled SNP key release should allow auth-approved boot info");
    }

    #[test]
    fn snp_key_release_leaves_tcb_and_advisory_policy_to_auth_api() {
        let mut boot_info = snp_boot_info();
        let policy = SevSnpKeyReleaseConfig {
            enabled: true,
            ..Default::default()
        };

        boot_info.tcb_status = "OutOfDate".to_string();
        boot_info.advisory_ids.push("SNP-TEST-ADVISORY".to_string());
        ensure_snp_key_release_allowed(&boot_info, &policy)
            .expect("TCB/advisory policy should be decided by the auth API, not this local gate");
    }

    #[test]
    fn snp_self_boot_info_uses_same_release_policy_for_temp_ca() {
        let boot_info = snp_boot_info();
        let disabled = SevSnpKeyReleaseConfig::default();
        let enabled = SevSnpKeyReleaseConfig {
            enabled: true,
            ..Default::default()
        };

        ensure_self_key_release_allowed(Some(&boot_info), &disabled)
            .expect_err("disabled SNP self boot info must not receive temp CA key material");
        ensure_self_key_release_allowed(Some(&boot_info), &enabled)
            .expect("enabled clean SNP self boot info should pass the temp CA release gate");
    }
}
