// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyResponse, GetAppKeyRequest, GetKmsKeyRequest, GetMetaResponse,
    GetTempCaCertResponse, KmsKeyResponse, KmsKeys, PublicKeyResponse, SignCertRequest,
    SignCertResponse,
};
use dstack_verifier::{CvmVerifier, VerificationDetails};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{CallContext, RpcCall};
use ra_tls::{
    attestation::{AttestationVerifier, TeeVariant, VerifiedAttestation},
    cert::{CaCert, CertRequest, CertSigningRequestV1, CertSigningRequestV2, Csr},
    kdf,
};
use scale::Decode;
use tokio::sync::OnceCell;
use tracing::{info, warn};
use upgrade_authority::{build_boot_info, ensure_app_id_len, local_kms_boot_info, BootInfo};

use crate::{
    config::KmsConfig,
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
    attestation_verifier: Arc<AttestationVerifier>,
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

/// remove a single cache entry (a hex-named subdir/file) under `parent_dir`, or
/// everything when `sub_dir == "all"`. A non-hex key is rejected to keep the
/// deletion confined to the cache.
fn remove_cache(parent_dir: &Path, sub_dir: &str) -> Result<()> {
    if sub_dir.is_empty() {
        return Ok(());
    }
    if sub_dir == "all" {
        if parent_dir.exists() {
            fs::remove_dir_all(parent_dir)?;
        }
        return Ok(());
    }
    if !sub_dir.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("invalid cache key");
    }
    let path = parent_dir.join(sub_dir);
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.is_file() {
        fs::remove_file(path)?;
    }
    Ok(())
}

impl KmsState {
    /// clear cached image and measurement material for the given hashes. Used by
    /// the admin `ClearImageCache` RPC; authorization is enforced by the admin
    /// listener's HTTP authenticator, not here.
    pub(crate) fn clear_image_cache(&self, image_hash: &str, config_hash: &str) -> Result<()> {
        let images_dir = self.config.image.cache_dir.join("images");
        remove_cache(&images_dir, image_hash).context("failed to clear image cache")?;
        // measurement cache is kept by the verifier under measurements/.
        let mr_cache_dir = self.config.image.cache_dir.join("measurements");
        remove_cache(&mr_cache_dir, config_hash).context("failed to clear measurement cache")?;
        Ok(())
    }

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
                config,
                root_ca,
                k256_key,
                temp_ca_cert,
                temp_ca_key,
                verifier,
                attestation_verifier,
                self_boot_info: OnceCell::new(),
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

fn ensure_key_release_allowed(
    boot_info: &BootInfo,
    snp_enabled: bool,
    aws_nitro_tpm_enabled: bool,
) -> Result<()> {
    match boot_info.tee_variant {
        TeeVariant::DstackAmdSevSnp if !snp_enabled => {
            bail!("amd sev-snp key release is not enabled")
        }
        TeeVariant::DstackAwsNitroTpm if !aws_nitro_tpm_enabled => {
            bail!("aws nitro-tpm key release is not enabled")
        }
        _ => Ok(()),
    }
}

fn ensure_self_key_release_allowed(
    self_boot_info: Option<&BootInfo>,
    snp_enabled: bool,
    aws_nitro_tpm_enabled: bool,
) -> Result<()> {
    if let Some(boot_info) = self_boot_info {
        ensure_key_release_allowed(boot_info, snp_enabled, aws_nitro_tpm_enabled)?;
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
            .get_or_try_init(|| local_kms_boot_info(&self.state.attestation_verifier))
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
        if boot_info.tee_variant != TeeVariant::DstackAmdSevSnp {
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
        ensure_key_release_allowed(
            &boot_info,
            self.state.config.sev_snp_key_release,
            self.state.config.aws_nitro_tpm_key_release,
        )?;
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
        ensure_key_release_allowed(
            &info,
            self.state.config.sev_snp_key_release,
            self.state.config.aws_nitro_tpm_key_release,
        )?;
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            keys: vec![KmsKeys {
                ca_key: self.state.inner.root_ca.key.serialize_pem(),
                k256_key: self.state.inner.k256_key.to_bytes().to_vec(),
            }],
        })
    }

    /// Serve the temp CA certificate and key.
    ///
    /// Both current callers - guests at boot, and KMS-to-KMS onboarding
    /// ([`crate::onboard_service`]) - fetch this CA and mint their client certificate
    /// from it, because the KMS used to pin the CA for mutual TLS and a self-issued
    /// certificate had nothing to chain to.
    ///
    /// That pin is gone: client certificates are now verified by the attestation they
    /// carry (`ra_rpc::ratls_client_verifier`), so a self-issued certificate would be
    /// accepted on the same terms. Neither caller has been migrated yet, so this RPC
    /// still has to work.
    ///
    /// The key it returns authenticates nobody: it is handed to any caller. Removing
    /// this RPC needs both callers migrated first.
    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        let self_boot_info = self
            .ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
        ensure_self_key_release_allowed(
            self_boot_info,
            self.state.config.sev_snp_key_release,
            self.state.config.aws_nitro_tpm_key_release,
        )?;
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
            .verify_with_ra_pubkey(&csr.pubkey, &self.state.attestation_verifier)
            .await
            .context("Quote verification failed")?;
        let app_info = self
            .ensure_app_attestation_allowed(&attestation, false, true, &request.vm_config)
            .await?;
        ensure_key_release_allowed(
            &app_info.boot_info,
            self.state.config.sev_snp_key_release,
            self.state.config.aws_nitro_tpm_key_release,
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
    use cc_eventlog::RuntimeEvent;
    use sha2::{Digest, Sha256, Sha384};

    #[test]
    fn remove_cache_only_deletes_the_named_hex_entry() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let keep = root.join("cafe");
        let drop = root.join("beef");
        fs::create_dir_all(&keep).unwrap();
        fs::create_dir_all(&drop).unwrap();

        remove_cache(root, "beef").unwrap();
        assert!(!drop.exists(), "named entry must be removed");
        assert!(keep.exists(), "other entries must be kept");

        // empty key is a no-op; a non-hex key is rejected before touching disk.
        remove_cache(root, "").unwrap();
        assert!(remove_cache(root, "../escape").is_err());
        assert!(keep.exists());

        // "all" clears the whole cache dir.
        remove_cache(root, "all").unwrap();
        assert!(!root.exists());
    }
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
        let err = ensure_key_release_allowed(&boot_info, false, false).unwrap_err();
        assert!(err.to_string().contains("not enabled"));
        // explicitly enabled permits it
        ensure_key_release_allowed(&boot_info, false, true).unwrap();

        // A TDX boot info is unaffected by the AWS gate even when it is disabled.
        boot_info.tee_variant = TeeVariant::DstackTdx;
        ensure_key_release_allowed(&boot_info, false, false).unwrap();
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
        assert_eq!(boot_info.device_id, vec![0xab; 64]);
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
    fn build_boot_info_for_attestation_accepts_self_contained_snp_input_without_config() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let vm_config = snp_vm_config(&input, &mr_config);

        let boot_info = build_boot_info_for_attestation(&attestation, false, &vm_config)
            .expect("self-contained SNP vm_config should not require KMS-local sev_snp config");
        assert_eq!(boot_info.tee_variant, TeeVariant::DstackAmdSevSnp);
        assert_eq!(boot_info.device_id, vec![0xab; 64]);
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
        let enabled = false;

        let err = ensure_key_release_allowed(&boot_info, enabled, false)
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
        let enabled = true;

        ensure_key_release_allowed(&boot_info, enabled, false)
            .expect("explicitly enabled SNP key release should allow auth-approved boot info");
    }

    #[test]
    fn snp_key_release_leaves_tcb_and_advisory_policy_to_auth_api() {
        let mut boot_info = snp_boot_info();
        let enabled = true;

        boot_info.tcb_status = "OutOfDate".to_string();
        boot_info.advisory_ids.push("SNP-TEST-ADVISORY".to_string());
        ensure_key_release_allowed(&boot_info, enabled, false)
            .expect("TCB/advisory policy should be decided by the auth API, not this local gate");
    }

    #[test]
    fn snp_self_boot_info_uses_same_release_policy_for_temp_ca() {
        let boot_info = snp_boot_info();
        let disabled = false;
        let enabled = true;

        ensure_self_key_release_allowed(Some(&boot_info), disabled, false)
            .expect_err("disabled SNP self boot info must not receive temp CA key material");
        ensure_self_key_release_allowed(Some(&boot_info), enabled, false)
            .expect("enabled clean SNP self boot info should pass the temp CA release gate");
    }
}
