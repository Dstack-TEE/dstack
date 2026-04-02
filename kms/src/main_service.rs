// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{path::PathBuf, sync::Arc};

use aes_siv::KeyInit;
use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    kms_server::{KmsRpc, KmsServer},
    AppId, AppKeyAmdResponse, AppKeyResponse, ClearImageCacheRequest, GetAppKeyAmdRequest,
    GetAppKeyRequest, GetKmsKeyRequest, GetMetaResponse, GetTempCaCertResponse, KmsKeyResponse,
    KmsKeys, PublicKeyResponse, SignCertRequest, SignCertResponse,
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
use tokio::sync::OnceCell;
use tracing::info;
use upgrade_authority::{build_boot_info, local_kms_boot_info, BootInfo};

use crate::{
    config::KmsConfig,
    crypto::{derive_k256_key, sign_message, sign_message_with_timestamp},
};

mod amd_attest;
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
        Ok(Self {
            inner: Arc::new(KmsStateInner {
                config,
                root_ca,
                k256_key,
                temp_ca_cert,
                temp_ca_key,
                verifier,
                self_boot_info: OnceCell::new(),
            }),
        })
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
    async fn ensure_self_allowed(&self) -> Result<()> {
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
        Ok(())
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
        let boot_info = build_boot_info(att, use_boottime_mr, vm_config_str)?;
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
        self.ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
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
        let _info = self.ensure_kms_allowed(&request.vm_config).await?;
        Ok(KmsKeyResponse {
            temp_ca_key: self.state.inner.temp_ca_key.clone(),
            keys: vec![KmsKeys {
                ca_key: self.state.inner.root_ca.key.serialize_pem(),
                k256_key: self.state.inner.k256_key.to_bytes().to_vec(),
            }],
        })
    }

    async fn get_temp_ca_cert(self) -> Result<GetTempCaCertResponse> {
        self.ensure_self_allowed()
            .await
            .context("KMS self authorization failed")?;
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

    async fn get_app_key_amd(self, request: GetAppKeyAmdRequest) -> Result<AppKeyAmdResponse> {
        use amd_attest::{
            compute_expected_measurement, validate_app_id, verify_amd_attestation, AmdAttestInput,
            OvmfSectionParam,
        };
        use ra_tls::attestation::AttestationMode;

        // 1. Decode hex app_id → bytes and validate.
        let app_id = hex::decode(&request.app_id).context("app_id is not valid hex")?;
        validate_app_id(&app_id).context("Invalid app_id")?;

        // 2. Verify AMD cert chain + SNP report signature.
        //    This proves the MEASUREMENT in the report is hardware-attested.
        let verified = verify_amd_attestation(&AmdAttestInput {
            report: &request.snp_report,
            ask_pem: &request.ask_pem,
            vcek_pem: &request.vcek_pem,
        })
        .context("AMD attestation verification failed")?;

        // 3. Verify that compose_hash / rootfs_hash match the attested MEASUREMENT.
        //    Without this check a malicious VM could send a genuine SNP report
        //    but lie about compose_hash/rootfs_hash to get keys for a different app.
        //
        //    We recompute the expected MEASUREMENT from the image fingerprints
        //    (kernel/initrd hashes + cmdline containing compose_hash + rootfs_hash)
        //    and compare byte-for-byte with the hardware-attested value.
        //
        //    If [core.sev_snp] is absent the check is skipped (dev/non-AMD deployments).
        if !request.kernel_hash.is_empty() && request.vcpus > 0 {
            if let Some(cfg) = &self.state.config.sev_snp {
                // Convert proto OvmfSection list to the internal param type.
                let ovmf_sections: Vec<OvmfSectionParam> = request
                    .ovmf_sections
                    .iter()
                    .map(|s| OvmfSectionParam {
                        gpa: s.gpa,
                        size: s.size,
                        section_type: s.section_type,
                    })
                    .collect();

                let expected = compute_expected_measurement(
                    cfg,
                    &amd_attest::MeasurementInput {
                        ovmf_hash: &request.ovmf_hash,
                        sev_hashes_table_gpa: request.sev_hashes_table_gpa,
                        sev_es_reset_eip: request.sev_es_reset_eip,
                        ovmf_sections: &ovmf_sections,
                        kernel_hash: &request.kernel_hash,
                        initrd_hash: &request.initrd_hash,
                        vcpus: request.vcpus,
                        vcpu_type: &request.vcpu_type,
                        compose_hash: &request.compose_hash,
                        rootfs_hash: &request.rootfs_hash,
                        docker_files_hash: if request.docker_files_hash.is_empty() {
                            None
                        } else {
                            Some(&request.docker_files_hash)
                        },
                    },
                )
                .context("Failed to recompute expected SNP MEASUREMENT")?;
                if expected != verified.measurement {
                    bail!(
                        "MEASUREMENT mismatch: compose_hash/rootfs_hash do not match the \
                         hardware-attested measurement (expected={}, got={})",
                        hex::encode(expected),
                        hex::encode(verified.measurement),
                    );
                }
            } else {
                tracing::warn!(
                    "AMD measurement verification skipped: [core.sev_snp] not configured"
                );
            }
        }

        // 3. Build BootInfo.
        //    mr_aggregated = the hardware-attested SNP MEASUREMENT (48 bytes).
        //    It covers OVMF + kernel + initrd + cmdline (which includes
        //    compose_hash and rootfs_hash), so the auth webhook can verify
        //    whether this measurement is in its allowlist.
        //
        //    instance_id = first 20 bytes of report_data.
        //    The auth-eth contract represents instanceId as `address` (20 bytes),
        //    so AMD path must provide a 20-byte value here.
        let instance_id = verified.report_data[..20].to_vec();
        // chip_id is 64 bytes; hash to bytes32 for contract compatibility.
        let device_id = sha2::Sha256::digest(verified.chip_id).to_vec();
        // measurement is 48 bytes (SNP GCTX); hash to bytes32 for contract compatibility.
        let mr_aggregated = sha2::Sha256::digest(verified.measurement).to_vec();

        // Hex-decode hash fields for BootInfo (consistent with how TDX stores them).
        let os_image_hash =
            hex::decode(&request.rootfs_hash).context("rootfs_hash is not valid hex")?;
        let compose_hash =
            hex::decode(&request.compose_hash).context("compose_hash is not valid hex")?;

        let boot_info = BootInfo {
            attestation_mode: AttestationMode::DstackSevSnp,
            mr_aggregated,
            os_image_hash,
            mr_system: vec![0u8; 32],
            app_id: app_id.clone(),
            compose_hash,
            instance_id,
            device_id,
            key_provider_info: vec![],
            tcb_status: String::new(),
            advisory_ids: vec![],
        };

        // 4. Ask the auth API whether this app is allowed to boot.
        let response = self
            .state
            .config
            .auth_api
            .is_app_allowed(&boot_info, false)
            .await
            .context("Auth API request failed")?;
        if !response.is_allowed {
            bail!("Boot denied: {}", response.reason);
        }

        // 5. Derive keys deterministically from app_id (same derivation as TDX).
        let instance_id_bytes = &boot_info.instance_id;

        let context_data = vec![&app_id[..], &instance_id_bytes[..], b"app-disk-crypt-key"];
        let app_disk_key = kdf::derive_dh_secret(&self.state.root_ca.key, &context_data)
            .context("Failed to derive app disk key")?;

        let env_crypt_key = {
            let secret =
                kdf::derive_dh_secret(&self.state.root_ca.key, &[&app_id[..], b"env-encrypt-key"])
                    .context("Failed to derive env encrypt key")?;
            x25519_dalek::StaticSecret::from(secret).to_bytes()
        };

        let (k256_app_key, k256_signature) =
            derive_k256_key(&self.state.k256_key, &app_id).context("Failed to derive k256 key")?;

        // 6. Encrypt the derived keys with the VM's X25519 public key embedded in report_data[0..32].
        //    This ensures only the attested VM (which holds the SEED) can decrypt the keys.
        //    The VM decrypts with: crypt-tool decrypt -s $SEED -d <hex_ciphertext> -p <hex(key_provider_pubkey)>
        if verified.report_data.len() < 32 {
            bail!("report_data too short to contain VM public key (need >=32 bytes)");
        }
        let vm_pk_bytes: [u8; 32] = verified.report_data[..32]
            .try_into()
            .context("Failed to extract VM public key from report_data")?;
        if vm_pk_bytes == [0u8; 32] {
            bail!("VM public key in report_data is all-zeros; VM must embed its X25519 pubkey");
        }
        let vm_pk = x25519_dalek::PublicKey::from(vm_pk_bytes);

        // Generate an ephemeral KMS keypair for this response.
        let kms_ephem_sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
        let kms_ephem_pk = x25519_dalek::PublicKey::from(&kms_ephem_sk);
        let shared_secret = kms_ephem_sk.diffie_hellman(&vm_pk);

        // Encrypt using AES-128-SIV (same scheme as crypt-tool decrypt: ECDH → Aes128Siv key).
        let mut cipher = aes_siv::siv::Aes128Siv::new(shared_secret.as_bytes().into());
        let encrypted_disk_key = cipher
            .encrypt(&[&[]], &app_disk_key)
            .map_err(|_| anyhow::anyhow!("Failed to encrypt disk_crypt_key"))?;
        let mut cipher = aes_siv::siv::Aes128Siv::new(shared_secret.as_bytes().into());
        let encrypted_env_key = cipher
            .encrypt(&[&[]], &env_crypt_key)
            .map_err(|_| anyhow::anyhow!("Failed to encrypt env_crypt_key"))?;
        let mut cipher = aes_siv::siv::Aes128Siv::new(shared_secret.as_bytes().into());
        let k256_key_bytes = k256_app_key.to_bytes();
        let encrypted_k256_key = cipher
            .encrypt(&[&[]], &k256_key_bytes)
            .map_err(|_| anyhow::anyhow!("Failed to encrypt k256_key"))?;

        Ok(AppKeyAmdResponse {
            ca_cert: self.state.root_ca.pem_cert.clone(),
            disk_crypt_key: encrypted_disk_key,
            env_crypt_key: encrypted_env_key,
            k256_key: encrypted_k256_key,
            k256_signature,
            tproxy_app_id: response.gateway_app_id.clone(),
            gateway_app_id: response.gateway_app_id,
            os_image_hash: boot_info.os_image_hash,
            key_provider_pubkey: kms_ephem_pk.as_bytes().to_vec(),
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
