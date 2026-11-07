// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use dstack_kms_rpc::{
    admin_client::AdminClient,
    kms_client::KmsClient,
    onboard_server::{OnboardRpc, OnboardServer},
    AttestationInfoResponse, BootstrapRequest, BootstrapResponse, GetKmsKeyRequest, KmsKeyResponse,
    OnboardRequest, OnboardResponse, SetupStatusResponse,
};
use fs_err as fs;
use k256::ecdsa::SigningKey;
use ra_rpc::{
    client::{CertInfo, RaClientConfig},
    CallContext, RpcCall,
};
use ra_tls::{
    attestation::{
        AttestationVerifier, GetDeviceId, PlatformEvidence, QuoteContentType, VerifiedAttestation,
        VersionedAttestation,
    },
    cert::CertRequest,
    rcgen::{Certificate, KeyPair, PKCS_ECDSA_P256_SHA256},
};
use safe_write::{safe_write, safe_write_with_mode};
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

use crate::{
    config::KmsConfig,
    main_service::{
        build_boot_info_for_attestation, root_chain_hashes, servable_epoch,
        upgrade_authority::{
            app_attest, dstack_client, ensure_kms_allowed, ensure_self_kms_allowed, pad64,
            RootEpochRegistry,
        },
    },
};

#[derive(Clone)]
pub struct OnboardState {
    config: KmsConfig,
    attestation_verifier: Arc<AttestationVerifier>,
    bootstrap_lock: Arc<AsyncMutex<()>>,
    shutdown: Arc<OnceLock<rocket::Shutdown>>,
}

impl OnboardState {
    pub fn new(config: KmsConfig) -> Result<Self> {
        let attestation_verifier = Arc::new(
            AttestationVerifier::load(&config.attestation)
                .context("failed to load attestation verifier")?,
        );
        Ok(Self {
            config,
            attestation_verifier,
            bootstrap_lock: Arc::new(AsyncMutex::new(())),
            shutdown: Arc::new(OnceLock::new()),
        })
    }

    /// Hand the Rocket shutdown handle to the service so `finish` can stop the
    /// server after its response has been sent.
    pub fn set_shutdown(&self, shutdown: rocket::Shutdown) -> Result<()> {
        self.shutdown
            .set(shutdown)
            .map_err(|_| anyhow::anyhow!("onboard shutdown handle is already set"))
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

fn validate_onboarding_domain(domain: &str) -> Result<()> {
    if domain.is_empty() || domain.len() > 253 || !domain.is_ascii() {
        bail!("domain must be a non-empty ASCII DNS name of at most 253 bytes");
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            bail!("domain contains an invalid DNS label");
        }
    }
    Ok(())
}

fn stored_k256_pubkey(cfg: &KmsConfig) -> Result<Vec<u8>> {
    let bytes = fs::read(cfg.k256_key()).context("failed to read k256 key")?;
    let key = SigningKey::from_slice(&bytes).context("failed to parse k256 key")?;
    Ok(key.verifying_key().to_sec1_bytes().to_vec())
}

fn setup_status(cfg: &KmsConfig) -> Result<SetupStatusResponse> {
    if !cfg.root_keys_exist() {
        return Ok(SetupStatusResponse::default());
    }
    let k256_pubkey = stored_k256_pubkey(cfg)?;
    let info = fs::read(cfg.bootstrap_info())
        .ok()
        .and_then(|bytes| serde_json::from_slice::<BootstrapResponse>(&bytes).ok())
        .filter(|info| info.k256_pubkey == k256_pubkey)
        .unwrap_or_default();
    Ok(SetupStatusResponse {
        provisioned: true,
        ready: cfg.keys_exists(),
        k256_pubkey,
        ca_pubkey: info.ca_pubkey,
        attestation: info.attestation,
    })
}

impl OnboardRpc for OnboardHandler {
    async fn bootstrap(self, request: BootstrapRequest) -> Result<BootstrapResponse> {
        validate_onboarding_domain(&request.domain)?;
        let _bootstrap_guard = self.state.bootstrap_lock.lock().await;
        let cfg = &self.state.config;
        if cfg.root_keys_exist() {
            bail!("KMS has already been bootstrapped");
        }
        ensure_self_kms_allowed(cfg, &self.state.attestation_verifier)
            .await
            .context("KMS is not allowed to bootstrap")?;
        let keys = Keys::generate(&request.domain, self.state.config.attest_rpc_cert)
            .await
            .context("Failed to generate keys")?;
        let response = keys.attest().await?;
        // Store the bootstrap info
        safe_write(cfg.bootstrap_info(), serde_json::to_vec(&response)?)?;
        keys.store(cfg)?;
        Ok(response)
    }

    async fn onboard(self, request: OnboardRequest) -> Result<OnboardResponse> {
        validate_onboarding_domain(&request.domain)?;
        let _bootstrap_guard = self.state.bootstrap_lock.lock().await;
        let cfg = &self.state.config;
        if cfg.root_keys_exist() {
            bail!("KMS has already been onboarded");
        }
        let source_url = request.source_url.trim_end_matches('/').to_string();
        let source_url = if source_url.ends_with("/prpc") {
            source_url
        } else {
            format!("{source_url}/prpc")
        };
        let keys = Keys::onboard(
            cfg,
            &source_url,
            &request.source_token,
            &request.domain,
            request.rotate,
            self.state.attestation_verifier.clone(),
        )
        .await
        .context("Failed to onboard")?;
        if !request.rotate {
            let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
            keys.store(cfg).context("Failed to store keys")?;
            return Ok(OnboardResponse {
                k256_pubkey,
                ..Default::default()
            });
        }
        // The attestation over the new epoch is what governance registers, so
        // it is persisted with the keys and stays readable via GetSetupStatus.
        let info = keys.attest().await?;
        safe_write(cfg.bootstrap_info(), serde_json::to_vec(&info)?)?;
        keys.store(cfg).context("Failed to store keys")?;
        Ok(OnboardResponse {
            k256_pubkey: info.k256_pubkey,
            ca_pubkey: info.ca_pubkey,
            attestation: info.attestation,
        })
    }

    async fn get_attestation_info(self) -> Result<AttestationInfoResponse> {
        // Get attestation from guest agent
        let report_data = pad64([0u8; 32]);
        let response = app_attest(report_data)
            .await
            .context("Failed to get attestation")?;

        // Decode and verify the attestation to get real device ID
        let attestation = VersionedAttestation::from_bytes(&response.attestation)
            .context("Failed to decode attestation")?;
        let tee_variant = match &attestation.clone().into_v1().platform {
            PlatformEvidence::Tdx { .. } => "dstack-tdx",
            PlatformEvidence::SevSnp { .. } => "dstack-amd-sev-snp",
            PlatformEvidence::GcpTdx { .. } => "dstack-gcp-tdx",
            PlatformEvidence::NitroEnclave { .. } => "dstack-nitro-enclave",
            PlatformEvidence::AwsNitroTpm { .. } => "dstack-aws-nitro-tpm",
        }
        .to_string();
        let verified = attestation
            .into_v1()
            .verify(&self.state.attestation_verifier)
            .await
            .context("Failed to verify attestation")?;

        // Get vm_config from guest agent
        let info = dstack_client()
            .info()
            .await
            .context("Failed to get VM info")?;

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

        build_attestation_info_response(
            &verified,
            tee_variant,
            &info.vm_config,
            self.state.config.site_name.clone(),
            eth_rpc_url,
            kms_contract_address,
        )
    }

    async fn get_setup_status(self) -> Result<SetupStatusResponse> {
        let _bootstrap_guard = self.state.bootstrap_lock.lock().await;
        setup_status(&self.state.config)
    }

    async fn finish(self) -> anyhow::Result<()> {
        let shutdown = self
            .state
            .shutdown
            .get()
            .context("onboard shutdown handle is unavailable")?;
        // Graceful shutdown lets Rocket finish sending this response before the
        // server stops, so the client learns that onboarding succeeded.
        shutdown.clone().notify();
        Ok(())
    }
}

fn build_attestation_info_response(
    verified: &VerifiedAttestation,
    tee_variant: String,
    vm_config: &str,
    site_name: String,
    eth_rpc_url: String,
    kms_contract_address: String,
) -> Result<AttestationInfoResponse> {
    let boot_info = build_boot_info_for_attestation(verified, false, vm_config)
        .context("Failed to decode app info")?;
    Ok(AttestationInfoResponse {
        device_id: boot_info.device_id,
        mr_aggregated: boot_info.mr_aggregated,
        os_image_hash: boot_info.os_image_hash,
        tee_variant,
        site_name,
        eth_rpc_url,
        kms_contract_address,
        ppid: verified.report.get_devide_id(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_service::amd_attest::{
        compute_expected_measurement, MeasurementInput, OvmfSectionParam,
    };
    use crate::main_service::upgrade_authority::CurrentRootEpoch;
    use dstack_kms_rpc::KmsKeys;
    use sha2::Digest;

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
            config: String::new(),
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

    #[test]
    fn attestation_info_response_uses_snp_boot_info_and_chip_id() {
        let input = valid_snp_measurement_input();
        let measurement = compute_expected_measurement(&input).unwrap();
        let mr_config = valid_snp_mr_config();
        let attestation = verified_snp_attestation(measurement, [0xab; 64]);
        let snp_document = snp_measurement_document(&input);
        let os_image_hash = dstack_types::image_hash_from_sha256sum(&snp_document.checksum_file);
        let vm_config = serde_json::json!({
            "os_image_hash": hex::encode(os_image_hash),
            "sev_snp_measurement": serde_json::to_string(&snp_document).unwrap(),
            "mr_config": mr_config.to_canonical_json(),
        })
        .to_string();

        let response = build_attestation_info_response(
            &attestation,
            "dstack-amd-sev-snp".to_string(),
            &vm_config,
            "test-site".to_string(),
            "https://rpc.example".to_string(),
            "0x1234".to_string(),
        )
        .expect("snp attestation info should be derived from snp boot info");

        assert_eq!(
            response.device_id,
            sha2::Sha256::digest([0xab; 64]).to_vec()
        );
        assert_eq!(response.ppid, vec![0xab; 64]);
        assert_eq!(response.mr_aggregated.len(), 32);
        assert_eq!(response.os_image_hash, os_image_hash.to_vec());
        assert_eq!(response.tee_variant, "dstack-amd-sev-snp");
        assert_eq!(response.site_name, "test-site");
        assert_eq!(response.eth_rpc_url, "https://rpc.example");
        assert_eq!(response.kms_contract_address, "0x1234");
    }

    #[test]
    fn onboarding_domain_accepts_dns_name() {
        validate_onboarding_domain("kms.example.com").unwrap();
    }

    #[test]
    fn onboarding_domain_rejects_empty_overlong_and_invalid_labels() {
        let overlong = "a".repeat(254);
        for domain in [
            "",
            overlong.as_str(),
            "-kms.example.com",
            "kms-.example.com",
            "kms..example.com",
            "kms_example.com",
        ] {
            assert!(validate_onboarding_domain(domain).is_err(), "{domain:?}");
        }
    }

    fn ca_cert_expiring_at(not_after: SystemTime) -> Vec<u8> {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        CertRequest::builder()
            .subject("Test CA")
            .ca_level(0)
            .not_after(not_after)
            .key(&key)
            .build()
            .self_signed()
            .unwrap()
            .pem()
            .into_bytes()
    }

    fn auto_bootstrap_config(cert_dir: &std::path::Path) -> KmsConfig {
        use rocket::figment::{
            providers::{Format, Toml},
            Figment,
        };
        let overrides = format!(
            r#"
            [core]
            cert_dir = "{}"
            attest_rpc_cert = false
            enforce_self_authorization = false

            [core.onboard]
            auto_bootstrap_domain = "kms.example.com"
            "#,
            cert_dir.display()
        );
        Figment::from(rocket::Config::default())
            .merge(Toml::string(crate::config::DEFAULT_CONFIG))
            .merge(Toml::string(&overrides))
            .focus("core")
            .extract()
            .unwrap()
    }

    #[rocket::async_test]
    async fn auto_bootstrap_refuses_to_replace_existing_root_keys() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let verifier = AttestationVerifier::load(&cfg.attestation).unwrap();

        bootstrap_keys(&cfg, &verifier).await.unwrap();
        let root_ca_key = fs::read(cfg.root_ca_key()).unwrap();
        let k256_key = fs::read(cfg.k256_key()).unwrap();

        // A single missing certificate is enough to make `keys_exists()` false,
        // which is what sends the KMS back into onboarding on the next start.
        fs::remove_file(cfg.rpc_cert()).unwrap();
        assert!(!cfg.keys_exists());

        let err = bootstrap_keys(&cfg, &verifier).await.unwrap_err();
        assert!(
            format!("{err:#}").contains("already been bootstrapped"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read(cfg.root_ca_key()).unwrap(), root_ca_key);
        assert_eq!(fs::read(cfg.k256_key()).unwrap(), k256_key);
    }

    #[rocket::async_test]
    async fn auto_bootstrap_overwrites_an_interrupted_bootstrap() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let verifier = AttestationVerifier::load(&cfg.attestation).unwrap();

        // A crash between the two root key writes.
        fs::write(cfg.root_ca_key(), "stale").unwrap();
        assert!(!cfg.root_keys_exist());

        bootstrap_keys(&cfg, &verifier).await.unwrap();
        assert!(cfg.keys_exists());
        assert_ne!(fs::read(cfg.root_ca_key()).unwrap(), b"stale");
    }

    #[test]
    fn setup_status_is_empty_before_root_keys_exist() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let status = setup_status(&cfg).unwrap();
        assert!(!status.provisioned);
        assert!(!status.ready);
        assert!(status.k256_pubkey.is_empty());
        assert!(status.ca_pubkey.is_empty());
        assert!(status.attestation.is_empty());
    }

    fn handover(epochs: u32) -> KmsKeyResponse {
        KmsKeyResponse {
            keys: (0..epochs)
                .map(|_| KmsKeys {
                    ca_key: KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
                        .unwrap()
                        .serialize_pem(),
                    k256_key: SigningKey::random(&mut rand::rngs::OsRng)
                        .to_bytes()
                        .to_vec(),
                })
                .collect(),
        }
    }

    /// The registry a correct handover of `res` would be checked against.
    fn current_of(res: &KmsKeyResponse, epoch: u32) -> RootEpochRegistry {
        let roots: Vec<_> = res
            .keys
            .iter()
            .map(|k| {
                (
                    KeyPair::from_pem(&k.ca_key).unwrap().public_key_der(),
                    SigningKey::from_slice(&k.k256_key)
                        .unwrap()
                        .verifying_key()
                        .to_sec1_bytes()
                        .to_vec(),
                )
            })
            .collect();
        let hashes = dstack_types::root_epoch::chain_hashes(
            roots.iter().map(|(ca, k256)| (&ca[..], &k256[..])),
        );
        RootEpochRegistry::Current(CurrentRootEpoch {
            epoch,
            chain_hash: hashes[epoch as usize],
        })
    }

    async fn onboard(
        cfg: &KmsConfig,
        res: KmsKeyResponse,
        rotate: bool,
        registry: RootEpochRegistry,
    ) -> Result<Keys> {
        Keys::from_key_response(cfg, res, "kms.example.com", rotate, registry).await
    }

    #[rocket::async_test]
    async fn join_imports_and_stores_every_epoch() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let res = handover(3);
        let sent: Vec<_> = res.keys.iter().map(|k| k.k256_key.clone()).collect();

        let keys = onboard(&cfg, res, false, RootEpochRegistry::Unchecked)
            .await
            .unwrap();
        keys.store(&cfg).unwrap();
        assert!(!cfg.cert_dir.join("tmp-ca.key").exists());
        assert!(!cfg.cert_dir.join("tmp-ca.crt").exists());

        assert_eq!(crate::main_service::read_root_epoch(&cfg).unwrap(), 2);
        for (epoch, k256) in (0..).zip(&sent) {
            assert_eq!(
                &fs::read(cfg.root_key_paths(epoch, 2).k256_key).unwrap(),
                k256
            );
        }
        assert_eq!(&fs::read(cfg.k256_key()).unwrap(), &sent[2]);
    }

    #[rocket::async_test]
    async fn rotation_imports_the_keyring_and_generates_the_next_epoch() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let res = handover(2);
        let registry = current_of(&res, 1);
        let sent: Vec<_> = res.keys.iter().map(|k| k.k256_key.clone()).collect();

        let keys = onboard(&cfg, res, true, registry).await.unwrap();
        assert_eq!(keys.epoch, 2);
        keys.store(&cfg).unwrap();

        assert_eq!(
            fs::read(cfg.root_key_paths(1, 2).k256_key).unwrap(),
            sent[1]
        );
        let current = fs::read(cfg.k256_key()).unwrap();
        assert!(!sent.contains(&current));
    }

    #[rocket::async_test]
    async fn onboarding_checks_the_handover_against_the_current_epoch() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let res = handover(2);
        let other = handover(2);

        // A join may hold an epoch pending activation beyond the current one.
        assert!(onboard(&cfg, res.clone(), false, current_of(&res, 1))
            .await
            .is_ok());
        assert!(onboard(&cfg, res.clone(), false, current_of(&res, 0))
            .await
            .is_ok());
        // A rotation must start at the current epoch.
        assert!(onboard(&cfg, res.clone(), true, current_of(&res, 0))
            .await
            .is_err());
        // A keyring other than the registered one.
        assert!(onboard(&cfg, res.clone(), false, current_of(&other, 1))
            .await
            .is_err());
        assert!(onboard(&cfg, res.clone(), true, current_of(&other, 1))
            .await
            .is_err());
        // A source behind the current epoch.
        assert!(onboard(&cfg, handover(1), false, current_of(&res, 1))
            .await
            .is_err());
        // A missing epoch shifts the rest, so the chain hash no longer matches.
        let mut gap = res.clone();
        gap.keys.remove(0);
        assert!(onboard(&cfg, gap, false, current_of(&res, 0))
            .await
            .is_err());
        assert!(
            onboard(&cfg, handover(0), false, RootEpochRegistry::Unchecked)
                .await
                .is_err()
        );
    }

    #[rocket::async_test]
    async fn an_unregistered_deployment_can_only_join_at_epoch_0() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        assert!(onboard(&cfg, handover(1), false, RootEpochRegistry::Empty)
            .await
            .is_ok());
        assert!(onboard(&cfg, handover(2), false, RootEpochRegistry::Empty)
            .await
            .is_err());
        assert!(onboard(&cfg, handover(1), true, RootEpochRegistry::Empty)
            .await
            .is_err());
    }

    /// A stored keyring at `latest`, loaded back.
    async fn stored_keyring(epochs: u32) -> (tempfile::TempDir, KmsConfig, KmsKeyResponse) {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let res = handover(epochs);
        onboard(&cfg, res.clone(), false, RootEpochRegistry::Unchecked)
            .await
            .unwrap()
            .store(&cfg)
            .unwrap();
        (cert_dir, cfg, res)
    }

    #[rocket::async_test]
    async fn a_keyring_serves_the_current_epoch_it_holds() {
        use crate::main_service::Keyring;

        let (_dir, cfg, res) = stored_keyring(3).await;
        let keyring = Keyring::load(&cfg).unwrap();
        assert_eq!(keyring.latest(), 2);
        assert_eq!(keyring.servable_epoch(current_of(&res, 1)).unwrap(), 1);
        assert_eq!(keyring.servable_epoch(current_of(&res, 2)).unwrap(), 2);
        assert_eq!(
            keyring
                .servable_epoch(RootEpochRegistry::Unchecked)
                .unwrap(),
            2
        );
        assert!(keyring.servable_epoch(RootEpochRegistry::Empty).is_err());
        assert!(keyring.servable_epoch(current_of(&handover(3), 1)).is_err());
        let mut ahead = handover(4);
        ahead.keys[..3].clone_from_slice(&res.keys);
        assert!(keyring.servable_epoch(current_of(&ahead, 3)).is_err());

        let (_dir, cfg, _) = stored_keyring(1).await;
        let keyring = Keyring::load(&cfg).unwrap();
        assert_eq!(keyring.servable_epoch(RootEpochRegistry::Empty).unwrap(), 0);
    }

    #[rocket::async_test]
    async fn setup_status_includes_bootstrap_info_when_present() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let keys = Keys::generate("kms.example.com", false).await.unwrap();
        keys.store(&cfg).unwrap();
        let expected_k256 = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        let stored = BootstrapResponse {
            ca_pubkey: vec![1, 2, 3],
            k256_pubkey: expected_k256.clone(),
            attestation: vec![7, 8, 9],
        };
        fs::write(cfg.bootstrap_info(), serde_json::to_vec(&stored).unwrap()).unwrap();
        let status = setup_status(&cfg).unwrap();
        assert!(status.provisioned);
        assert!(status.ready);
        assert_eq!(status.ca_pubkey, stored.ca_pubkey);
        assert_eq!(status.attestation, stored.attestation);
        assert_eq!(status.k256_pubkey, expected_k256);
    }

    #[rocket::async_test]
    async fn setup_status_ignores_absent_or_invalid_bootstrap_info() {
        let cert_dir = tempfile::tempdir().unwrap();
        let cfg = auto_bootstrap_config(cert_dir.path());
        let keys = Keys::generate("kms.example.com", false).await.unwrap();
        let expected_k256 = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        keys.store(&cfg).unwrap();
        let stored = BootstrapResponse {
            ca_pubkey: vec![1, 2, 3],
            k256_pubkey: vec![4, 5, 6],
            attestation: vec![7, 8, 9],
        };
        for ready in [true, false] {
            if !ready {
                fs::remove_file(cfg.rpc_cert()).unwrap();
                fs::remove_file(cfg.bootstrap_info()).unwrap();
            }
            for info in [
                None,
                Some(b"invalid json".to_vec()),
                Some(serde_json::to_vec(&stored).unwrap()),
            ] {
                if let Some(info) = info {
                    fs::write(cfg.bootstrap_info(), info).unwrap();
                }
                let status = setup_status(&cfg).unwrap();
                assert!(status.provisioned);
                assert_eq!(status.ready, ready);
                assert_eq!(status.k256_pubkey, expected_k256);
                assert!(status.ca_pubkey.is_empty());
                assert!(status.attestation.is_empty());
            }
        }

        fs::write(cfg.k256_key(), b"invalid key").unwrap();
        let err = setup_status(&cfg).unwrap_err();
        assert!(format!("{err:#}").contains("failed to parse k256 key"));
    }

    #[test]
    fn ca_certificate_is_renewed_only_within_the_renewal_window() {
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let inside_window = ca_cert_expiring_at(now + CA_RENEWAL_WINDOW - Duration::from_secs(1));
        let outside_window = ca_cert_expiring_at(now + CA_RENEWAL_WINDOW + Duration::from_secs(1));

        assert!(ca_cert_expires_within(&inside_window, now, CA_RENEWAL_WINDOW).unwrap());
        assert!(!ca_cert_expires_within(&outside_window, now, CA_RENEWAL_WINDOW).unwrap());
    }
}

/// Root keys of an epoch older than the current one.
struct HistoricalRoot {
    ca_key: KeyPair,
    ca_cert: Certificate,
    k256_key: SigningKey,
}

impl HistoricalRoot {
    fn new(ca_key: KeyPair, k256_key: SigningKey) -> Result<Self> {
        let ca_cert = self_signed_root_ca(&ca_key)?;
        Ok(Self {
            ca_key,
            ca_cert,
            k256_key,
        })
    }
}

struct Keys {
    /// Epoch of the root keys below; `history` holds epochs `0..epoch`.
    epoch: u32,
    history: Vec<HistoricalRoot>,
    k256_key: SigningKey,
    ca_key: KeyPair,
    ca_cert: Certificate,
    rpc_key: KeyPair,
    rpc_cert: Certificate,
    rpc_domain: String,
}

impl Keys {
    async fn generate(domain: &str, attest_rpc_cert: bool) -> Result<Self> {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let k256_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self::from_keys(ca_key, rpc_key, k256_key, domain, attest_rpc_cert).await
    }

    /// Attest the current root public keys. Epoch 0 keeps the original
    /// bootstrap encoding; later epochs also bind the epoch number.
    async fn attest(&self) -> Result<BootstrapResponse> {
        let ca_pubkey = self.ca_key.public_key_der();
        let k256_pubkey = self.k256_key.verifying_key().to_sec1_bytes().to_vec();
        let attestation = attest_keys(self.epoch, &ca_pubkey, &k256_pubkey).await?;
        Ok(BootstrapResponse {
            ca_pubkey,
            k256_pubkey,
            attestation,
        })
    }

    async fn from_keys(
        ca_key: KeyPair,
        rpc_key: KeyPair,
        k256_key: SigningKey,
        domain: &str,
        attest_rpc_cert: bool,
    ) -> Result<Self> {
        let ca_cert = self_signed_root_ca(&ca_key)?;
        // The only place the KMS embeds its own attestation. Skipping it lets
        // the KMS run outside a TEE for development; it does not affect the
        // verification of quotes presented *to* the KMS, which is a separate
        // path (main_service::ensure_app_attestation_allowed) and stays on.
        let attestation = if attest_rpc_cert {
            let pubkey = rpc_key.public_key_der();
            let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
            let response = app_attest(report_data.to_vec()).await.context(
                "failed to get a quote for the KMS RPC certificate. The KMS attests \
                     itself through the dstack guest agent, so it must run inside a dstack \
                     CVM. For local development set attest_rpc_cert = false",
            )?;
            Some(
                VersionedAttestation::from_bytes(&response.attestation)
                    .context("Invalid attestation")?,
            )
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
        Ok(Keys {
            epoch: 0,
            history: Vec::new(),
            k256_key,
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
        source_token: &str,
        domain: &str,
        rotate: bool,
        attestation_verifier: Arc<AttestationVerifier>,
    ) -> Result<Self> {
        let attestation_slot = Arc::new(Mutex::new(None::<VerifiedAttestation>));
        let attestation_slot_out = attestation_slot.clone();
        let capture_source_attestation = Box::new(move |info: Option<CertInfo>| {
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
        });
        let source_attestation = || {
            attestation_slot
                .lock()
                .map_err(|_| anyhow::anyhow!("source attestation mutex poisoned"))?
                .clone()
                .context("Missing source KMS attestation")
        };

        let (ra_cert, ra_key) = gen_ra_cert().await?;
        let client = RaClientConfig::builder()
            .tls_skip_ca_verification(true)
            .tls_built_in_root_certs(false)
            .remote_uri(other_kms_url.to_string())
            .tls_client_cert(ra_cert)
            .tls_client_key(ra_key)
            .cert_validator(capture_source_attestation)
            .attestation_verifier(attestation_verifier.clone())
            .maybe_bearer_token((!source_token.is_empty()).then(|| source_token.to_string()))
            .build()
            .into_client()?;
        let info = dstack_client().info().await.context("Failed to get info")?;
        let request = GetKmsKeyRequest {
            vm_config: info.vm_config,
        };
        let keys_res = if source_token.is_empty() {
            KmsClient::new(client).get_kms_key(request).await?
        } else {
            AdminClient::new(client).get_kms_key(request).await?
        };
        // The attestation is captured only on the connection that returned the keys;
        // nothing received is used before the source passes this check.
        ensure_kms_allowed(cfg, &source_attestation()?, &attestation_verifier, !rotate)
            .await
            .context("Source KMS is not allowed for onboarding")?;
        Self::from_registered_key_response(cfg, keys_res, domain, rotate).await
    }

    /// [`Self::from_key_response`] after reading the registered epochs, so a
    /// source holding any keyring other than the registered one is refused.
    async fn from_registered_key_response(
        cfg: &KmsConfig,
        keys_res: KmsKeyResponse,
        domain: &str,
        rotate: bool,
    ) -> Result<Self> {
        let registry = cfg
            .auth_api
            .get_info()
            .await
            .context("failed to read the current root epoch")?
            .root_epochs;
        Self::from_key_response(cfg, keys_res, domain, rotate, registry).await
    }

    /// Import the source's whole keyring, epochs 0..=latest; a rotation then
    /// generates epoch latest+1.
    async fn from_key_response(
        cfg: &KmsConfig,
        keys_res: KmsKeyResponse,
        domain: &str,
        rotate: bool,
        registry: RootEpochRegistry,
    ) -> Result<Self> {
        let latest = keys_res
            .keys
            .len()
            .checked_sub(1)
            .context("source KMS handed over no keys")? as u32;
        let mut roots = keys_res
            .keys
            .into_iter()
            .map(|keys| {
                let ca_key = KeyPair::from_pem(&keys.ca_key).context("Failed to parse CA key")?;
                let k256_key =
                    SigningKey::from_slice(&keys.k256_key).context("Failed to parse ECDSA key")?;
                Ok((ca_key, k256_key))
            })
            .collect::<Result<Vec<_>>>()?;
        ensure_handover_registered(&roots, registry, rotate)?;
        let epoch = if rotate { latest + 1 } else { latest };
        let (ca_key, k256_key) = if rotate {
            (
                KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?,
                SigningKey::random(&mut rand::rngs::OsRng),
            )
        } else {
            roots.pop().context("source KMS handed over no keys")?
        };
        let history = roots
            .into_iter()
            .map(|(ca_key, k256_key)| HistoricalRoot::new(ca_key, k256_key))
            .collect::<Result<Vec<_>>>()?;

        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let keys = Self::from_keys(ca_key, rpc_key, k256_key, domain, cfg.attest_rpc_cert).await?;
        Ok(Self {
            epoch,
            history,
            ..keys
        })
    }

    /// The root keys go last: see [`KmsConfig::root_keys_exist`].
    fn store(&self, cfg: &KmsConfig) -> Result<()> {
        for (epoch, root) in (0..).zip(&self.history) {
            let paths = cfg.root_key_paths(epoch, self.epoch);
            if let Some(dir) = paths.ca_key.parent() {
                fs::create_dir_all(dir)?;
            }
            safe_write(&paths.ca_cert, root.ca_cert.pem())?;
            safe_write_with_mode(&paths.ca_key, root.ca_key.serialize_pem(), 0o600)?;
            safe_write_with_mode(&paths.k256_key, root.k256_key.to_bytes(), 0o600)?;
        }
        self.store_certs(cfg)?;
        safe_write(cfg.rpc_domain(), self.rpc_domain.as_bytes())?;
        safe_write(cfg.root_epoch(), self.epoch.to_string())?;
        self.store_keys(cfg)?;
        Ok(())
    }

    fn store_keys(&self, cfg: &KmsConfig) -> Result<()> {
        safe_write_with_mode(cfg.rpc_key(), self.rpc_key.serialize_pem(), 0o600)?;
        safe_write_with_mode(cfg.root_ca_key(), self.ca_key.serialize_pem(), 0o600)?;
        safe_write_with_mode(cfg.k256_key(), self.k256_key.to_bytes(), 0o600)?;
        Ok(())
    }

    fn store_certs(&self, cfg: &KmsConfig) -> Result<()> {
        safe_write(cfg.root_ca_cert(), self.ca_cert.pem())?;
        safe_write(cfg.rpc_cert(), self.rpc_cert.pem())?;
        Ok(())
    }
}

/// Reissue the RPC certificate under the root CA of the served `epoch`, so
/// guests reach this KMS through the CA of the keys it serves.
pub(crate) async fn update_certs(cfg: &KmsConfig, epoch: u32, latest: u32) -> Result<()> {
    let roots = cfg.root_key_paths(epoch, latest);
    // Read existing keys
    let ca_key = KeyPair::from_pem(&fs::read_to_string(&roots.ca_key)?)?;
    let rpc_key = KeyPair::from_pem(&fs::read_to_string(cfg.rpc_key())?)?;

    // Read k256 key
    let k256_key_bytes = fs::read(&roots.k256_key)?;
    let k256_key = SigningKey::from_slice(&k256_key_bytes)?;

    let domain = if cfg.onboard.auto_bootstrap_domain.is_empty() {
        fs::read_to_string(cfg.rpc_domain())?
    } else {
        cfg.onboard.auto_bootstrap_domain.clone()
    };
    let domain = domain.trim();

    // Regenerate certificates using existing keys
    let keys = Keys::from_keys(ca_key, rpc_key, k256_key, domain, cfg.attest_rpc_cert)
        .await
        .context("Failed to regenerate certificates")?;

    renew_ca_cert_if_expiring(
        &roots.ca_cert,
        keys.ca_cert.pem(),
        "KMS root CA certificate",
    )?;
    // The RPC leaf depends on the refreshed domain and platform attestation, so
    // it is reissued on every startup.
    safe_write(cfg.rpc_cert(), keys.rpc_cert.pem())?;
    info!("Reissued the KMS RPC certificate for {domain}");

    Ok(())
}

const CA_RENEWAL_WINDOW: Duration = Duration::from_secs(365 * 24 * 60 * 60);

fn renew_ca_cert_if_expiring(
    path: impl AsRef<std::path::Path>,
    renewed_pem: String,
    description: &str,
) -> Result<()> {
    let path = path.as_ref();
    let current_pem = fs::read(path)
        .with_context(|| format!("Failed to read {description} from {}", path.display()))?;
    if !ca_cert_expires_within(&current_pem, SystemTime::now(), CA_RENEWAL_WINDOW)? {
        return Ok(());
    }
    safe_write(path, renewed_pem)?;
    info!("Renewed {description}");
    Ok(())
}

fn ca_cert_expires_within(cert_pem: &[u8], now: SystemTime, window: Duration) -> Result<bool> {
    let (_, pem) =
        x509_parser::pem::parse_x509_pem(cert_pem).context("Failed to parse CA certificate PEM")?;
    let cert = pem.parse_x509().context("Failed to parse CA certificate")?;
    let now = now
        .duration_since(UNIX_EPOCH)
        .context("System time is before the Unix epoch")?
        .as_secs();
    let renewal_deadline = now.saturating_add(window.as_secs());
    let not_after = u64::try_from(cert.validity().not_after.timestamp()).unwrap_or(0);
    Ok(not_after <= renewal_deadline)
}

pub(crate) async fn bootstrap_keys(cfg: &KmsConfig, verifier: &AttestationVerifier) -> Result<()> {
    validate_onboarding_domain(&cfg.onboard.auto_bootstrap_domain)?;
    // `keys_exists()` wants every key *and* certificate, so losing one derived
    // certificate - a restored disk image - sends the KMS back here. Generating
    // new root keys then would silently change every app key and orphan every
    // encrypted disk, so refuse and let the operator recover the missing file
    // instead. Same guard as the `Onboard.Bootstrap` RPC.
    if cfg.root_keys_exist() {
        bail!("KMS has already been bootstrapped");
    }
    ensure_self_kms_allowed(cfg, verifier)
        .await
        .context("KMS is not allowed to auto-bootstrap")?;
    let keys = Keys::generate(&cfg.onboard.auto_bootstrap_domain, cfg.attest_rpc_cert)
        .await
        .context("Failed to generate keys")?;
    keys.store(cfg)?;
    Ok(())
}

/// Check the handed-over roots against governance: they must include the
/// current epoch with a matching chain hash. A rotation must start from the
/// current epoch with nothing pending activation, or it would collide with the
/// next registered epoch.
fn ensure_handover_registered(
    roots: &[(KeyPair, SigningKey)],
    registry: RootEpochRegistry,
    rotate: bool,
) -> Result<()> {
    if rotate && registry == RootEpochRegistry::Empty {
        bail!("register root epoch 0 before rotating");
    }
    let hashes = root_chain_hashes(roots.iter().map(|(ca, k256)| (ca, k256)));
    let current = servable_epoch(&hashes, registry)?;
    let latest = roots.len() as u32 - 1;
    if rotate && current != latest {
        bail!(
            "the source holds root epochs up to {latest}, but {current} is current; rotate from \
             a source at the current epoch with no epoch pending activation"
        );
    }
    Ok(())
}

fn self_signed_root_ca(ca_key: &KeyPair) -> Result<Certificate> {
    CertRequest::builder()
        .org_name("Dstack")
        .subject("Dstack KMS CA")
        .ca_level(1)
        .key(ca_key)
        .build()
        .self_signed()
}

async fn attest_keys(epoch: u32, p256_pubkey: &[u8], k256_pubkey: &[u8]) -> Result<Vec<u8>> {
    let p256_hex = hex::encode(p256_pubkey);
    let k256_hex = hex::encode(k256_pubkey);
    let content_to_quote = if epoch == 0 {
        format!("dstack-kms-genereted-keys-v1:{p256_hex};{k256_hex};")
    } else {
        format!("dstack-kms-generated-keys-v2:{epoch};{p256_hex};{k256_hex};")
    };
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

/// Mint a self-issued RA-TLS client certificate.
async fn gen_ra_cert() -> Result<(String, String)> {
    use ra_tls::cert::CertRequest;
    use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
    let pubkey = key.public_key_der();
    let report_data = QuoteContentType::RaTlsCert.to_report_data(&pubkey);
    let response = app_attest(report_data.to_vec())
        .await
        .context("Failed to get quote")?;
    let attestation =
        VersionedAttestation::from_bytes(&response.attestation).context("Invalid attestation")?;
    let req = CertRequest::builder()
        .subject("RA-TLS Client Cert")
        .attestation(&attestation)
        .key(&key)
        .usage_client_auth(true)
        .build();
    let cert = req.self_signed().context("Failed to sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}
