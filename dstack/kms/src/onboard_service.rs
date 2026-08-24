// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
use sha2::Digest;
use tokio::sync::Mutex as AsyncMutex;
use tracing::info;

use crate::{
    config::KmsConfig,
    main_service::{
        build_boot_info_for_attestation,
        upgrade_authority::{
            app_attest, dstack_client, ensure_kms_allowed, ensure_self_kms_allowed, pad64,
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

impl OnboardRpc for OnboardHandler {
    async fn bootstrap(self, request: BootstrapRequest) -> Result<BootstrapResponse> {
        validate_onboarding_domain(&request.domain)?;
        let _bootstrap_guard = self.state.bootstrap_lock.lock().await;
        let cfg = &self.state.config;
        if cfg.bootstrap_info().exists() || cfg.root_ca_key().exists() || cfg.k256_key().exists() {
            bail!("KMS has already been bootstrapped");
        }
        ensure_self_kms_allowed(cfg, &self.state.attestation_verifier)
            .await
            .context("KMS is not allowed to bootstrap")?;
        let keys = Keys::generate(&request.domain, self.state.config.attest_rpc_cert)
            .await
            .context("Failed to generate keys")?;

        let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        let ca_pubkey = keys.ca_key.public_key_der();
        let attestation = attest_keys(&ca_pubkey, &k256_pubkey).await?;

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
        validate_onboarding_domain(&request.domain)?;
        let _bootstrap_guard = self.state.bootstrap_lock.lock().await;
        let cfg = &self.state.config;
        if cfg.root_ca_key().exists() || cfg.k256_key().exists() {
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
            &request.domain,
            self.state.attestation_verifier.clone(),
        )
        .await
        .context("Failed to onboard")?;
        let k256_pubkey = keys.k256_key.verifying_key().to_sec1_bytes().to_vec();
        keys.store(cfg).context("Failed to store keys")?;
        Ok(OnboardResponse { k256_pubkey })
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
    let raw_device_id = verified.report.get_devide_id();
    Ok(AttestationInfoResponse {
        device_id: sha2::Sha256::digest(&raw_device_id).to_vec(),
        mr_aggregated: boot_info.mr_aggregated,
        os_image_hash: boot_info.os_image_hash,
        tee_variant,
        site_name,
        eth_rpc_url,
        kms_contract_address,
        ppid: raw_device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_service::amd_attest::{
        compute_expected_measurement, MeasurementInput, OvmfSectionParam,
    };
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

    #[test]
    fn ca_certificate_is_renewed_only_within_the_renewal_window() {
        let now = UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let inside_window = ca_cert_expiring_at(now + CA_RENEWAL_WINDOW - Duration::from_secs(1));
        let outside_window = ca_cert_expiring_at(now + CA_RENEWAL_WINDOW + Duration::from_secs(1));

        assert!(ca_cert_expires_within(&inside_window, now, CA_RENEWAL_WINDOW).unwrap());
        assert!(!ca_cert_expires_within(&outside_window, now, CA_RENEWAL_WINDOW).unwrap());
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
    async fn generate(domain: &str, attest_rpc_cert: bool) -> Result<Self> {
        let tmp_ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let rpc_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let k256_key = SigningKey::random(&mut rand::rngs::OsRng);
        Self::from_keys(
            tmp_ca_key,
            ca_key,
            rpc_key,
            k256_key,
            domain,
            attest_rpc_cert,
        )
        .await
    }

    async fn from_keys(
        tmp_ca_key: KeyPair,
        ca_key: KeyPair,
        rpc_key: KeyPair,
        k256_key: SigningKey,
        domain: &str,
        attest_rpc_cert: bool,
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
        attestation_verifier: Arc<AttestationVerifier>,
    ) -> Result<Self> {
        let attestation_slot = Arc::new(Mutex::new(None::<VerifiedAttestation>));
        let attestation_slot_out = attestation_slot.clone();
        // Self-issued: the source KMS authenticates the quote inside this certificate,
        // not whoever signed it, so there is no CA to fetch first. This requires a
        // source running 0.6.0 or later; older releases pin their temp CA and refuse a
        // self-issued certificate at the handshake.
        let (ra_cert, ra_key) = gen_ra_cert().await?;
        // One client, not two. The connection that carries the root key is the one
        // whose `cert_validator` runs, so the source's attestation is verified on the
        // handshake that matters rather than on an earlier, separate connection.
        let client = RaClientConfig::builder()
            .tls_no_check(true)
            .tls_built_in_root_certs(false)
            .remote_uri(other_kms_url.to_string())
            .tls_client_cert(ra_cert)
            .tls_client_key(ra_key)
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
            .attestation_verifier(attestation_verifier.clone())
            .build()
            .into_client()?;
        let kms_client = KmsClient::new(client);

        let info = dstack_client().info().await.context("Failed to get info")?;
        let keys_res = kms_client
            .get_kms_key(GetKmsKeyRequest {
                vm_config: info.vm_config,
            })
            .await?;

        let source_attestation = attestation_slot
            .lock()
            .map_err(|_| anyhow::anyhow!("source attestation mutex poisoned"))?
            .clone()
            .context("Missing source KMS attestation")?;
        ensure_kms_allowed(cfg, &source_attestation, &attestation_verifier)
            .await
            .context("Source KMS is not allowed for onboarding")?;

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
            cfg.attest_rpc_cert,
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
        safe_write_with_mode(cfg.tmp_ca_key(), self.tmp_ca_key.serialize_pem(), 0o600)?;
        safe_write_with_mode(cfg.root_ca_key(), self.ca_key.serialize_pem(), 0o600)?;
        safe_write_with_mode(cfg.rpc_key(), self.rpc_key.serialize_pem(), 0o600)?;
        safe_write_with_mode(cfg.k256_key(), self.k256_key.to_bytes(), 0o600)?;
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
        cfg.attest_rpc_cert,
    )
    .await
    .context("Failed to regenerate certificates")?;

    renew_ca_cert_if_expiring(
        cfg.root_ca_cert(),
        keys.ca_cert.pem(),
        "KMS root CA certificate",
    )?;
    renew_ca_cert_if_expiring(
        cfg.tmp_ca_cert(),
        keys.tmp_ca_cert.pem(),
        "temporary client CA certificate",
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
    ensure_self_kms_allowed(cfg, verifier)
        .await
        .context("KMS is not allowed to auto-bootstrap")?;
    let keys = Keys::generate(&cfg.onboard.auto_bootstrap_domain, cfg.attest_rpc_cert)
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

/// Mint the self-issued RA-TLS certificate this KMS presents while onboarding.
///
/// The quote binds the certificate's own public key, which is the identity the source
/// KMS authenticates, so no CA is involved. The quote comes from the guest agent
/// (`app_attest`) rather than from `ra_tls`'s direct quote path, because the KMS is an
/// application inside a CVM and its attestation has to carry the agent's app info.
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
    let cert = CertRequest::builder()
        .subject("RA-TLS Self-Signed Cert")
        .attestation(&attestation)
        .key(&key)
        .usage_client_auth(true)
        .build()
        .self_signed()
        .context("Failed to self-sign certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}
