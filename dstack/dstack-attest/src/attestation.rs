// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Attestation functions

/// Byte range of the REPORT_DATA field within a TDX quote.
/// In Intel TDX ECDSA quote format, the TD Report body starts at offset 568
/// and REPORT_DATA occupies bytes 568..632 (64 bytes).
pub const TDX_QUOTE_REPORT_DATA_RANGE: std::ops::Range<usize> = 568..632;

use std::{borrow::Cow, time::SystemTime};

use anyhow::{anyhow, bail, Context, Result};
use cc_eventlog::{EventLogVersion, RuntimeEvent, TdxEvent};
use dcap_qvl::{
    collateral::CollateralClient,
    quote::{EnclaveReport, Quote, Report, TDReport10, TDReport15},
    verify::VerifiedReport as TdxVerifiedReport,
};
pub use dstack_types::CollateralUrls;
#[cfg(feature = "quote")]
use dstack_types::SysConfig;
use dstack_types::{mr_config::MrConfigV3, KeyProviderInfo, Platform, VmConfig};
use ez_hash::{sha256, Hasher, Sha256, Sha384};
use or_panic::ResultOrPanic;
use scale::{Decode, Encode, Error as ScaleError, Input, Output};
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;
use sha2::Digest as _;
use tpm_qvl::verify::VerifiedReport as TpmVerifiedReport;

/// File paths for attestation trust anchors. Empty fields retain the vendor
/// production roots. Paths are read by the verifier, never by the attester.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootCaPaths {
    pub tdx: Option<std::path::PathBuf>,
    pub gcp_tpm: Option<std::path::PathBuf>,
    pub aws_nitro_enclave: Option<std::path::PathBuf>,
    pub aws_nitro_tpm: Option<std::path::PathBuf>,
    pub sev_snp_milan: Option<std::path::PathBuf>,
    pub sev_snp_genoa: Option<std::path::PathBuf>,
    pub sev_snp_turin: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationVerifierConfig {
    #[serde(default)]
    pub insecure_allow_external_trust_anchors: bool,
    #[serde(default)]
    pub urls: CollateralUrls,
    #[serde(default)]
    pub root_ca: RootCaPaths,
}

pub struct AttestationVerifier {
    tdx: dcap_qvl::verify::QuoteVerifier,
    tdx_collateral: CollateralClient,
    gcp_tpm: tpm_qvl::QuoteVerifier,
    aws_nitro_enclave: nsm_qvl::QuoteVerifier,
    aws_nitro_tpm: nsm_qvl::QuoteVerifier,
    sev_snp: sev_snp_qvl::QuoteVerifier,
    amd_kds: AmdKdsClient,
}

impl AttestationVerifier {
    pub fn load(config: &AttestationVerifierConfig) -> Result<Self> {
        let roots = &config.root_ca;
        let RootCaPaths {
            tdx,
            gcp_tpm,
            aws_nitro_enclave,
            aws_nitro_tpm,
            sev_snp_milan,
            sev_snp_genoa,
            sev_snp_turin,
        } = roots;
        let external_requested = [
            tdx,
            gcp_tpm,
            aws_nitro_enclave,
            aws_nitro_tpm,
            sev_snp_milan,
            sev_snp_genoa,
            sev_snp_turin,
        ]
        .into_iter()
        .any(Option::is_some);
        anyhow::ensure!(
            !external_requested || config.insecure_allow_external_trust_anchors,
            "external attestation trust anchors are configured but \
             insecure_allow_external_trust_anchors is false"
        );
        let tdx = match read_root_file(tdx.as_deref(), "TDX")? {
            Some(root) => dcap_qvl::verify::QuoteVerifier::new(tdx_root_der(root)?),
            None => dcap_qvl::verify::QuoteVerifier::new_prod(),
        };
        let gcp_tpm = match read_root_file(gcp_tpm.as_deref(), "GCP TPM")? {
            Some(root) => tpm_qvl::QuoteVerifier::new(validated_pem_string(root, "GCP TPM")?),
            None => tpm_qvl::QuoteVerifier::new_prod(Platform::Gcp)?,
        };
        let nsm = |path, name| -> Result<nsm_qvl::QuoteVerifier> {
            Ok(match read_root_file(path, name)? {
                Some(root) => nsm_qvl::QuoteVerifier::new(validated_pem_string(root, name)?),
                None => nsm_qvl::QuoteVerifier::new_prod(),
            })
        };
        let mut sev_snp = sev_snp_qvl::QuoteVerifier::new_prod();
        for (path, name, product) in [
            (
                sev_snp_milan.as_deref(),
                "SEV-SNP Milan",
                sev_snp_qvl::AmdSnpProduct::Milan,
            ),
            (
                sev_snp_genoa.as_deref(),
                "SEV-SNP Genoa",
                sev_snp_qvl::AmdSnpProduct::Genoa,
            ),
            (
                sev_snp_turin.as_deref(),
                "SEV-SNP Turin",
                sev_snp_qvl::AmdSnpProduct::Turin,
            ),
        ] {
            if let Some(root) = read_root_file(path, name)? {
                validate_x509_certificate(&root, name)?;
                sev_snp = sev_snp.with_root(product, root);
            }
        }
        let pccs = config
            .urls
            .pccs
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(dcap_qvl::collateral::PHALA_PCCS_URL);
        let amd_kds = config
            .urls
            .amd_kds
            .as_deref()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or(sev_snp_qvl::AMD_KDS_DEFAULT_BASE_URL);
        Ok(Self {
            tdx,
            tdx_collateral: CollateralClient::with_default_http(pccs)?,
            gcp_tpm,
            aws_nitro_enclave: nsm(aws_nitro_enclave.as_deref(), "AWS Nitro Enclave")?,
            aws_nitro_tpm: nsm(aws_nitro_tpm.as_deref(), "AWS NitroTPM")?,
            sev_snp,
            amd_kds: AmdKdsClient::with_base_url(amd_kds)?,
        })
    }

    pub fn new_prod(collateral_urls: Option<&CollateralUrls>) -> Result<Self> {
        let collateral_urls = collateral_urls.cloned().unwrap_or_default();
        Ok(Self {
            tdx: dcap_qvl::verify::QuoteVerifier::new_prod(),
            tdx_collateral: CollateralClient::with_default_http(
                collateral_urls
                    .pccs
                    .as_deref()
                    .filter(|url| !url.trim().is_empty())
                    .unwrap_or(dcap_qvl::collateral::PHALA_PCCS_URL),
            )?,
            gcp_tpm: tpm_qvl::QuoteVerifier::new_prod(Platform::Gcp)?,
            aws_nitro_enclave: nsm_qvl::QuoteVerifier::new_prod(),
            aws_nitro_tpm: nsm_qvl::QuoteVerifier::new_prod(),
            sev_snp: sev_snp_qvl::QuoteVerifier::new_prod(),
            amd_kds: AmdKdsClient::with_base_url(
                collateral_urls
                    .amd_kds
                    .as_deref()
                    .filter(|url| !url.trim().is_empty())
                    .unwrap_or(sev_snp_qvl::AMD_KDS_DEFAULT_BASE_URL),
            )?,
        })
    }

    async fn verify_tdx_quote(&self, quote: &[u8]) -> Result<TdxVerifiedReport> {
        let collateral = self.tdx_collateral.fetch(quote).await?;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_secs();
        self.tdx.verify(quote, &collateral, now)
    }
}

fn read_root_file(path: Option<&std::path::Path>, platform: &str) -> Result<Option<Vec<u8>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    fs_err::read(path)
        .with_context(|| format!("failed to read {platform} root CA from {}", path.display()))
        .map(Some)
}

fn validated_pem_string(root: Vec<u8>, platform: &str) -> Result<String> {
    validate_x509_certificate(&root, platform)?;
    String::from_utf8(root).with_context(|| format!("{platform} root CA is not UTF-8 PEM"))
}

fn validate_x509_certificate(root: &[u8], platform: &str) -> Result<()> {
    use x509_parser::prelude::{FromDer, X509Certificate};
    let der = if root.starts_with(b"-----BEGIN") {
        pem::parse(root)
            .with_context(|| format!("failed to parse {platform} root CA PEM"))?
            .into_contents()
    } else {
        root.to_vec()
    };
    let (remaining, certificate) = X509Certificate::from_der(&der)
        .with_context(|| format!("failed to parse {platform} root CA certificate"))?;
    anyhow::ensure!(remaining.is_empty(), "trailing data in {platform} root CA");
    anyhow::ensure!(
        certificate.is_ca(),
        "{platform} root certificate is not a CA"
    );
    Ok(())
}

fn tdx_root_der(root: Vec<u8>) -> Result<Vec<u8>> {
    validate_x509_certificate(&root, "TDX")?;
    if root.starts_with(b"-----BEGIN") {
        return Ok(pem::parse(root)?.into_contents());
    }
    Ok(root)
}

// Re-export TpmQuote from tpm-types
pub use tpm_types::TpmQuote;

use crate::amd_sev_snp::{AmdKdsClient, VerifiedAmdSnpReport};
use crate::v1::{strip_tdx_event_log_for_config, strip_tdx_runtime_event_log};
pub use crate::v1::{Attestation as AttestationV1, PlatformEvidence, StackEvidence};

pub const SNP_REPORT_DATA_RANGE: std::ops::Range<usize> = 0x50..0x90;

/// Path to sys-config.json in the host-shared dir.
///
/// Honors `DSTACK_HOST_SHARED_DIR` (exported by `dstack-util setup` because the
/// canonical `/dstack/.host-shared` is only bind-mounted after setup finishes).
#[cfg(feature = "quote")]
fn sys_config_path() -> std::path::PathBuf {
    dstack_types::shared_filenames::host_shared_dir()
        .join(dstack_types::shared_filenames::SYS_CONFIG)
}

/// Global lock for quote generation. The underlying TDX driver does not support concurrent access.
#[cfg(feature = "quote")]
static QUOTE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Read vm_config from sys-config.json
#[cfg(feature = "quote")]
fn read_vm_config(path: Option<&std::path::Path>) -> Result<String> {
    let path = path.map_or_else(sys_config_path, std::path::Path::to_path_buf);
    let content = match fs_err::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(err) => return Err(err).context("Failed to read sys-config"),
    };
    let sys_config: SysConfig =
        serde_json::from_str(&content).context("Failed to parse sys-config")?;
    Ok(sys_config.vm_config)
}

/// Read the canonical mr_config document from sys-config.json.
///
/// Uses the same accessor as the guest config-id verifier so both agree on
/// where `mr_config` lives (top-level field, falling back to the one embedded
/// in `vm_config`).
#[cfg(feature = "quote")]
fn read_mr_config_document(path: Option<&std::path::Path>) -> Result<Option<String>> {
    let path = path.map_or_else(sys_config_path, std::path::Path::to_path_buf);
    let content = match fs_err::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("Failed to read sys-config"),
    };
    let sys_config: SysConfig =
        serde_json::from_str(&content).context("Failed to parse sys-config")?;
    Ok(sys_config.mr_config_document())
}

fn is_msgpack_map_prefix(byte: u8) -> bool {
    // fixmap (0x80..=0x8f), map16 (0xde), map32 (0xdf)
    matches!(byte, 0x80..=0x8f | 0xde | 0xdf)
}

impl From<Attestation> for AttestationV1 {
    fn from(attestation: Attestation) -> Self {
        let Attestation {
            quote,
            runtime_events,
            report_data,
            config,
            report: _,
        } = attestation;

        let platform = platform_from_legacy_quote(quote);
        let stack = StackEvidence::Dstack {
            report_data: report_data.to_vec(),
            runtime_events,
            config,
        };
        Self::new(platform, stack)
    }
}

fn platform_from_legacy_quote(quote: AttestationQuote) -> PlatformEvidence {
    match quote {
        AttestationQuote::DstackTdx(TdxQuote { quote, event_log }) => {
            PlatformEvidence::Tdx { quote, event_log }
        }
        AttestationQuote::DstackAmdSevSnp(SnpQuote {
            report,
            cert_chain,
            mr_config,
        }) => PlatformEvidence::SevSnp {
            report,
            cert_chain,
            mr_config,
        },
        AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
            tdx_quote: TdxQuote { quote, event_log },
            tpm_quote,
        }) => PlatformEvidence::GcpTdx {
            quote,
            event_log,
            tpm_quote,
        },
        AttestationQuote::DstackNitroEnclave(DstackNitroQuote { nsm_quote }) => {
            PlatformEvidence::NitroEnclave { nsm_quote }
        }
        AttestationQuote::DstackAwsNitroTpm(DstackAwsNitroTpmQuote { attestation_doc }) => {
            PlatformEvidence::AwsNitroTpm { attestation_doc }
        }
    }
}

fn platform_into_legacy_quote(platform: PlatformEvidence) -> AttestationQuote {
    match platform {
        PlatformEvidence::Tdx { quote, event_log } => {
            AttestationQuote::DstackTdx(TdxQuote { quote, event_log })
        }
        PlatformEvidence::SevSnp {
            report,
            cert_chain,
            mr_config,
        } => AttestationQuote::DstackAmdSevSnp(SnpQuote {
            report,
            cert_chain,
            mr_config,
        }),
        PlatformEvidence::GcpTdx {
            quote,
            event_log,
            tpm_quote,
        } => AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
            tdx_quote: TdxQuote { quote, event_log },
            tpm_quote,
        }),
        PlatformEvidence::NitroEnclave { nsm_quote } => {
            AttestationQuote::DstackNitroEnclave(DstackNitroQuote { nsm_quote })
        }
        PlatformEvidence::AwsNitroTpm { attestation_doc } => {
            AttestationQuote::DstackAwsNitroTpm(DstackAwsNitroTpmQuote { attestation_doc })
        }
    }
}

fn replay_runtime_events<H: Hasher>(
    runtime_events: &[RuntimeEvent],
    to_event: Option<&str>,
) -> H::Output {
    cc_eventlog::replay_events::<H>(runtime_events, to_event)
}

fn find_event(runtime_events: &[RuntimeEvent], name: &str) -> Result<RuntimeEvent> {
    for event in runtime_events {
        if event.event == "system-ready" {
            break;
        }
        if event.event == name {
            return Ok(event.clone());
        }
    }
    Err(anyhow!("event {name} not found"))
}

fn find_event_payload(runtime_events: &[RuntimeEvent], event: &str) -> Result<Vec<u8>> {
    find_event(runtime_events, event).map(|event| event.payload)
}

/// Returns ordered payloads for matching boot-time events.
///
/// Events after `system-ready` are application-controlled and intentionally
/// excluded from system measurements exposed through decoded app info.
fn find_event_payloads(runtime_events: &[RuntimeEvent], name: &str) -> Vec<Vec<u8>> {
    runtime_events
        .iter()
        .take_while(|event| event.event != "system-ready")
        .filter(|event| event.event == name)
        .map(|event| event.payload.clone())
        .collect()
}

fn decode_vm_config_with_fallback(config: &str, fallback_config: &str) -> Result<VmConfig> {
    let config = if config.is_empty() {
        fallback_config
    } else {
        config
    };
    let config = if config.is_empty() { "{}" } else { config };
    let config = vm_config_json_from_config(config).unwrap_or(Cow::Borrowed(config));
    serde_json::from_str(&config).context("Failed to parse vm config")
}

fn vm_config_json_from_config(config: &str) -> Option<Cow<'_, str>> {
    let value = serde_json::from_str::<serde_json::Value>(config).ok()?;
    value
        .get("vm_config")
        .and_then(|value| value.as_str())
        .map(|vm_config| Cow::Owned(vm_config.to_string()))
}

fn mr_config_document_from_value(value: &serde_json::Value) -> Result<Option<String>> {
    let Some(mr_config) = value.get("mr_config") else {
        return Ok(None);
    };
    let document = mr_config
        .as_str()
        .context("amd sev-snp mr_config must be a JSON string")?;
    MrConfigV3::from_document(document).context("Invalid amd sev-snp mr_config document")?;
    Ok(Some(document.to_string()))
}

fn mr_config_document_from_config(config: &str) -> Result<Option<String>> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(config) else {
        return Ok(None);
    };
    if let Some(mr_config) = mr_config_document_from_value(&value)? {
        return Ok(Some(mr_config));
    }

    let Some(vm_config) = value.get("vm_config").and_then(|value| value.as_str()) else {
        return Ok(None);
    };
    let vm_config = serde_json::from_str::<serde_json::Value>(vm_config)
        .context("Failed to parse nested vm_config for amd sev-snp mr_config")?;
    mr_config_document_from_value(&vm_config)
}

pub use dstack_types::TeeVariant;

#[cfg(feature = "quote")]
fn has_sev_snp_tsm_provider() -> bool {
    crate::sev_snp::has_sev_snp_tsm_provider(std::path::Path::new("/sys/kernel/config/tsm/report"))
}

#[cfg(not(feature = "quote"))]
fn has_sev_snp_tsm_provider() -> bool {
    false
}

fn choose_dstack_tee_variant(has_tdx: bool, has_sev_snp: bool) -> Result<TeeVariant> {
    if has_tdx {
        return Ok(TeeVariant::DstackTdx);
    }
    if has_sev_snp {
        return Ok(TeeVariant::DstackAmdSevSnp);
    }
    bail!("Unsupported platform: Dstack(-tdx/-amd-sev-snp)");
}

/// Detect the attestation variant exposed by the current guest environment.
pub fn detect_tee_variant() -> Result<TeeVariant> {
    let has_tdx = tdx_attest::is_tdx_available();
    let has_sev_snp = std::path::Path::new("/dev/sev-guest").exists() || has_sev_snp_tsm_provider();

    // First, try to detect platform from DMI product name
    let platform = Platform::detect_or_dstack();
    match platform {
        Platform::Dstack => choose_dstack_tee_variant(has_tdx, has_sev_snp),
        Platform::Gcp => {
            // GCP platform: TDX + TPM dual mode
            if has_tdx {
                return Ok(TeeVariant::DstackGcpTdx);
            }
            bail!("Unsupported platform: GCP(-tdx)");
        }
        Platform::NitroEnclave => Ok(TeeVariant::DstackNitroEnclave),
        Platform::AwsEc2 => {
            if std::path::Path::new("/dev/tpmrm0").exists()
                || std::path::Path::new("/dev/tpm0").exists()
            {
                return Ok(TeeVariant::DstackAwsNitroTpm);
            }
            bail!("unsupported platform: AWS EC2 without NitroTPM");
        }
    }
}

/// The content type of a quote. A CVM should only generate quotes for these types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuoteContentType<'a> {
    /// The public key of KMS root CA
    KmsRootCa,
    /// The public key of the RA-TLS certificate
    RaTlsCert,
    /// App defined data
    AppData,
    /// The custom content type
    Custom(&'a str),
}

/// The default hash algorithm used to hash the report data.
pub const DEFAULT_HASH_ALGORITHM: &str = "sha512";

impl QuoteContentType<'_> {
    /// The tag of the content type used in the report data.
    pub fn tag(&self) -> &str {
        match self {
            Self::KmsRootCa => "kms-root-ca",
            Self::RaTlsCert => "ratls-cert",
            Self::AppData => "app-data",
            Self::Custom(tag) => tag,
        }
    }

    /// Convert the content to the report data.
    pub fn to_report_data(&self, content: &[u8]) -> [u8; 64] {
        self.to_report_data_with_hash(content, "")
            .or_panic("sha512 hash should not fail")
    }

    /// Convert the content to the report data with a specific hash algorithm.
    pub fn to_report_data_with_hash(&self, content: &[u8], hash: &str) -> Result<[u8; 64]> {
        macro_rules! do_hash {
            ($hash: ty) => {{
                // The format is:
                // hash(<tag>:<content>)
                let mut hasher = <$hash>::new();
                hasher.update(self.tag().as_bytes());
                hasher.update(b":");
                hasher.update(content);
                let output = hasher.finalize();

                let mut padded = [0u8; 64];
                padded[..output.len()].copy_from_slice(&output);
                padded
            }};
        }
        let hash = if hash.is_empty() {
            DEFAULT_HASH_ALGORITHM
        } else {
            hash
        };
        let output = match hash {
            "sha256" => do_hash!(sha2::Sha256),
            "sha384" => do_hash!(sha2::Sha384),
            "sha512" => do_hash!(sha2::Sha512),
            "sha3-256" => do_hash!(sha3::Sha3_256),
            "sha3-384" => do_hash!(sha3::Sha3_384),
            "sha3-512" => do_hash!(sha3::Sha3_512),
            "keccak256" => do_hash!(sha3::Keccak256),
            "keccak384" => do_hash!(sha3::Keccak384),
            "keccak512" => do_hash!(sha3::Keccak512),
            "raw" => content.try_into().ok().context("invalid content length")?,
            _ => bail!("invalid hash algorithm"),
        };
        Ok(output)
    }
}

/// Verified Nitro Enclave attestation report
#[derive(Clone, Debug, Serialize)]
pub struct NitroVerifiedReport {
    /// Module ID
    pub module_id: String,
    /// PCR0 - Enclave image hash
    pub pcrs: NitroPcrs,
    /// User data from attestation
    #[serde(with = "serde_human_bytes")]
    pub user_data: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
}

/// Verified AWS EC2 NitroTPM attestation report.
#[derive(Clone, Debug, Serialize)]
pub struct AwsNitroTpmVerifiedReport {
    /// Module ID from the NitroTPM attestation document.
    pub module_id: String,
    /// Signature-verified NitroTPM PCR map.
    pub pcrs: std::collections::BTreeMap<u16, Vec<u8>>,
    /// Optional public key from the NitroTPM attestation document.
    pub public_key: Option<Vec<u8>>,
    /// User data from attestation.
    #[serde(with = "serde_human_bytes")]
    pub user_data: Vec<u8>,
    /// Optional nonce from the NitroTPM attestation document.
    pub nonce: Option<Vec<u8>>,
    /// Timestamp.
    pub timestamp: u64,
}

/// Represents a verified attestation
#[derive(Clone)]
pub enum DstackVerifiedReport {
    DstackTdx(TdxVerifiedReport),
    DstackGcpTdx {
        tdx_report: TdxVerifiedReport,
        tpm_report: TpmVerifiedReport,
    },
    DstackNitroEnclave(NitroVerifiedReport),
    DstackAmdSevSnp(VerifiedAmdSnpReport),
    DstackAwsNitroTpm(AwsNitroTpmVerifiedReport),
}

impl DstackVerifiedReport {
    pub fn tdx_report(&self) -> Option<&TdxVerifiedReport> {
        match self {
            DstackVerifiedReport::DstackTdx(report) => Some(report),
            DstackVerifiedReport::DstackAmdSevSnp(_) => None,
            DstackVerifiedReport::DstackGcpTdx { tdx_report, .. } => Some(tdx_report),
            DstackVerifiedReport::DstackNitroEnclave(_)
            | DstackVerifiedReport::DstackAwsNitroTpm(_) => None,
        }
    }

    pub fn amd_snp_report(&self) -> Option<&VerifiedAmdSnpReport> {
        match self {
            DstackVerifiedReport::DstackAmdSevSnp(report) => Some(report),
            DstackVerifiedReport::DstackTdx(_)
            | DstackVerifiedReport::DstackGcpTdx { .. }
            | DstackVerifiedReport::DstackNitroEnclave(_)
            | DstackVerifiedReport::DstackAwsNitroTpm(_) => None,
        }
    }
}

/// Represents a verified attestation
pub type VerifiedAttestation = Attestation<DstackVerifiedReport>;

/// Represents a TDX quote
#[derive(Clone, Encode, Decode)]
pub struct TdxQuote {
    /// The quote gererated by Intel QE
    pub quote: Vec<u8>,
    /// The event log
    pub event_log: Vec<TdxEvent>,
}

/// Represents an AMD SEV-SNP attestation report.
#[derive(Clone, Encode, Decode)]
pub struct SnpQuote {
    /// Raw SNP report bytes.
    pub report: Vec<u8>,
    /// Optional certificate chain blobs, when exposed by the kernel/firmware path.
    pub cert_chain: Vec<Vec<u8>>,
    /// MrConfigV3 document bound by the report HOST_DATA field.
    pub mr_config: String,
}

/// Represents an NSM (Nitro Security Module) attestation document
#[derive(Clone, Encode, Decode)]
pub struct NsmQuote {
    /// The COSE Sign1 attestation document from NSM
    pub document: Vec<u8>,
}

#[derive(Clone, Encode, Decode)]
enum LegacyVersionedAttestation {
    V0 { attestation: Attestation },
}

/// Maximum size for encoded attestation bytes (10 MiB).
/// Prevents OOM when decoding untrusted input.
const MAX_ATTESTATION_BYTES: usize = 10 * 1024 * 1024;

/// Represents a versioned attestation.
///
/// **SCALE note**: `VersionedAttestation` implements `Encode`/`Decode` so it can
/// be embedded in SCALE structs (e.g. `CertSigningRequestV2`).  The `Decode` impl
/// consumes all remaining input, so it **must** be the last field in any SCALE
/// container.
#[derive(Clone)]
pub enum VersionedAttestation {
    /// Legacy SCALE-encoded attestation.
    V0 {
        /// The attestation report
        attestation: Attestation,
    },
    /// CBOR-encoded attestation schema.
    V1 {
        /// The version 1 attestation.
        attestation: AttestationV1,
    },
}

impl Encode for VersionedAttestation {
    fn size_hint(&self) -> usize {
        0
    }

    fn encode_to<T: Output + ?Sized>(&self, dest: &mut T) {
        let bytes = self
            .to_bytes()
            .or_panic("VersionedAttestation should always encode successfully");
        dest.write(&bytes);
    }
}

impl Decode for VersionedAttestation {
    fn decode<I: Input>(input: &mut I) -> Result<Self, ScaleError> {
        let Some(remaining_len) = input.remaining_len()? else {
            return Err(ScaleError::from(
                "VersionedAttestation requires a bounded input to decode",
            ));
        };
        if remaining_len > MAX_ATTESTATION_BYTES {
            return Err(ScaleError::from(
                "attestation bytes exceed maximum allowed size",
            ));
        }
        let mut bytes = vec![0u8; remaining_len];
        input.read(&mut bytes)?;
        Self::from_bytes(&bytes).map_err(|err| {
            ScaleError::from(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                err.to_string(),
            ))
        })
    }
}

impl VersionedAttestation {
    /// Decode versioned attestation bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ATTESTATION_BYTES {
            bail!(
                "attestation bytes too large: {} > {}",
                bytes.len(),
                MAX_ATTESTATION_BYTES
            );
        }
        let Some(first) = bytes.first().copied() else {
            bail!("Empty attestation bytes");
        };
        if first == 0x00 {
            let mut input = bytes;
            let legacy = LegacyVersionedAttestation::decode(&mut input)
                .context("Failed to decode legacy VersionedAttestation")?;
            if !input.is_empty() {
                bail!(
                    "Trailing bytes after legacy VersionedAttestation: {}",
                    input.len()
                );
            }
            return match legacy {
                LegacyVersionedAttestation::V0 { attestation } => Ok(Self::V0 { attestation }),
            };
        }
        if is_msgpack_map_prefix(first) {
            let attestation = AttestationV1::from_msgpack(bytes)?;
            return Ok(Self::V1 { attestation });
        }
        bail!("Unknown attestation wire format");
    }

    /// Encode versioned attestation bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Self::V0 { attestation } => Ok(LegacyVersionedAttestation::V0 {
                attestation: attestation.clone(),
            }
            .encode()),
            Self::V1 { attestation } => attestation.to_msgpack(),
        }
    }

    #[doc(hidden)]
    pub fn from_scale(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }

    #[doc(hidden)]
    pub fn to_scale(&self) -> Result<Vec<u8>> {
        self.to_bytes()
    }

    /// Project any version into the V1 attestation schema.
    pub fn into_v1(self) -> AttestationV1 {
        match self {
            Self::V0 { attestation } => attestation.into_v1(),
            Self::V1 { attestation } => attestation,
        }
    }

    /// Strip data for certificate embedding.
    pub fn into_stripped(self) -> Self {
        match self {
            Self::V0 { mut attestation } => {
                match &mut attestation.quote {
                    AttestationQuote::DstackTdx(tdx_quote) => {
                        tdx_quote.event_log = strip_tdx_event_log_for_config(
                            std::mem::take(&mut tdx_quote.event_log),
                            &attestation.config,
                        );
                    }
                    AttestationQuote::DstackGcpTdx(quote) => {
                        quote.tdx_quote.event_log = strip_tdx_runtime_event_log(std::mem::take(
                            &mut quote.tdx_quote.event_log,
                        ));
                    }
                    AttestationQuote::DstackAmdSevSnp(_)
                    | AttestationQuote::DstackNitroEnclave(_)
                    | AttestationQuote::DstackAwsNitroTpm(_) => {}
                }
                Self::V0 { attestation }
            }
            Self::V1 { attestation } => Self::V1 {
                attestation: attestation.into_stripped(),
            },
        }
    }
}

/// TDX-specific helpers for attestation schemas that carry TDX platform evidence.
pub trait TdxAttestationExt {
    /// Returns the raw TDX quote bytes if the attestation is backed by TDX.
    fn tdx_quote_bytes(&self) -> Option<Vec<u8>>;

    /// Returns the parsed TDX event log if the attestation is backed by TDX.
    fn tdx_event_log(&self) -> Option<&[TdxEvent]>;

    /// Returns the TDX event log serialized as JSON.
    fn tdx_event_log_string(&self) -> Option<String> {
        self.tdx_event_log().map(|event_log| {
            let mut events: Vec<TdxEvent> = event_log.to_vec();
            cc_eventlog::tdx::fill_v2_preimages(&mut events);
            serde_json::to_string(&events).unwrap_or_default()
        })
    }

    /// Returns the parsed TD10 report from the embedded TDX quote.
    fn td10_report(&self) -> Option<TDReport10>;
}

impl TdxAttestationExt for AttestationV1 {
    fn tdx_quote_bytes(&self) -> Option<Vec<u8>> {
        self.platform.tdx_quote().map(|quote| quote.to_vec())
    }

    fn tdx_event_log(&self) -> Option<&[TdxEvent]> {
        self.platform.tdx_event_log()
    }

    fn td10_report(&self) -> Option<TDReport10> {
        self.platform
            .tdx_quote()
            .and_then(|quote| Quote::parse(quote).ok())
            .and_then(|quote| quote.report.as_td10().cloned())
    }
}

impl AttestationV1 {
    /// Convert a V1 dstack attestation back to the legacy SCALE schema.
    ///
    /// This is only lossless for the original dstack stack with V1 runtime
    /// events. Pod payloads and newer event encodings must remain on the V1
    /// msgpack wire format.
    pub fn try_into_legacy(self) -> Result<Attestation> {
        let Self {
            platform, stack, ..
        } = self;
        let StackEvidence::Dstack {
            report_data,
            runtime_events,
            config,
        } = stack
        else {
            bail!("dstack-pod attestation cannot be represented by the legacy schema");
        };
        if runtime_events
            .iter()
            .any(|event| !matches!(event.version, EventLogVersion::V1))
        {
            bail!("non-V1 runtime events cannot be represented by the legacy schema");
        }
        Ok(Attestation {
            quote: platform_into_legacy_quote(platform),
            runtime_events,
            report_data: report_data
                .try_into()
                .map_err(|_| anyhow!("stack.report_data must be 64 bytes"))?,
            config,
            report: (),
        })
    }

    /// Decode the VM config from the external or embedded config.
    pub fn decode_vm_config<'a>(&'a self, config: &'a str) -> Result<VmConfig> {
        decode_vm_config_with_fallback(config, self.stack.config())
    }

    /// Decode the app info from the platform-specific app info source.
    pub fn decode_app_info(&self, boottime_mr: bool) -> Result<AppInfo> {
        self.decode_app_info_ex(boottime_mr, "")
    }

    /// Decode the app info from the platform-specific app info source with an
    /// optional external vm_config.
    #[errify::errify("decode app info")]
    pub fn decode_app_info_ex(&self, boottime_mr: bool, vm_config: &str) -> Result<AppInfo> {
        let runtime_events = self.stack.runtime_events();

        let non_snp_context = || -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
            let key_provider_info = if boottime_mr {
                vec![]
            } else {
                find_event_payload(runtime_events, "key-provider").unwrap_or_default()
            };
            let mr_key_provider = if key_provider_info.is_empty() {
                [0u8; 32]
            } else {
                sha256(&key_provider_info)
            };
            let os_image_hash = self
                .decode_vm_config(vm_config)
                .context("Failed to decode os image hash")?
                .os_image_hash;
            Ok((key_provider_info, mr_key_provider, os_image_hash))
        };
        let build_app_info = |mrs: Mrs,
                              key_provider_info: Vec<u8>,
                              os_image_hash: Vec<u8>,
                              compose_hash: Vec<u8>| {
            AppInfo {
                app_id: find_event_payload(runtime_events, "app-id").unwrap_or_default(),
                instance_id: find_event_payload(runtime_events, "instance-id").unwrap_or_default(),
                device_id: sha256(Vec::<u8>::new()).to_vec(),
                mr_system: mrs.mr_system,
                mr_aggregated: mrs.mr_aggregated,
                key_provider_info,
                os_image_hash,
                compose_hash,
                init_script_hashes: Some(find_event_payloads(runtime_events, "init-script-hash")),
            }
        };

        match &self.platform {
            PlatformEvidence::SevSnp {
                report, mr_config, ..
            } => decode_app_info_sev_snp(report, Some(mr_config), self.stack.config(), vm_config),
            PlatformEvidence::Tdx { quote, .. } => {
                let (key_provider_info, mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs =
                    decode_mr_tdx_from_quote(boottime_mr, &mr_key_provider, quote, runtime_events)?;
                let compose_hash =
                    find_event_payload(runtime_events, "compose-hash").unwrap_or_default();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
            PlatformEvidence::GcpTdx { tpm_quote, .. } => {
                let (key_provider_info, mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs = decode_mr_gcp_tpm_from_v1(
                    boottime_mr,
                    &mr_key_provider,
                    &os_image_hash,
                    tpm_quote,
                    runtime_events,
                )?;
                let compose_hash =
                    find_event_payload(runtime_events, "compose-hash").unwrap_or_default();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
            PlatformEvidence::NitroEnclave { nsm_quote } => {
                let (key_provider_info, _mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs = decode_mr_nitro_nsm_from_v1(&DstackNitroQuote {
                    nsm_quote: nsm_quote.clone(),
                })?;
                let compose_hash = os_image_hash.clone();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
            PlatformEvidence::AwsNitroTpm { attestation_doc } => {
                let (key_provider_info, mr_key_provider, os_image_hash) = non_snp_context()?;
                let pcrs = DstackAwsNitroTpmQuote {
                    attestation_doc: attestation_doc.clone(),
                }
                .decode_pcrs()?;
                let mrs = decode_mr_aws_nitro_tpm_from_pcrs(
                    boottime_mr,
                    &mr_key_provider,
                    &pcrs,
                    runtime_events,
                )?;
                let compose_hash =
                    find_event_payload(runtime_events, "compose-hash").unwrap_or_default();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
        }
    }

    pub async fn verify(self, verifier: &AttestationVerifier) -> Result<VerifiedAttestation> {
        self.verify_with_time(verifier, None).await
    }

    pub async fn verify_with_time(
        self,
        verifier: &AttestationVerifier,
        now: Option<SystemTime>,
    ) -> Result<VerifiedAttestation> {
        let AttestationV1 {
            version: _,
            platform,
            stack,
        } = self;
        // Verify report_data_payload binding: if present, the report_data must
        // be derived from the payload via the AppData content type scheme.
        if let Some(payload) = stack.report_data_payload() {
            let report_data: [u8; 64] = stack.report_data()?;
            let expected = QuoteContentType::AppData.to_report_data(payload.as_bytes());
            if report_data != expected {
                bail!("report_data does not match report_data_payload");
            }
        }
        let (report_data, runtime_events, config) = match stack {
            StackEvidence::Dstack {
                report_data,
                runtime_events,
                config,
            }
            | StackEvidence::DstackPod {
                report_data,
                runtime_events,
                config,
                ..
            } => (
                report_data
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow!("stack.report_data must be 64 bytes"))?,
                runtime_events,
                config,
            ),
        };
        let report = match &platform {
            PlatformEvidence::Tdx { quote, .. } => DstackVerifiedReport::DstackTdx(
                verify_tdx_quote_with_events(verifier, quote, &runtime_events, &report_data)
                    .await?,
            ),
            PlatformEvidence::GcpTdx {
                quote, tpm_quote, ..
            } => {
                let tdx_report =
                    verify_tdx_quote_with_events(verifier, quote, &runtime_events, &report_data)
                        .await?;
                let tpm_report = verifier
                    .gcp_tpm
                    .fetch_and_verify(tpm_quote)
                    .await
                    .context("failed to verify TPM quote")?;
                let qualifying_data = sha256(quote);
                if tpm_report.attest.qualified_data != qualifying_data[..] {
                    bail!("tpm qualified_data mismatch");
                }
                let pcr_ind: u32 = 14; // GcpTdx runtime PCR
                let replayed_rt_pcr = cc_eventlog::replay_events::<Sha256>(&runtime_events, None);
                let quoted_rt_pcr = tpm_report
                    .get_pcr(pcr_ind)
                    .context("no runtime PCR in TPM report")?;
                if replayed_rt_pcr != quoted_rt_pcr[..] {
                    bail!(
                        "PCR{pcr_ind} mismatch, quoted: {}, replayed: {}",
                        hex::encode(quoted_rt_pcr),
                        hex::encode(replayed_rt_pcr),
                    );
                }
                DstackVerifiedReport::DstackGcpTdx {
                    tdx_report,
                    tpm_report,
                }
            }
            PlatformEvidence::NitroEnclave { nsm_quote } => {
                let nsm = DstackNitroQuote {
                    nsm_quote: nsm_quote.clone(),
                };
                let verified_report = verifier
                    .aws_nitro_enclave
                    .verify(&nsm.nsm_quote, None, now)
                    .context("NSM attestation verification failed")?;
                let Some(user_data) = verified_report.user_data.clone() else {
                    bail!("NSM attestation document does not contain user_data");
                };
                if user_data != report_data[..] {
                    bail!("NSM user_data does not match report_data");
                }
                // Use the PCRs from the signature-verified report, not a
                // re-parse of the raw document, so the values that feed
                // os_image_hash / MR derivation are authenticated.
                let pcrs = NitroPcrs::from_verified(&verified_report.pcrs)
                    .context("verified NSM report missing PCR0/1/2")?;
                DstackVerifiedReport::DstackNitroEnclave(NitroVerifiedReport {
                    module_id: verified_report.module_id,
                    pcrs,
                    user_data,
                    timestamp: verified_report.timestamp,
                })
            }
            PlatformEvidence::AwsNitroTpm { attestation_doc } => {
                let verified_report = verify_aws_nitro_tpm_attestation_doc(
                    verifier,
                    attestation_doc,
                    &runtime_events,
                    &report_data,
                    now,
                )
                .context("NitroTPM attestation verification failed")?;
                DstackVerifiedReport::DstackAwsNitroTpm(verified_report)
            }
            PlatformEvidence::SevSnp {
                report,
                cert_chain,
                mr_config,
            } => {
                let verified = verifier
                    .sev_snp
                    .fetch_and_verify(&verifier.amd_kds, report, cert_chain, &report_data)
                    .await?;
                verify_snp_mr_config_host_data(mr_config, &verified.host_data)?;
                DstackVerifiedReport::DstackAmdSevSnp(verified)
            }
        };

        match &platform {
            PlatformEvidence::Tdx { event_log, .. }
            | PlatformEvidence::GcpTdx { event_log, .. } => {
                cc_eventlog::tdx::validate_v2_preimages(event_log)
                    .context("Failed to validate TDX V2 event digest preimages")?;
            }
            _ => {}
        }

        Ok(VerifiedAttestation {
            quote: platform_into_legacy_quote(platform),
            runtime_events,
            report_data,
            config,
            report,
        })
    }

    /// Verify the quote against a RA-TLS public key.
    pub async fn verify_with_ra_pubkey(
        self,
        ra_pubkey_der: &[u8],
        verifier: &AttestationVerifier,
    ) -> Result<VerifiedAttestation> {
        let expected_report_data = QuoteContentType::RaTlsCert.to_report_data(ra_pubkey_der);
        if self.report_data()? != expected_report_data {
            bail!("report data mismatch");
        }
        self.verify(verifier).await
    }
}

#[derive(Clone, Encode, Decode)]
pub struct DstackGcpTdxQuote {
    pub tdx_quote: TdxQuote,
    pub tpm_quote: TpmQuote,
}

#[derive(Clone, Encode, Decode)]
pub struct DstackNitroQuote {
    pub nsm_quote: Vec<u8>,
}

#[derive(Clone, Encode, Decode)]
pub struct DstackAwsNitroTpmQuote {
    pub attestation_doc: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NitroPcrs {
    #[serde(with = "serde_human_bytes")]
    pub pcr0: Vec<u8>,
    #[serde(with = "serde_human_bytes")]
    pub pcr1: Vec<u8>,
    #[serde(with = "serde_human_bytes")]
    pub pcr2: Vec<u8>,
}

impl NitroPcrs {
    /// Build `NitroPcrs` from the PCR map of a signature-verified NSM report
    /// (`nsm_qvl::NsmVerifiedReport::pcrs`). This is the trusted source of PCR
    /// values: it has been authenticated by the COSE signature, unlike
    /// [`DstackNitroQuote::decode_pcrs`] which re-parses the raw document.
    pub fn from_verified(pcrs: &std::collections::BTreeMap<u16, Vec<u8>>) -> Result<NitroPcrs> {
        let pcr0 = pcrs.get(&0).cloned().context("PCR 0 not found")?;
        let pcr1 = pcrs.get(&1).cloned().context("PCR 1 not found")?;
        let pcr2 = pcrs.get(&2).cloned().context("PCR 2 not found")?;
        Ok(NitroPcrs { pcr0, pcr1, pcr2 })
    }

    fn is_zero(&self) -> bool {
        self.pcr0.iter().all(|&b| b == 0)
            && self.pcr1.iter().all(|&b| b == 0)
            && self.pcr2.iter().all(|&b| b == 0)
    }

    /// Whether the enclave ran in debug mode. AWS zeroes PCR0/1/2 for debug
    /// enclaves, so there is no measurement of the actual code; verifiers must
    /// refuse to authorize such enclaves.
    pub fn is_debug(&self) -> bool {
        self.is_zero()
    }

    /// The OS image hash = sha256(pcr0 || pcr1 || pcr2). Callers must reject
    /// debug enclaves (see [`is_debug`](Self::is_debug)) before trusting this.
    pub fn image_hash(&self) -> Vec<u8> {
        sha256([&self.pcr0, &self.pcr1, &self.pcr2]).to_vec()
    }
}

impl DstackNitroQuote {
    pub fn decode_cose(&self) -> Result<nsm_attest::AttestationDocument> {
        nsm_attest::AttestationDocument::from_cose(&self.nsm_quote)
            .context("Failed to decode NSM attestation document")
    }

    pub fn decode_image_hash(&self) -> Result<Vec<u8>> {
        let pcrs = self.decode_pcrs()?;
        let hash = if pcrs.is_zero() {
            [0u8; 32]
        } else {
            sha256([&pcrs.pcr0, &pcrs.pcr1, &pcrs.pcr2])
        };
        Ok(hash.to_vec())
    }

    pub fn decode_pcrs(&self) -> Result<NitroPcrs> {
        let doc = self.decode_cose()?;
        let pcr0 = doc.pcrs.get(&0).cloned().context("PCR 0 not found")?;
        let pcr1 = doc.pcrs.get(&1).cloned().context("PCR 1 not found")?;
        let pcr2 = doc.pcrs.get(&2).cloned().context("PCR 2 not found")?;
        Ok(NitroPcrs { pcr0, pcr1, pcr2 })
    }
}

const AWS_NITRO_TPM_BOOT_PCRS: &[u16] = &[4, 7, 12];
/// All dstack measured events (TDX RTMR3 analogue). Non-resettable on NitroTPM.
const AWS_NITRO_TPM_EVENT_PCR: u16 = 14;
/// Optional config commitment PCR, extended once from the guest-computed MrConfig V2 id.
pub(crate) const AWS_NITRO_TPM_CONFIG_PCR: u16 = 8;

fn aws_nitro_tpm_pcr(pcrs: &std::collections::BTreeMap<u16, Vec<u8>>, index: u16) -> Result<&[u8]> {
    pcrs.get(&index)
        .map(Vec::as_slice)
        .with_context(|| format!("PCR {index} not found"))
}

fn aws_nitro_tpm_replayed_event_pcr(
    runtime_events: &[RuntimeEvent],
    boottime_mr: bool,
) -> <Sha384 as Hasher>::Output {
    replay_runtime_events::<Sha384>(runtime_events, boottime_mr.then_some("boot-mr-done"))
}

/// Bind the event log to the quoted PCR14 register.
///
/// Always replays the **full** event log and requires it to equal the quoted
/// PCR14, exactly like the TDX RTMR3 (`verify_tdx_quote_with_events`) and GCP
/// PCR14 verify paths. The boot-time snapshot boundary is a property of the MR
/// derivation, not of this integrity check, so it is intentionally not applied
/// here — otherwise a full runtime quote could never satisfy a boot-time
/// (`boottime_mr`) decode.
fn aws_nitro_tpm_verify_event_pcr(
    pcrs: &std::collections::BTreeMap<u16, Vec<u8>>,
    runtime_events: &[RuntimeEvent],
) -> Result<()> {
    let quoted = aws_nitro_tpm_pcr(pcrs, AWS_NITRO_TPM_EVENT_PCR)?;
    let replayed = aws_nitro_tpm_replayed_event_pcr(runtime_events, false);
    if quoted != replayed.as_slice() {
        bail!(
            "PCR{AWS_NITRO_TPM_EVENT_PCR} mismatch, quoted: {}, replayed: {}",
            hex::encode(quoted),
            hex::encode(replayed),
        );
    }
    Ok(())
}

fn aws_nitro_tpm_boot_pcr_values(
    pcrs: &std::collections::BTreeMap<u16, Vec<u8>>,
) -> Result<Vec<&[u8]>> {
    AWS_NITRO_TPM_BOOT_PCRS
        .iter()
        .map(|index| aws_nitro_tpm_pcr(pcrs, *index))
        .collect()
}

/// Compute the AWS NitroTPM `boot_pcr_digest` as `sha256(PCR4 || PCR7 || PCR12)`.
///
/// This is the single source of truth for the boot-PCR binding; the verifier
/// and KMS must derive the value the same way, so both call this rather than
/// re-hardcoding the PCR set. The value is checked against
/// `aws_measurement.boot_pcr_digest` (`aws_measurement` is mandatory on AWS).
pub fn aws_nitro_tpm_boot_pcr_digest(
    pcrs: &std::collections::BTreeMap<u16, Vec<u8>>,
) -> Result<Vec<u8>> {
    Ok(sha256(aws_nitro_tpm_boot_pcr_values(pcrs)?).to_vec())
}

impl DstackAwsNitroTpmQuote {
    pub(crate) fn decode_pcrs(&self) -> Result<std::collections::BTreeMap<u16, Vec<u8>>> {
        let cose = nsm_qvl::CoseSign1::from_bytes(&self.attestation_doc)
            .context("failed to decode NitroTPM COSE document")?;
        let doc = nsm_qvl::AttestationDocument::from_cbor(&cose.payload)
            .context("failed to decode NitroTPM attestation document")?;
        Ok(doc.pcrs)
    }
}

#[derive(Clone, Encode, Decode)]
pub enum AttestationQuote {
    DstackTdx(TdxQuote),
    DstackGcpTdx(DstackGcpTdxQuote),
    DstackNitroEnclave(DstackNitroQuote),
    DstackAmdSevSnp(SnpQuote),
    /// Keep this last to preserve SCALE discriminants for existing variants.
    DstackAwsNitroTpm(DstackAwsNitroTpmQuote),
}

impl AttestationQuote {
    pub fn variant(&self) -> TeeVariant {
        match self {
            AttestationQuote::DstackTdx(_) => TeeVariant::DstackTdx,
            AttestationQuote::DstackAmdSevSnp(_) => TeeVariant::DstackAmdSevSnp,
            AttestationQuote::DstackGcpTdx(_) => TeeVariant::DstackGcpTdx,
            AttestationQuote::DstackNitroEnclave(_) => TeeVariant::DstackNitroEnclave,
            AttestationQuote::DstackAwsNitroTpm(_) => TeeVariant::DstackAwsNitroTpm,
        }
    }
}

#[cfg(test)]
mod compatibility_tests {
    use super::*;
    use scale::Encode;

    #[test]
    fn tee_variant_scale_discriminants_preserve_existing_wire_values() {
        assert_eq!(TeeVariant::DstackTdx.encode(), vec![0]);
        assert_eq!(TeeVariant::DstackGcpTdx.encode(), vec![1]);
        assert_eq!(TeeVariant::DstackNitroEnclave.encode(), vec![2]);
        assert_eq!(TeeVariant::DstackAmdSevSnp.encode(), vec![3]);
        assert_eq!(TeeVariant::DstackAwsNitroTpm.encode(), vec![4]);
    }

    #[test]
    fn tee_variant_deserializes_canonical_names() {
        let parse = |value| serde_json::from_str::<TeeVariant>(value).unwrap();
        assert_eq!(parse(r#""dstack-tdx""#), TeeVariant::DstackTdx);
        assert_eq!(parse(r#""dstack-gcp-tdx""#), TeeVariant::DstackGcpTdx);
        assert_eq!(
            parse(r#""dstack-amd-sev-snp""#),
            TeeVariant::DstackAmdSevSnp
        );
        assert_eq!(
            parse(r#""dstack-nitro-enclave""#),
            TeeVariant::DstackNitroEnclave
        );
    }

    #[test]
    fn attestation_quote_scale_discriminants_preserve_existing_wire_values() {
        let gcp = AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
            tdx_quote: TdxQuote {
                quote: Vec::new(),
                event_log: Vec::new(),
            },
            tpm_quote: TpmQuote {
                message: Vec::new(),
                signature: Vec::new(),
                pcr_values: Vec::new(),
                ak_cert: Vec::new(),
                platform: dstack_types::Platform::Gcp,
                event_log: Vec::new(),
            },
        });
        assert_eq!(gcp.encode()[0], 1);
        let nitro = AttestationQuote::DstackNitroEnclave(DstackNitroQuote {
            nsm_quote: Vec::new(),
        });
        assert_eq!(nitro.encode()[0], 2);
        let quote = AttestationQuote::DstackAmdSevSnp(SnpQuote {
            report: Vec::new(),
            cert_chain: Vec::new(),
            mr_config: String::new(),
        });
        assert_eq!(quote.encode()[0], 3);
        let quote = AttestationQuote::DstackAwsNitroTpm(DstackAwsNitroTpmQuote {
            attestation_doc: Vec::new(),
        });
        assert_eq!(quote.encode()[0], 4);
    }

    #[test]
    fn dstack_tee_variant_prefers_tdx_when_both_tdx_and_tsm_exist() {
        assert_eq!(
            choose_dstack_tee_variant(true, true).unwrap(),
            TeeVariant::DstackTdx
        );
    }

    #[test]
    fn dstack_tee_variant_uses_snp_when_only_snp_exists() {
        assert_eq!(
            choose_dstack_tee_variant(false, true).unwrap(),
            TeeVariant::DstackAmdSevSnp
        );
    }
}

/// Attestation data
#[derive(Clone, Encode, Decode)]
pub struct Attestation<R = ()> {
    /// The quote
    pub quote: AttestationQuote,

    /// Runtime events carried by runtime-event-sourced platforms.
    pub runtime_events: Vec<RuntimeEvent>,

    /// The report data
    pub report_data: [u8; 64],

    /// The configuration of the VM
    pub config: String,

    /// Verified report
    pub report: R,
}

impl<T> Attestation<T> {
    pub fn report_data_payload(&self) -> Option<&str> {
        None
    }

    pub fn tdx_quote_mut(&mut self) -> Option<&mut TdxQuote> {
        match &mut self.quote {
            AttestationQuote::DstackTdx(quote) => Some(quote),
            AttestationQuote::DstackAmdSevSnp(_) => None,
            AttestationQuote::DstackGcpTdx(q) => Some(&mut q.tdx_quote),
            AttestationQuote::DstackNitroEnclave(_) | AttestationQuote::DstackAwsNitroTpm(_) => {
                None
            }
        }
    }

    pub fn tdx_quote(&self) -> Option<&TdxQuote> {
        match &self.quote {
            AttestationQuote::DstackTdx(quote) => Some(quote),
            AttestationQuote::DstackAmdSevSnp(_) => None,
            AttestationQuote::DstackGcpTdx(q) => Some(&q.tdx_quote),
            AttestationQuote::DstackNitroEnclave(_) | AttestationQuote::DstackAwsNitroTpm(_) => {
                None
            }
        }
    }

    pub fn tpm_quote(&self) -> Option<&TpmQuote> {
        match &self.quote {
            AttestationQuote::DstackTdx(_) => None,
            AttestationQuote::DstackAmdSevSnp(_) => None,
            AttestationQuote::DstackGcpTdx(q) => Some(&q.tpm_quote),
            AttestationQuote::DstackNitroEnclave(_) | AttestationQuote::DstackAwsNitroTpm(_) => {
                None
            }
        }
    }

    /// Get TDX quote bytes
    pub fn get_tdx_quote_bytes(&self) -> Option<Vec<u8>> {
        self.tdx_quote().map(|q| q.quote.clone())
    }

    /// Populate `preimage` on every V2 runtime event in the TDX event log.
    ///
    /// Useful before serializing an attestation so relying parties get the
    /// digest pre-images alongside events.
    pub fn fill_event_preimages(&mut self) {
        if let Some(q) = self.tdx_quote_mut() {
            cc_eventlog::tdx::fill_v2_preimages(&mut q.event_log);
        }
    }

    /// Get TDX event log bytes
    pub fn get_tdx_event_log_bytes(&self) -> Option<Vec<u8>> {
        self.tdx_quote()
            .map(|q| serde_json::to_vec(&q.event_log).unwrap_or_default())
    }

    /// Get TDX event log string with RTMR[0-2] payloads stripped to reduce size.
    /// Only digests are kept for boot-time events; runtime events (RTMR3) retain full payload.
    ///
    pub fn get_tdx_event_log_string(&self) -> Option<String> {
        self.tdx_quote().map(|q| {
            let mut stripped: Vec<_> = q
                .event_log
                .iter()
                .map(|event| {
                    let mut stripped = event.stripped();
                    // Keep the marker used by TDX-lite verification to identify
                    // the three RTMR0 ACPI digest events.
                    if cc_eventlog::tdx::is_tdx_acpi_data_event(event) {
                        stripped.event_payload = event.event_payload.clone();
                    }
                    stripped
                })
                .collect();
            cc_eventlog::tdx::fill_v2_preimages(&mut stripped);
            serde_json::to_string(&stripped).unwrap_or_default()
        })
    }

    pub fn get_td10_report(&self) -> Option<TDReport10> {
        self.tdx_quote()
            .and_then(|q| Quote::parse(&q.quote).ok())
            .and_then(|quote| quote.report.as_td10().cloned())
    }
}

pub trait GetDeviceId {
    fn get_devide_id(&self) -> Vec<u8>;

    /// The signature-verified Nitro PCRs, when this report is a verified Nitro
    /// report. Returns `None` for raw/unverified reports (e.g. `()`), in which
    /// case callers fall back to parsing the raw document.
    fn verified_nitro_pcrs(&self) -> Option<&NitroPcrs> {
        None
    }

    fn verified_aws_nitro_tpm_pcrs(&self) -> Option<&std::collections::BTreeMap<u16, Vec<u8>>> {
        None
    }
}

impl GetDeviceId for () {
    fn get_devide_id(&self) -> Vec<u8> {
        Vec::new()
    }
}

impl GetDeviceId for DstackVerifiedReport {
    fn get_devide_id(&self) -> Vec<u8> {
        match self {
            DstackVerifiedReport::DstackTdx(tdx_report) => tdx_report.ppid.to_vec(),
            DstackVerifiedReport::DstackAmdSevSnp(report) => report.chip_id.to_vec(),
            DstackVerifiedReport::DstackGcpTdx { tdx_report, .. } => tdx_report.ppid.to_vec(),
            DstackVerifiedReport::DstackNitroEnclave(report) => {
                // i-1234567890abcdef0-enc9876543210abcde -> i-1234567890abcdef0
                report
                    .module_id
                    .split_once('-')
                    .map(|(id, _)| id.as_bytes().to_vec())
                    .unwrap_or_default()
            }
            DstackVerifiedReport::DstackAwsNitroTpm(report) => report.module_id.as_bytes().to_vec(),
        }
    }

    fn verified_nitro_pcrs(&self) -> Option<&NitroPcrs> {
        match self {
            DstackVerifiedReport::DstackNitroEnclave(report) => Some(&report.pcrs),
            _ => None,
        }
    }

    fn verified_aws_nitro_tpm_pcrs(&self) -> Option<&std::collections::BTreeMap<u16, Vec<u8>>> {
        match self {
            DstackVerifiedReport::DstackAwsNitroTpm(report) => Some(&report.pcrs),
            _ => None,
        }
    }
}

struct Mrs {
    mr_system: [u8; 32],
    mr_aggregated: [u8; 32],
}

fn key_provider_info_from_mr_config(mr_config: &MrConfigV3) -> Result<Vec<u8>> {
    serde_json::to_vec(&KeyProviderInfo::new(
        mr_config.key_provider_name().to_string(),
        hex::encode(mr_config.key_provider_id.as_deref().unwrap_or_default()),
    ))
    .context("Failed to serialize key provider info")
}

fn verify_snp_mr_config_host_data(
    mr_config_document: &str,
    host_data: &[u8; 32],
) -> Result<MrConfigV3> {
    let mr_config = MrConfigV3::from_document(mr_config_document)
        .context("Invalid amd sev-snp mr_config document")?;
    let expected = MrConfigV3::snp_host_data_from_document(mr_config_document);
    if expected != *host_data {
        bail!(
            "amd sev-snp HOST_DATA mismatch, quoted: {}, expected: {}",
            hex::encode(host_data),
            hex::encode(expected),
        );
    }
    Ok(mr_config)
}

fn decode_mr_sev_snp(measurement: &[u8; 48], host_data: &[u8; 32]) -> Mrs {
    let mr_system = sha2::Sha256::digest(measurement).into();
    let mr_aggregated = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(measurement);
        hasher.update(host_data);
        hasher.finalize().into()
    };
    Mrs {
        mr_system,
        mr_aggregated,
    }
}

fn decode_app_info_sev_snp(
    report: &[u8],
    mr_config: Option<&str>,
    embedded_config: &str,
    external_vm_config: &str,
) -> Result<AppInfo> {
    let parsed = crate::amd_sev_snp::parse_amd_snp_report(report)?;
    let mr_config_document = if let Some(mr_config) = mr_config {
        Cow::Borrowed(mr_config)
    } else if let Some(mr_config) = mr_config_document_from_config(external_vm_config)? {
        Cow::Owned(mr_config)
    } else if let Some(mr_config) = mr_config_document_from_config(embedded_config)? {
        Cow::Owned(mr_config)
    } else {
        bail!("amd sev-snp mr_config is missing");
    };
    let mr_config = verify_snp_mr_config_host_data(mr_config_document.as_ref(), &parsed.host_data)?;

    let key_provider_info = key_provider_info_from_mr_config(&mr_config)?;
    let os_image_hash =
        decode_vm_config_with_fallback(external_vm_config, embedded_config)?.os_image_hash;
    let mrs = decode_mr_sev_snp(&parsed.measurement, &parsed.host_data);

    Ok(AppInfo {
        app_id: mr_config.app_id.unwrap_or_default(),
        instance_id: mr_config.instance_id.unwrap_or_default(),
        device_id: sha256(parsed.chip_id).to_vec(),
        mr_system: mrs.mr_system,
        mr_aggregated: mrs.mr_aggregated,
        key_provider_info,
        os_image_hash,
        compose_hash: mr_config.compose_hash,
        init_script_hashes: mr_config.init_script_hashes,
    })
}

fn decode_mr_gcp_tpm_from_v1(
    boottime_mr: bool,
    mr_key_provider: &[u8],
    os_image_hash: &[u8],
    tpm_quote: &TpmQuote,
    runtime_events: &[RuntimeEvent],
) -> Result<Mrs> {
    let mr_system = sha256([os_image_hash, mr_key_provider]);
    let pcr0 = tpm_quote
        .pcr_values
        .iter()
        .find(|p| p.index == 0)
        .context("PCR 0 not found")?;
    let pcr2 = tpm_quote
        .pcr_values
        .iter()
        .find(|p| p.index == 2)
        .context("PCR 2 not found")?;
    let runtime_pcr =
        cc_eventlog::replay_events::<Sha256>(runtime_events, boottime_mr.then_some("boot-mr-done"));
    let mr_aggregated = sha256([&pcr0.value[..], &pcr2.value, &runtime_pcr]);
    Ok(Mrs {
        mr_system,
        mr_aggregated,
    })
}

fn decode_mr_aws_nitro_tpm_from_pcrs(
    boottime_mr: bool,
    mr_key_provider: &[u8],
    pcrs: &std::collections::BTreeMap<u16, Vec<u8>>,
    runtime_events: &[RuntimeEvent],
) -> Result<Mrs> {
    let mut boot_pcrs = aws_nitro_tpm_boot_pcr_values(pcrs)?;
    let mut mr_system_inputs = boot_pcrs.clone();
    mr_system_inputs.push(mr_key_provider);
    let mr_system = sha256(mr_system_inputs);
    // Bind the full event log to the quoted PCR14 first (defense-in-depth,
    // mirrors the TDX/GCP verify paths), then take the boot-snapshot value for
    // the MR. Splitting these two lets a full runtime quote still produce a
    // boot-time (`boottime_mr`) MR instead of failing the integrity check.
    aws_nitro_tpm_verify_event_pcr(pcrs, runtime_events)?;
    let launch_pcr = aws_nitro_tpm_replayed_event_pcr(runtime_events, boottime_mr);
    boot_pcrs.push(launch_pcr.as_slice());
    let mr_aggregated = sha256(boot_pcrs);
    Ok(Mrs {
        mr_system,
        mr_aggregated,
    })
}

fn decode_mr_nitro_nsm_from_v1(nsm_quote: &DstackNitroQuote) -> Result<Mrs> {
    let pcrs = nsm_quote.decode_pcrs()?;
    let mr_system = sha256([&pcrs.pcr0, &pcrs.pcr1, &pcrs.pcr2]);
    let mr_aggregated = mr_system;
    Ok(Mrs {
        mr_system,
        mr_aggregated,
    })
}

fn decode_mr_tdx_from_quote(
    boottime_mr: bool,
    mr_key_provider: &[u8],
    quote: &[u8],
    runtime_events: &[RuntimeEvent],
) -> Result<Mrs> {
    let quote = Quote::parse(quote).context("Failed to parse quote")?;
    let rtmr3 =
        replay_runtime_events::<Sha384>(runtime_events, boottime_mr.then_some("boot-mr-done"));
    let td_report = quote.report.as_td10().context("TDX report not found")?;
    let mr_system = sha256([
        &td_report.mr_td[..],
        &td_report.rt_mr0,
        &td_report.rt_mr1,
        &td_report.rt_mr2,
        mr_key_provider,
    ]);
    let mr_aggregated = {
        let mut hasher = sha2::Sha256::new();
        for d in [
            &td_report.mr_td,
            &td_report.rt_mr0,
            &td_report.rt_mr1,
            &td_report.rt_mr2,
            &rtmr3,
        ] {
            hasher.update(d);
        }
        if td_report.mr_config_id != [0u8; 48]
            || td_report.mr_owner != [0u8; 48]
            || td_report.mr_owner_config != [0u8; 48]
        {
            hasher.update(td_report.mr_config_id);
            hasher.update(td_report.mr_owner);
            hasher.update(td_report.mr_owner_config);
        }
        hasher.finalize().into()
    };
    Ok(Mrs {
        mr_system,
        mr_aggregated,
    })
}

async fn verify_tdx_quote_with_events(
    verifier: &AttestationVerifier,
    quote: &[u8],
    runtime_events: &[RuntimeEvent],
    report_data: &[u8; 64],
) -> Result<TdxVerifiedReport> {
    let tdx_report = verifier
        .verify_tdx_quote(quote)
        .await
        .context("failed to verify TDX quote")?;
    validate_tcb(&tdx_report)?;

    let td_report = tdx_report.report.as_td10().context("no td report")?;
    let replayed_rtmr = replay_runtime_events::<Sha384>(runtime_events, None);
    if replayed_rtmr != td_report.rt_mr3 {
        bail!(
            "RTMR3 mismatch, quoted: {}, replayed: {}",
            hex::encode(td_report.rt_mr3),
            hex::encode(replayed_rtmr)
        );
    }

    if td_report.report_data != report_data[..] {
        bail!("tdx report_data mismatch");
    }
    Ok(tdx_report)
}

fn verify_aws_nitro_tpm_attestation_doc(
    verifier: &AttestationVerifier,
    attestation_doc: &[u8],
    runtime_events: &[RuntimeEvent],
    report_data: &[u8; 64],
    now: Option<SystemTime>,
) -> Result<AwsNitroTpmVerifiedReport> {
    let verified_report = verifier
        .aws_nitro_tpm
        .verify(attestation_doc, None, now)
        .context("COSE attestation document verification failed")?;

    let Some(user_data) = verified_report.user_data.clone() else {
        bail!("NitroTPM attestation document does not contain user_data");
    };
    if user_data != report_data[..] {
        bail!("NitroTPM user_data does not match report_data");
    }

    aws_nitro_tpm_verify_event_pcr(&verified_report.pcrs, runtime_events)?;

    Ok(AwsNitroTpmVerifiedReport {
        module_id: verified_report.module_id,
        pcrs: verified_report.pcrs,
        public_key: verified_report.public_key,
        user_data,
        nonce: verified_report.nonce,
        timestamp: verified_report.timestamp,
    })
}

impl<T: GetDeviceId> Attestation<T> {
    fn decode_mr_gcp_tpm(
        &self,
        boottime_mr: bool,
        mr_key_provider: &[u8],
        os_image_hash: &[u8],
        tpm_quote: &TpmQuote,
    ) -> Result<Mrs> {
        let mr_system = sha256([os_image_hash, mr_key_provider]);
        let pcr0 = tpm_quote
            .pcr_values
            .iter()
            .find(|p| p.index == 0)
            .context("PCR 0 not found")?;
        let pcr2 = tpm_quote
            .pcr_values
            .iter()
            .find(|p| p.index == 2)
            .context("PCR 2 not found")?;
        let runtime_pcr =
            self.replay_runtime_events::<Sha256>(boottime_mr.then_some("boot-mr-done"));
        let mr_aggregated = sha256([&pcr0.value[..], &pcr2.value, &runtime_pcr]);
        Ok(Mrs {
            mr_system,
            mr_aggregated,
        })
    }

    fn decode_mr_nitro_nsm(&self, nsm_quote: &DstackNitroQuote) -> Result<Mrs> {
        // Prefer the signature-verified PCRs from the report; only fall back to
        // re-parsing the raw document for unverified reports (e.g. previews),
        // which never feed an authorization decision.
        let pcrs = match self.report.verified_nitro_pcrs() {
            Some(pcrs) => pcrs.clone(),
            None => nsm_quote.decode_pcrs()?,
        };

        // Compute mr_system from PCR values and mr_key_provider
        let mr_system = sha256([&pcrs.pcr0, &pcrs.pcr1, &pcrs.pcr2]);
        let mr_aggregated = mr_system;

        Ok(Mrs {
            mr_system,
            mr_aggregated,
        })
    }

    fn decode_mr_aws_nitro_tpm(
        &self,
        boottime_mr: bool,
        mr_key_provider: &[u8],
        quote: &DstackAwsNitroTpmQuote,
    ) -> Result<Mrs> {
        let pcrs = match self.report.verified_aws_nitro_tpm_pcrs() {
            Some(pcrs) => pcrs.clone(),
            None => quote.decode_pcrs()?,
        };
        decode_mr_aws_nitro_tpm_from_pcrs(boottime_mr, mr_key_provider, &pcrs, &self.runtime_events)
    }

    fn decode_mr_tdx(
        &self,
        boottime_mr: bool,
        mr_key_provider: &[u8],
        tdx_quote: &TdxQuote,
    ) -> Result<Mrs> {
        let quote = Quote::parse(&tdx_quote.quote).context("Failed to parse quote")?;
        let rtmr3 = self.replay_runtime_events::<Sha384>(boottime_mr.then_some("boot-mr-done"));
        let td_report = quote.report.as_td10().context("TDX report not found")?;
        let mr_system = sha256([
            &td_report.mr_td[..],
            &td_report.rt_mr0,
            &td_report.rt_mr1,
            &td_report.rt_mr2,
            mr_key_provider,
        ]);
        let mr_aggregated = {
            let mut hasher = sha2::Sha256::new();
            for d in [
                &td_report.mr_td,
                &td_report.rt_mr0,
                &td_report.rt_mr1,
                &td_report.rt_mr2,
                &rtmr3,
            ] {
                hasher.update(d);
            }
            // For backward compatibility. Don't include mr_config_id, mr_owner, mr_owner_config if they are all 0.
            if td_report.mr_config_id != [0u8; 48]
                || td_report.mr_owner != [0u8; 48]
                || td_report.mr_owner_config != [0u8; 48]
            {
                hasher.update(td_report.mr_config_id);
                hasher.update(td_report.mr_owner);
                hasher.update(td_report.mr_owner_config);
            }
            hasher.finalize().into()
        };
        Ok(Mrs {
            mr_system,
            mr_aggregated,
        })
    }

    /// Decode the VM config from the external or embedded config
    pub fn decode_vm_config<'a>(&'a self, mut config: &'a str) -> Result<VmConfig> {
        if config.is_empty() {
            config = &self.config;
        }
        if config.is_empty() {
            // No vm config for nitro enclave
            config = "{}";
        }
        let vm_config: VmConfig =
            serde_json::from_str(config).context("Failed to parse vm config")?;
        Ok(vm_config)
    }

    /// Decode the app info from the platform-specific app info source.
    pub fn decode_app_info(&self, boottime_mr: bool) -> Result<AppInfo> {
        self.decode_app_info_ex(boottime_mr, "")
    }

    #[errify::errify("decode app info")]
    pub fn decode_app_info_ex(&self, boottime_mr: bool, vm_config: &str) -> Result<AppInfo> {
        let non_snp_context = || -> Result<(Vec<u8>, [u8; 32], Vec<u8>)> {
            let key_provider_info = if boottime_mr {
                vec![]
            } else {
                self.find_event_payload("key-provider").unwrap_or_default()
            };
            let mr_key_provider = if key_provider_info.is_empty() {
                [0u8; 32]
            } else {
                sha256(&key_provider_info)
            };
            let os_image_hash = self
                .decode_vm_config(vm_config)
                .context("Failed to decode os image hash")?
                .os_image_hash;
            Ok((key_provider_info, mr_key_provider, os_image_hash))
        };
        let build_app_info = |mrs: Mrs,
                              key_provider_info: Vec<u8>,
                              os_image_hash: Vec<u8>,
                              compose_hash: Vec<u8>| {
            AppInfo {
                app_id: self.find_event_payload("app-id").unwrap_or_default(),
                instance_id: self.find_event_payload("instance-id").unwrap_or_default(),
                device_id: sha256(self.report.get_devide_id()).to_vec(),
                mr_system: mrs.mr_system,
                mr_aggregated: mrs.mr_aggregated,
                key_provider_info,
                os_image_hash,
                compose_hash,
                init_script_hashes: Some(find_event_payloads(
                    &self.runtime_events,
                    "init-script-hash",
                )),
            }
        };

        match &self.quote {
            AttestationQuote::DstackAmdSevSnp(q) => {
                decode_app_info_sev_snp(&q.report, Some(&q.mr_config), &self.config, vm_config)
            }
            AttestationQuote::DstackTdx(q) => {
                let (key_provider_info, mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs = self.decode_mr_tdx(boottime_mr, &mr_key_provider, q)?;
                let compose_hash = self.find_event_payload("compose-hash").unwrap_or_default();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
            AttestationQuote::DstackGcpTdx(q) => {
                let (key_provider_info, mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs = self.decode_mr_gcp_tpm(
                    boottime_mr,
                    &mr_key_provider,
                    &os_image_hash,
                    &q.tpm_quote,
                )?;
                let compose_hash = self.find_event_payload("compose-hash").unwrap_or_default();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
            AttestationQuote::DstackNitroEnclave(q) => {
                let (key_provider_info, _mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs = self.decode_mr_nitro_nsm(q)?;
                let compose_hash = os_image_hash.clone();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
            AttestationQuote::DstackAwsNitroTpm(q) => {
                let (key_provider_info, mr_key_provider, os_image_hash) = non_snp_context()?;
                let mrs = self.decode_mr_aws_nitro_tpm(boottime_mr, &mr_key_provider, q)?;
                let compose_hash = self.find_event_payload("compose-hash").unwrap_or_default();
                Ok(build_app_info(
                    mrs,
                    key_provider_info,
                    os_image_hash,
                    compose_hash,
                ))
            }
        }
    }
}

impl<T> Attestation<T> {
    /// Decode the quote
    pub fn decode_tdx_quote(&self) -> Result<Quote> {
        let Some(tdx_quote) = self.tdx_quote() else {
            bail!("tdx_quote not found");
        };
        Quote::parse(&tdx_quote.quote)
    }

    fn find_event(&self, name: &str) -> Result<RuntimeEvent> {
        for event in &self.runtime_events {
            if event.event == "system-ready" {
                break;
            }
            if event.event == name {
                return Ok(event.clone());
            }
        }
        Err(anyhow!("event {name} not found"))
    }

    /// Replay event logs
    pub fn replay_runtime_events<H: Hasher>(&self, to_event: Option<&str>) -> H::Output {
        cc_eventlog::replay_events::<H>(&self.runtime_events, to_event)
    }

    fn find_event_payload(&self, event: &str) -> Result<Vec<u8>> {
        self.find_event(event).map(|event| event.payload)
    }

    /// SHA-256 payloads of all measured init scripts, in execution order.
    /// Application-emitted events after `system-ready` are excluded.
    pub fn decode_init_script_hashes(&self) -> Vec<Vec<u8>> {
        find_event_payloads(&self.runtime_events, "init-script-hash")
    }

    fn find_event_hex_payload(&self, event: &str) -> Result<String> {
        self.find_event(event)
            .map(|event| hex::encode(&event.payload))
    }

    /// Decode the app-id from the event log
    pub fn decode_app_id(&self) -> Result<String> {
        self.find_event_hex_payload("app-id")
    }

    /// Decode the instance-id from the event log
    pub fn decode_instance_id(&self) -> Result<String> {
        self.find_event_hex_payload("instance-id")
    }

    /// Decode the upgraded app-id from the event log
    pub fn decode_compose_hash(&self) -> Result<String> {
        self.find_event_hex_payload("compose-hash")
    }

    /// Decode the rootfs hash from the event log
    pub fn decode_rootfs_hash(&self) -> Result<String> {
        self.find_event_hex_payload("rootfs-hash")
    }
}

impl Attestation {
    /// Reconstruct from tdx quote and event log, for backward compatibility
    pub fn from_tdx_quote(quote: Vec<u8>, event_log: &[u8]) -> Result<Self> {
        let tdx_eventlog: Vec<TdxEvent> =
            serde_json::from_slice(event_log).context("Failed to parse tdx_event_log")?;
        let runtime_events = tdx_eventlog
            .iter()
            .flat_map(|event| event.to_runtime_event())
            .collect();
        let report_data = {
            let quote = Quote::parse(&quote).context("Invalid TDX quote")?;
            let report = quote.report.as_td10().context("Invalid TDX report")?;
            report.report_data
        };
        Ok(Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote,
                event_log: tdx_eventlog,
            }),
            runtime_events,
            report_data,
            config: "".into(),
            report: (),
        })
    }
}

#[cfg(feature = "quote")]
impl Attestation {
    /// Create an attestation for local machine (auto-detect mode)
    pub fn local() -> Result<Self> {
        Self::quote(&[0u8; 64])
    }

    /// Create an attestation from a report data
    pub fn quote(report_data: &[u8; 64]) -> Result<Self> {
        Self::quote_with_app_id(report_data, None)
    }

    pub fn quote_with_app_id(report_data: &[u8; 64], app_id: Option<[u8; 20]>) -> Result<Self> {
        Self::quote_with_app_id_and_sys_config(report_data, app_id, None)
    }

    /// Create an attestation using an explicit sys-config path.
    pub fn quote_with_sys_config(
        report_data: &[u8; 64],
        sys_config: &std::path::Path,
    ) -> Result<Self> {
        Self::quote_with_app_id_and_sys_config(report_data, None, Some(sys_config))
    }

    fn quote_with_app_id_and_sys_config(
        report_data: &[u8; 64],
        app_id: Option<[u8; 20]>,
        sys_config: Option<&std::path::Path>,
    ) -> Result<Self> {
        // Lock to prevent concurrent quote generation (TDX driver doesn't support it)
        let _guard = QUOTE_LOCK
            .lock()
            .map_err(|_| anyhow!("Quote lock poisoned"))?;

        let mode = detect_tee_variant()?;
        let config = match mode {
            TeeVariant::DstackAmdSevSnp
            | TeeVariant::DstackTdx
            | TeeVariant::DstackGcpTdx
            // AWS prefers host-shared vm_config because it carries the
            // aws_measurement and unified os_image_hash validated below.
            | TeeVariant::DstackAwsNitroTpm => {
                read_vm_config(sys_config).context("Failed to read vm config")?
            }
            // NitroEnclave derives config from the signed image hash below.
            TeeVariant::DstackNitroEnclave => String::new(),
        };
        let runtime_events = match mode {
            TeeVariant::DstackTdx | TeeVariant::DstackGcpTdx | TeeVariant::DstackAwsNitroTpm => {
                RuntimeEvent::read_all().context("Failed to read runtime events")?
            }
            TeeVariant::DstackAmdSevSnp => vec![],
            TeeVariant::DstackNitroEnclave => match app_id {
                Some(app_id) => vec![RuntimeEvent::new(
                    "app-id".to_string(),
                    app_id.to_vec(),
                    EventLogVersion::V1,
                )],
                None => vec![],
            },
        };

        let mut quote = match mode {
            TeeVariant::DstackTdx => {
                let quote = tdx_attest::get_quote(report_data).context("Failed to get quote")?;
                let event_log =
                    cc_eventlog::tdx::read_event_log().context("Failed to read event log")?;
                AttestationQuote::DstackTdx(TdxQuote { quote, event_log })
            }
            TeeVariant::DstackAmdSevSnp => {
                let quote = crate::sev_snp::get_report(*report_data)
                    .context("Failed to get SEV-SNP report")?;
                AttestationQuote::DstackAmdSevSnp(quote)
            }
            TeeVariant::DstackGcpTdx => {
                let quote = tdx_attest::get_quote(report_data).context("Failed to get quote")?;
                let event_log =
                    cc_eventlog::tdx::read_event_log().context("Failed to read event log")?;
                let tpm_qualifying_data = sha256(&quote);
                let tdx_quote = TdxQuote { quote, event_log };
                let tpm_ctx =
                    tpm_attest::TpmContext::detect().context("Failed to open TPM context")?;
                let tpm_quote = tpm_ctx
                    .create_quote(&tpm_qualifying_data, &tpm_attest::dstack_pcr_policy())
                    .context("Failed to create TPM quote")?;
                AttestationQuote::DstackGcpTdx(DstackGcpTdxQuote {
                    tdx_quote,
                    tpm_quote,
                })
            }
            TeeVariant::DstackNitroEnclave => {
                let nsm_quote = nsm_attest::get_attestation(report_data)
                    .context("Failed to get NSM attestation")?;
                AttestationQuote::DstackNitroEnclave(DstackNitroQuote { nsm_quote })
            }
            TeeVariant::DstackAwsNitroTpm => {
                // Challenge binding is report_data → NitroTPM user_data only
                // (same role as TDX/GCP report_data; no separate nonce/public_key).
                let attestation_doc = crate::aws_nitro_tpm::attestation_document(report_data)
                    .context("failed to get NitroTPM attestation document")?;
                AttestationQuote::DstackAwsNitroTpm(DstackAwsNitroTpmQuote { attestation_doc })
            }
        };
        let config = match &quote {
            AttestationQuote::DstackAmdSevSnp(_)
            | AttestationQuote::DstackTdx(_)
            | AttestationQuote::DstackGcpTdx(_) => config,
            AttestationQuote::DstackNitroEnclave(quote) => {
                let os_image_hash = quote
                    .decode_image_hash()
                    .context("Failed to decode image hash")?;
                serde_json::to_string(&serde_json::json!({
                    "os_image_hash": hex::encode(os_image_hash),
                }))
                .context("Failed to serialize config")?
            }
            AttestationQuote::DstackAwsNitroTpm(quote) => {
                // The embedded vm_config must be self-verifiable against the
                // signed PCRs: os_image_hash → aws_measurement → boot_pcr_digest.
                // Anything else is an unverifiable host claim — fail loudly
                // instead of silently rewriting it.
                let pcrs = quote
                    .decode_pcrs()
                    .context("failed to decode NitroTPM PCRs")?;
                let vm_config: VmConfig = serde_json::from_str(&config)
                    .context("invalid vm_config in sys-config on AWS NitroTPM")?;
                let document = vm_config
                    .aws_measurement
                    .as_ref()
                    .context("vm_config.aws_measurement is required on AWS NitroTPM")?;
                document
                    .verify(&vm_config.os_image_hash)
                    .map_err(anyhow::Error::msg)
                    .context("aws_measurement does not match os_image_hash")?;
                let measurement = document
                    .decode_measurement()
                    .map_err(anyhow::Error::msg)
                    .context("failed to decode aws_measurement")?;
                let quoted_digest = aws_nitro_tpm_boot_pcr_digest(&pcrs)
                    .context("failed to compute boot_pcr_digest from attestation")?;
                if measurement.boot_pcr_digest.as_slice() != quoted_digest.as_slice() {
                    bail!(
                        "aws_measurement boot_pcr_digest mismatch vs attestation: expected={}, quoted={}",
                        hex::encode(&measurement.boot_pcr_digest),
                        hex::encode(&quoted_digest)
                    );
                }
                config
            }
        };
        if let AttestationQuote::DstackAmdSevSnp(quote) = &mut quote {
            quote.mr_config =
                read_mr_config_document(sys_config)?.context("amd sev-snp mr_config is missing")?;
        }

        Ok(Self {
            quote,
            runtime_events,
            report_data: *report_data,
            config,
            report: (),
        })
    }
}

impl Attestation {
    pub fn into_v1(self) -> AttestationV1 {
        self.into()
    }

    pub async fn verify(self, verifier: &AttestationVerifier) -> Result<VerifiedAttestation> {
        self.verify_with_time(verifier, None).await
    }

    pub async fn verify_with_time(
        self,
        verifier: &AttestationVerifier,
        now: Option<SystemTime>,
    ) -> Result<VerifiedAttestation> {
        let report = match &self.quote {
            AttestationQuote::DstackTdx(q) => {
                let report = self.verify_tdx(verifier, &q.quote).await?;
                DstackVerifiedReport::DstackTdx(report)
            }
            AttestationQuote::DstackAmdSevSnp(q) => {
                let verified = verifier
                    .sev_snp
                    .fetch_and_verify(
                        &verifier.amd_kds,
                        &q.report,
                        &q.cert_chain,
                        &self.report_data,
                    )
                    .await?;
                verify_snp_mr_config_host_data(&q.mr_config, &verified.host_data)?;
                DstackVerifiedReport::DstackAmdSevSnp(verified)
            }
            AttestationQuote::DstackGcpTdx(q) => {
                let tdx_report = self.verify_tdx(verifier, &q.tdx_quote.quote).await?;
                let tpm_report = self
                    .verify_tpm(verifier, &q.tpm_quote, &sha256(&q.tdx_quote.quote))
                    .await
                    .context("Failed to verify TPM quote")?;
                DstackVerifiedReport::DstackGcpTdx {
                    tdx_report,
                    tpm_report,
                }
            }
            AttestationQuote::DstackNitroEnclave(quote) => {
                let report = self
                    .verify_nitro_enclave_with_time(verifier, quote, now)
                    .await
                    .context("Failed to verify Nitro Enclave")?;
                DstackVerifiedReport::DstackNitroEnclave(report)
            }
            AttestationQuote::DstackAwsNitroTpm(quote) => {
                let report = verify_aws_nitro_tpm_attestation_doc(
                    verifier,
                    &quote.attestation_doc,
                    &self.runtime_events,
                    &self.report_data,
                    now,
                )
                .context("failed to verify NitroTPM attestation document")?;
                DstackVerifiedReport::DstackAwsNitroTpm(report)
            }
        };

        match &self.quote {
            AttestationQuote::DstackTdx(q) => {
                cc_eventlog::tdx::validate_v2_preimages(&q.event_log)
                    .context("Failed to validate TDX V2 event digest preimages")?;
            }
            AttestationQuote::DstackGcpTdx(q) => {
                cc_eventlog::tdx::validate_v2_preimages(&q.tdx_quote.event_log)
                    .context("Failed to validate TDX V2 event digest preimages")?;
            }
            _ => {}
        }

        Ok(VerifiedAttestation {
            quote: self.quote,
            runtime_events: self.runtime_events,
            report_data: self.report_data,
            config: self.config,
            report,
        })
    }

    /// Wrap into a versioned attestation for encoding.
    ///
    /// When any runtime event uses a non-V1 event-log version, force the V1
    /// msgpack wire format so the `version` field is preserved (SCALE
    /// V0 skips it for legacy binary compat). Otherwise default to V0 for
    /// backward compat with callers that expect the SCALE format.
    pub fn into_versioned(mut self) -> VersionedAttestation {
        // V2 event digests cannot be reconstructed from the serialized event
        // fields alone. Populate their canonical preimages before the legacy
        // quote is projected into either wire schema.
        self.fill_event_preimages();
        let has_v2 = self
            .runtime_events
            .iter()
            .any(|e| !matches!(e.version, EventLogVersion::V1));
        if has_v2 {
            VersionedAttestation::V1 {
                attestation: self.into(),
            }
        } else {
            VersionedAttestation::V0 { attestation: self }
        }
    }

    /// Verify the quote
    pub async fn verify_with_ra_pubkey(
        self,
        ra_pubkey_der: &[u8],
        verifier: &AttestationVerifier,
    ) -> Result<VerifiedAttestation> {
        let expected_report_data = QuoteContentType::RaTlsCert.to_report_data(ra_pubkey_der);
        if self.report_data != expected_report_data {
            bail!("report data mismatch");
        }
        self.verify(verifier).await
    }

    /// Verify Nitro Enclave attestation with optional custom time (testing hook)
    ///
    /// This performs full cryptographic verification:
    /// 1. Verifies COSE Sign1 signature using ECDSA P-384 with SHA-384
    /// 2. Verifies certificate chain from attestation document to AWS Nitro root CA
    /// 3. Validates user_data matches expected report_data
    async fn verify_nitro_enclave_with_time(
        &self,
        verifier: &AttestationVerifier,
        nsm_quote: &DstackNitroQuote,
        now: Option<SystemTime>,
    ) -> Result<NitroVerifiedReport> {
        // Verify COSE signature and certificate chain using nsm-qvl
        // CRL fetch is unreliable (e.g. 403 from S3), so keep it disabled here by default.
        let verified_report = verifier
            .aws_nitro_enclave
            .verify(&nsm_quote.nsm_quote, None, now)
            .context("NSM attestation verification failed")?;

        // Verify user_data matches report_data
        let Some(user_data) = verified_report.user_data.clone() else {
            bail!("NSM attestation document does not contain user_data");
        };
        if user_data != self.report_data {
            bail!("NSM user_data does not match report_data");
        }

        // Decode PCRs from quote
        let pcrs = nsm_quote
            .decode_pcrs()
            .context("Failed to decode nitro pcrs")?;

        Ok(NitroVerifiedReport {
            module_id: verified_report.module_id,
            pcrs,
            user_data,
            timestamp: verified_report.timestamp,
        })
    }

    async fn verify_tpm(
        &self,
        verifier: &AttestationVerifier,
        quote: &TpmQuote,
        qualifying_data: &[u8],
    ) -> Result<TpmVerifiedReport> {
        let report = verifier.gcp_tpm.fetch_and_verify(quote).await?;
        let pcr_ind = self
            .quote
            .variant()
            .tpm_event_pcr_and_bank()
            .map(|(pcr, _)| pcr)
            .context("Failed to get event PCR no")?;
        let replayed_rt_pcr = self.replay_runtime_events::<Sha256>(None);
        let quoted_rt_pcr = report
            .get_pcr(pcr_ind)
            .context("No runtime PCR in TPM report")?;
        if replayed_rt_pcr != quoted_rt_pcr[..] {
            bail!(
                "PCR{pcr_ind} mismatch, quoted: {}, replayed: {}",
                hex::encode(quoted_rt_pcr),
                hex::encode(replayed_rt_pcr),
            );
        }
        if report.attest.qualified_data != qualifying_data {
            bail!("tpm qualified_data mismatch");
        }
        Ok(report)
    }

    async fn verify_tdx(
        &self,
        verifier: &AttestationVerifier,
        quote: &[u8],
    ) -> Result<TdxVerifiedReport> {
        let tdx_report = verifier
            .verify_tdx_quote(quote)
            .await
            .context("failed to verify TDX quote")?;
        validate_tcb(&tdx_report)?;

        let td_report = tdx_report.report.as_td10().context("no td report")?;
        let replayed_rtmr = self.replay_runtime_events::<Sha384>(None);
        if replayed_rtmr != td_report.rt_mr3 {
            bail!(
                "RTMR3 mismatch, quoted: {}, replayed: {}",
                hex::encode(td_report.rt_mr3),
                hex::encode(replayed_rtmr)
            );
        }

        if td_report.report_data != self.report_data[..] {
            bail!("tdx report_data mismatch");
        }
        Ok(tdx_report)
    }
}

/// Validate the TCB attributes
pub fn validate_tcb(report: &TdxVerifiedReport) -> Result<()> {
    fn validate_td10(report: &TDReport10) -> Result<()> {
        let is_debug = report.td_attributes[0] & 0x01 != 0;
        if is_debug {
            bail!("Debug mode is not allowed");
        }
        if report.mr_signer_seam != [0u8; 48] {
            bail!("Invalid mr signer seam");
        }
        Ok(())
    }
    fn validate_td15(report: &TDReport15) -> Result<()> {
        if report.mr_service_td != [0u8; 48] {
            bail!("Invalid mr service td");
        }
        validate_td10(&report.base)
    }
    fn validate_sgx(report: &EnclaveReport) -> Result<()> {
        let is_debug = report.attributes[0] & 0x02 != 0;
        if is_debug {
            bail!("Debug mode is not allowed");
        }
        Ok(())
    }
    match &report.report {
        Report::TD15(report) => validate_td15(report),
        Report::TD10(report) => validate_td10(report),
        Report::SgxEnclave(report) => validate_sgx(report),
    }
}

/// Information about the app extracted from the platform-specific app info source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppInfo {
    /// App ID
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    /// SHA256 of the app compose file
    #[serde(with = "hex_bytes")]
    pub compose_hash: Vec<u8>,
    /// ID of the CVM instance
    #[serde(with = "hex_bytes")]
    pub instance_id: Vec<u8>,
    /// ID of the device
    #[serde(with = "hex_bytes")]
    pub device_id: Vec<u8>,
    /// Measurement of everything except the app info
    #[serde(with = "hex_bytes")]
    pub mr_system: [u8; 32],
    /// Measurement of the entire vm execution environment
    #[serde(with = "hex_bytes")]
    pub mr_aggregated: [u8; 32],
    /// Measurement of the app image
    #[serde(with = "hex_bytes")]
    pub os_image_hash: Vec<u8>,
    /// Key provider info
    #[serde(with = "hex_bytes")]
    pub key_provider_info: Vec<u8>,
    /// Optional SHA-256 pins for init scripts, in execution order. `None`
    /// means the evidence did not bind this field. On SEV-SNP, `Some(vec![])`
    /// explicitly binds an empty script list. On TDX and Nitro it only means
    /// that no `init-script-hash` events were measured before `system-ready`;
    /// pre-0.6.0 images emit no such events even when they run an init script.
    #[serde(default, with = "dstack_types::init_script_hashes::option")]
    pub init_script_hashes: Option<Vec<Vec<u8>>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_info_defaults_missing_init_script_hashes() {
        let app_info: AppInfo = serde_json::from_value(serde_json::json!({
            "app_id": "",
            "compose_hash": "",
            "instance_id": "",
            "device_id": "",
            "mr_system": "0000000000000000000000000000000000000000000000000000000000000000",
            "mr_aggregated": "0000000000000000000000000000000000000000000000000000000000000000",
            "os_image_hash": "",
            "key_provider_info": ""
        }))
        .unwrap();
        assert!(app_info.init_script_hashes.is_none());
    }

    #[test]
    fn app_info_preserves_explicit_empty_init_script_hashes() {
        let app_info: AppInfo = serde_json::from_value(serde_json::json!({
            "app_id": "",
            "compose_hash": "",
            "instance_id": "",
            "device_id": "",
            "mr_system": "0000000000000000000000000000000000000000000000000000000000000000",
            "mr_aggregated": "0000000000000000000000000000000000000000000000000000000000000000",
            "os_image_hash": "",
            "key_provider_info": "",
            "init_script_hashes": []
        }))
        .unwrap();
        assert_eq!(app_info.init_script_hashes, Some(Vec::new()));
    }

    #[test]
    fn external_trust_anchor_requires_explicit_insecure_opt_in() {
        let config = AttestationVerifierConfig {
            root_ca: RootCaPaths {
                tdx: Some("/tmp/mock-tdx-root.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let error = AttestationVerifier::load(&config)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("insecure_allow_external_trust_anchors is false"));
    }

    #[test]
    fn production_attestation_verifier_loads_all_safe_defaults() {
        AttestationVerifier::load(&AttestationVerifierConfig::default())
            .expect("production roots and URLs must load");
    }

    #[test]
    fn opted_in_external_root_is_read_during_load() {
        let config = AttestationVerifierConfig {
            insecure_allow_external_trust_anchors: true,
            root_ca: RootCaPaths {
                tdx: Some("/definitely/missing/tdx-root.pem".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        let error = AttestationVerifier::load(&config)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("failed to read TDX root CA"));
    }

    #[test]
    fn root_file_is_loaded_without_environment_indirection() {
        let path = std::env::temp_dir().join(format!("dstack-root-ca-test-{}", std::process::id()));
        fs_err::write(&path, b"test root").unwrap();
        assert_eq!(
            read_root_file(Some(&path), "test").unwrap(),
            Some(b"test root".to_vec())
        );
        fs_err::remove_file(path).unwrap();
    }

    #[test]
    fn every_external_root_is_parsed_during_load() {
        let path = std::env::temp_dir().join(format!(
            "dstack-invalid-root-ca-test-{}",
            std::process::id()
        ));
        fs_err::write(&path, b"not a certificate").unwrap();
        let roots = [
            RootCaPaths {
                tdx: Some(path.clone()),
                ..Default::default()
            },
            RootCaPaths {
                gcp_tpm: Some(path.clone()),
                ..Default::default()
            },
            RootCaPaths {
                aws_nitro_enclave: Some(path.clone()),
                ..Default::default()
            },
            RootCaPaths {
                aws_nitro_tpm: Some(path.clone()),
                ..Default::default()
            },
            RootCaPaths {
                sev_snp_milan: Some(path.clone()),
                ..Default::default()
            },
            RootCaPaths {
                sev_snp_genoa: Some(path.clone()),
                ..Default::default()
            },
            RootCaPaths {
                sev_snp_turin: Some(path.clone()),
                ..Default::default()
            },
        ];
        for root_ca in roots {
            let config = AttestationVerifierConfig {
                insecure_allow_external_trust_anchors: true,
                root_ca,
                ..Default::default()
            };
            let error = AttestationVerifier::load(&config)
                .err()
                .expect("invalid external root must fail during load");
            assert!(
                format!("{error:#}").contains("root CA"),
                "unexpected error: {error:#}"
            );
        }
        fs_err::remove_file(path).unwrap();
    }

    fn patch_v1_report_data(attestation: AttestationV1, report_data: [u8; 64]) -> AttestationV1 {
        attestation.with_report_data(report_data)
    }

    fn dummy_tdx_attestation(report_data: [u8; 64]) -> Attestation {
        Attestation {
            quote: AttestationQuote::DstackTdx(TdxQuote {
                quote: vec![0u8; TDX_QUOTE_REPORT_DATA_RANGE.end],
                event_log: Vec::new(),
            }),
            runtime_events: Vec::new(),
            report_data,
            config: "{}".into(),
            report: (),
        }
    }

    fn tdx_event(imr: u32, event_type: u32, event_payload: &[u8]) -> TdxEvent {
        TdxEvent {
            imr,
            event_type,
            digest: vec![event_type as u8; 48],
            event: String::new(),
            event_payload: event_payload.to_vec(),
            version: EventLogVersion::V1,
            preimage: None,
        }
    }

    #[test]
    fn get_quote_event_log_keeps_acpi_data_payloads() {
        let mut attestation = dummy_tdx_attestation([0u8; 64]);
        let AttestationQuote::DstackTdx(tdx_quote) = &mut attestation.quote else {
            panic!("expected TDX attestation");
        };
        tdx_quote.event_log = vec![
            tdx_event(0, 10, b"ACPI DATA"),
            tdx_event(0, 10, b"ACPI DATA"),
            tdx_event(0, 10, b"ACPI DATA"),
            tdx_event(0, 4, b"boot-payload"),
            tdx_event(
                3,
                cc_eventlog::DSTACK_RUNTIME_EVENT_TYPE,
                b"v1-runtime-payload",
            ),
            {
                let mut event = tdx_event(
                    3,
                    cc_eventlog::DSTACK_RUNTIME_EVENT_TYPE,
                    b"v2-runtime-payload",
                );
                event.version = EventLogVersion::V2;
                event
            },
        ];

        // The ACPI DATA marker payload is retained regardless of the
        // vm_config's tdx_attestation_variant (including no vm_config at
        // all), so a verifier can choose lite verification for any TDX boot.
        let events: Vec<TdxEvent> = serde_json::from_str(
            &attestation
                .get_tdx_event_log_string()
                .expect("TDX event log"),
        )
        .unwrap_or_else(|e| panic!("decode GetQuote event log: {e}"));
        assert_eq!(
            events
                .iter()
                .filter(|event| cc_eventlog::tdx::is_tdx_acpi_data_event(event))
                .count(),
            3,
            "GetQuote must retain all three TDX-lite ACPI DATA markers"
        );
        assert!(events[3].event_payload.is_empty());
        assert_eq!(events[4].event_payload, b"v1-runtime-payload");
        assert!(
            events[4].preimage.is_none(),
            "V1 output must remain unchanged"
        );
        assert_eq!(events[5].event_payload, b"v2-runtime-payload");
        assert!(events[5].preimage.is_some(), "V2 must include its preimage");
    }

    #[test]
    fn test_to_report_data_with_hash() {
        let content_type = QuoteContentType::AppData;
        let content = b"test content";

        let report_data = content_type.to_report_data(content);
        assert_eq!(
            hex::encode(report_data),
            "7ea0b744ed5e9c0c83ff9f575668e1697652cd349f2027cdf26f918d4c53e8cd50b5ea9b449b4c3d50e20ae00ec29688d5a214e8daff8a10041f5d624dae8a01"
        );

        // Test SHA-256
        let result = content_type
            .to_report_data_with_hash(content, "sha256")
            .unwrap();
        assert_eq!(result[32..], [0u8; 32]); // Check padding
        assert_ne!(result[..32], [0u8; 32]); // Check hash is non-zero

        // Test SHA-384
        let result = content_type
            .to_report_data_with_hash(content, "sha384")
            .unwrap();
        assert_eq!(result[48..], [0u8; 16]); // Check padding
        assert_ne!(result[..48], [0u8; 48]); // Check hash is non-zero

        // Test default
        let result = content_type.to_report_data_with_hash(content, "").unwrap();
        assert_ne!(result, [0u8; 64]); // Should fill entire buffer

        // Test raw content
        let exact_content = [42u8; 64];
        let result = content_type
            .to_report_data_with_hash(&exact_content, "raw")
            .unwrap();
        assert_eq!(result, exact_content);

        // Test invalid raw content length
        let invalid_content = [42u8; 65];
        assert!(content_type
            .to_report_data_with_hash(&invalid_content, "raw")
            .is_err());

        // Test invalid hash algorithm
        assert!(content_type
            .to_report_data_with_hash(content, "invalid")
            .is_err());
    }

    #[test]
    fn v1_roundtrip_preserves_payload_in_stack() {
        let report_data = [42u8; 64];
        let payload = r#"{"pod_uid":"abc","workload_id":"default/app"}"#.to_string();
        let attestation = dummy_tdx_attestation(report_data)
            .into_v1()
            .into_dstack_pod(payload.clone());
        let encoded = VersionedAttestation::V1 { attestation }.to_bytes().unwrap();
        assert!(matches!(encoded.first(), Some(0x80..=0x8f)));
        let decoded = VersionedAttestation::from_bytes(&encoded)
            .expect("decode attestation")
            .into_v1();
        assert_eq!(decoded.report_data_payload(), Some(payload.as_str()));
        assert_eq!(decoded.report_data().unwrap(), report_data);
        let attestation = decoded;
        assert!(matches!(attestation.platform, PlatformEvidence::Tdx { .. }));
        assert!(matches!(
            attestation.stack,
            StackEvidence::DstackPod {
                report_data_payload, ..
            } if report_data_payload == payload
        ));
    }

    #[test]
    fn patching_v1_report_data_preserves_payload_in_stack() {
        let original = dummy_tdx_attestation([1u8; 64])
            .into_v1()
            .into_dstack_pod("payload".into());
        let patched = patch_v1_report_data(original, [9u8; 64]);
        assert_eq!(patched.report_data_payload(), Some("payload"));
        assert_eq!(patched.report_data().unwrap(), [9u8; 64]);
    }

    #[test]
    fn legacy_v0_upgrade_uses_dstack_stack() {
        let upgraded = dummy_tdx_attestation([3u8; 64]).into_v1();
        assert!(matches!(upgraded.platform, PlatformEvidence::Tdx { .. }));
        assert!(matches!(upgraded.stack, StackEvidence::Dstack { .. }));
    }

    #[test]
    fn v1_dstack_with_v1_events_converts_losslessly_to_legacy() {
        let mut legacy = dummy_tdx_attestation([0x5a; 64]);
        legacy.runtime_events.push(cc_eventlog::RuntimeEvent::new(
            "legacy-event".into(),
            vec![1, 2, 3],
            cc_eventlog::EventLogVersion::V1,
        ));
        let converted = legacy.clone().into_v1().try_into_legacy().unwrap();
        assert_eq!(converted.report_data, legacy.report_data);
        assert_eq!(converted.runtime_events.len(), 1);
        assert!(matches!(
            converted.into_versioned(),
            VersionedAttestation::V0 { .. }
        ));
    }

    #[test]
    fn v1_conversion_rejects_lossy_legacy_projection() {
        let pod = dummy_tdx_attestation([0x5b; 64])
            .into_v1()
            .into_dstack_pod("payload".into());
        assert!(pod.try_into_legacy().is_err());
        let mut v2 = dummy_tdx_attestation([0x5c; 64]).into_v1();
        if let StackEvidence::Dstack { runtime_events, .. } = &mut v2.stack {
            runtime_events.push(cc_eventlog::RuntimeEvent::new(
                "v2-event".into(),
                vec![4, 5, 6],
                cc_eventlog::EventLogVersion::V2,
            ));
        }
        assert!(v2.try_into_legacy().is_err());
    }

    #[test]
    fn versioned_v0_projects_to_v1() {
        let projected = dummy_tdx_attestation([5u8; 64]).into_versioned().into_v1();
        assert!(matches!(projected.platform, PlatformEvidence::Tdx { .. }));
        match projected.stack {
            StackEvidence::Dstack {
                report_data,
                runtime_events,
                config,
            } => {
                assert_eq!(report_data, vec![5u8; 64]);
                assert!(runtime_events.is_empty());
                assert_eq!(config, "{}");
            }
            _ => panic!("expected dstack stack"),
        }
    }

    #[test]
    fn into_versioned_uses_v0_when_all_events_are_v1() {
        let mut att = dummy_tdx_attestation([7u8; 64]);
        att.runtime_events.push(cc_eventlog::RuntimeEvent::new(
            "app-id".into(),
            vec![1, 2, 3],
            cc_eventlog::EventLogVersion::V1,
        ));
        let versioned = att.into_versioned();
        assert!(
            matches!(versioned, VersionedAttestation::V0 { .. }),
            "V1-only events should stay on the V0/SCALE wire format"
        );
    }

    #[test]
    fn into_versioned_upgrades_to_v1_when_any_event_is_v2() {
        let mut att = dummy_tdx_attestation([8u8; 64]);
        let AttestationQuote::DstackTdx(tdx_quote) = &mut att.quote else {
            panic!("expected TDX attestation");
        };
        tdx_quote.event_log.push(
            cc_eventlog::RuntimeEvent::new(
                "compose-hash".into(),
                vec![4, 5, 6],
                cc_eventlog::EventLogVersion::V2,
            )
            .into(),
        );
        att.runtime_events.push(cc_eventlog::RuntimeEvent::new(
            "app-id".into(),
            vec![1, 2, 3],
            cc_eventlog::EventLogVersion::V1,
        ));
        att.runtime_events.push(cc_eventlog::RuntimeEvent::new(
            "compose-hash".into(),
            vec![4, 5, 6],
            cc_eventlog::EventLogVersion::V2,
        ));
        let encoded = att.into_versioned().to_bytes().unwrap();
        let VersionedAttestation::V1 { attestation } =
            VersionedAttestation::from_bytes(&encoded).unwrap()
        else {
            panic!("presence of a V2 event must force the V1 msgpack wire format");
        };
        let PlatformEvidence::Tdx { event_log, .. } = attestation.platform else {
            panic!("expected TDX platform evidence");
        };
        assert!(
            event_log[0].preimage.is_some(),
            "serialized V2 TDX events must carry their canonical digest preimage"
        );
        cc_eventlog::tdx::validate_v2_preimages(&event_log).unwrap();
    }
    fn v1_event(event: String, payload: Vec<u8>) -> RuntimeEvent {
        RuntimeEvent::new(event, payload, EventLogVersion::V1)
    }

    #[test]
    fn init_script_hashes_exclude_application_events_after_system_ready() {
        let events = vec![
            v1_event("init-script-hash".into(), vec![0x11; 32]),
            v1_event("init-script-hash".into(), vec![0x22; 32]),
            v1_event("system-ready".into(), Vec::new()),
            v1_event("init-script-hash".into(), vec![0xff; 32]),
        ];

        assert_eq!(
            find_event_payloads(&events, "init-script-hash"),
            vec![vec![0x11; 32], vec![0x22; 32]]
        );
    }

    #[test]
    fn nitro_pcrs_from_verified_extracts_0_1_2() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(0u16, vec![0xaa; 48]);
        map.insert(1u16, vec![0xbb; 48]);
        map.insert(2u16, vec![0xcc; 48]);
        map.insert(3u16, vec![0xdd; 48]); // ignored
        let pcrs = NitroPcrs::from_verified(&map).unwrap();
        assert_eq!(pcrs.pcr0, vec![0xaa; 48]);
        assert_eq!(pcrs.pcr1, vec![0xbb; 48]);
        assert_eq!(pcrs.pcr2, vec![0xcc; 48]);

        // missing a required PCR is an error
        map.remove(&1u16);
        assert!(NitroPcrs::from_verified(&map).is_err());
    }

    #[test]
    fn nitro_pcrs_debug_detection_and_image_hash() {
        let debug = NitroPcrs {
            pcr0: vec![0u8; 48],
            pcr1: vec![0u8; 48],
            pcr2: vec![0u8; 48],
        };
        assert!(debug.is_debug());

        let prod = NitroPcrs {
            pcr0: vec![1u8; 48],
            pcr1: vec![0u8; 48],
            pcr2: vec![0u8; 48],
        };
        assert!(!prod.is_debug());
        // image_hash = sha256(pcr0 || pcr1 || pcr2), never the all-zero sentinel
        assert_eq!(
            prod.image_hash(),
            sha256([&prod.pcr0, &prod.pcr1, &prod.pcr2]).to_vec()
        );
    }

    #[test]
    fn aws_nitro_tpm_mr_aggregated_replays_pcr14_like_rtmr3() -> Result<()> {
        let pcr4 = vec![0x04; 48];
        let pcr7 = vec![0x07; 48];
        let pcr12 = vec![0x12; 48];
        let mut pcrs = std::collections::BTreeMap::new();
        pcrs.insert(4u16, pcr4.clone());
        pcrs.insert(7u16, pcr7.clone());
        pcrs.insert(12u16, pcr12.clone());

        let mr_key_provider = sha256(b"aws nitrotpm key provider");
        let events = vec![
            v1_event("system-preparing".into(), Vec::new()),
            v1_event("app-id".into(), vec![0x11; 20]),
            v1_event("compose-hash".into(), vec![0x22; 32]),
            v1_event("instance-id".into(), vec![0x33; 20]),
            v1_event("boot-mr-done".into(), Vec::new()),
            v1_event("key-provider".into(), b"tpm".to_vec()),
            v1_event("system-ready".into(), Vec::new()),
        ];
        let replayed_pcr14 = cc_eventlog::replay_events::<Sha384>(&events, None);
        pcrs.insert(AWS_NITRO_TPM_EVENT_PCR, replayed_pcr14.to_vec());

        let mrs = decode_mr_aws_nitro_tpm_from_pcrs(false, &mr_key_provider, &pcrs, &events)?;

        assert_eq!(
            mrs.mr_system,
            sha256([
                pcr4.as_slice(),
                pcr7.as_slice(),
                pcr12.as_slice(),
                mr_key_provider.as_slice(),
            ])
        );
        assert_eq!(
            mrs.mr_aggregated,
            sha256([
                pcr4.as_slice(),
                pcr7.as_slice(),
                pcr12.as_slice(),
                replayed_pcr14.as_slice(),
            ])
        );

        let mut changed_events = events.clone();
        changed_events[2] = v1_event("compose-hash".into(), vec![0xee; 32]);
        let changed_pcr14 = cc_eventlog::replay_events::<Sha384>(&changed_events, None);
        let mut changed_pcrs = pcrs.clone();
        changed_pcrs.insert(AWS_NITRO_TPM_EVENT_PCR, changed_pcr14.to_vec());
        let changed_mrs = decode_mr_aws_nitro_tpm_from_pcrs(
            false,
            &mr_key_provider,
            &changed_pcrs,
            &changed_events,
        )?;

        assert_eq!(mrs.mr_system, changed_mrs.mr_system);
        assert_ne!(mrs.mr_aggregated, changed_mrs.mr_aggregated);

        let mut changed_pcrs = pcrs.clone();
        changed_pcrs.insert(12, vec![0x99; 48]);
        let changed_pcr12 =
            decode_mr_aws_nitro_tpm_from_pcrs(false, &mr_key_provider, &changed_pcrs, &events)?;
        assert_ne!(mrs.mr_system, changed_pcr12.mr_system);
        assert_ne!(mrs.mr_aggregated, changed_pcr12.mr_aggregated);

        let mut missing_pcrs = pcrs.clone();
        missing_pcrs.remove(&AWS_NITRO_TPM_EVENT_PCR);
        let err = match decode_mr_aws_nitro_tpm_from_pcrs(
            false,
            &mr_key_provider,
            &missing_pcrs,
            &events,
        ) {
            Ok(_) => panic!("missing PCR14 must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("PCR 14 not found"));

        let mut mismatched_pcrs = pcrs.clone();
        mismatched_pcrs.insert(AWS_NITRO_TPM_EVENT_PCR, vec![0xff; 48]);
        let err = match decode_mr_aws_nitro_tpm_from_pcrs(
            false,
            &mr_key_provider,
            &mismatched_pcrs,
            &events,
        ) {
            Ok(_) => panic!("mismatched PCR14 must be rejected"),
            Err(err) => err,
        };
        assert!(format!("{err:#}").contains("PCR14 mismatch"));
        Ok(())
    }

    #[test]
    fn aws_nitro_tpm_pcr14_replays_full_event_log_like_rtmr3() -> Result<()> {
        // Single PCR14 lane: all events (including after system-ready) are
        // measured and must be replayed for full (non-boottime) decode.
        let events = vec![
            v1_event("system-preparing".into(), Vec::new()),
            v1_event("app-id".into(), vec![0x11; 20]),
            v1_event("compose-hash".into(), vec![0x22; 32]),
            v1_event("instance-id".into(), vec![0x33; 20]),
            v1_event("boot-mr-done".into(), Vec::new()),
            v1_event("storage-fs".into(), b"ext4".to_vec()),
            v1_event("system-ready".into(), Vec::new()),
            v1_event("app-runtime".into(), b"ready".to_vec()),
        ];

        let full_pcr = cc_eventlog::replay_events::<Sha384>(&events, None);
        let early_pcr = cc_eventlog::replay_events::<Sha384>(&events, Some("boot-mr-done"));
        let mr_key_provider = sha256(b"aws nitrotpm key provider");
        let pcrs = std::collections::BTreeMap::from([
            (4u16, vec![0x04; 48]),
            (7u16, vec![0x07; 48]),
            (12u16, vec![0x12; 48]),
            (AWS_NITRO_TPM_EVENT_PCR, full_pcr.to_vec()),
        ]);

        let mrs = decode_mr_aws_nitro_tpm_from_pcrs(false, &mr_key_provider, &pcrs, &events)?;
        assert_eq!(
            mrs.mr_aggregated,
            sha256([
                pcrs[&4].as_slice(),
                pcrs[&7].as_slice(),
                pcrs[&12].as_slice(),
                full_pcr.as_slice(),
            ])
        );

        // A full runtime quote (PCR14 covers the whole log) decoded in
        // boottime mode binds the full replay to the quoted register, then
        // returns the boot-mr-done snapshot for the MR — it must NOT fail the
        // integrity check. This is the SignCert path (runtime quote, boot-time
        // MR).
        let early_from_full =
            decode_mr_aws_nitro_tpm_from_pcrs(true, &mr_key_provider, &pcrs, &events)?;
        assert_eq!(
            early_from_full.mr_aggregated,
            sha256([
                pcrs[&4].as_slice(),
                pcrs[&7].as_slice(),
                pcrs[&12].as_slice(),
                early_pcr.as_slice(),
            ])
        );

        // A genuine early quote carries both the truncated PCR14 and the
        // truncated event log; the full replay of that log equals the quoted
        // early PCR14, so the binding passes and the MR uses the same value.
        let early_events: Vec<RuntimeEvent> = events
            .iter()
            .take_while(|event| event.event != "boot-mr-done")
            .cloned()
            .chain(std::iter::once(v1_event("boot-mr-done".into(), Vec::new())))
            .collect();
        let mut early_pcrs = pcrs.clone();
        early_pcrs.insert(AWS_NITRO_TPM_EVENT_PCR, early_pcr.to_vec());
        let early_ok =
            decode_mr_aws_nitro_tpm_from_pcrs(true, &mr_key_provider, &early_pcrs, &early_events)?;
        assert_eq!(
            early_ok.mr_aggregated,
            sha256([
                early_pcrs[&4].as_slice(),
                early_pcrs[&7].as_slice(),
                early_pcrs[&12].as_slice(),
                early_pcr.as_slice(),
            ])
        );
        Ok(())
    }

    #[test]
    fn versioned_wire_formats_reject_malformed_boundaries() {
        assert!(VersionedAttestation::from_bytes(&[]).is_err());
        assert!(VersionedAttestation::from_bytes(&[0xff]).is_err());
        assert!(VersionedAttestation::from_bytes(&vec![0xff; MAX_ATTESTATION_BYTES + 1]).is_err());

        let legacy = dummy_tdx_attestation([0x31; 64]).into_versioned();
        assert!(matches!(legacy, VersionedAttestation::V0 { .. }));
        let legacy_bytes = legacy.to_bytes().unwrap();
        let decoded = VersionedAttestation::from_bytes(&legacy_bytes).unwrap();
        assert_eq!(decoded.into_v1().report_data().unwrap(), [0x31; 64]);
        assert!(VersionedAttestation::from_bytes(&legacy_bytes[..legacy_bytes.len() - 1]).is_err());
        assert!(
            VersionedAttestation::from_bytes(&[legacy_bytes.as_slice(), &[0xaa]].concat()).is_err()
        );

        let current = dummy_tdx_attestation([0x32; 64])
            .into_v1()
            .into_dstack_pod("versioned-boundary".into());
        let current = VersionedAttestation::V1 {
            attestation: current,
        };
        let current_bytes = current.to_bytes().unwrap();
        let decoded = VersionedAttestation::from_bytes(&current_bytes).unwrap();
        assert_eq!(decoded.into_v1().report_data().unwrap(), [0x32; 64]);
        assert!(
            VersionedAttestation::from_bytes(&current_bytes[..current_bytes.len() - 1]).is_err()
        );
        assert!(
            VersionedAttestation::from_bytes(&[current_bytes.as_slice(), &[0xaa]].concat())
                .is_err()
        );
    }
}
