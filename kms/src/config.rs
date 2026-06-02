// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use load_config::load_config;
use rocket::figment::Figment;
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("kms", DEFAULT_CONFIG, config_file, false)
}

const TEMP_CA_CERT: &str = "tmp-ca.crt";
const TEMP_CA_KEY: &str = "tmp-ca.key";
const ROOT_CA_CERT: &str = "root-ca.crt";
const ROOT_CA_KEY: &str = "root-ca.key";
const RPC_CERT: &str = "rpc.crt";
const RPC_KEY: &str = "rpc.key";
const RPC_DOMAIN: &str = "rpc-domain";
const K256_KEY: &str = "root-k256.key";
const BOOTSTRAP_INFO: &str = "bootstrap-info.json";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ImageConfig {
    pub verify: bool,
    pub cache_dir: PathBuf,
    pub download_url: String,
    #[serde(with = "serde_duration")]
    pub download_timeout: Duration,
}

/// Configuration for AMD SEV-SNP measurement/app binding validation.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SevSnpMeasureConfig {
    /// Path to the AMD SEV-SNP OVMF binary used for this VM image.
    ///
    /// Optional when callers provide OVMF section metadata with the request.
    pub ovmf_path: Option<String>,
    /// SNP guest features bitmask used at launch. Defaults to SNP with kernel
    /// hashes enabled.
    #[serde(default = "default_guest_features")]
    pub guest_features: u64,
}

fn default_guest_features() -> u64 {
    0x1
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SevSnpKeyReleaseConfig {
    /// Enable AMD SEV-SNP key/cert release after attestation, measurement
    /// binding, and external auth-policy checks have all succeeded.
    #[serde(default)]
    pub enabled: bool,
    /// Verifier-derived TCB statuses that are acceptable for releasing
    /// sensitive key/cert material. Defaults to the strict production value.
    #[serde(default = "default_allowed_tcb_statuses")]
    pub allowed_tcb_statuses: Vec<String>,
    /// Advisory IDs that are acceptable for releasing sensitive key/cert
    /// material. Defaults to empty, which rejects any advisory.
    #[serde(default)]
    pub allowed_advisory_ids: Vec<String>,
}

impl Default for SevSnpKeyReleaseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_tcb_statuses: default_allowed_tcb_statuses(),
            allowed_advisory_ids: Vec::new(),
        }
    }
}

fn default_allowed_tcb_statuses() -> Vec<String> {
    vec!["UpToDate".to_string()]
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub cert_dir: PathBuf,
    pub pccs_url: Option<String>,
    pub auth_api: AuthApi,
    pub onboard: OnboardConfig,
    pub image: ImageConfig,
    /// AMD SEV-SNP measurement verification configuration. Optional at config
    /// load time for non-SNP/dev deployments; SNP binding helpers require it.
    #[serde(default)]
    #[allow(dead_code)]
    pub sev_snp: Option<SevSnpMeasureConfig>,
    /// Additional local release gate for AMD SEV-SNP key/cert material. This is
    /// separate from the auth API so production deployments need an explicit KMS
    /// opt-in as well as a successful external policy decision.
    #[serde(default)]
    pub sev_snp_key_release: SevSnpKeyReleaseConfig,
    #[serde(with = "serde_human_bytes")]
    pub admin_token_hash: Vec<u8>,
    #[serde(default)]
    pub site_name: String,
    /// Whether trusted RPCs require the KMS to first attest itself to its
    /// own auth API. Defaults to `true` (strict). Set `false` only for local
    /// dev/testing where the KMS runs outside a TEE and cannot reach a guest
    /// agent socket.
    #[serde(default = "default_true")]
    pub enforce_self_authorization: bool,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MetricsConfig {
    /// Whether to expose the unauthenticated Prometheus `/metrics` endpoint.
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

impl KmsConfig {
    pub fn keys_exists(&self) -> bool {
        self.tmp_ca_cert().exists()
            && self.tmp_ca_key().exists()
            && self.root_ca_cert().exists()
            && self.root_ca_key().exists()
            && self.rpc_cert().exists()
            && self.rpc_key().exists()
            && self.k256_key().exists()
    }

    pub fn tmp_ca_cert(&self) -> PathBuf {
        self.cert_dir.join(TEMP_CA_CERT)
    }

    pub fn tmp_ca_key(&self) -> PathBuf {
        self.cert_dir.join(TEMP_CA_KEY)
    }

    pub fn root_ca_cert(&self) -> PathBuf {
        self.cert_dir.join(ROOT_CA_CERT)
    }

    pub fn root_ca_key(&self) -> PathBuf {
        self.cert_dir.join(ROOT_CA_KEY)
    }

    pub fn rpc_cert(&self) -> PathBuf {
        self.cert_dir.join(RPC_CERT)
    }

    pub fn rpc_key(&self) -> PathBuf {
        self.cert_dir.join(RPC_KEY)
    }

    pub fn rpc_domain(&self) -> PathBuf {
        self.cert_dir.join(RPC_DOMAIN)
    }

    pub fn k256_key(&self) -> PathBuf {
        self.cert_dir.join(K256_KEY)
    }

    pub fn bootstrap_info(&self) -> PathBuf {
        self.cert_dir.join(BOOTSTRAP_INFO)
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum AuthApi {
    #[serde(rename = "dev")]
    Dev { dev: Dev },
    #[serde(rename = "webhook")]
    Webhook { webhook: Webhook },
}

impl AuthApi {
    pub fn is_dev(&self) -> bool {
        matches!(self, AuthApi::Dev { .. })
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Webhook {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Dev {
    pub gateway_app_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OnboardConfig {
    pub enabled: bool,
    pub auto_bootstrap_domain: String,
}
