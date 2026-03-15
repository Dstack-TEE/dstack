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

/// Configuration for AMD SEV-SNP measurement verification.
/// When present, the KMS recomputes the expected SNP MEASUREMENT in pure Rust
/// (no external tooling required) and compares it against the hardware-attested
/// value in the SNP attestation report.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct SevSnpMeasureConfig {
    /// Path to the AMD SEV-SNP OVMF binary (ovmf.fd) used for this VM image.
    ///
    /// **Optional** when the VM sends `ovmf_sections` in the request (extracted
    /// by `extract_ovmf_info.py` on the launcher host before launch).  In that
    /// case the KMS never reads the OVMF file and this field may be omitted.
    ///
    /// Required only as a fallback for older VM images that do not send
    /// `ovmf_sections`.  The file is parsed for GPA metadata only
    /// (section descriptors, reset EIP, sev_hashes_table_gpa).
    pub ovmf_path: Option<String>,
    /// SNP guest features bitmask (0x1 = SNP with kernel hashes enabled).
    /// Must match the value used when the VM was launched.
    #[serde(default = "default_guest_features")]
    pub guest_features: u64,
}

fn default_guest_features() -> u64 {
    0x1
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub cert_dir: PathBuf,
    pub pccs_url: Option<String>,
    pub auth_api: AuthApi,
    pub onboard: OnboardConfig,
    pub image: ImageConfig,
    #[serde(with = "serde_human_bytes")]
    pub admin_token_hash: Vec<u8>,
    /// AMD SEV-SNP measurement verification. Optional: if absent, measurement
    /// recomputation is skipped (useful for dev environments without OVMF).
    pub sev_snp: Option<SevSnpMeasureConfig>,
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
