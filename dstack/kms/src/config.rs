// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use dstack_attest::attestation::AttestationVerifierConfig;
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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub cert_dir: PathBuf,
    #[serde(default)]
    pub attestation: AttestationVerifierConfig,
    pub auth_api: AuthApi,
    pub onboard: OnboardConfig,
    pub image: ImageConfig,
    /// Whether to enable the additional local release gate for AMD SEV-SNP
    /// key/cert material. This is separate from the auth API so production
    /// deployments need an explicit KMS opt-in as well as a successful external
    /// policy decision.
    #[serde(default)]
    pub sev_snp_key_release: bool,
    /// Whether to enable the additional local release gate for AWS EC2 NitroTPM
    /// key/cert material. NitroTPM is a new, non-confidential-compute attestation
    /// mode (the AWS hypervisor is in the TCB), so production deployments need an
    /// explicit KMS opt-in as well as a successful external policy decision —
    /// mirroring `sev_snp_key_release`.
    #[serde(default)]
    pub aws_nitro_tpm_key_release: bool,
    #[serde(default)]
    pub site_name: String,
    /// Whether the KMS embeds an attestation in its own RPC certificate.
    /// Defaults to `true`. Set `false` only for local dev/testing where the KMS
    /// runs outside a TEE and cannot reach a guest agent socket.
    ///
    /// This narrows what the KMS asserts about itself; it relaxes no
    /// verification anywhere. Quotes presented *to* the KMS are still fully
    /// checked, so key release stays gated, and relying parties keep their own
    /// policy: a guest accepts an unattested KMS certificate but then does not
    /// extend `mr-kms`, so a remote verifier can still tell, and another KMS
    /// refuses to onboard from one.
    #[serde(default = "default_true")]
    pub attest_rpc_cert: bool,
    /// Whether trusted RPCs require the KMS to first attest itself to its
    /// own auth API. Defaults to `true` (strict). Set `false` only for local
    /// dev/testing where the KMS runs outside a TEE and cannot reach a guest
    /// agent socket.
    #[serde(default = "default_true")]
    pub enforce_self_authorization: bool,
    pub metrics: MetricsConfig,
    /// Optional stable identity for an MPC-backed KMS. Cryptographic MPC
    /// operations are provided by the key backend; this section defines the
    /// identity that applications pin independently of cluster membership.
    #[serde(default)]
    pub mpc: MpcConfig,
    /// Admin API listener + authentication. The admin RPCs (e.g.
    /// `ClearImageCache`) are served here, behind the shared HTTP authenticator.
    #[serde(default)]
    pub admin: AdminConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct MpcConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub protocol_version: u16,
    #[serde(default)]
    pub cluster_id: String,
    #[serde(default)]
    pub identity_file: PathBuf,
    #[serde(default)]
    pub p256_group_pubkey: String,
    #[serde(default)]
    pub k256_group_pubkey: String,
    #[serde(default)]
    pub derivation_group_pubkey: String,
    #[serde(default)]
    pub node_id: String,
    #[serde(default)]
    pub manifest_file: PathBuf,
    #[serde(default)]
    pub checkpoint_file: PathBuf,
    /// Development-only compatibility escape hatch for unsigned manifests.
    #[serde(default)]
    pub allow_unsigned_manifest: bool,
    #[serde(default = "default_mpc_max_sessions")]
    pub max_sessions: usize,
    #[serde(default = "default_mpc_session_ttl", with = "serde_duration")]
    pub session_ttl: Duration,
    #[serde(default)]
    pub p256_share_file: PathBuf,
    #[serde(default)]
    pub k256_share_file: PathBuf,
    #[serde(default)]
    pub derivation_share_file: PathBuf,
}

fn default_mpc_max_sessions() -> usize {
    128
}

fn default_mpc_session_ttl() -> Duration {
    Duration::from_secs(300)
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MetricsConfig {
    /// Whether to expose the unauthenticated Prometheus `/metrics` endpoint.
    pub enabled: bool,
}

/// Admin API listener + authentication, mirroring the gateway `[core.admin]`
/// section. The listen `address`/`port` are read from the same `[core.admin]`
/// section by Rocket. The token travels in the `Authorization`/`X-Admin-Token`
/// header.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct AdminConfig {
    /// Whether to serve the admin API at all.
    #[serde(default)]
    pub enabled: bool,
    /// Shared admin token required to call any admin RPC. Can also be supplied
    /// via `DSTACK_KMS_ADMIN_TOKEN` / `ADMIN_API_TOKEN`. Required unless
    /// `insecure_no_auth = true`.
    #[serde(default)]
    pub auth_token: String,
    /// Optional Apache bcrypt htpasswd file, accepted in addition to the token.
    #[serde(default)]
    pub htpasswd_file: PathBuf,
    /// Development-only escape hatch: serve the admin API with no auth. Never
    /// enable on a network-reachable listener.
    #[serde(default)]
    pub insecure_no_auth: bool,
}

fn default_true() -> bool {
    true
}

impl KmsConfig {
    pub fn keys_exists(&self) -> bool {
        if self.mpc.enabled {
            return self.tmp_ca_cert().exists()
                && self.tmp_ca_key().exists()
                && self.root_ca_cert().exists()
                && self.rpc_cert().exists()
                && self.rpc_key().exists()
                && self.mpc.p256_share_file.exists()
                && self.mpc.k256_share_file.exists()
                && self.mpc.derivation_share_file.exists();
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::providers::{Format, Toml};

    #[test]
    fn default_config_parses_with_admin_disabled_and_no_hash() {
        let figment = load_config_figment(None);
        let config: KmsConfig = figment
            .focus("core")
            .extract()
            .expect("kms.toml must parse into KmsConfig");
        assert!(!config.admin.enabled, "admin must be off by default");
        assert!(
            config.admin.auth_token.is_empty(),
            "default admin token must be empty (fail-closed)"
        );
        assert!(!config.admin.insecure_no_auth);
    }

    #[test]
    fn rpc_cert_is_attested_by_default() {
        let figment = load_config_figment(None);
        let config: KmsConfig = figment
            .focus("core")
            .extract()
            .expect("kms.toml must parse into KmsConfig");
        assert!(
            config.attest_rpc_cert,
            "the KMS must attest its own RPC certificate unless explicitly told not to"
        );
    }

    #[test]
    fn omitting_the_key_keeps_the_attested_default() {
        // Configs written before this key existed must keep working, and must
        // land on the attested side.
        #[derive(Deserialize)]
        struct Probe {
            #[serde(default = "default_true")]
            attest_rpc_cert: bool,
        }
        let probe: Probe = Figment::from(Toml::string(""))
            .extract()
            .expect("an absent attest_rpc_cert must parse");
        assert!(probe.attest_rpc_cert);
    }
}
