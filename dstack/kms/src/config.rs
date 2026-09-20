// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::main_service::upgrade_authority::{AuthApiInfoResponse, BootResponse, InFlight};
use dstack_attest::attestation::AttestationVerifierConfig;
use load_config::load_config;
use rocket::figment::Figment;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc, time::Duration};
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
    ///
    /// It is also the *only* gate that sees the platform: NitroTPM has no TCB
    /// surface, so the verifier reports a synthesized `tcb_status` of
    /// `"UpToDate"` and `IAppAuth.AppBootInfo` carries no `tee_variant`, which
    /// makes `DstackApp.requireTcbUpToDate` vacuous for every app on it. See
    /// `aws_nitro_tpm_tcb_status_is_synthesized_and_no_backend_can_tell`.
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
    /// checked, so key release stays gated, and another KMS refuses to onboard
    /// from an unattested one.
    #[serde(default = "default_true")]
    pub attest_rpc_cert: bool,
    /// Whether trusted RPCs require the KMS to first attest itself to its
    /// own auth API. Defaults to `true` (strict). Set `false` only for local
    /// dev/testing where the KMS runs outside a TEE and cannot reach a guest
    /// agent socket.
    #[serde(default = "default_true")]
    pub enforce_self_authorization: bool,
    pub metrics: MetricsConfig,
    /// Admin API listener + authentication. The admin RPCs (e.g.
    /// `ClearImageCache`) are served here, behind the shared HTTP authenticator.
    #[serde(default)]
    pub admin: AdminConfig,
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

/// What the two irreplaceable root secrets look like on disk.
///
/// `root-ca.key` and `root-k256.key` are the only material a KMS cannot
/// regenerate: every app key, every encrypted disk and every issued
/// certificate in the deployment hangs off them. So "has this KMS been
/// bootstrapped?" is a question about these two files and nothing else, and
/// every path that can mint new root keys - the `Onboard.Bootstrap` RPC, the
/// `Onboard.Onboard` RPC, `bootstrap_keys` - asks it the same way.
///
/// [`KmsConfig::keys_exists`] answers a different question: whether the
/// *derived* material is complete. The two used to be compared as if they were
/// the same question, which is what made a partial write unrecoverable - an
/// incomplete cert dir sent the KMS into onboarding, where every RPC then
/// refused because a root key existed. The gap between them is a repair
/// ([`crate::onboard_service::update_certs`]), not a rebootstrap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootKeys {
    /// Neither key exists. Nothing has been published, so generating a fresh
    /// set or onboarding from another KMS is safe.
    Absent,
    /// Exactly one key exists, which only a crash between the two writes in
    /// `Keys::store` can produce. Terminal: the surviving half cannot be
    /// paired again, and minting a partner for it would silently rekey the
    /// deployment.
    Partial {
        present: &'static str,
        missing: &'static str,
    },
    /// Both keys exist. This KMS is bootstrapped.
    Present,
}

impl KmsConfig {
    /// See [`RootKeys`]. This is the one definition of "already bootstrapped".
    pub(crate) fn root_keys(&self) -> RootKeys {
        match (self.root_ca_key().exists(), self.k256_key().exists()) {
            (true, true) => RootKeys::Present,
            (false, false) => RootKeys::Absent,
            (true, false) => RootKeys::Partial {
                present: ROOT_CA_KEY,
                missing: K256_KEY,
            },
            (false, true) => RootKeys::Partial {
                present: K256_KEY,
                missing: ROOT_CA_KEY,
            },
        }
    }

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
    /// Shared across every clone of this config, so every RPC handler on one
    /// KMS coalesces against the same set of in-flight calls. Not configurable
    /// and not serialized - see
    /// [`crate::main_service::upgrade_authority::InFlight`].
    #[serde(skip)]
    pub boot_calls: Arc<InFlight<BootResponse>>,
    #[serde(skip)]
    pub info_calls: Arc<InFlight<AuthApiInfoResponse>>,
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
