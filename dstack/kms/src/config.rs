// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use dstack_attest::attestation::AttestationVerifierConfig;
use load_config::load_config;
use rocket::figment::{providers::Serialized, Figment};
use serde::Deserialize;
use std::{path::PathBuf, time::Duration};
pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("kms", DEFAULT_CONFIG, config_file, false)
}

/// Settings that moved to `[listeners.*]`. The defaults (`kms.toml`) have none
/// of them, so one present was set by the operator and would otherwise be
/// silently ignored.
const MOVED_SETTINGS: [(&str, &str); 6] = [
    ("rpc", "listeners.guest"),
    ("core.admin", "listeners.admin"),
    ("core.onboard.address", "listeners.onboard.address"),
    ("core.onboard.port", "listeners.onboard.port"),
    ("core.onboard.tls", "listeners.onboard.tls"),
    ("default", "listeners.default"),
];

/// Refuse a config that sets a moved setting.
pub(crate) fn reject_moved_settings(figment: &Figment) -> Result<()> {
    let moved: Vec<String> = MOVED_SETTINGS
        .iter()
        .filter(|(old, _)| figment.find_value(old).is_ok())
        .map(|(old, new)| format!("{old} -> {new}"))
        .collect();
    if !moved.is_empty() {
        bail!(
            "the config sets listener settings at their old locations; move them: {}",
            moved.join(", ")
        );
    }
    Ok(())
}

/// The `enabled` switches of the optional listeners. Their bind settings
/// (`address`, `port`, `tls`, `proxy_protocol`) are read by Rocket, see
/// [`listener_figment`].
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct ListenersConfig {
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub public: ListenerSwitch,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct ListenerSwitch {
    #[serde(default)]
    pub enabled: bool,
}

impl ListenersConfig {
    pub fn load(figment: &Figment) -> Result<Self> {
        Ok(figment.extract_inner("listeners")?)
    }
}

/// The Rocket config of listener `name`: `[listeners.default]` overridden by
/// `[listeners.<name>]`. The onboard listener does not inherit the default
/// `tls`, since it runs before the KMS has certificates.
pub(crate) fn listener_figment(figment: &Figment, name: &str) -> Result<Figment> {
    let mut defaults = figment
        .find_value("listeners.default")
        .ok()
        .and_then(|value| value.into_dict())
        .unwrap_or_default();
    if name == "onboard" {
        defaults.remove("tls");
    }
    let listener = figment.find_value(&format!("listeners.{name}"))?;
    Ok(Figment::from(rocket::Config::default())
        .merge(Serialized::defaults(defaults))
        .merge(Serialized::defaults(listener)))
}

const TEMP_CA_CERT: &str = "tmp-ca.crt";
const TEMP_CA_KEY: &str = "tmp-ca.key";
const ROOT_CA_CERT: &str = "root-ca.crt";
const ROOT_CA_KEY: &str = "root-ca.key";
const RPC_CERT: &str = "rpc.crt";
const RPC_KEY: &str = "rpc.key";
const RPC_DOMAIN: &str = "rpc-domain";
const K256_KEY: &str = "root-k256.key";
const ROOT_EPOCH: &str = "root-epoch";
const EPOCHS_DIR: &str = "epochs";
const BOOTSTRAP_INFO: &str = "bootstrap-info.json";

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct ImageConfig {
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
    /// Whether to enable the additional local release gate for AWS Nitro Enclave
    /// key/cert material. The NSM document measures the enclave image (PCR0/1/2),
    /// which is what `os_image_hash` and `compose_hash` are built from, but the
    /// AWS hypervisor is in the TCB and dstack extends no runtime measurement
    /// register on this platform — so `app_id` and `instance_id` are read from an
    /// event list nothing replays against hardware. Production deployments
    /// therefore need an explicit KMS opt-in as well as a successful external
    /// policy decision — mirroring `sev_snp_key_release` and
    /// `aws_nitro_tpm_key_release`.
    #[serde(default)]
    pub nitro_enclave_key_release: bool,
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
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MetricsConfig {
    /// Whether to expose the unauthenticated Prometheus `/metrics` endpoint.
    pub enabled: bool,
}

/// The admin listener, `[listeners.admin]`: whether it is served and its
/// authentication. The token travels in the `Authorization`/`X-Admin-Token`
/// header.
#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct AdminConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Shared admin token required to call any admin RPC. Can also be supplied
    /// via `DSTACK_KMS_ADMIN_TOKEN` / `ADMIN_API_TOKEN`. Required unless
    /// `insecure_no_auth = true`.
    #[serde(default)]
    pub auth_token: String,
    /// Hex SHA-256 of the admin token, for configs that are not secret, such
    /// as an app compose, so the token itself stays out of them.
    #[serde(default)]
    pub auth_token_hash: String,
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

/// Without the public handover, other KMS nodes can get the keys only from the
/// admin listener over TLS. A KMS without either would strand them, so it
/// refuses to start, in any mode.
pub(crate) fn check_key_handover(
    config: &KmsConfig,
    listeners: &ListenersConfig,
    figment: &Figment,
) -> Result<()> {
    if config.onboard.public_key_handover {
        return Ok(());
    }
    let admin = listener_figment(figment, "admin")?;
    let set = |key: &str| {
        admin
            .find_value(key)
            .ok()
            .and_then(|value| value.into_string())
            .is_some_and(|value| !value.is_empty())
    };
    let missing = if !listeners.admin.enabled {
        "[listeners.admin] enabled = true"
    } else if !set("tls.key") {
        "the admin listener's tls key"
    } else if !set("tls.certs") {
        "the admin listener's tls certs"
    } else {
        return Ok(());
    };
    bail!(
        "no key handover path for onboarding other KMS nodes: {missing} is not set. \
         Configure the admin listener with TLS ([listeners.admin] enabled = true with an \
         admin credential, and tls key and certs in [listeners.admin.tls] or \
         [listeners.default.tls]), or set core.onboard.public_key_handover = true"
    )
}

impl KmsConfig {
    /// The root keys are the last files a bootstrap writes, so both existing
    /// marks a completed one. Anything short of that is left over from an
    /// interrupted bootstrap and may be overwritten.
    pub fn root_keys_exist(&self) -> bool {
        self.root_ca_key().exists() && self.k256_key().exists()
    }

    pub fn keys_exists(&self) -> bool {
        self.root_ca_cert().exists()
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

    /// Records the newest epoch this KMS holds, whose roots are the top-level
    /// root files. Absent means 0.
    pub fn root_epoch(&self) -> PathBuf {
        self.cert_dir.join(ROOT_EPOCH)
    }

    /// Root key paths of `epoch` in a keyring whose newest epoch is `latest`:
    /// the newest roots are the top-level root files, so paths that predate
    /// epochs are unchanged. Older epochs live in `epochs/<n>/`.
    pub fn root_key_paths(&self, epoch: u32, latest: u32) -> RootKeyPaths {
        let dir = if epoch == latest {
            self.cert_dir.clone()
        } else {
            self.cert_dir.join(EPOCHS_DIR).join(epoch.to_string())
        };
        RootKeyPaths {
            ca_cert: dir.join(ROOT_CA_CERT),
            ca_key: dir.join(ROOT_CA_KEY),
            k256_key: dir.join(K256_KEY),
        }
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
    /// Per-call timeout. Defaulted so an existing section with only `url` still parses.
    #[serde(default = "default_webhook_timeout", with = "serde_duration")]
    pub timeout: Duration,
}

/// Matches the `ra_rpc::client` request timeout.
fn default_webhook_timeout() -> Duration {
    Duration::from_secs(60)
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Dev {
    pub gateway_app_id: String,
}

pub(crate) struct RootKeyPaths {
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub k256_key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct OnboardConfig {
    pub enabled: bool,
    pub auto_bootstrap_domain: String,
    /// Also serve GetKmsKey on the public RPC listener, for legacy onboarding clients.
    #[serde(default)]
    pub public_key_handover: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::figment::providers::{Format, Toml};

    #[test]
    fn default_config_serves_the_handover_on_the_admin_listener() {
        let figment = load_config_figment(None);
        let config: KmsConfig = figment
            .focus("core")
            .extract()
            .expect("kms.toml must parse into KmsConfig");
        let listeners = ListenersConfig::load(&figment).unwrap();
        assert!(listeners.admin.enabled);
        assert!(!listeners.public.enabled);
        check_key_handover(&config, &listeners, &figment)
            .expect("the default config has a handover path");
        assert!(
            listeners.admin.auth_token.is_empty(),
            "default admin token must be empty (fail-closed)"
        );
        assert!(!listeners.admin.insecure_no_auth);
        assert!(
            !config.onboard.public_key_handover,
            "public key handover must be off by default"
        );
    }

    fn handover_check(toml: &str) -> Result<()> {
        let figment = load_config_figment(None).merge(Toml::string(toml));
        let config: KmsConfig = figment.focus("core").extract().unwrap();
        check_key_handover(&config, &ListenersConfig::load(&figment).unwrap(), &figment)
    }

    #[test]
    fn moved_listener_settings_are_refused() {
        reject_moved_settings(&load_config_figment(None)).expect("kms.toml uses the new names");
        for (toml, old) in [
            ("[rpc]\nport = 9100\n", "rpc -> listeners.guest"),
            (
                "[core.admin]\nport = 9101\n",
                "core.admin -> listeners.admin",
            ),
            (
                "[core.admin]\nauth_token = \"t\"\n",
                "core.admin -> listeners.admin",
            ),
            ("[core.onboard]\nport = 9102\n", "core.onboard.port -> "),
            ("[default]\nworkers = 8\n", "default -> listeners.default"),
        ] {
            let figment = load_config_figment(None).merge(Toml::string(toml));
            let err = reject_moved_settings(&figment).unwrap_err().to_string();
            assert!(err.contains(old), "{err}");
        }
        let onboarding = "[core.onboard]\nenabled = false\n";
        reject_moved_settings(&load_config_figment(None).merge(Toml::string(onboarding)))
            .expect("onboarding options stay in core");
    }

    #[test]
    fn a_serving_kms_needs_a_key_handover_path() {
        let public = "[core.onboard]\npublic_key_handover = true\n";
        let no_admin = "[listeners.admin]\nenabled = false\n";
        let no_key = "[listeners.admin.tls]\nkey = \"\"\n";
        let no_certs = "[listeners.admin.tls]\ncerts = \"\"\n";
        assert!(handover_check("").is_ok());
        // onboarding and bootstrap modes are checked alike.
        let onboarding = "[core.onboard]\nenabled = true\nauto_bootstrap_domain = \"kms.test\"\n";
        assert!(handover_check(onboarding).is_ok());
        assert!(handover_check(&format!("{onboarding}{no_admin}")).is_err());
        for missing in [no_admin, no_key, no_certs] {
            assert!(handover_check(&format!("{public}{missing}")).is_ok());
        }
        for (toml, setting) in [
            (no_admin, "[listeners.admin] enabled = true"),
            (no_key, "the admin listener's tls key"),
            (no_certs, "the admin listener's tls certs"),
        ] {
            let err = handover_check(toml).unwrap_err().to_string();
            assert!(err.contains(setting), "{err}");
            assert!(err.contains("public_key_handover = true"), "{err}");
        }
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
