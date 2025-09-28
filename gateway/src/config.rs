// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use cmd_lib::run_cmd as cmd;
use ipnet::Ipv4Net;
use load_config::load_config;
use rocket::figment::Figment;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;
use tracing::info;

#[derive(Debug, Clone, Deserialize)]
pub struct WgConfig {
    pub public_key: String,
    pub private_key: String,
    pub listen_port: u16,
    pub ip: Ipv4Net,
    pub reserved_net: Vec<Ipv4Net>,
    pub client_ip_range: Ipv4Net,
    pub interface: String,
    pub config_path: String,
    pub endpoint: String,
}

impl WgConfig {
    fn validate(&self) -> Result<()> {
        validate(self.ip, &self.reserved_net, self.client_ip_range)
    }
}

fn validate(ip: Ipv4Net, reserved_net: &[Ipv4Net], client_ip_range: Ipv4Net) -> Result<()> {
    // The reserved net must be in the network
    for net in reserved_net {
        if !ip.contains(net) {
            bail!("Reserved net is not in the network");
        }
    }

    // The ip must be in one of the reserved net
    if !reserved_net.iter().any(|net| net.contains(&ip.addr())) {
        bail!("Wg peer IP is not in the reserved net");
    }

    // The client ip range must be in the network
    if !ip.trunc().contains(&client_ip_range) {
        bail!("Client IP range is not in the network");
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub enum CryptoProvider {
    #[serde(rename = "aws-lc-rs")]
    AwsLcRs,
    #[serde(rename = "ring")]
    Ring,
}

#[derive(Debug, Clone, Deserialize)]
pub enum TlsVersion {
    #[serde(rename = "1.2")]
    Tls12,
    #[serde(rename = "1.3")]
    Tls13,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyProtocolConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub trust_strategy: ProxyProtocolTrustStrategy,
    #[serde(default)]
    pub backend_default: BackendProxyMode,
    pub backend_overrides: Option<std::collections::HashMap<String, BackendProxyConfig>>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyProtocolTrustStrategy {
    #[serde(rename = "type", default = "default_trust_all")]
    pub strategy_type: TrustStrategyType,
    pub addresses: Option<Vec<String>>,
    pub ranges: Option<Vec<String>>,
}

fn default_trust_all() -> TrustStrategyType {
    TrustStrategyType::All
}

impl Default for ProxyProtocolTrustStrategy {
    fn default() -> Self {
        Self {
            strategy_type: TrustStrategyType::All,
            addresses: None,
            ranges: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustStrategyType {
    None,
    All,
    Ips,
    Cidrs,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendProxyMode {
    #[serde(default = "default_passthrough_mode")]
    pub mode: ForwardingMode,
    pub version: Option<ProxyProtocolVersionConfig>,
}

fn default_passthrough_mode() -> ForwardingMode {
    ForwardingMode::Passthrough
}

impl Default for BackendProxyMode {
    fn default() -> Self {
        Self {
            mode: ForwardingMode::Passthrough,
            version: None,
        }
    }
}

fn default_proxy_protocol() -> Option<ProxyProtocolConfig> {
    Some(ProxyProtocolConfig {
        enabled: true,
        trust_strategy: ProxyProtocolTrustStrategy::default(),
        backend_default: BackendProxyMode::default(),
        backend_overrides: None,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendProxyConfig {
    pub mode: ForwardingMode,
    pub version: Option<ProxyProtocolVersionConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingMode {
    Never,
    Passthrough,
    Always,
    Conditional,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocolVersionConfig {
    V1,
    V2,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub cert_chain: String,
    pub cert_key: String,
    pub tls_crypto_provider: CryptoProvider,
    pub tls_versions: Vec<TlsVersion>,
    pub base_domain: String,
    pub external_port: u16,
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub agent_port: u16,
    pub timeouts: Timeouts,
    pub buffer_size: usize,
    pub connect_top_n: usize,
    pub localhost_enabled: bool,
    pub workers: usize,
    pub app_address_ns_prefix: String,
    pub app_address_ns_compat: bool,
    #[serde(default = "default_proxy_protocol")]
    pub proxy_protocol: Option<ProxyProtocolConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Timeouts {
    #[serde(with = "serde_duration")]
    pub connect: Duration,
    #[serde(with = "serde_duration")]
    pub handshake: Duration,
    #[serde(with = "serde_duration")]
    pub total: Duration,

    #[serde(with = "serde_duration")]
    pub cache_top_n: Duration,

    pub data_timeout_enabled: bool,
    #[serde(with = "serde_duration")]
    pub idle: Duration,
    #[serde(with = "serde_duration")]
    pub write: Duration,
    #[serde(with = "serde_duration")]
    pub shutdown: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecycleConfig {
    pub enabled: bool,
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
    #[serde(with = "serde_duration")]
    pub node_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    pub enabled: bool,
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    #[serde(with = "serde_duration")]
    pub broadcast_interval: Duration,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
    pub my_url: String,
    pub bootnode: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub wg: WgConfig,
    pub proxy: ProxyConfig,
    pub certbot: CertbotConfig,
    pub pccs_url: Option<String>,
    pub recycle: RecycleConfig,
    pub state_path: String,
    pub set_ulimit: bool,
    pub rpc_domain: String,
    pub kms_url: String,
    pub admin: AdminConfig,
    pub run_in_dstack: bool,
    pub sync: SyncConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    pub url: String,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
}

impl Config {
    pub fn id(&self) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.wg.public_key.as_bytes());
        hasher.finalize()[..20].to_vec()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdminConfig {
    pub enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub key: String,
    pub certs: String,
    pub mutual: MutualConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MutualConfig {
    pub ca_certs: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CertbotConfig {
    /// Enable certbot
    pub enabled: bool,
    /// Path to the working directory
    pub workdir: String,
    /// ACME server URL
    pub acme_url: String,
    /// Cloudflare API token
    pub cf_api_token: String,
    /// Cloudflare zone ID
    pub cf_zone_id: String,
    /// Auto set CAA record
    pub auto_set_caa: bool,
    /// Domain to issue certificates for
    pub domain: String,
    /// Renew interval
    #[serde(with = "serde_duration")]
    pub renew_interval: Duration,
    /// Time gap before expiration to trigger renewal
    #[serde(with = "serde_duration")]
    pub renew_before_expiration: Duration,
    /// Renew timeout
    #[serde(with = "serde_duration")]
    pub renew_timeout: Duration,
}

impl CertbotConfig {
    fn to_bot_config(&self) -> certbot::CertBotConfig {
        let workdir = certbot::WorkDir::new(&self.workdir);
        certbot::CertBotConfig::builder()
            .auto_create_account(true)
            .cert_dir(workdir.backup_dir())
            .cert_file(workdir.cert_path())
            .key_file(workdir.key_path())
            .credentials_file(workdir.account_credentials_path())
            .acme_url(self.acme_url.clone())
            .cert_subject_alt_names(vec![self.domain.clone()])
            .cf_zone_id(self.cf_zone_id.clone())
            .cf_api_token(self.cf_api_token.clone())
            .renew_interval(self.renew_interval)
            .renew_timeout(self.renew_timeout)
            .renew_expires_in(self.renew_before_expiration)
            .auto_set_caa(self.auto_set_caa)
            .build()
    }

    pub async fn build_bot(&self) -> Result<certbot::CertBot> {
        self.to_bot_config().build_bot().await
    }
}

pub const DEFAULT_CONFIG: &str = include_str!("../gateway.toml");
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("gateway", DEFAULT_CONFIG, config_file, false)
}

pub fn setup_wireguard(config: &WgConfig) -> Result<()> {
    config.validate().context("Invalid wireguard config")?;

    info!("Setting up wireguard interface");

    let ifname = &config.interface;

    // Check if interface exists by trying to run ip link show
    if cmd!(ip link show $ifname > /dev/null).is_ok() {
        info!("WireGuard interface {ifname} already exists");
        return Ok(());
    }

    let addr = format!("{}", config.ip);
    // Interface doesn't exist, create and configure it
    cmd! {
        ip link add $ifname type wireguard;
        ip address add $addr dev $ifname;
        ip link set $ifname up;
    }?;

    info!("Created and configured WireGuard interface {ifname}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_proxy_protocol_defaults() {
        // Test that default values work correctly
        let default_config = default_proxy_protocol().unwrap();
        assert!(default_config.enabled);
        assert!(matches!(
            default_config.trust_strategy.strategy_type,
            TrustStrategyType::All
        ));
        assert!(matches!(
            default_config.backend_default.mode,
            ForwardingMode::Passthrough
        ));
        assert!(default_config.backend_overrides.is_none());
    }

    #[test]
    fn test_proxy_protocol_struct_defaults() {
        // Test that Default trait implementations work correctly
        let trust_strategy = ProxyProtocolTrustStrategy::default();
        assert!(matches!(
            trust_strategy.strategy_type,
            TrustStrategyType::All
        ));
        assert!(trust_strategy.addresses.is_none());
        assert!(trust_strategy.ranges.is_none());

        let backend_mode = BackendProxyMode::default();
        assert!(matches!(backend_mode.mode, ForwardingMode::Passthrough));
        assert!(backend_mode.version.is_none());

        // Test that default_proxy_protocol creates the expected config
        let default_config = default_proxy_protocol().unwrap();
        assert!(default_config.enabled);
        assert!(matches!(
            default_config.trust_strategy.strategy_type,
            TrustStrategyType::All
        ));
        assert!(matches!(
            default_config.backend_default.mode,
            ForwardingMode::Passthrough
        ));
    }

    #[test]
    fn test_validate() {
        // Valid configuration
        let ip = Ipv4Net::from_str("10.1.2.3/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.2.0/30").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.1.2.128/25").unwrap(),
        );
        assert!(result.is_ok());

        // Reserved net does not contain network
        let ip = Ipv4Net::from_str("10.2.0.1/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.0.0/16").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.2.0.128/25").unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Reserved net is not in the network"
        );

        // IP not in reserved net
        let ip = Ipv4Net::from_str("10.1.2.16/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.2.0/30").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.1.2.128/25").unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Wg peer IP is not in the reserved net"
        );

        // Client IP range not in network
        let ip = Ipv4Net::from_str("10.1.2.3/24").unwrap();
        let reserved_net = Ipv4Net::from_str("10.1.2.0/30").unwrap();
        let result = validate(
            ip,
            &[reserved_net],
            Ipv4Net::from_str("10.1.3.128/25").unwrap(),
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Client IP range is not in the network"
        );
    }
}
