use anyhow::Result;
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
    pub ip: Ipv4Addr,
    pub client_ip_range: Ipv4Net,
    pub interface: String,
    pub config_path: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyConfig {
    pub cert_chain: String,
    pub cert_key: String,
    pub base_domain: String,
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub tappd_port: u16,
    pub timeouts: Timeouts,
    pub buffer_size: usize,
    pub connect_top_n: usize,
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

#[derive(Debug, Clone, Deserialize)]
pub struct CertbotConfig {
    pub workdir: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecycleConfig {
    pub enabled: bool,
    #[serde(with = "serde_duration")]
    pub interval: Duration,
    #[serde(with = "serde_duration")]
    pub timeout: Duration,
}

mod serde_duration {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if duration == &Duration::MAX {
            return serializer.serialize_str("never");
        }
        let (value, unit) = if duration.as_secs() % (24 * 3600) == 0 {
            (duration.as_secs() / (24 * 3600), "d")
        } else if duration.as_secs() % 3600 == 0 {
            (duration.as_secs() / 3600, "h")
        } else if duration.as_secs() % 60 == 0 {
            (duration.as_secs() / 60, "m")
        } else {
            (duration.as_secs(), "s")
        };
        serializer.serialize_str(&format!("{}{}", value, unit))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom("Duration string cannot be empty"));
        }
        if s == "never" {
            return Ok(Duration::MAX);
        }
        let (value, unit) = s.split_at(s.len() - 1);
        let value = value.parse::<u64>().map_err(serde::de::Error::custom)?;

        let seconds = match unit {
            "s" => value,
            "m" => value * 60,
            "h" => value * 3600,
            "d" => value * 24 * 3600,
            _ => {
                return Err(serde::de::Error::custom(
                    "Invalid time unit. Use s, m, h, or d",
                ))
            }
        };

        Ok(Duration::from_secs(seconds))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub wg: WgConfig,
    pub proxy: ProxyConfig,
    pub certbot: CertbotConfig,
    pub pccs_url: String,
    pub recycle: RecycleConfig,
    pub state_path: String,
    pub set_ulimit: bool,
    pub tls_domain: String,
    pub kms_url: String,
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

pub const DEFAULT_CONFIG: &str = include_str!("../tproxy.toml");
pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("tproxy", DEFAULT_CONFIG, config_file, false)
}

pub fn setup_wireguard(config: &WgConfig) -> Result<()> {
    info!("Setting up wireguard interface");

    let ifname = &config.interface;

    // Check if interface exists by trying to run ip link show
    if cmd!(ip link show $ifname > /dev/null).is_ok() {
        info!("WireGuard interface {ifname} already exists");
        return Ok(());
    }

    let addr = format!("{}/{}", config.ip, config.client_ip_range.prefix_len());
    // Interface doesn't exist, create and configure it
    cmd! {
        ip link add $ifname type wireguard;
        ip address add $addr dev $ifname;
        ip link set $ifname up;
    }?;

    info!("Created and configured WireGuard interface {ifname}");

    Ok(())
}
