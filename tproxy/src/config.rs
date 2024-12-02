use ipnet::Ipv4Net;
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::time::Duration;

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
    pub connect_timeout: u16,
    pub first_byte_timeout: u16,
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
}

pub const CONFIG_FILENAME: &str = "tproxy.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/tproxy/tproxy.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../tproxy.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    let leaf_config = match config_file {
        Some(path) => Toml::file(path),
        None => Toml::file(CONFIG_FILENAME),
    };
    Figment::from(rocket::Config::default())
        .merge(Toml::string(DEFAULT_CONFIG))
        .merge(Toml::file(SYSTEM_CONFIG_FILENAME))
        .merge(leaf_config)
}
