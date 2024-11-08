use std::collections::BTreeMap;

use anyhow::Result;
use rocket::figment::{
    providers::{Format, Toml},
    Figment,
};
use serde::Deserialize;

pub const CONFIG_FILENAME: &str = "kms.toml";
pub const SYSTEM_CONFIG_FILENAME: &str = "/etc/kms/kms.toml";
pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

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

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub allowed_mr: AllowedMr,
    pub root_ca_cert: String,
    pub root_ca_key: String,
    pub subject_postfix: String,
    pub cert_log_dir: String,
    pub allow_any_upgrade: bool,
    pub upgrade_registry_dir: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AppUpgradeRegistry {
    pub registry: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub(crate) struct AllowedMr {
    pub allow_all: bool,
    pub mrtd: Vec<[u8; 48]>,
    pub rtmr0: Vec<[u8; 48]>,
    pub rtmr1: Vec<[u8; 48]>,
    pub rtmr2: Vec<[u8; 48]>,
}

impl<'de> Deserialize<'de> for AllowedMr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawAllowedMr {
            #[serde(default)]
            allow_all: bool,
            #[serde(default)]
            mrtd: Vec<String>,
            #[serde(default)]
            rtmr0: Vec<String>,
            #[serde(default)]
            rtmr1: Vec<String>,
            #[serde(default)]
            rtmr2: Vec<String>,
        }

        let raw = RawAllowedMr::deserialize(deserializer)?;

        fn parse_mrlist<'d, D: serde::Deserializer<'d>>(
            list: Vec<String>,
        ) -> Result<Vec<[u8; 48]>, D::Error> {
            list.into_iter()
                .map(|s| {
                    let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
                    bytes
                        .try_into()
                        .map_err(|_| serde::de::Error::custom("invalid MR config"))
                })
                .collect()
        }

        Ok(AllowedMr {
            allow_all: raw.allow_all,
            mrtd: parse_mrlist::<D>(raw.mrtd)?,
            rtmr0: parse_mrlist::<D>(raw.rtmr0)?,
            rtmr1: parse_mrlist::<D>(raw.rtmr1)?,
            rtmr2: parse_mrlist::<D>(raw.rtmr2)?,
        })
    }
}
