use load_config::load_config;
use rocket::figment::Figment;
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = include_str!("../kms.toml");

pub fn load_config_figment(config_file: Option<&str>) -> Figment {
    load_config("kms", DEFAULT_CONFIG, config_file, false)
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct KmsConfig {
    pub root_ca_cert: String,
    pub root_ca_key: String,
    pub ecdsa_root_key: String,
    pub subject_postfix: String,
    pub pccs_url: String,
    pub boot_authority: BootAuthority,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub(crate) enum BootAuthority {
    #[serde(rename = "dev")]
    Dev,
    #[serde(rename = "webhook")]
    Webhook(Webhook),
}

impl BootAuthority {
    pub fn is_dev(&self) -> bool {
        matches!(self, BootAuthority::Dev)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct Webhook {
    pub url: String,
}
