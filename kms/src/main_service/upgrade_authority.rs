use crate::config::BootAuthority;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_human_bytes as hex_bytes;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BootInfo {
    #[serde(with = "hex_bytes")]
    pub mrtd: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub image_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub rootfs_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub app_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub compose_hash: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub instance_id: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub device_id: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BootResponse {
    pub is_allowed: bool,
    pub reason: String,
}

impl BootAuthority {
    pub async fn is_allowed(&self, boot_info: &BootInfo) -> Result<BootResponse> {
        match self {
            BootAuthority::Dev => Ok(BootResponse {
                is_allowed: true,
                reason: "".to_string(),
            }),
            BootAuthority::Webhook(webhook) => {
                let client = reqwest::Client::new();
                let response = client.post(&webhook.url).json(&boot_info).send().await?;
                Ok(response.json().await?)
            }
        }
    }
}
