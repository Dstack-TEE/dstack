// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

use std::path::PathBuf;

pub struct Config {
    pub port: u16,
    pub port_mtls: u16,
    pub kms_volume: PathBuf,
    pub authority_pubkey: String,
    pub kms_url: String,
    pub lease_ttl_secs: u64,
    pub slot_quota: usize,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8001".to_string())
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid PORT: {}", e))?;

        let port_mtls = std::env::var("PORT_MTLS")
            .unwrap_or_else(|_| "8002".to_string())
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid PORT_MTLS: {}", e))?;

        let kms_volume = PathBuf::from(
            std::env::var("KMS_VOLUME").unwrap_or_else(|_| "/kms".to_string()),
        );

        let authority_pubkey = std::env::var("AUTHORITY_PUBKEY").unwrap_or_default();

        let kms_url = std::env::var("KMS_URL")
            .unwrap_or_else(|_| "http://kms:8000".to_string());

        let lease_ttl_secs = std::env::var("LEASE_TTL_SECS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse::<u64>()
            .map_err(|e| anyhow::anyhow!("invalid LEASE_TTL_SECS: {}", e))?;

        let slot_quota = std::env::var("SLOT_QUOTA")
            .unwrap_or_else(|_| "100".to_string())
            .parse::<usize>()
            .map_err(|e| anyhow::anyhow!("invalid SLOT_QUOTA: {}", e))?;

        Ok(Self {
            port,
            port_mtls,
            kms_volume,
            authority_pubkey,
            kms_url,
            lease_ttl_secs,
            slot_quota,
        })
    }
}
