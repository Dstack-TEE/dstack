// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

/// Static configuration for the lite launcher, all from env. The launcher boots
/// with NO license; the operator's courier run drives the rest.
pub struct Config {
    /// Plain-HTTP courier + status port (default 9000). The IAP tunnel is the channel.
    pub port: u16,
    /// Pinned Authority Ed25519 verifying key (base64, 32 bytes). In the measured
    /// compose this is pinned literal; for now read from env. Empty ⇒ fail-closed
    /// (license verification refuses every license).
    pub authority_pubkey: String,
    /// vTPM-sealed persistent dir holding the license high-water + last license
    /// (e.g. /dstack/persistent/lite). license_seq lives at state_dir/license_seq.
    pub state_dir: PathBuf,
    /// Optional self-identity hints when the guest agent can't be reached.
    pub app_id: Option<String>,
    pub compose_hash: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let port = std::env::var("LITE_PORT")
            .unwrap_or_else(|_| "9000".to_string())
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid LITE_PORT: {}", e))?;

        let authority_pubkey = std::env::var("LITE_AUTHORITY_PUBKEY").unwrap_or_default();

        let state_dir = PathBuf::from(
            std::env::var("LITE_STATE_DIR")
                .unwrap_or_else(|_| "/dstack/persistent/lite".to_string()),
        );

        let app_id = non_empty(std::env::var("DSTACK_APP_ID").ok());
        let compose_hash = non_empty(std::env::var("DSTACK_COMPOSE_HASH").ok());

        Ok(Self {
            port,
            authority_pubkey,
            state_dir,
            app_id,
            compose_hash,
        })
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}
