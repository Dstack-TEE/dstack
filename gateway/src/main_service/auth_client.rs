// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use crate::config::AuthConfig;
use anyhow::{Context, Result};
use ra_tls::attestation::AppInfo;
use reqwest::Client;

pub(crate) struct AuthClient {
    config: AuthConfig,
    client: Client,
}

impl AuthClient {
    pub(crate) fn new(config: AuthConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    pub(crate) async fn ensure_app_authorized(&self, app_info: &AppInfo) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }
        let req = self.client.post(&self.config.url).json(app_info).send();
        let res = tokio::time::timeout(self.config.timeout, req)
            .await
            .context("Auth timeout")?
            .context("Failed to send request")?;
        res.error_for_status().context("Request failed")?;
        Ok(())
    }
}
