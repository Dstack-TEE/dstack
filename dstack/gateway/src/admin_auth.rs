// SPDX-FileCopyrightText: © 2025-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Backwards-compatible Gateway adapter for the shared API authenticator.

use anyhow::{bail, Result};
use dstack_api_auth::{Authenticator, HttpAuthConfig, HttpAuthFairing};
use rocket::Route;

use crate::config::AdminConfig;

const ENV_ADMIN_TOKEN: &str = "DSTACK_GATEWAY_ADMIN_TOKEN";
const ENV_ADMIN_TOKEN_COMPAT: &str = "ADMIN_API_TOKEN";

pub struct AdminAuthFairing(HttpAuthFairing);

impl AdminAuthFairing {
    pub fn from_config(config: &AdminConfig) -> Result<Self> {
        if config.insecure_no_auth {
            return Ok(Self(HttpAuthFairing::new(
                Authenticator::disabled(),
                http_config(),
            )));
        }
        let token = if !config.auth_token.is_empty() {
            config.auth_token.trim().to_owned()
        } else {
            std::env::var(ENV_ADMIN_TOKEN)
                .or_else(|_| std::env::var(ENV_ADMIN_TOKEN_COMPAT))
                .unwrap_or_default()
                .trim()
                .to_owned()
        };
        if token.is_empty() && config.htpasswd_file.as_os_str().is_empty() {
            bail!(
                "admin API is enabled but neither auth_token nor htpasswd_file is configured; \
                 set core.admin.auth_token, {ENV_ADMIN_TOKEN}, {ENV_ADMIN_TOKEN_COMPAT}, \
                 core.admin.htpasswd_file, or insecure_no_auth = true (testing only)"
            );
        }
        let mut auth = Authenticator::from_tokens([token]);
        if !config.htpasswd_file.as_os_str().is_empty() {
            auth = auth.with_htpasswd_file(&config.htpasswd_file)?;
        }
        Ok(Self(HttpAuthFairing::new(auth, http_config())))
    }
}

fn http_config() -> HttpAuthConfig {
    HttpAuthConfig {
        realm: "dstack-gateway admin".into(),
        token_header: Some("X-Admin-Token".into()),
        allow_get_query_token: true,
    }
}

#[rocket::async_trait]
impl rocket::fairing::Fairing for AdminAuthFairing {
    fn info(&self) -> rocket::fairing::Info {
        self.0.info()
    }
    async fn on_request(&self, req: &mut rocket::Request<'_>, data: &mut rocket::Data<'_>) {
        self.0.on_request(req, data).await
    }
}

pub fn routes() -> Vec<Route> {
    dstack_api_auth::routes()
}
