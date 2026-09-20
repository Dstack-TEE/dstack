// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! KMS adapter for the shared API authenticator, guarding the onboarding listener.
//!
//! RA-TLS cannot gate this listener. Onboarding runs before the KMS has any
//! certificate to serve, and the caller is an operator - or the onboarding web
//! UI in their browser - not an attested peer. So it uses the same
//! shared-token/htpasswd mechanism as the admin API, configured via
//! `core.onboard.auth_token` or the `DSTACK_KMS_ONBOARD_TOKEN` environment
//! variable.
//!
//! Unlike the admin API this one defaults to open rather than failing closed:
//! the documented bring-up calls `Onboard.Bootstrap` and `/finish` with plain
//! `curl`, so requiring a credential would break every existing deployment.
//! Leaving it open is warned about at startup, because until `/finish` runs the
//! listener answers on whatever address `core.onboard` binds - `0.0.0.0` by
//! default, published by the shipped compose file - and an anonymous caller can
//! then choose the KMS domain, name the KMS to onboard from, or stop the
//! bring-up.

use anyhow::Result;
use dstack_api_auth::{Authenticator, HttpAuthConfig, HttpAuthFairing};
use rocket::Route;
use tracing::warn;

use crate::config::OnboardConfig;

const ENV_ONBOARD_TOKEN: &str = "DSTACK_KMS_ONBOARD_TOKEN";

pub struct OnboardAuthFairing(HttpAuthFairing);

impl OnboardAuthFairing {
    pub fn from_config(config: &OnboardConfig) -> Result<Self> {
        let token = if config.auth_token.is_empty() {
            std::env::var(ENV_ONBOARD_TOKEN).unwrap_or_default()
        } else {
            config.auth_token.clone()
        };
        let token = token.trim().to_owned();
        let has_htpasswd = !config.htpasswd_file.as_os_str().is_empty();
        if token.is_empty() && !has_htpasswd {
            warn!(
                "the onboarding listener is served without authentication; anyone who can reach \
                 core.onboard address:port until onboarding finishes can bootstrap this KMS or \
                 stop it from starting. set core.onboard.auth_token, {ENV_ONBOARD_TOKEN}, or \
                 core.onboard.htpasswd_file"
            );
            return Ok(Self(HttpAuthFairing::new(
                Authenticator::disabled(),
                http_config(),
            )));
        }
        let mut auth = Authenticator::from_tokens([token]);
        if has_htpasswd {
            auth = auth.with_htpasswd_file(&config.htpasswd_file)?;
        }
        Ok(Self(HttpAuthFairing::new(auth, http_config())))
    }
}

fn http_config() -> HttpAuthConfig {
    HttpAuthConfig {
        realm: "dstack-kms onboard".into(),
        token_header: Some("X-Onboard-Token".into()),
        // The onboarding UI is opened in a browser, which cannot set a header
        // on a plain link; the admin API has no such caller and keeps this off.
        allow_get_query_token: true,
    }
}

#[rocket::async_trait]
impl rocket::fairing::Fairing for OnboardAuthFairing {
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
