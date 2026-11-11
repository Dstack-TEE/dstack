// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! KMS adapter for the shared API authenticator, guarding the admin listener.
//!
//! Unlike the KMS public RPC surface (which authenticates callers by RA-TLS
//! attestation), the admin API is reached by operators/tooling, so it uses the
//! same shared-token/htpasswd HTTP mechanism as the VMM and gateway. The token
//! is configured via `core.admin.auth_token`, or the `DSTACK_KMS_ADMIN_TOKEN` /
//! `ADMIN_API_TOKEN` environment variables, or as its SHA-256 in
//! `core.admin.auth_token_hash`.

use anyhow::{bail, Context, Result};
use dstack_api_auth::{Authenticator, HttpAuthConfig, HttpAuthFairing};
use rocket::Route;
use sha2::{Digest, Sha256};

use crate::config::AdminConfig;

const ENV_ADMIN_TOKEN: &str = "DSTACK_KMS_ADMIN_TOKEN";
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
        Ok(Self(HttpAuthFairing::new(
            authenticator(config)?,
            http_config(),
        )))
    }
}

fn authenticator(config: &AdminConfig) -> Result<Authenticator> {
    let token = if !config.auth_token.is_empty() {
        config.auth_token.trim().to_owned()
    } else {
        std::env::var(ENV_ADMIN_TOKEN)
            .or_else(|_| std::env::var(ENV_ADMIN_TOKEN_COMPAT))
            .unwrap_or_default()
            .trim()
            .to_owned()
    };
    let mut hashes = Vec::new();
    if !token.is_empty() {
        hashes.push(Sha256::digest(token.as_bytes()).into());
    }
    let hash = config.auth_token_hash.trim();
    if !hash.is_empty() {
        let hash = hex::decode(hash)
            .ok()
            .and_then(|hash| <[u8; 32]>::try_from(hash).ok())
            .context("core.admin.auth_token_hash must be a hex SHA-256 digest")?;
        hashes.push(hash);
    }
    if hashes.is_empty() && config.htpasswd_file.as_os_str().is_empty() {
        bail!(
            "admin API is enabled but no credential is configured; set core.admin.auth_token, \
             {ENV_ADMIN_TOKEN}, {ENV_ADMIN_TOKEN_COMPAT}, core.admin.auth_token_hash, \
             core.admin.htpasswd_file, or insecure_no_auth = true (testing only)"
        );
    }
    let mut auth = Authenticator::from_token_hashes(hashes);
    if !config.htpasswd_file.as_os_str().is_empty() {
        auth = auth.with_htpasswd_file(&config.htpasswd_file)?;
    }
    Ok(auth)
}

fn http_config() -> HttpAuthConfig {
    HttpAuthConfig {
        realm: "dstack-kms admin".into(),
        token_header: Some("X-Admin-Token".into()),
        allow_get_query_token: false,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enabled_without_credentials_fails_closed() {
        // the token can also come from the environment; make sure neither var is
        // set so this exercises the missing-credential path.
        std::env::remove_var(ENV_ADMIN_TOKEN);
        std::env::remove_var(ENV_ADMIN_TOKEN_COMPAT);
        let cfg = AdminConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(AdminAuthFairing::from_config(&cfg).is_err());
    }

    #[test]
    fn insecure_no_auth_is_allowed() {
        let cfg = AdminConfig {
            enabled: true,
            insecure_no_auth: true,
            ..Default::default()
        };
        assert!(AdminAuthFairing::from_config(&cfg).is_ok());
    }

    #[test]
    fn a_token_hash_admits_its_token() {
        let cfg = AdminConfig {
            enabled: true,
            auth_token_hash: hex::encode(Sha256::digest(b"secret")),
            ..Default::default()
        };
        let auth = authenticator(&cfg).unwrap();
        assert!(auth.verify_token("secret"));
        assert!(!auth.verify_token("other"));
        let bad = AdminConfig {
            auth_token_hash: "00".into(),
            ..cfg
        };
        assert!(authenticator(&bad).is_err());
    }

    #[test]
    fn configured_token_builds() {
        let cfg = AdminConfig {
            enabled: true,
            auth_token: "secret".into(),
            ..Default::default()
        };
        assert!(AdminAuthFairing::from_config(&cfg).is_ok());
    }
}
