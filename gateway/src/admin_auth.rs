// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rocket::{
    catch, catchers,
    http::Status,
    request::{FromRequest, Outcome},
    response::{Responder, Response},
    Catcher, Request,
};
use sha2::{Digest, Sha256};
use std::io::Cursor;

use crate::config::AdminConfig;

const ENV_ADMIN_TOKEN: &str = "DSTACK_GATEWAY_ADMIN_TOKEN";

pub struct AdminAuth {
    token_hash: Option<[u8; 32]>,
}

impl AdminAuth {
    pub fn from_config(config: &AdminConfig) -> Result<Self> {
        if !config.enabled || config.insecure_no_auth {
            return Ok(Self { token_hash: None });
        }

        let token = config
            .api_token
            .clone()
            .filter(|token| !token.trim().is_empty())
            .or_else(|| std::env::var(ENV_ADMIN_TOKEN).ok())
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty());

        let Some(token) = token else {
            bail!(
                "admin API is enabled but no API token is configured; set core.admin.api_token \
                 or {ENV_ADMIN_TOKEN}"
            );
        };

        Ok(Self {
            token_hash: Some(hash_token(&token)),
        })
    }

    pub fn verify(&self, authorization: Option<&str>) -> bool {
        let Some(expected) = self.token_hash else {
            return true;
        };

        let Some(header) = authorization else {
            return false;
        };

        if let Some(token) = parse_bearer_token(header) {
            return verify_token(&expected, token);
        }

        if let Some(token) = parse_basic_password(header) {
            return verify_token(&expected, &token);
        }

        false
    }
}

#[catch(401)]
fn unauthorized() -> BasicAuthChallenge {
    BasicAuthChallenge
}

struct BasicAuthChallenge;

impl<'r> Responder<'r, 'static> for BasicAuthChallenge {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build()
            .status(Status::Unauthorized)
            .raw_header(
                "WWW-Authenticate",
                r#"Basic realm="dstack gateway admin", charset="UTF-8""#,
            )
            .sized_body(12, Cursor::new("Unauthorized"))
            .ok()
    }
}

pub fn catchers() -> Vec<Catcher> {
    catchers![unauthorized]
}

fn verify_token(expected: &[u8; 32], token: &str) -> bool {
    fixed_time_eq(&expected, &hash_token(token))
}

#[derive(Debug)]
pub struct AdminAuthorized;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AdminAuthorized {
    type Error = &'static str;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let Some(auth) = request.rocket().state::<AdminAuth>() else {
            return Outcome::Error((Status::InternalServerError, "admin auth state missing"));
        };

        if auth.verify(request.headers().get_one("Authorization")) {
            Outcome::Success(AdminAuthorized)
        } else {
            Outcome::Error((Status::Unauthorized, "invalid admin API token"))
        }
    }
}

fn parse_bearer_token(header: &str) -> Option<&str> {
    header.strip_prefix("Bearer ")
}

fn parse_basic_password(header: &str) -> Option<String> {
    let credentials = header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(credentials).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (_username, password) = decoded.split_once(':')?;
    Some(password.to_string())
}

fn hash_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn fixed_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_bearer_token() {
        let auth = AdminAuth {
            token_hash: Some(hash_token("secret")),
        };

        assert!(auth.verify(Some("Bearer secret")));
        assert!(!auth.verify(Some("Bearer wrong")));
        assert!(!auth.verify(Some("secret")));
        assert!(!auth.verify(None));
    }

    #[test]
    fn verifies_basic_auth_password() {
        let auth = AdminAuth {
            token_hash: Some(hash_token("secret")),
        };

        assert!(auth.verify(Some("Basic YWRtaW46c2VjcmV0")));
        assert!(!auth.verify(Some("Basic YWRtaW46d3Jvbmc=")));
        assert!(!auth.verify(Some("Basic bm8tY29sb24=")));
    }

    #[test]
    fn disabled_auth_allows_requests() {
        let auth = AdminAuth { token_hash: None };

        assert!(auth.verify(None));
        assert!(auth.verify(Some("Bearer anything")));
    }

    #[test]
    fn blank_config_token_falls_back_to_env() {
        // Single test exercising both empty and whitespace api_token to avoid
        // parallel tests racing on the process-wide DSTACK_GATEWAY_ADMIN_TOKEN.
        //
        // Reproduces the regression where api_token = "" in the baked default
        // gateway.toml shadowed the env-var fallback.
        for blank in ["", "   "] {
            let token = "env-token-value";
            std::env::set_var(ENV_ADMIN_TOKEN, token);
            let auth = AdminAuth::from_config(&AdminConfig {
                enabled: true,
                api_token: Some(blank.to_string()),
                insecure_no_auth: false,
            })
            .expect("blank config token must defer to env-var");
            std::env::remove_var(ENV_ADMIN_TOKEN);

            assert!(
                auth.verify(Some(&format!("Bearer {token}"))),
                "expected fallback to env-var when api_token={blank:?}"
            );
            assert!(!auth.verify(Some("Bearer wrong")));
        }
    }
}
