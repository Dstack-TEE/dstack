// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome},
    Request,
};
use sha2::{Digest, Sha256};

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

    fn verify(&self, authorization: Option<&str>) -> bool {
        let Some(expected) = self.token_hash else {
            return true;
        };
        let Some(token) = authorization.and_then(parse_bearer_token) else {
            return false;
        };
        fixed_time_eq(&expected, &hash_token(token))
    }
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
    fn disabled_auth_allows_requests() {
        let auth = AdminAuth { token_hash: None };

        assert!(auth.verify(None));
        assert!(auth.verify(Some("Bearer anything")));
    }
}
