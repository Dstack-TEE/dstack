// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Admin server authentication.
//!
//! Attaches to the admin Rocket instance and rejects requests that do not
//! present the configured shared secret. The token is accepted via, in order:
//!   1. `X-Admin-Token` header (any method)
//!   2. `Authorization: Bearer <token>` header (any method)
//!   3. `?token=<token>` query parameter (GET only, for dashboard links)
//!
//! For (3), the `token` query parameter is stripped from the request URI after
//! successful validation so it doesn't propagate to access logs, downstream
//! handlers, or the Referer header.
//!
//! Rejected requests are forwarded to a sentinel route that returns HTTP 401,
//! so all admin routes (prpc-generated and dashboard) are protected by a single
//! attachment without modifying the route declarations.
//!
//! The token is only ever held in memory as its SHA-256 hash; the configured
//! plaintext is dropped right after the fairing is constructed.

use anyhow::{bail, Result};
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{uri::Origin, Method, Status},
    Data, Request, Route,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::AdminConfig;

const UNAUTH_URI: &str = "/__admin_unauthorized";
const HEADER_NAME: &str = "X-Admin-Token";
const QUERY_PARAM: &str = "token";
const ENV_ADMIN_TOKEN: &str = "DSTACK_GATEWAY_ADMIN_TOKEN";
const ENV_ADMIN_TOKEN_COMPAT: &str = "ADMIN_API_TOKEN";

pub struct AdminAuthFairing {
    /// SHA-256 of the configured token. `None` = auth disabled (insecure mode).
    token_hash: Option<[u8; 32]>,
}

impl AdminAuthFairing {
    /// Build a fairing from a resolved plaintext token. Empty disables auth.
    pub fn new(token: &str) -> Self {
        Self {
            token_hash: (!token.is_empty()).then(|| sha256(token.as_bytes())),
        }
    }

    /// Resolve a token from config + env, applying the auth policy:
    ///   - `insecure_no_auth = true` → disabled (caller is expected to warn)
    ///   - else require a non-empty token from `admin_token`,
    ///     `DSTACK_GATEWAY_ADMIN_TOKEN`, or `ADMIN_API_TOKEN`.
    pub fn from_config(config: &AdminConfig) -> Result<Self> {
        if config.insecure_no_auth {
            return Ok(Self { token_hash: None });
        }
        let token = if !config.admin_token.is_empty() {
            config.admin_token.clone()
        } else {
            std::env::var(ENV_ADMIN_TOKEN)
                .or_else(|_| std::env::var(ENV_ADMIN_TOKEN_COMPAT))
                .unwrap_or_default()
        };
        let token = token.trim();
        if token.is_empty() {
            bail!(
                "admin API is enabled but no admin_token is configured; \
                 set core.admin.admin_token, {ENV_ADMIN_TOKEN}, or {ENV_ADMIN_TOKEN_COMPAT}, \
                 or set core.admin.insecure_no_auth = true (testing only)"
            );
        }
        Ok(Self::new(token))
    }

    fn extract_token(req: &Request<'_>) -> Option<String> {
        if let Some(t) = req.headers().get_one(HEADER_NAME) {
            return Some(t.to_string());
        }
        if let Some(auth) = req.headers().get_one("Authorization") {
            if let Some(t) = auth.strip_prefix("Bearer ") {
                return Some(t.to_string());
            }
        }
        // Query token is intended for browser links to the dashboard, so only
        // accept it on GET to avoid leaking via mutating request URIs.
        if req.method() == Method::Get {
            for field in req.query_fields() {
                if field.name.key_lossy().as_str() == QUERY_PARAM {
                    return Some(field.value.to_string());
                }
            }
        }
        None
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Rebuild the request URI without the `token` query parameter, if present.
/// Returns `None` when there is nothing to strip.
fn strip_token_query(uri: &Origin<'_>) -> Option<Origin<'static>> {
    let query = uri.query()?.as_str();
    let mut kept = Vec::new();
    let mut found = false;
    for pair in query.split('&') {
        let key = pair.split('=').next().unwrap_or("");
        if key == QUERY_PARAM {
            found = true;
        } else if !pair.is_empty() {
            kept.push(pair);
        }
    }
    if !found {
        return None;
    }
    let path = uri.path().as_str();
    let new_uri = if kept.is_empty() {
        path.to_string()
    } else {
        format!("{}?{}", path, kept.join("&"))
    };
    Origin::parse_owned(new_uri).ok()
}

#[rocket::async_trait]
impl Fairing for AdminAuthFairing {
    fn info(&self) -> Info {
        Info {
            name: "admin auth",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        let Some(expected_hash) = self.token_hash.as_ref() else {
            return;
        };
        // Avoid infinite re-routing if the fairing fires on the sentinel itself.
        if req.uri().path() == UNAUTH_URI {
            return;
        }
        let provided = Self::extract_token(req).unwrap_or_default();
        let provided_hash = sha256(provided.as_bytes());
        let matches: bool = provided_hash.ct_eq(expected_hash).into();
        if !matches {
            if let Ok(origin) = Origin::parse_owned(UNAUTH_URI.to_string()) {
                req.set_uri(origin);
            }
            return;
        }
        // Authorized — strip ?token=... so it doesn't propagate to logs/handlers.
        if let Some(stripped) = strip_token_query(req.uri()) {
            req.set_uri(stripped);
        }
    }
}

// Sentinel 401 handlers for every HTTP method Rocket can dispatch. We have to
// enumerate them because Rocket doesn't support a method-agnostic route.

#[rocket::get("/__admin_unauthorized")]
fn unauth_get() -> Status {
    Status::Unauthorized
}

#[rocket::post("/__admin_unauthorized", data = "<_data>")]
fn unauth_post(_data: Data<'_>) -> Status {
    Status::Unauthorized
}

#[rocket::put("/__admin_unauthorized", data = "<_data>")]
fn unauth_put(_data: Data<'_>) -> Status {
    Status::Unauthorized
}

#[rocket::patch("/__admin_unauthorized", data = "<_data>")]
fn unauth_patch(_data: Data<'_>) -> Status {
    Status::Unauthorized
}

#[rocket::delete("/__admin_unauthorized")]
fn unauth_delete() -> Status {
    Status::Unauthorized
}

#[rocket::options("/__admin_unauthorized")]
fn unauth_options() -> Status {
    Status::Unauthorized
}

#[rocket::head("/__admin_unauthorized")]
fn unauth_head() -> Status {
    Status::Unauthorized
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        unauth_get,
        unauth_post,
        unauth_put,
        unauth_patch,
        unauth_delete,
        unauth_options,
        unauth_head,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::http::{ContentType, Header, Status};
    use rocket::local::asynchronous::Client;

    #[rocket::get("/protected")]
    fn protected_get() -> &'static str {
        "ok"
    }

    #[rocket::post("/protected", data = "<_data>")]
    fn protected_post(_data: Data<'_>) -> &'static str {
        "ok"
    }

    #[rocket::get("/echo?<token>&<other>")]
    fn echo(token: Option<&str>, other: Option<&str>) -> String {
        format!(
            "token={} other={}",
            token.unwrap_or("<absent>"),
            other.unwrap_or("<absent>")
        )
    }

    async fn make_client(token: &str) -> Client {
        let r = rocket::build()
            .attach(AdminAuthFairing::new(token))
            .mount("/", routes())
            .mount("/", rocket::routes![protected_get, protected_post, echo]);
        Client::tracked(r).await.unwrap()
    }

    #[rocket::async_test]
    async fn empty_token_disables_auth() {
        let client = make_client("").await;
        let resp = client.get("/protected").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
        let resp = client.post("/protected").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn missing_token_returns_401() {
        let client = make_client("s3cret").await;
        let resp = client.get("/protected").dispatch().await;
        assert_eq!(resp.status(), Status::Unauthorized);
        let resp = client.post("/protected").dispatch().await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn header_token_accepted() {
        let client = make_client("s3cret").await;
        let resp = client
            .get("/protected")
            .header(Header::new(HEADER_NAME, "s3cret"))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let resp = client
            .post("/protected")
            .header(ContentType::JSON)
            .header(Header::new(HEADER_NAME, "s3cret"))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn bearer_token_accepted() {
        let client = make_client("s3cret").await;
        let resp = client
            .get("/protected")
            .header(Header::new("Authorization", "Bearer s3cret"))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn wrong_token_rejected() {
        let client = make_client("s3cret").await;
        let resp = client
            .get("/protected")
            .header(Header::new(HEADER_NAME, "wrong"))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn header_takes_precedence_over_query() {
        let client = make_client("s3cret").await;
        // Wrong query token but correct header → authorized.
        let resp = client
            .get("/protected?token=wrong")
            .header(Header::new(HEADER_NAME, "s3cret"))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
    }

    #[rocket::async_test]
    async fn query_token_only_accepted_on_get() {
        let client = make_client("s3cret").await;
        // GET with ?token= → allowed
        let resp = client.get("/protected?token=s3cret").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
        // POST with ?token= → rejected (query auth not honored on mutating methods)
        let resp = client.post("/protected?token=s3cret").dispatch().await;
        assert_eq!(resp.status(), Status::Unauthorized);
    }

    #[rocket::async_test]
    async fn query_token_stripped_after_auth() {
        let client = make_client("s3cret").await;
        // Token is stripped → handler sees no `token` param, only `other`.
        let resp = client.get("/echo?token=s3cret&other=keep").dispatch().await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert_eq!(body, "token=<absent> other=keep");
    }

    #[rocket::async_test]
    async fn query_token_stripped_when_authed_via_header() {
        let client = make_client("s3cret").await;
        let resp = client
            .get("/echo?token=anything&other=keep")
            .header(Header::new(HEADER_NAME, "s3cret"))
            .dispatch()
            .await;
        assert_eq!(resp.status(), Status::Ok);
        let body = resp.into_string().await.unwrap();
        assert_eq!(body, "token=<absent> other=keep");
    }

    fn hash_of(fairing: &AdminAuthFairing) -> Option<[u8; 32]> {
        fairing.token_hash
    }

    #[test]
    fn from_config_disabled_when_insecure_flag_set() {
        let cfg = AdminConfig {
            enabled: true,
            admin_token: String::new(),
            insecure_no_auth: true,
        };
        let fairing = match AdminAuthFairing::from_config(&cfg) {
            Ok(f) => f,
            Err(e) => panic!("expected Ok, got err: {e}"),
        };
        assert!(hash_of(&fairing).is_none());
    }

    #[test]
    fn from_config_uses_config_token() {
        let cfg = AdminConfig {
            enabled: true,
            admin_token: "from-config".into(),
            insecure_no_auth: false,
        };
        let fairing = match AdminAuthFairing::from_config(&cfg) {
            Ok(f) => f,
            Err(e) => panic!("expected Ok, got err: {e}"),
        };
        assert_eq!(hash_of(&fairing), Some(sha256(b"from-config")));
    }

    // Env-touching cases are combined into a single test so cargo's parallel
    // runner doesn't race on `DSTACK_GATEWAY_ADMIN_TOKEN` / `ADMIN_API_TOKEN`.
    #[test]
    fn from_config_env_paths() {
        let empty_cfg = AdminConfig {
            enabled: true,
            admin_token: String::new(),
            insecure_no_auth: false,
        };

        // Baseline: no env, no config token → error.
        unsafe {
            std::env::remove_var(ENV_ADMIN_TOKEN);
            std::env::remove_var(ENV_ADMIN_TOKEN_COMPAT);
        }
        let err = match AdminAuthFairing::from_config(&empty_cfg) {
            Err(e) => e,
            Ok(_) => panic!("expected error, got Ok"),
        };
        assert!(err.to_string().contains("no admin_token is configured"));

        // Primary env var picked up.
        unsafe {
            std::env::set_var(ENV_ADMIN_TOKEN, "from-env");
        }
        let fairing = match AdminAuthFairing::from_config(&empty_cfg) {
            Ok(f) => f,
            Err(e) => panic!("expected Ok, got err: {e}"),
        };
        assert_eq!(hash_of(&fairing), Some(sha256(b"from-env")));
        unsafe {
            std::env::remove_var(ENV_ADMIN_TOKEN);
        }

        // Compat env var picked up when primary is absent.
        unsafe {
            std::env::set_var(ENV_ADMIN_TOKEN_COMPAT, "from-compat");
        }
        let fairing = match AdminAuthFairing::from_config(&empty_cfg) {
            Ok(f) => f,
            Err(e) => panic!("expected Ok, got err: {e}"),
        };
        assert_eq!(hash_of(&fairing), Some(sha256(b"from-compat")));
        unsafe {
            std::env::remove_var(ENV_ADMIN_TOKEN_COMPAT);
        }
    }

    #[rocket::async_test]
    async fn unauth_returns_401_on_all_methods() {
        let client = make_client("s3cret").await;
        // PUT / DELETE / PATCH / OPTIONS to a protected URI with no token
        // should be rewritten to the sentinel and return 401, not 404.
        for m in [Method::Put, Method::Delete, Method::Patch, Method::Options] {
            let resp = client.req(m, "/protected").dispatch().await;
            assert_eq!(
                resp.status(),
                Status::Unauthorized,
                "method {m:?} expected 401, got {}",
                resp.status()
            );
        }
    }
}
