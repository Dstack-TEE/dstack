// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Shared HTTP API authentication for dstack services.
//!
//! Supports bearer/shared-secret tokens, HTTP Basic credentials backed by an
//! Apache htpasswd file, and an optional GET-only query token for compatibility
//! with browser dashboard links.

use std::{path::Path, sync::Arc};

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::{uri::Origin, Header, Method, Status},
    response::Responder,
    Data, Request, Response, Route,
};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};

const UNAUTH_URI: &str = "/__dstack_api_auth_unauthorized";

#[derive(Clone, Default)]
pub struct Authenticator {
    enabled: bool,
    token_hashes: Arc<Vec<[u8; 32]>>,
    htpasswd: Option<Arc<Vec<(String, String)>>>,
}

impl Authenticator {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn from_tokens(tokens: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self {
            enabled: true,
            token_hashes: Arc::new(
                tokens
                    .into_iter()
                    .filter(|token| !token.as_ref().is_empty())
                    .map(|token| sha256(token.as_ref().as_bytes()))
                    .collect(),
            ),
            htpasswd: None,
        }
    }

    pub fn from_token_hashes(hashes: Vec<[u8; 32]>) -> Self {
        Self {
            enabled: true,
            token_hashes: Arc::new(hashes),
            htpasswd: None,
        }
    }

    pub fn with_htpasswd_file(mut self, path: impl AsRef<Path>) -> Result<Self> {
        self.enabled = true;
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read htpasswd file {}", path.display()))?;
        let entries = contents
            .lines()
            .filter(|line| !line.trim().is_empty() && !line.starts_with('#'))
            .map(|line| {
                let (username, hash) = line.split_once(':').with_context(|| {
                    format!("invalid htpasswd entry in {}", path.display())
                })?;
                if username.is_empty() || !matches!(hash.get(..4), Some("$2a$") | Some("$2b$") | Some("$2y$")) {
                    anyhow::bail!(
                        "unsupported htpasswd entry for {username:?} in {}; only bcrypt hashes are supported",
                        path.display()
                    );
                }
                Ok((username.to_owned(), hash.to_owned()))
            })
            .collect::<Result<Vec<_>>>()?;
        if entries.is_empty() {
            anyhow::bail!("htpasswd file {} contains no users", path.display());
        }
        self.htpasswd = Some(Arc::new(entries));
        Ok(self)
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn verify_token(&self, token: &str) -> bool {
        let candidate = sha256(token.as_bytes());
        let matched = self
            .token_hashes
            .iter()
            .fold(Choice::from(0), |matched, expected| {
                matched | candidate.ct_eq(expected)
            });
        bool::from(matched)
    }

    pub fn verify_basic(&self, username: &str, password: &str) -> bool {
        self.htpasswd.as_ref().is_some_and(|entries| {
            entries.iter().any(|(expected_user, hash)| {
                expected_user == username && bcrypt::verify(password, hash).unwrap_or(false)
            })
        })
            // Preserve the old dashboard behavior: Basic user:token and
            // token: are aliases for a shared token.
            || self.verify_token(password)
            || (password.is_empty() && self.verify_token(username))
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Verify a plaintext token against the legacy wire/config representation of
/// a SHA-256 digest. Invalid digest lengths simply fail authentication.
pub fn verify_sha256_token(token: &str, expected: &[u8]) -> bool {
    let candidate = sha256(token.as_bytes());
    expected.len() == candidate.len() && bool::from(candidate.as_slice().ct_eq(expected))
}

#[derive(Clone)]
pub struct HttpAuthConfig {
    pub realm: String,
    pub token_header: Option<String>,
    pub allow_get_query_token: bool,
}

impl Default for HttpAuthConfig {
    fn default() -> Self {
        Self {
            realm: "dstack API".into(),
            token_header: None,
            allow_get_query_token: false,
        }
    }
}

pub struct HttpAuthFairing {
    authenticator: Authenticator,
    config: HttpAuthConfig,
}

impl HttpAuthFairing {
    pub fn new(authenticator: Authenticator, config: HttpAuthConfig) -> Self {
        Self {
            authenticator,
            config,
        }
    }

    fn authorized(&self, req: &Request<'_>) -> bool {
        if !self.authenticator.is_enabled() {
            return true;
        }
        if let Some(header) = &self.config.token_header {
            if req
                .headers()
                .get_one(header)
                .is_some_and(|token| self.authenticator.verify_token(token))
            {
                return true;
            }
        }
        if let Some(value) = req.headers().get_one("Authorization") {
            if let Some(token) = value.strip_prefix("Bearer ") {
                return self.authenticator.verify_token(token.trim());
            }
            if let Some(encoded) = value.strip_prefix("Basic ") {
                if let Some((username, password)) = decode_basic(encoded.trim()) {
                    return self.authenticator.verify_basic(&username, &password);
                }
            }
        }
        self.config.allow_get_query_token
            && req.method() == Method::Get
            && req.query_fields().any(|field| {
                field.name.key_lossy().as_str() == "token"
                    && self.authenticator.verify_token(field.value.as_ref())
            })
    }
}

fn decode_basic(encoded: &str) -> Option<(String, String)> {
    let decoded = BASE64.decode(encoded).ok()?;
    let text = std::str::from_utf8(&decoded).ok()?;
    let (username, password) = text.split_once(':').unwrap_or((text, ""));
    Some((username.to_owned(), password.to_owned()))
}

fn strip_token_query(uri: &Origin<'_>) -> Option<Origin<'static>> {
    let mut found = false;
    let kept: Vec<_> = uri
        .query()?
        .as_str()
        .split('&')
        .filter(|pair| {
            let remove = pair.split('=').next() == Some("token");
            found |= remove;
            !remove && !pair.is_empty()
        })
        .collect();
    found.then(|| {
        let path = uri.path().as_str();
        Origin::parse_owned(if kept.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{}", kept.join("&"))
        })
        .ok()
    })?
}

#[rocket::async_trait]
impl Fairing for HttpAuthFairing {
    fn info(&self) -> Info {
        Info {
            name: "dstack API authentication",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        req.local_cache(|| RequestRealm(self.config.realm.clone()));
        if req.uri().path() == UNAUTH_URI {
            return;
        }
        if !self.authorized(req) {
            if let Ok(uri) = Origin::parse_owned(UNAUTH_URI.to_owned()) {
                req.set_uri(uri);
            }
        } else if self.config.allow_get_query_token {
            if let Some(uri) = strip_token_query(req.uri()) {
                req.set_uri(uri);
            }
        }
    }
}

struct Unauthorized;

impl<'r> Responder<'r, 'static> for Unauthorized {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let realm = &req.local_cache(|| RequestRealm("dstack API".into())).0;
        Response::build()
            .status(Status::Unauthorized)
            .header(Header::new(
                "WWW-Authenticate",
                format!("Basic realm=\"{realm}\""),
            ))
            .ok()
    }
}

struct RequestRealm(String);

#[rocket::get("/__dstack_api_auth_unauthorized")]
fn unauth_get() -> Unauthorized {
    Unauthorized
}
#[rocket::post("/__dstack_api_auth_unauthorized", data = "<_data>")]
fn unauth_post(_data: Data<'_>) -> Unauthorized {
    Unauthorized
}
#[rocket::put("/__dstack_api_auth_unauthorized", data = "<_data>")]
fn unauth_put(_data: Data<'_>) -> Unauthorized {
    Unauthorized
}
#[rocket::patch("/__dstack_api_auth_unauthorized", data = "<_data>")]
fn unauth_patch(_data: Data<'_>) -> Unauthorized {
    Unauthorized
}
#[rocket::delete("/__dstack_api_auth_unauthorized")]
fn unauth_delete() -> Unauthorized {
    Unauthorized
}
#[rocket::options("/__dstack_api_auth_unauthorized")]
fn unauth_options() -> Unauthorized {
    Unauthorized
}
#[rocket::head("/__dstack_api_auth_unauthorized")]
fn unauth_head() -> Unauthorized {
    Unauthorized
}

pub fn routes() -> Vec<Route> {
    rocket::routes![
        unauth_get,
        unauth_post,
        unauth_put,
        unauth_patch,
        unauth_delete,
        unauth_options,
        unauth_head
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rocket::{http::Header, local::asynchronous::Client};

    #[rocket::get("/ok")]
    fn ok() -> &'static str {
        "ok"
    }

    #[rocket::post("/ok")]
    fn post_ok() -> &'static str {
        "ok"
    }

    #[rocket::get("/echo?<token>&<other>")]
    fn echo(token: Option<&str>, other: Option<&str>) -> String {
        format!("{}:{}", token.unwrap_or("none"), other.unwrap_or("none"))
    }

    async fn client(auth: Authenticator) -> Client {
        Client::tracked(
            rocket::build()
                .attach(HttpAuthFairing::new(
                    auth,
                    HttpAuthConfig {
                        realm: "test realm".into(),
                        token_header: Some("X-Admin-Token".into()),
                        allow_get_query_token: true,
                    },
                ))
                .mount("/", rocket::routes![ok, post_ok, echo])
                .mount("/", routes()),
        )
        .await
        .unwrap()
    }

    #[test]
    fn verifies_tokens_and_apache_hashes() {
        let dir = std::env::temp_dir().join(format!("dstack-api-auth-{}", std::process::id()));
        let password = format!("test-password-{}", std::process::id());
        let hash = bcrypt::hash(&password, 4).unwrap();
        std::fs::write(&dir, format!("alice:{hash}\n")).unwrap();
        let auth = Authenticator::from_tokens(["secret"])
            .with_htpasswd_file(&dir)
            .unwrap();
        assert!(auth.verify_token("secret"));
        assert!(!auth.verify_token("wrong"));
        assert!(auth.verify_basic("alice", &password));
        assert!(!auth.verify_basic("alice", &format!("{password}-wrong")));
        let _ = std::fs::remove_file(dir);
    }

    #[rocket::async_test]
    async fn protects_all_methods_and_accepts_compatible_credentials() {
        let client = client(Authenticator::from_tokens(["secret"])).await;
        let response = client.get("/ok").dispatch().await;
        assert_eq!(response.status(), Status::Unauthorized);
        assert_eq!(
            response.headers().get_one("WWW-Authenticate"),
            Some("Basic realm=\"test realm\"")
        );

        assert_eq!(
            client
                .get("/ok")
                .header(Header::new("Authorization", "Bearer secret"))
                .dispatch()
                .await
                .status(),
            Status::Ok
        );
        assert_eq!(
            client
                .get("/ok")
                .header(Header::new("X-Admin-Token", "secret"))
                .dispatch()
                .await
                .status(),
            Status::Ok
        );
        assert_eq!(
            client.get("/ok?token=secret").dispatch().await.status(),
            Status::Ok
        );
        assert_eq!(
            client.post("/ok?token=secret").dispatch().await.status(),
            Status::Unauthorized
        );
        assert_eq!(
            client
                .get("/ok")
                .header(Header::new(
                    "Authorization",
                    format!("Basic {}", BASE64.encode("admin:secret")),
                ))
                .dispatch()
                .await
                .status(),
            Status::Ok
        );
        assert_eq!(
            client
                .put("/ok")
                .header(Header::new("Authorization", "Bearer wrong"))
                .dispatch()
                .await
                .status(),
            Status::Unauthorized
        );
        let body = client
            .get("/echo?token=secret&other=keep")
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap();
        assert_eq!(body, "none:keep");
    }

    #[rocket::async_test]
    async fn enabled_with_no_credentials_denies_access() {
        let client = client(Authenticator::from_tokens(Vec::<String>::new())).await;
        assert_eq!(
            client.get("/ok").dispatch().await.status(),
            Status::Unauthorized
        );
    }
}
