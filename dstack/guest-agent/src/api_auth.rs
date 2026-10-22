// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Access control for the guest agent's external listener.
//!
//! Every request that reaches `[external]` names a scope, and the caller has
//! to be granted it: either by an Ed25519 JWT, or -- when the host configured
//! it -- by being anonymous. Nothing is granted by default.
//!
//! This is deliberately not a trust boundary. The measured `public_*` switches
//! in app-compose still decide whether confidential data (logs, sysinfo, TCB
//! info) may leave the TEE at all; a scope can only narrow that, never widen
//! it. What scopes decide is who may *ask* -- which the host configures, and
//! which therefore cannot be part of the measurement.

use std::{
    sync::{Arc, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use dstack_api_auth::jwt::{self, IssuerKeys, ScopeSet, Verifier};
use dstack_types::{GuestAgentApiConfig, SysConfig};
use ed25519_dalek::VerifyingKey;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::uri::Origin,
    request::{FromRequest, Outcome},
    Data, Request,
};
use tracing::warn;

/// What a caller may do on the external listener.
#[derive(Clone)]
pub struct GuestApiAuth {
    verifier: Verifier,
    anonymous: ScopeSet,
    /// The app id every token must be bound to. Not known until the boot
    /// attestation has been decoded: until then anonymous access still works,
    /// but no token can be checked, so none is accepted.
    app_id: Arc<OnceLock<String>>,
}

impl GuestApiAuth {
    /// Build from sys-config, given the app root key (if it parsed) and the
    /// app id.
    ///
    /// `anonymous_scopes` is validated eagerly: a name outside the vocabulary
    /// never matches anything, so a typo would otherwise read as "the host
    /// asked for a permission that does not exist" only when someone could
    /// not reach the dashboard.
    pub fn new(config: Option<&GuestAgentApiConfig>, app_root_key: Option<&[u8]>) -> Result<Self> {
        let config = config.cloned().unwrap_or_default();
        let anonymous = ScopeSet::from_names(config.anonymous_scopes.iter().cloned());
        for name in config.anonymous_scopes {
            if !jwt::scope::is_known(&name) {
                anyhow::bail!("guest_agent_api: unknown anonymous scope {name:?}");
            }
        }

        let internal = match app_root_key {
            Some(root) => {
                let secret = ra_tls::api_v1::derive_app_key(
                    root,
                    jwt::INTERNAL_ISSUER_DOMAIN,
                    ra_tls::api_v1::KeyAlgorithm::Ed25519,
                )
                .context("failed to derive the internal issuer key")?;
                Some(ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key())
            }
            None => None,
        };

        let mut external = Vec::with_capacity(config.external_issuers.len());
        for issuer in config.external_issuers {
            let mut keys = Vec::with_capacity(issuer.public_keys.len());
            for encoded in &issuer.public_keys {
                let bytes = hex::decode(encoded)
                    .with_context(|| format!("issuer {:?}: public key is not hex", issuer.name))?;
                let Ok(bytes): Result<[u8; 32], _> = bytes.try_into() else {
                    anyhow::bail!("issuer {:?}: public key must be 32 bytes", issuer.name);
                };
                keys.push(VerifyingKey::from_bytes(&bytes).with_context(|| {
                    format!(
                        "issuer {:?}: public key is not a valid Ed25519 key",
                        issuer.name
                    )
                })?);
            }
            if keys.is_empty() {
                warn!("issuer {:?} has no public keys", issuer.name);
            }
            external.push(IssuerKeys {
                name: issuer.name,
                keys,
            });
        }

        Ok(Self {
            verifier: Verifier::new(internal, external),
            anonymous,
            app_id: Arc::default(),
        })
    }

    /// Build from a sys-config file's contents.
    pub fn from_sys_config(sys_config: &SysConfig, app_root_key: Option<&[u8]>) -> Result<Self> {
        Self::new(sys_config.guest_agent_api.as_ref(), app_root_key)
    }

    /// Bind tokens to `app_id`. Called once the boot attestation has been
    /// decoded; a second call is ignored, since the value cannot change.
    pub fn bind_app_id(&self, app_id: String) {
        let _ = self.app_id.set(app_id);
    }

    /// The scopes a request carries, or `Err` when it presented a token that
    /// did not verify.
    ///
    /// A rejected token never falls back to anonymous: a caller that meant to
    /// authenticate and got it wrong should see a refusal, not whatever the
    /// host happened to leave open.
    fn resolve(&self, token: Option<&str>) -> Result<ScopeSet> {
        let Some(token) = token else {
            return Ok(self.anonymous.clone());
        };
        let Some(app_id) = self.app_id.get().map(String::as_str) else {
            anyhow::bail!("no token can be accepted until the app identity is known");
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let granted = self
            .verifier
            .verify(token, app_id, now)
            .context("rejected bearer token")?;
        Ok(self.anonymous.union(&granted))
    }
}

/// The scopes in force for one request, published by [`ScopeFairing`].
///
/// A request guard rather than a fairing-only side effect because the
/// dashboard renders *parts* of itself by scope: it needs the set, not a
/// yes/no.
pub struct EffectiveScopes(pub ScopeSet);

impl EffectiveScopes {
    pub fn allows(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for EffectiveScopes {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, ()> {
        match request.local_cache(|| None::<ScopeSet>) {
            Some(scopes) => Outcome::Success(EffectiveScopes(scopes.clone())),
            None => Outcome::Forward(rocket::http::Status::Forbidden),
        }
    }
}

/// The scope a request to the external listener needs, or `None` when the
/// request names no scope at all (an unknown route, which the router answers).
///
/// `/prpc` and `/prpc/v0` are the same frozen surface, and the frozen mounts
/// trim the `Worker.` prefix, so `/prpc/Worker.Info`, `/prpc/v0/Info` and
/// `/prpc/Info` are one route with three spellings. Normalising here is what
/// keeps a caller from picking the spelling whose check was forgotten.
///
/// The segments come from Rocket's own parser rather than from the raw path,
/// because that is what the router matches on: it percent-decodes and drops
/// empty segments, so `/%70rpc/Info` and `/prpc//Info` reach the same handler
/// as `/prpc/Info`. Comparing raw strings would let those spellings through
/// unchecked.
pub fn required_scope(path: &str) -> Option<&'static str> {
    let origin = Origin::parse(path).ok()?;
    let segments: Vec<&str> = origin.path().segments().filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        [] => Some(jwt::scope::DASHBOARD),
        ["metrics"] => Some(jwt::scope::METRICS),
        ["logs", ..] => Some(jwt::scope::LOGS),
        _ => None,
    }
    .or_else(|| {
        let method = match segments.as_slice() {
            ["prpc", method] | ["prpc", "v0" | "v1", method] => *method,
            _ => return None,
        };
        match method.strip_prefix("Worker.").unwrap_or(method) {
            "Version" => Some(jwt::scope::VERSION),
            "Health" => Some(jwt::scope::HEALTH),
            "Info" => Some(jwt::scope::INFO),
            "GetAttestationForAppKey" => Some(jwt::scope::ATTEST_APP_KEY),
            _ => None,
        }
    })
}

/// Refuses a request whose caller lacks the scope it names.
pub struct ScopeFairing {
    auth: GuestApiAuth,
}

impl ScopeFairing {
    pub fn new(auth: GuestApiAuth) -> Self {
        Self { auth }
    }
}

#[rocket::async_trait]
impl Fairing for ScopeFairing {
    fn info(&self) -> Info {
        Info {
            name: "guest API scope enforcement",
            kind: Kind::Request,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _: &mut Data<'_>) {
        let path = req.uri().path().as_str();
        let token = req
            .headers()
            .get_one("Authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim);
        let scopes = match self.auth.resolve(token) {
            Ok(scopes) => scopes,
            Err(err) => {
                warn!("{err:#}");
                deny(req);
                return;
            }
        };
        let denied = required_scope(path).is_some_and(|scope| !scopes.contains(scope));
        if denied {
            deny(req);
            return;
        }
        req.local_cache(|| Some(scopes));
    }
}

fn deny(req: &mut Request<'_>) {
    // `Bearer`, not the shared-token `Basic` default: the way to get in here is
    // to present a token, and a client told to send Basic would send the wrong
    // thing.
    req.local_cache(|| dstack_api_auth::Challenge::Bearer);
    if let Ok(uri) = Origin::parse_owned(dstack_api_auth::UNAUTHORIZED_PATH.to_owned()) {
        req.set_uri(uri);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_spelling_of_a_route_needs_the_same_scope() {
        for path in [
            "/prpc/Info",
            "/prpc/v0/Info",
            "/prpc/Worker.Info",
            "/prpc/v0/Worker.Info",
        ] {
            assert_eq!(required_scope(path), Some(jwt::scope::INFO), "{path}");
        }
        // The frozen surface has no `Health`, but requiring the scope for that
        // spelling too is what keeps the check keyed on the method name rather
        // than on which mount happened to answer.
        for path in ["/prpc/v1/Health", "/prpc/Health", "/prpc/Worker.Health"] {
            assert_eq!(required_scope(path), Some(jwt::scope::HEALTH), "{path}");
        }
        assert_eq!(required_scope("/"), Some(jwt::scope::DASHBOARD));
        assert_eq!(required_scope("/metrics"), Some(jwt::scope::METRICS));
        assert_eq!(required_scope("/logs/app-1"), Some(jwt::scope::LOGS));
        assert_eq!(
            required_scope("/prpc/GetAttestationForAppKey"),
            Some(jwt::scope::ATTEST_APP_KEY)
        );
        assert_eq!(required_scope("/nope"), None);

        // The router matches on decoded, non-empty segments, so these reach
        // the same handler and must not be able to slip past the check.
        for path in ["/%70rpc/Info", "/prpc//Info", "/prpc/v0//Worker.Info"] {
            assert_eq!(required_scope(path), Some(jwt::scope::INFO), "{path}");
        }
        assert_eq!(required_scope("/%6detrics"), Some(jwt::scope::METRICS));
    }

    fn auth(anonymous: &[&str]) -> GuestApiAuth {
        GuestApiAuth::new(
            Some(&GuestAgentApiConfig {
                anonymous_scopes: anonymous.iter().map(|s| s.to_string()).collect(),
                external_issuers: vec![],
            }),
            Some(&[7u8; 32]),
        )
        .unwrap()
    }

    #[test]
    fn anonymous_grants_only_what_was_configured() {
        assert!(auth(&[]).resolve(None).unwrap().is_empty());
        let scopes = auth(&["guest:version"]).resolve(None).unwrap();
        assert!(scopes.contains(jwt::scope::VERSION));
        assert!(!scopes.contains(jwt::scope::INFO));
    }

    #[test]
    fn a_bad_token_is_refused_rather_than_downgraded_to_anonymous() {
        assert!(auth(&["guest:dashboard"])
            .resolve(Some("not-a-token"))
            .is_err());
    }

    #[test]
    fn an_unknown_anonymous_scope_fails_at_startup() {
        let err = GuestApiAuth::new(
            Some(&GuestAgentApiConfig {
                anonymous_scopes: vec!["guest:everything".into()],
                external_issuers: vec![],
            }),
            Some(&[7u8; 32]),
        )
        .err()
        .expect("should reject");
        assert!(err.to_string().contains("guest:everything"), "{err}");
    }
}
