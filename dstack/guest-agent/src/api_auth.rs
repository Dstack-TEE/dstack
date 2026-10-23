// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Access control for the guest agent's external listener.
//!
//! Every request that reaches `[external]` names a scope, and the caller has
//! to be granted it: either by an Ed25519 JWT, or -- when the host configured
//! it -- by being anonymous. Nothing is granted without one or the other.
//!
//! This is deliberately not a trust boundary. The measured `public_*` switches
//! in app-compose still decide whether confidential data (logs, sysinfo, TCB
//! info) may leave the TEE at all; a scope can only narrow that, never widen
//! it. What scopes decide is who may *ask* -- which the host configures, and
//! which therefore cannot be part of the measurement.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use dstack_api_auth::jwt::{self, Decoded, IssuerKeys, ScopeSet, Verifier};
use dstack_types::GuestAgentApiConfig;
use ed25519_dalek::VerifyingKey;
use rocket::{
    fairing::{Fairing, Info, Kind},
    http::uri::Origin,
    request::{FromRequest, Outcome},
    Data, Request,
};
use tracing::warn;

use crate::rpc_service::AppState;

/// What a caller may do on the external listener.
#[derive(Clone)]
pub struct GuestApiAuth {
    verifier: Verifier,
    anonymous: ScopeSet,
}

impl GuestApiAuth {
    /// Build from sys-config's `guest_agent_api` block and the app root key.
    ///
    /// `anonymous_scopes` is validated eagerly so a typo is a boot error rather
    /// than a permission that silently never matches.
    pub fn new(config: Option<&GuestAgentApiConfig>, app_root_key: &[u8]) -> Result<Self> {
        let config = config.cloned().unwrap_or_default();
        if let Some(name) = config
            .anonymous_scopes
            .iter()
            .find(|name| !jwt::scope::is_known(name))
        {
            anyhow::bail!("guest_agent_api: unknown anonymous scope {name:?}");
        }
        let anonymous = ScopeSet::from_names(config.anonymous_scopes);

        let secret = ra_tls::api_v1::derive_app_key(
            app_root_key,
            jwt::INTERNAL_ISSUER_DOMAIN,
            ra_tls::api_v1::KeyAlgorithm::Ed25519,
        )
        .context("failed to derive the internal issuer key")?;
        let internal = ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key();

        let external = config
            .external_issuers
            .into_iter()
            .map(|issuer| {
                let keys = issuer
                    .public_keys
                    .iter()
                    .map(|encoded| parse_public_key(encoded))
                    .collect::<Result<Vec<_>>>()
                    .with_context(|| format!("issuer {:?}", issuer.name))?;
                if keys.is_empty() {
                    warn!("issuer {:?} has no public keys", issuer.name);
                }
                Ok(IssuerKeys {
                    name: issuer.name,
                    keys,
                })
            })
            .collect::<Result<_>>()?;

        Ok(Self {
            verifier: Verifier::new(internal, external),
            anonymous,
        })
    }

    /// The scopes a request carries, or `Err` when it presented a token that
    /// did not verify.
    ///
    /// A rejected token never falls back to anonymous: a caller that meant to
    /// authenticate and got it wrong should see a refusal, not whatever the
    /// host happened to leave open. `app_id` is `None` while the app identity
    /// is unavailable, in which case no token can be checked.
    fn resolve(&self, token: Option<&Decoded>, app_id: Option<&str>) -> Result<ScopeSet> {
        let Some(token) = token else {
            return Ok(self.anonymous.clone());
        };
        let app_id = app_id.context("no token can be accepted until the app identity is known")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let granted = self
            .verifier
            .verify_decoded(token, app_id, now)
            .context("rejected bearer token")?;
        Ok(self.anonymous.union(&granted))
    }
}

fn parse_public_key(encoded: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(encoded)
        .context("public key is not hex")?
        .try_into()
        .ok()
        .context("public key must be 32 bytes")?;
    VerifyingKey::from_bytes(&bytes).context("public key is not a valid Ed25519 key")
}

/// The scopes in force for one request, published by [`ScopeFairing`].
///
/// A request guard because the dashboard renders parts of itself by scope: it
/// needs the set, not a yes/no.
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
            // Unreachable: `ScopeFairing` either publishes a set or rewrites
            // the request to the 401 route. Kept as a 401 rather than a 403 so
            // a request that somehow got past the fairing still looks like
            // every other refusal.
            None => Outcome::Error((rocket::http::Status::Unauthorized, ())),
        }
    }
}

/// The scope a request to the external listener needs, or `None` for a path
/// that names no known route. `None` is refused: the check fails closed, so a
/// spelling this function does not recognise can never reach a handler.
///
/// Segments come from Rocket's own parser, because that is what the router
/// matches on: it percent-decodes and drops empty segments, so `/%70rpc/Info`
/// and `/prpc//Info` reach the same handler as `/prpc/Info`.
///
/// The frozen mounts (`/prpc`, `/prpc/v0`) strip one `Worker.` prefix before
/// dispatch, exactly as here; `/prpc/v1` strips nothing.
pub fn required_scope(path: &str) -> Option<&'static str> {
    let origin = Origin::parse(path).ok()?;
    let segments: Vec<&str> = origin.path().segments().filter(|s| !s.is_empty()).collect();
    let method = match segments.as_slice() {
        [] => return Some(jwt::scope::DASHBOARD),
        ["metrics"] => return Some(jwt::scope::METRICS),
        ["logs", _] => return Some(jwt::scope::LOGS),
        ["prpc", "v1", method] => *method,
        ["prpc", "v0", method] | ["prpc", method] => {
            method.strip_prefix("Worker.").unwrap_or(method)
        }
        _ => return None,
    };
    match method {
        "Version" => Some(jwt::scope::VERSION),
        "Health" => Some(jwt::scope::HEALTH),
        "Info" => Some(jwt::scope::INFO),
        "GetAttestationForAppKey" => Some(jwt::scope::ATTEST_APP_KEY),
        _ => None,
    }
}

/// Refuses a request whose caller lacks the scope its route needs.
pub struct ScopeFairing {
    state: AppState,
}

impl ScopeFairing {
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

/// The token from an `Authorization: Bearer` header. The scheme is
/// case-insensitive (RFC 9110 §11.1); any other scheme is no token at all.
fn bearer_token<'r>(req: &'r Request<'_>) -> Option<&'r str> {
    let (scheme, token) = req.headers().get_one("Authorization")?.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then_some(token.trim())
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
        // Read the token's shape first. It is the only cheap step, and it is
        // the one an unauthenticated caller can drive; the app id lookup below
        // can cost a boot attestation, so nothing that arrives here gets that
        // far unless it is at least a well-formed Ed25519 token.
        let token = match bearer_token(req).map(jwt::decode).transpose() {
            Ok(token) => token,
            Err(err) => {
                tracing::debug!("{err:#}");
                return deny(req);
            }
        };
        // Only a token needs the app id. Going through `identity()` rather
        // than a value bound at startup is what lets a boot whose first decode
        // failed recover: the retry is driven by the callers that need it.
        let app_id = match token {
            Some(_) => self
                .state
                .identity()
                .await
                .ok()
                .map(|identity| hex::encode(&identity.app_id)),
            None => None,
        };
        let scopes = match self
            .state
            .api_auth()
            .resolve(token.as_ref(), app_id.as_deref())
        {
            Ok(scopes) => scopes,
            Err(err) => {
                // Every caller on the internet reaches this. A warning per
                // attempt is a log the public gets to size.
                tracing::debug!("{err:#}");
                return deny(req);
            }
        };
        match required_scope(req.uri().path().as_str()) {
            Some(scope) if scopes.contains(scope) => {
                req.local_cache(|| Some(scopes));
            }
            _ => deny(req),
        }
    }
}

fn deny(req: &mut Request<'_>) {
    // `Bearer`, not the shared-token `Basic` default: the way in is a token.
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
        // Fails closed: anything not named here is refused, including a
        // second service prefix the dispatcher would not strip.
        for path in [
            "/nope",
            "/prpc/Worker.Worker.Info",
            "/prpc/v0/Worker.Worker.Info",
            "/prpc/v1/Worker.Health",
            "/prpc/GetQuote",
        ] {
            assert_eq!(required_scope(path), None, "{path}");
        }

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
            &[7u8; 32],
        )
        .unwrap()
    }

    /// Stands in for a token that is well-formed but not signed by anything
    /// this agent trusts.
    fn decoded(claims: jwt::Claims) -> Decoded {
        let token = jwt::sign(&[1u8; 32], &claims).unwrap();
        jwt::decode(&token).unwrap()
    }

    #[test]
    fn anonymous_grants_only_what_was_configured() {
        assert!(auth(&[]).resolve(None, None).unwrap().is_empty());
        let scopes = auth(&["guest:version"]).resolve(None, None).unwrap();
        assert!(scopes.contains(jwt::scope::VERSION));
        assert!(!scopes.contains(jwt::scope::INFO));
    }

    #[test]
    fn a_bad_token_is_refused_rather_than_downgraded_to_anonymous() {
        let claims = jwt::Claims {
            iss: jwt::internal_issuer("00"),
            aud: "00".into(),
            iat: 0,
            exp: u64::MAX / 2,
            scope: jwt::scope::DASHBOARD.into(),
        };
        // Signed by the wrong key, so it decodes and fails to verify.
        assert!(auth(&["guest:dashboard"])
            .resolve(Some(&decoded(claims)), Some("00"))
            .is_err());
    }

    #[test]
    fn an_unknown_anonymous_scope_fails_at_startup() {
        let err = GuestApiAuth::new(
            Some(&GuestAgentApiConfig {
                anonymous_scopes: vec!["guest:everything".into()],
                external_issuers: vec![],
            }),
            &[7u8; 32],
        )
        .err()
        .expect("should reject");
        assert!(err.to_string().contains("guest:everything"), "{err}");
    }
}
