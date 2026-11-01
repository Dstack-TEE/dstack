// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Ed25519 JWT tokens for the guest agent's external API.
//!
//! Deliberately a small subset: one algorithm, a fixed claim set, and no
//! key-discovery header. Everything a general-purpose JWT library would let a
//! caller negotiate is something an attacker would like to negotiate too --
//! `none`, an HMAC verified with a public key as the secret, or a `jku`/`x5u`/
//! `jwk` header naming a key the verifier never configured. Here those are not
//! rejected by policy but impossible to express.

use std::collections::BTreeSet;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Tolerance for clock skew in either direction.
pub const CLOCK_LEEWAY_SECS: u64 = 30;

/// The base64url header every token carries.
///
/// A constant, not a serialized struct: a header this module writes is a
/// header it can also verify exactly.
const HEADER: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9";

/// The scope names the guest agent understands.
///
/// A vocabulary rather than free-form strings, so a typo in `anonymous_scopes`
/// is a startup error instead of a permission that silently never matches.
pub mod scope {
    /// `Worker.Version` on either pRPC surface.
    pub const VERSION: &str = "guest:version";
    /// `Worker.Health` on the v1 surface.
    pub const HEALTH: &str = "guest:health";
    /// `Worker.Info` on either pRPC surface.
    pub const INFO: &str = "guest:info";
    /// `Worker.GetAttestationForAppKey` on the frozen surface.
    pub const ATTEST_APP_KEY: &str = "guest:attest-app-key";
    /// The HTML dashboard itself.
    pub const DASHBOARD: &str = "guest:dashboard";
    /// The container table on the dashboard.
    pub const CONTAINERS: &str = "guest:containers";
    /// `/logs/<container>`.
    pub const LOGS: &str = "guest:logs";
    /// `/metrics`, and the sysinfo block on the dashboard.
    pub const METRICS: &str = "guest:metrics";

    /// Every name above, in the order a dashboard shows them.
    pub const ALL: &[&str] = &[
        VERSION,
        HEALTH,
        INFO,
        ATTEST_APP_KEY,
        DASHBOARD,
        CONTAINERS,
        LOGS,
        METRICS,
    ];

    pub fn is_known(name: &str) -> bool {
        ALL.contains(&name)
    }
}

/// A set of granted scopes.
///
/// Space-separated on the wire, because that is what RFC 8693 and every
/// OAuth-adjacent tool produces, and a collection here because the only
/// operation is membership.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScopeSet(BTreeSet<String>);

impl ScopeSet {
    /// Parse the space-separated `scope` claim.
    pub fn parse(scope: &str) -> Self {
        Self(scope.split_whitespace().map(str::to_owned).collect())
    }

    pub fn from_names(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self(names.into_iter().map(Into::into).collect())
    }

    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Everything in both sets. Used to add the anonymous baseline to a
    /// caller's own grants.
    pub fn union(&self, other: &Self) -> Self {
        Self(self.0.union(&other.0).cloned().collect())
    }
}

/// The claims this module issues and accepts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Who minted the token.
    pub iss: String,
    /// Which application the token is for, hex-encoded.
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    /// Space-separated [`scope`] names.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub scope: String,
}

impl Claims {
    pub fn scopes(&self) -> ScopeSet {
        ScopeSet::parse(&self.scope)
    }
}

/// The domain the internal issuer key is derived under.
///
/// Part of the wire contract between the agent (which derives the public half
/// to verify with) and the application (which derives the private half to
/// sign with). Changing it invalidates every token in flight, and a host and
/// guest on either side of the change would stop trusting each other, so it
/// never changes.
pub const INTERNAL_ISSUER_DOMAIN: &str = "dstack:guest-api:issuer:v1";

/// The `iss` an internally minted token carries.
///
/// Bound to the app id so a token minted for one application cannot be
/// replayed against another: `aud` alone would already stop that, but naming
/// the application in the issuer too keeps the two checks independent.
pub fn internal_issuer(app_id_hex: &str) -> String {
    format!("dstack:guest-api:{app_id_hex}")
}

/// A token whose shape and claims have been read, with the signature still
/// unchecked.
///
/// Split out from verification so a caller can refuse a malformed token before
/// it does anything expensive. The guest agent needs exactly that: checking a
/// token it was handed must not cost a boot attestation.
#[derive(Clone, Debug)]
pub struct Decoded {
    signing_input: String,
    signature: Vec<u8>,
    pub claims: Claims,
}

/// Read a token's header and claims without verifying it.
///
/// Everything here is cheap and local. The result says nothing about whether
/// the token was signed by anyone; [`Verifier::verify_decoded`] answers that.
pub fn decode(token: &str) -> Result<Decoded> {
    let mut parts = token.split('.');
    let (Some(header), Some(encoded_payload), Some(encoded_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        bail!("token is not a JWT");
    };
    if header != HEADER {
        // Covers `alg: none`, HMAC, and any header carrying key material.
        bail!("unsupported JWT header");
    }
    let payload = URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .context("payload is not base64url")?;
    let claims = serde_json::from_slice(&payload).context("malformed claims")?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .context("signature is not base64url")?;
    Ok(Decoded {
        signing_input: format!("{header}.{encoded_payload}"),
        signature,
        claims,
    })
}

/// Mint a token. `signing_key` is the raw 32-byte Ed25519 seed.
pub fn sign(signing_key: &[u8; 32], claims: &Claims) -> Result<String> {
    let payload = serde_json::to_vec(claims).context("failed to serialize claims")?;
    let signing_input = format!("{HEADER}.{}", URL_SAFE_NO_PAD.encode(payload));
    let signature = SigningKey::from_bytes(signing_key).sign(signing_input.as_bytes());
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

/// The public keys one issuer may sign with.
///
/// A list so a key can be rotated without a flag day: publish the new key
/// alongside the old, wait out the tokens signed by the old one, drop it.
#[derive(Clone, Debug)]
pub struct IssuerKeys {
    /// The exact `iss` this issuer's tokens must carry.
    pub name: String,
    pub keys: Vec<VerifyingKey>,
}

/// Verifies tokens and reports what they grant.
#[derive(Clone)]
pub struct Verifier {
    internal: VerifyingKey,
    external: Vec<IssuerKeys>,
}

impl Verifier {
    pub fn new(internal: VerifyingKey, external: Vec<IssuerKeys>) -> Self {
        Self { internal, external }
    }

    /// Verify `token` for the application whose id is `app_id_hex`.
    ///
    /// `now` is seconds since the UNIX epoch, passed in rather than read here
    /// so the expiry rules can be tested.
    pub fn verify(&self, token: &str, app_id_hex: &str, now: u64) -> Result<ScopeSet> {
        self.verify_decoded(&decode(token)?, app_id_hex, now)
    }

    /// Check the signature and claims of a token [`decode`] already read.
    ///
    /// Separate from [`Verifier::verify`] so a caller can pay for [`decode`]
    /// alone -- it needs no key material and no app id -- and refuse the token
    /// before doing anything that costs.
    ///
    /// The signature is checked before the claims: a claim error from an
    /// unsigned token is a guess about a caller's intent, not a fact.
    pub fn verify_decoded(&self, token: &Decoded, app_id_hex: &str, now: u64) -> Result<ScopeSet> {
        let Decoded {
            signing_input,
            signature,
            claims,
        } = token;
        let signature =
            Signature::from_slice(signature).context("signature has the wrong length")?;

        let keys = self.keys_for(&claims.iss, app_id_hex);
        if keys.is_empty() {
            bail!("unknown token issuer");
        }
        if !keys.iter().any(|key| {
            key.verify_strict(signing_input.as_bytes(), &signature)
                .is_ok()
        }) {
            bail!("token signature does not verify");
        }

        if claims.aud != app_id_hex {
            bail!("token was issued for a different application");
        }
        if claims.exp < now.saturating_sub(CLOCK_LEEWAY_SECS) {
            bail!("token has expired");
        }
        if claims.iat > now + CLOCK_LEEWAY_SECS {
            bail!("token was issued in the future");
        }
        Ok(claims.scopes())
    }

    fn keys_for(&self, iss: &str, app_id_hex: &str) -> Vec<&VerifyingKey> {
        if iss == internal_issuer(app_id_hex) {
            return vec![&self.internal];
        }
        self.external
            .iter()
            .find(|issuer| issuer.name == iss)
            .map(|issuer| issuer.keys.iter().collect())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP_ID: &str = "00112233445566778899aabbccddeeff00112233";

    fn signing_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn mint(seed: u8, iss: &str, aud: &str, iat: u64, exp: u64, scope: &str) -> String {
        sign(
            &signing_key(seed),
            &Claims {
                iss: iss.to_owned(),
                aud: aud.to_owned(),
                iat,
                exp,
                scope: scope.to_owned(),
            },
        )
        .unwrap()
    }

    fn verifier(seed: u8) -> Verifier {
        Verifier::new(
            SigningKey::from_bytes(&signing_key(seed)).verifying_key(),
            vec![],
        )
    }

    #[test]
    fn round_trips_scopes() {
        let token = mint(
            1,
            &internal_issuer(APP_ID),
            APP_ID,
            1000,
            1300,
            "guest:info guest:logs",
        );
        let scopes = verifier(1).verify(&token, APP_ID, 1100).unwrap();
        assert!(scopes.contains(scope::INFO));
        assert!(scopes.contains(scope::LOGS));
        assert!(!scopes.contains(scope::METRICS));
    }

    #[test]
    fn rejects_a_token_for_another_application() {
        let token = mint(
            1,
            &internal_issuer(APP_ID),
            APP_ID,
            1000,
            1300,
            "guest:info",
        );
        let other = "ffeeddccbbaa99887766554433221100ffeeddcc";
        assert!(verifier(1).verify(&token, other, 1100).is_err());
    }

    #[test]
    fn rejects_alg_none_and_foreign_signatures() {
        for token in [
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ4In0.".to_owned(),
            mint(
                2,
                &internal_issuer(APP_ID),
                APP_ID,
                1000,
                1300,
                "guest:info",
            ),
        ] {
            assert!(verifier(1).verify(&token, APP_ID, 1100).is_err());
        }
    }

    #[test]
    fn rejects_expired_and_future_tokens() {
        let expired = mint(
            1,
            &internal_issuer(APP_ID),
            APP_ID,
            1000,
            1100,
            "guest:info",
        );
        assert!(verifier(1).verify(&expired, APP_ID, 1200).is_err());

        let future = mint(
            1,
            &internal_issuer(APP_ID),
            APP_ID,
            5000,
            5300,
            "guest:info",
        );
        assert!(verifier(1).verify(&future, APP_ID, 1000).is_err());
    }

    #[test]
    fn decoding_refuses_a_shape_no_token_could_have() {
        for token in [
            "not-a-token",
            "a.b.c.d",
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJpc3MiOiJ4In0.",
            "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.!!!.c2ln",
        ] {
            assert!(decode(token).is_err(), "{token}");
        }
        // A well-formed token decodes without any key: that is what lets the
        // caller refuse it before doing work.
        let token = mint(
            1,
            &internal_issuer(APP_ID),
            APP_ID,
            1000,
            1300,
            "guest:info",
        );
        assert_eq!(decode(&token).unwrap().claims.aud, APP_ID);
    }

    #[test]
    fn accepts_an_external_issuer_by_name() {
        let verifier = Verifier::new(
            SigningKey::from_bytes(&signing_key(1)).verifying_key(),
            vec![IssuerKeys {
                name: "ops".into(),
                keys: vec![SigningKey::from_bytes(&signing_key(9)).verifying_key()],
            }],
        );
        let token = mint(9, "ops", APP_ID, 1000, 1300, "guest:containers");
        assert!(verifier
            .verify(&token, APP_ID, 1100)
            .unwrap()
            .contains(scope::CONTAINERS));

        // The same key under the internal issuer name is not an internal token.
        let impostor = mint(
            9,
            &internal_issuer(APP_ID),
            APP_ID,
            1000,
            1300,
            "guest:info",
        );
        assert!(verifier.verify(&impostor, APP_ID, 1100).is_err());
    }
}
