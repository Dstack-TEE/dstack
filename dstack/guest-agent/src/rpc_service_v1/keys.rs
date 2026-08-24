// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Key derivation and signature-chain claims for the v1 API.
//!
//! Everything here is normative wire behaviour: the byte strings this module
//! builds are what relying parties re-derive when they check a chain, and
//! `docs/guest-api-v1.md` is the specification they implement from. Changing a
//! constant or a field order here changes every key and every claim a deployed
//! agent produces.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use k256::ecdsa::SigningKey;
use ra_tls::kdf::derive_key;
use sha3::{Digest, Keccak256};

/// Context tag bound into every v1 key derivation.
pub(crate) const KEY_CONTEXT_TAG: &[u8] = b"dstack-guest-v1-key";

/// Context tag bound into every v1 signature-chain key claim.
///
/// Distinct from [`KEY_CONTEXT_TAG`] so that no derivation input can ever be
/// read as a claim, or the other way round -- the two encodings are otherwise
/// built the same way and would share a prefix.
pub(crate) const CLAIM_CONTEXT_TAG: &[u8] = b"dstack-guest-v1-key-claim";

/// The key types the v1 API serves.
///
/// A closed set, matched exhaustively: an algorithm name that is not one of
/// these is an error, never a default. v0 defaulted an empty string to
/// secp256k1 and accepted `k256` as an alias, so a caller could ask for
/// nothing in particular and get a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Algorithm {
    Secp256k1,
    Ed25519,
}

impl Algorithm {
    pub(crate) fn parse(name: &str) -> Result<Self> {
        match name {
            "secp256k1" => Ok(Self::Secp256k1),
            "ed25519" => Ok(Self::Ed25519),
            "" => bail!("algorithm is required, use `secp256k1` or `ed25519`"),
            other => bail!("unsupported algorithm `{other}`, use `secp256k1` or `ed25519`"),
        }
    }

    /// The canonical name, and the exact bytes bound into derivations and
    /// claims. Never the string the caller sent.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Secp256k1 => "secp256k1",
            Self::Ed25519 => "ed25519",
        }
    }
}

/// Append one length-prefixed field: a 4-byte big-endian length, then the
/// bytes.
///
/// Prefixing rather than joining with a delimiter is the whole point. A domain
/// is an arbitrary caller-chosen string -- it may contain `:`, `/`, or NUL --
/// so any delimiter it could also contain lets two different `(domain,
/// algorithm)` pairs encode to the same byte string and share a key.
fn push_field(out: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len = u32::try_from(field.len()).context("field is too long to encode")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// The HKDF `info` for a v1 application key.
///
/// `LP(tag) || LP(algorithm) || LP(domain)`, where `LP(x)` is `len(x)` as a
/// 4-byte big-endian integer followed by `x`.
pub(crate) fn key_derivation_info(domain: &str, algorithm: Algorithm) -> Result<Vec<u8>> {
    let mut info = Vec::new();
    push_field(&mut info, KEY_CONTEXT_TAG)?;
    push_field(&mut info, algorithm.name().as_bytes())?;
    push_field(&mut info, domain.as_bytes())?;
    Ok(info)
}

/// The claim the app root key signs to vouch for a derived public key.
///
/// `LP(tag) || LP(algorithm) || LP(domain) || LP(public_key)`, with the public
/// key as raw bytes.
///
/// Raw bytes, and a length prefix in front of them, are what makes this
/// unforgeable through the v0 surface. v0's claim is
/// `keccak256("{purpose}:{hex(pubkey)}")` over a caller-chosen `purpose`, so
/// the app root key can be made to sign nearly any ASCII string that ends in
/// `:` followed by lowercase hex. This encoding ends in `LP(public_key)`,
/// whose four length bytes are `00 00 00 21` for secp256k1 and `00 00 00 20`
/// for ed25519 and sit inside the region a v0 preimage requires to be
/// hex-only. `0x00` is not a hex character, so no `purpose` reproduces this
/// byte string -- the exclusion is structural, not probabilistic.
pub(crate) fn key_claim(algorithm: Algorithm, domain: &str, public_key: &[u8]) -> Result<Vec<u8>> {
    let mut claim = Vec::new();
    push_field(&mut claim, CLAIM_CONTEXT_TAG)?;
    push_field(&mut claim, algorithm.name().as_bytes())?;
    push_field(&mut claim, domain.as_bytes())?;
    push_field(&mut claim, public_key)?;
    Ok(claim)
}

/// An application key derived for one `(domain, algorithm)` pair.
pub(crate) struct AppKey {
    algorithm: Algorithm,
    domain: String,
    secret: [u8; 32],
    public_key: Vec<u8>,
}

impl AppKey {
    /// Derive the key for `(domain, algorithm)` from the app root key.
    ///
    /// HKDF-SHA256 over the app root secp256k1 key, with the `info` from
    /// [`key_derivation_info`]. Same primitive and same salt as v0; what
    /// changed is that the algorithm and a version tag are now inputs, so the
    /// two curves no longer share one secret and a v1 domain is not a v0 path.
    ///
    /// Flat, not hierarchical: `a/b` is an opaque domain string like any
    /// other, unrelated to `a`, and no key here derives another.
    pub(crate) fn derive(app_root_key: &[u8], domain: &str, algorithm: Algorithm) -> Result<Self> {
        let info = key_derivation_info(domain, algorithm)?;
        let derived = derive_key(app_root_key, &[&info], 32)
            .map_err(|_| anyhow!("failed to derive the application key"))?;
        let secret: [u8; 32] = derived
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("derived key has the wrong length"))?;
        let public_key = match algorithm {
            // Rejects a scalar that is zero or at least the group order. That
            // is a ~2^-128 event for one domain and the caller can just pick
            // another one, so failing is better than folding the scalar into
            // range and quietly landing two domains on one key.
            Algorithm::Secp256k1 => SigningKey::from_slice(&secret)
                .context("derived secp256k1 key is not a valid scalar")?
                .verifying_key()
                .to_sec1_bytes()
                .to_vec(),
            Algorithm::Ed25519 => Ed25519SigningKey::from_bytes(&secret)
                .verifying_key()
                .to_bytes()
                .to_vec(),
        };
        Ok(Self {
            algorithm,
            domain: domain.to_string(),
            secret,
            public_key,
        })
    }

    /// The raw 32-byte private key.
    pub(crate) fn secret(&self) -> Vec<u8> {
        self.secret.to_vec()
    }

    /// SEC1 compressed for secp256k1, 32 raw bytes for ed25519.
    pub(crate) fn public_key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// The app root key's signature over this key's claim: the first link of
    /// the signature chain.
    ///
    /// 65 bytes, `r || s || recovery_id`, over `keccak256` of the claim. The
    /// recovery byte is kept so a relying party can recover the app root
    /// public key from the link alone and compare it against what the second
    /// link attests.
    pub(crate) fn claim_signature(&self, app_root_key: &[u8]) -> Result<Vec<u8>> {
        let claim = key_claim(self.algorithm, &self.domain, &self.public_key)?;
        let app_signing_key = SigningKey::from_slice(app_root_key)
            .context("failed to parse the app root k256 key")?;
        let (signature, recovery_id) = app_signing_key
            .sign_digest_recoverable(Keccak256::new_with_prefix(&claim))
            .context("failed to sign the key claim")?;
        let mut link = signature.to_vec();
        link.push(recovery_id.to_byte());
        Ok(link)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app root key the committed vectors were generated from. Same value
    /// the handler tests use, so a vector can be reproduced end to end.
    const TEST_APP_ROOT_KEY: [u8; 32] = [
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B, 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C,
        0x6D, 0x7E, 0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0x0F,
        0x1A, 0x2B,
    ];

    fn derive(domain: &str, algorithm: Algorithm) -> AppKey {
        AppKey::derive(&TEST_APP_ROOT_KEY, domain, algorithm).unwrap()
    }

    #[test]
    fn rejects_an_empty_or_unknown_algorithm() {
        assert_eq!(
            Algorithm::parse("").unwrap_err().to_string(),
            "algorithm is required, use `secp256k1` or `ed25519`"
        );
        assert_eq!(
            Algorithm::parse("k256").unwrap_err().to_string(),
            "unsupported algorithm `k256`, use `secp256k1` or `ed25519`"
        );
        assert!(Algorithm::parse("secp256k1_prehashed").is_err());
        assert!(Algorithm::parse("rsa").is_err());
    }

    #[test]
    fn encodes_derivation_info_with_length_prefixes() {
        let info = key_derivation_info("wallet", Algorithm::Secp256k1).unwrap();
        let expected = [
            &19u32.to_be_bytes()[..],
            b"dstack-guest-v1-key",
            &9u32.to_be_bytes()[..],
            b"secp256k1",
            &6u32.to_be_bytes()[..],
            b"wallet",
        ]
        .concat();
        assert_eq!(info, expected);
    }

    /// A delimiter-joined encoding would collide here; a length-prefixed one
    /// cannot. A domain carrying the delimiter is the shape that breaks
    /// `join(":")`.
    #[test]
    fn no_two_domains_encode_the_same_way() {
        let a = key_derivation_info("a\u{0}b", Algorithm::Ed25519).unwrap();
        let b = key_derivation_info("a", Algorithm::Ed25519).unwrap();
        let c = key_derivation_info("ab", Algorithm::Ed25519).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    /// Committed vectors, also published in `docs/guest-api-v1.md` so a
    /// non-Rust implementation can check itself against them.
    ///
    /// These bytes are the v1 keys of every deployment whose app root key is
    /// `TEST_APP_ROOT_KEY`. A diff here is a change to deployed key material,
    /// not a fixture update: fix the derivation, do not update the vector.
    #[test]
    fn derives_the_committed_key_vectors() {
        let vectors = [
            (
                "",
                Algorithm::Secp256k1,
                "463e877bc7322c1c09e567844b3101e88f353bfb33177c41cb13832cb67eef1c",
                "03c45e036d19662802e628d9a712c07a9d9d64bee28e1754a72d75010860a789c2",
            ),
            (
                "",
                Algorithm::Ed25519,
                "a41f6458de9d11a43f79640b6ab2c62d02aceda7b16c5f159dc7ad69621c7eb0",
                "7a5740fa9ab4791a232cc1fc7e73d5ff47ad41be2589a71b05f128dee4223f08",
            ),
            (
                "wallet",
                Algorithm::Secp256k1,
                "c2b47271c2956c020eb471f3d6ec9a08bac4ce72d158078592c3bfd9db67808c",
                "0375b11b6fabbe6e18b9bac26b082070dea76487ce512323870bc784a28ec5404b",
            ),
            (
                "wallet",
                Algorithm::Ed25519,
                "fce7a47f848fc9f7a799a34e061f4d07d7e8ef3adda98d8fc36a5de3f5146cdf",
                "5e8076b492634770e9b12dc8b136c9f5e3e8a86adc657040ba7a320296dcf6b0",
            ),
            (
                "a/b/c",
                Algorithm::Secp256k1,
                "448f92c86abd72c1c35b7ff75b5c9971114694e7825518e5ed0d2101711527cd",
                "03011845be1d30004c148ae49ef3a82585094f856a7c9bc3ed06edf959537a4eac",
            ),
            // A domain carrying NUL and `:`, the two characters a
            // delimiter-joined encoding would choke on.
            (
                "k\u{0}:ey",
                Algorithm::Ed25519,
                "3cfcf09543e94d23c87aec1e5774ca3803feb3dd8ee298507650409b20ebfdde",
                "9ba2d94591b97db4f089fc187cfcb09a9cd55bdd553e066d80cc8cb2977bd841",
            ),
        ];
        for (domain, algorithm, expected_secret, expected_public) in vectors {
            let key = derive(domain, algorithm);
            let name = algorithm.name();
            assert_eq!(
                hex::encode(key.secret()),
                expected_secret,
                "v1 key vector changed for ({domain:?}, {name})"
            );
            assert_eq!(
                hex::encode(key.public_key()),
                expected_public,
                "v1 public key vector changed for ({domain:?}, {name})"
            );
        }
    }

    /// The claim signature is deterministic: RFC 6979 fixes `k` from the key
    /// and the digest, so a committed vector pins the whole chain-link
    /// encoding, recovery byte included.
    #[test]
    fn produces_the_committed_claim_signature_vector() {
        let key = derive("wallet", Algorithm::Secp256k1);
        assert_eq!(
            hex::encode(key.claim_signature(&TEST_APP_ROOT_KEY).unwrap()),
            "96726db35263cb2a7067fc5ebb0d06621f7cab2d0f0aa15a83858dbf9ff7f12c\
             6e1c5640223fcca1a03ba5ccf09d353609db6481f9563add16e16a8ad8544c29\
             00"
        );
    }

    #[test]
    fn the_two_algorithms_never_share_key_material() {
        for domain in ["", "wallet", "a/b/c", "\u{0}"] {
            assert_ne!(
                derive(domain, Algorithm::Secp256k1).secret(),
                derive(domain, Algorithm::Ed25519).secret(),
                "cross-algorithm key reuse at {domain:?}"
            );
        }
    }

    /// v0 derived `derive_key(app_root, [path], 32)` and handed the same 32
    /// bytes to both curves. v1 must not land on those bytes when the domain
    /// string equals the old path.
    #[test]
    fn v1_keys_differ_from_v0_keys_for_the_same_name() {
        for name in ["", "wallet", "vms"] {
            let v0 = derive_key(&TEST_APP_ROOT_KEY, &[name.as_bytes()], 32).unwrap();
            assert_ne!(derive(name, Algorithm::Secp256k1).secret(), v0);
            assert_ne!(derive(name, Algorithm::Ed25519).secret(), v0);
        }
    }

    #[test]
    fn encodes_the_claim_with_the_raw_public_key() {
        let key = derive("wallet", Algorithm::Secp256k1);
        let public_key = key.public_key();
        assert_eq!(public_key.len(), 33, "expected a compressed SEC1 point");
        let claim = key_claim(Algorithm::Secp256k1, "wallet", &public_key).unwrap();
        let expected = [
            &25u32.to_be_bytes()[..],
            b"dstack-guest-v1-key-claim",
            &9u32.to_be_bytes()[..],
            b"secp256k1",
            &6u32.to_be_bytes()[..],
            b"wallet",
            &33u32.to_be_bytes()[..],
            &public_key,
        ]
        .concat();
        assert_eq!(claim, expected);
    }

    /// The forgery a malicious app would attempt: v0's `purpose` is
    /// caller-chosen, so it picks one that reproduces the v1 claim's prefix
    /// and lets v0 append `":" + hex(pubkey)` itself.
    #[test]
    fn a_v0_claim_cannot_be_crafted_into_a_v1_claim() {
        let key = derive("wallet", Algorithm::Secp256k1);
        let public_key = key.public_key();
        let v1_claim = key_claim(Algorithm::Secp256k1, "wallet", &public_key).unwrap();

        // Best case for the attacker: the v1 claim minus exactly the suffix v0
        // appends on its own, used verbatim as `purpose`.
        let hex_pubkey = hex::encode(&public_key);
        let appended = format!(":{hex_pubkey}");
        let purpose_len = v1_claim.len().saturating_sub(appended.len());
        let purpose = String::from_utf8_lossy(&v1_claim[..purpose_len]).into_owned();
        let v0_claim = format!("{purpose}:{hex_pubkey}").into_bytes();

        assert_ne!(
            v0_claim, v1_claim,
            "a v0 purpose reproduced the v1 claim byte string"
        );
        assert_ne!(
            Keccak256::digest(&v0_claim),
            Keccak256::digest(&v1_claim),
            "a v0 claim collided with a v1 claim"
        );

        // And the structural reason, so a future encoding change cannot make
        // the assertion above pass by accident: a v0 preimage ends in `:`
        // followed by lowercase hex only, while the v1 claim's last 37 bytes
        // start with the public key's `00 00 00 21` length prefix.
        let tail = &v1_claim[v1_claim.len() - 37..];
        assert_eq!(&tail[..4], &33u32.to_be_bytes());
        assert!(
            tail.iter().any(|b| !b.is_ascii_hexdigit()),
            "the v1 claim tail is entirely hex, which v0 could reproduce"
        );
    }

    #[test]
    fn the_two_context_tags_are_not_prefixes_of_one_another_once_encoded() {
        let derivation = key_derivation_info("p", Algorithm::Ed25519).unwrap();
        let claim = key_claim(Algorithm::Ed25519, "p", &[0u8; 32]).unwrap();
        assert!(!claim.starts_with(&derivation));
        assert!(!derivation.starts_with(&claim));
    }

    #[test]
    fn the_claim_signature_verifies_under_the_app_root_key() {
        use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

        let key = derive("wallet", Algorithm::Secp256k1);
        let link = key.claim_signature(&TEST_APP_ROOT_KEY).unwrap();
        assert_eq!(link.len(), 65);

        let claim = key_claim(Algorithm::Secp256k1, "wallet", &key.public_key()).unwrap();
        let digest = Keccak256::new_with_prefix(&claim);
        let signature = K256Signature::from_slice(&link[..64]).unwrap();
        let recovery_id = RecoveryId::from_byte(link[64]).unwrap();

        let recovered = VerifyingKey::recover_from_digest(digest, &signature, recovery_id).unwrap();
        let app_root = *SigningKey::from_slice(&TEST_APP_ROOT_KEY)
            .unwrap()
            .verifying_key();
        assert_eq!(recovered, app_root);
    }
}
