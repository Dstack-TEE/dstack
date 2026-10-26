// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Normative constants and encodings for the v1 application-key API.
//!
//! Everything here is wire behaviour, specified in `docs/guest-api-v1.md`. The
//! byte strings these functions build are what a relying party re-derives to
//! check a signature chain, so a change to a constant or a field order changes
//! every key and every claim a deployed agent produces.
//!
//! This lives in `ra-tls` rather than in the guest agent so that the agent, the
//! verifier and the Rust SDK link against one definition. The alternative is
//! each of them transcribing the constants out of the specification prose,
//! which is how cross-implementation crypto drift starts.
//!
//! The module is named for the version of the construction, not for the API
//! that happens to expose it: `ra-tls` hosts versioned crypto, and knowing
//! about a guest API is not its job.

use crate::kdf::derive_key_with_salt;
use anyhow::{anyhow, bail, Context, Result};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

/// The HKDF salt for every v1 derivation.
///
/// Distinct from [`crate::kdf::LEGACY_SALT`], which gives v1 its own derivation
/// tree rather than a differently-labelled branch of the old one. Under a
/// shared salt the two surfaces are separated only by their HKDF `info`, and
/// the legacy `info` is the caller's `path` verbatim -- so a caller that passed
/// the v1 `info` byte string as a v0 path would reproduce a v1 key. Different
/// salts close that by construction, whatever either side puts in `info`.
pub const KDF_SALT: &[u8] = b"dstack-guest-v1";

/// Context tag bound into every v1 key derivation.
pub const KEY_CONTEXT_TAG: &[u8] = b"dstack-guest-v1-key";

/// Context tag bound into every v1 signature-chain key claim.
///
/// Distinct from [`KEY_CONTEXT_TAG`] so that no derivation input can ever be
/// read as a claim, or the other way round -- the two encodings are otherwise
/// built the same way and would share a prefix.
pub const CLAIM_CONTEXT_TAG: &[u8] = b"dstack-guest-v1-key-claim";

/// The key types the v1 API serves.
///
/// A closed set, matched exhaustively: an algorithm name that is not one of
/// these is an error, never a default. v0 defaulted an empty string to
/// secp256k1 and accepted `k256` as an alias, so a caller could ask for nothing
/// in particular and get a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// secp256k1, SEC1-compressed public keys.
    Secp256k1,
    /// Ed25519, RFC 8032 raw public keys.
    Ed25519,
}

impl KeyAlgorithm {
    /// Parse a wire algorithm name. There is no default and no alias.
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "secp256k1" => Ok(Self::Secp256k1),
            "ed25519" => Ok(Self::Ed25519),
            "" => bail!("algorithm is required, use `secp256k1` or `ed25519`"),
            other => bail!("unsupported algorithm `{other}`, use `secp256k1` or `ed25519`"),
        }
    }

    /// The canonical name, and the exact bytes bound into derivations and
    /// claims. Never the string the caller sent.
    pub fn name(self) -> &'static str {
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
pub fn push_length_prefixed(out: &mut Vec<u8>, field: &[u8]) -> Result<()> {
    let len = u32::try_from(field.len()).context("field is too long to encode")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// The HKDF `info` for a v1 application key.
///
/// `LP(tag) || LP(algorithm) || LP(domain)`, where `LP(x)` is `len(x)` as a
/// 4-byte big-endian integer followed by `x`.
pub fn key_derivation_info(domain: &str, algorithm: KeyAlgorithm) -> Result<Vec<u8>> {
    let mut info = Vec::new();
    push_length_prefixed(&mut info, KEY_CONTEXT_TAG)?;
    push_length_prefixed(&mut info, algorithm.name().as_bytes())?;
    push_length_prefixed(&mut info, domain.as_bytes())?;
    Ok(info)
}

/// Derive the 32 raw bytes of a v1 application key.
///
/// HKDF-SHA256 over the app root secp256k1 key, under [`KDF_SALT`], with the
/// `info` from [`key_derivation_info`].
pub fn derive_app_key(
    app_root_key: &[u8],
    domain: &str,
    algorithm: KeyAlgorithm,
) -> Result<[u8; 32]> {
    let info = key_derivation_info(domain, algorithm)?;
    let derived = derive_key_with_salt(KDF_SALT, app_root_key, &[&info], 32)
        .map_err(|_| anyhow!("failed to derive the application key"))?;
    derived
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("derived key has the wrong length"))
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
/// `:` followed by lowercase hex. This encoding ends in `LP(public_key)`, whose
/// four length bytes are `00 00 00 21` for secp256k1 and `00 00 00 20` for
/// ed25519 and sit inside the region a v0 preimage requires to be hex-only.
/// `0x00` is not a hex character, so no `purpose` reproduces this byte string
/// -- the exclusion is structural, not probabilistic.
pub fn key_claim(algorithm: KeyAlgorithm, domain: &str, public_key: &[u8]) -> Result<Vec<u8>> {
    let mut claim = Vec::new();
    push_length_prefixed(&mut claim, CLAIM_CONTEXT_TAG)?;
    push_length_prefixed(&mut claim, algorithm.name().as_bytes())?;
    push_length_prefixed(&mut claim, domain.as_bytes())?;
    push_length_prefixed(&mut claim, public_key)?;
    Ok(claim)
}

/// Sign `message` as `keccak256(message)`, recoverably.
///
/// Returns the 65-byte `r || s || v` envelope every dstack signature chain link
/// uses: `r` and `s` big-endian and low-S normalised, then the one-byte
/// recovery id. The recovery byte lets a relying party recover the signing
/// public key from the link alone.
///
/// One definition, because three copies of this five-line envelope had already
/// accumulated and a chain link that disagrees about byte order verifies
/// nowhere.
pub fn sign_recoverable_keccak256(key: &SigningKey, message: &[u8]) -> Result<Vec<u8>> {
    let (signature, recovery_id) = key
        .sign_digest_recoverable(Keccak256::new_with_prefix(message))
        .context("failed to sign the message")?;
    let mut envelope = signature.to_vec();
    envelope.push(recovery_id.to_byte());
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The app root key the committed vectors were generated from.
    const TEST_APP_ROOT_KEY: [u8; 32] = [
        0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B, 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C,
        0x6D, 0x7E, 0x8F, 0x9A, 0x0B, 0x1C, 0x2D, 0x3E, 0x4F, 0x5A, 0x6B, 0x7C, 0x8D, 0x9E, 0x0F,
        0x1A, 0x2B,
    ];

    #[test]
    fn rejects_an_empty_or_unknown_algorithm() {
        assert_eq!(
            KeyAlgorithm::parse("").unwrap_err().to_string(),
            "algorithm is required, use `secp256k1` or `ed25519`"
        );
        assert_eq!(
            KeyAlgorithm::parse("k256").unwrap_err().to_string(),
            "unsupported algorithm `k256`, use `secp256k1` or `ed25519`"
        );
        assert!(KeyAlgorithm::parse("secp256k1_prehashed").is_err());
        assert!(KeyAlgorithm::parse("rsa").is_err());
    }

    #[test]
    fn encodes_derivation_info_with_length_prefixes() {
        let info = key_derivation_info("storage-encryption", KeyAlgorithm::Secp256k1).unwrap();
        let expected = [
            &19u32.to_be_bytes()[..],
            b"dstack-guest-v1-key",
            &9u32.to_be_bytes()[..],
            b"secp256k1",
            &18u32.to_be_bytes()[..],
            b"storage-encryption",
        ]
        .concat();
        assert_eq!(info, expected);
    }

    /// A delimiter-joined encoding would collide here; a length-prefixed one
    /// cannot. A domain carrying the delimiter is the shape that breaks
    /// `join(":")`.
    #[test]
    fn no_two_domains_encode_the_same_way() {
        let a = key_derivation_info("a\u{0}b", KeyAlgorithm::Ed25519).unwrap();
        let b = key_derivation_info("a", KeyAlgorithm::Ed25519).unwrap();
        let c = key_derivation_info("ab", KeyAlgorithm::Ed25519).unwrap();
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
                KeyAlgorithm::Secp256k1,
                "59f60584ce6fd2a3a31997256db9d77322463fc8a6b1520110401bcb1ee92387",
            ),
            (
                "",
                KeyAlgorithm::Ed25519,
                "b023493030669cf22e9cafa6a464d4cf3ae4edfe5474ec796710f21ea011946d",
            ),
            (
                "storage-encryption",
                KeyAlgorithm::Secp256k1,
                "5510330f86902ddae38c6d89c93a8408019332c17a429e1abd01c4a28d1544a6",
            ),
            (
                "storage-encryption",
                KeyAlgorithm::Ed25519,
                "3c4c3ece12fa99ccb93fc0090877f80e70545fdd971e2ac93d3398c4684538d3",
            ),
            (
                "a/b/c",
                KeyAlgorithm::Secp256k1,
                "7f0973449298085d2d36a3b4c4d3243c100ba1981ffa885fe9e9dee883e69538",
            ),
            // A domain carrying NUL and `:`, the two characters a
            // delimiter-joined encoding would choke on.
            (
                "k\u{0}:ey",
                KeyAlgorithm::Ed25519,
                "42da8bf0b479ed125c370e3b91f982735bf08ff592abbd586985affa43ee96a1",
            ),
        ];
        for (domain, algorithm, expected) in vectors {
            let key = derive_app_key(&TEST_APP_ROOT_KEY, domain, algorithm).unwrap();
            assert_eq!(
                hex::encode(key),
                expected,
                "v1 key vector changed for ({domain:?}, {})",
                algorithm.name()
            );
        }
    }

    #[test]
    fn the_two_algorithms_never_share_key_material() {
        for domain in ["", "storage-encryption", "a/b/c", "\u{0}"] {
            assert_ne!(
                derive_app_key(&TEST_APP_ROOT_KEY, domain, KeyAlgorithm::Secp256k1).unwrap(),
                derive_app_key(&TEST_APP_ROOT_KEY, domain, KeyAlgorithm::Ed25519).unwrap(),
                "cross-algorithm key reuse at {domain:?}"
            );
        }
    }

    /// v0 derived `derive_key(app_root, [path], 32)` and handed the same 32
    /// bytes to both curves. v1 must not land on those bytes when the domain
    /// string equals the old path.
    #[test]
    fn v1_keys_differ_from_v0_keys_for_the_same_name() {
        for name in ["", "storage-encryption", "vms"] {
            let v0 = crate::kdf::derive_key(&TEST_APP_ROOT_KEY, &[name.as_bytes()], 32).unwrap();
            for algorithm in [KeyAlgorithm::Secp256k1, KeyAlgorithm::Ed25519] {
                assert_ne!(
                    derive_app_key(&TEST_APP_ROOT_KEY, name, algorithm)
                        .unwrap()
                        .as_slice(),
                    v0.as_slice()
                );
            }
        }
    }

    /// The one v0 path that could reach a v1 key under a shared salt: the
    /// legacy `info` is the caller's `path` verbatim, so passing the v1 `info`
    /// byte string as a v0 path made the two derivations identical.
    ///
    /// The v1 salt closes it by construction. This is the test that would have
    /// failed before the salt changed, so it is the one that keeps it changed.
    #[test]
    fn a_v0_path_cannot_reproduce_a_v1_key() {
        for (domain, algorithm) in [
            ("", KeyAlgorithm::Secp256k1),
            ("storage-encryption", KeyAlgorithm::Secp256k1),
            ("storage-encryption", KeyAlgorithm::Ed25519),
        ] {
            let info = key_derivation_info(domain, algorithm).unwrap();
            // The best a v0 caller can do: hand the whole v1 info to `path`.
            let v0 = crate::kdf::derive_key(&TEST_APP_ROOT_KEY, &[&info], 32).unwrap();
            assert_ne!(
                derive_app_key(&TEST_APP_ROOT_KEY, domain, algorithm)
                    .unwrap()
                    .as_slice(),
                v0.as_slice(),
                "a v0 path reproduced the v1 key for ({domain:?}, {})",
                algorithm.name()
            );
        }
    }

    #[test]
    fn the_v1_salt_is_not_the_legacy_salt() {
        assert_eq!(KDF_SALT, b"dstack-guest-v1");
        assert_ne!(KDF_SALT, crate::kdf::LEGACY_SALT);
    }

    #[test]
    fn encodes_the_claim_with_the_raw_public_key() {
        let public_key =
            hex::decode("03d962450a41748021c8b02787ac36ce642ff0ae25f4c55019eb527e1112cfd764")
                .unwrap();
        let claim = key_claim(KeyAlgorithm::Secp256k1, "storage-encryption", &public_key).unwrap();
        let expected = [
            &25u32.to_be_bytes()[..],
            b"dstack-guest-v1-key-claim",
            &9u32.to_be_bytes()[..],
            b"secp256k1",
            &18u32.to_be_bytes()[..],
            b"storage-encryption",
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
        let public_key =
            hex::decode("03d962450a41748021c8b02787ac36ce642ff0ae25f4c55019eb527e1112cfd764")
                .unwrap();
        let v1_claim =
            key_claim(KeyAlgorithm::Secp256k1, "storage-encryption", &public_key).unwrap();

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
        let derivation = key_derivation_info("p", KeyAlgorithm::Ed25519).unwrap();
        let claim = key_claim(KeyAlgorithm::Ed25519, "p", &[0u8; 32]).unwrap();
        assert!(!claim.starts_with(&derivation));
        assert!(!derivation.starts_with(&claim));
    }

    /// The claim signature is deterministic: RFC 6979 fixes `k` from the key
    /// and the digest, so a committed vector pins the whole chain-link
    /// encoding, recovery byte included.
    #[test]
    fn produces_the_committed_claim_signature_vector() {
        let public_key =
            hex::decode("03d962450a41748021c8b02787ac36ce642ff0ae25f4c55019eb527e1112cfd764")
                .unwrap();
        let claim = key_claim(KeyAlgorithm::Secp256k1, "storage-encryption", &public_key).unwrap();
        let key = SigningKey::from_slice(&TEST_APP_ROOT_KEY).unwrap();
        assert_eq!(
            hex::encode(sign_recoverable_keccak256(&key, &claim).unwrap()),
            "5b6193729ce7976ec67863f21692d4b98c69832698aae8e001a7d33a6f818b6e\
             46ca950725b6e90e8ca9bcf394abd03ce264bf9b7eec1e91693247f9dd53c269\
             01"
        );
    }

    #[test]
    fn the_chain_link_envelope_recovers_the_signer() {
        use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

        let key = SigningKey::from_slice(&TEST_APP_ROOT_KEY).unwrap();
        let link = sign_recoverable_keccak256(&key, b"message").unwrap();
        assert_eq!(link.len(), 65);

        let recovered = VerifyingKey::recover_from_digest(
            Keccak256::new_with_prefix(b"message"),
            &Signature::from_slice(&link[..64]).unwrap(),
            RecoveryId::from_byte(link[64]).unwrap(),
        )
        .unwrap();
        assert_eq!(&recovered, key.verifying_key());
    }
}
