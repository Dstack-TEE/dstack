// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Local signature and signature-chain verification.
//!
//! Verification needs no key material and no attestation, so it does not belong
//! behind an RPC to the guest agent: the agent's answer arrives over the socket
//! unattested, which is no better than a caller checking the signature itself.
//! The `Verify` RPC these functions replace was removed in v0.6.0.
//!
//! Two levels are available:
//!
//! * [`verify_signature`] checks one signature against a public key you already
//!   have. It is the direct replacement for the old RPC and, on its own, proves
//!   only that whoever holds that key signed the data.
//! * [`verify_signature_chain`] walks the full chain from a [`SignResponse`]
//!   back to a KMS root key **you supply**, which is what actually establishes
//!   that the signer was a dstack app under that KMS.

use anyhow::{bail, Context, Result};
use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use sha3::Keccak256;

/// Domain-separation prefix the KMS signs app root keys under.
const KMS_ISSUED_PREFIX: &[u8] = b"dstack-kms-issued";
/// `Sign` derives its key at this path with this purpose; both are fixed agent-side.
pub const SIGN_PATH: &str = "vms";
pub const SIGN_PURPOSE: &str = "signing";

/// `k256` and `ed25519` name the same thing; the agent normalized these too.
fn normalize_algorithm(algorithm: &str) -> &str {
    match algorithm {
        "k256" => "secp256k1",
        other => other,
    }
}

fn parse_k256_signature(signature: &[u8]) -> Result<K256Signature> {
    let sig = K256Signature::from_slice(signature).context("invalid secp256k1 signature")?;
    // ECDSA is malleable: (r, n-s) verifies wherever (r, s) does. k256 rejects the
    // high-S form, so we must too -- otherwise a signature stops being a unique
    // identifier for a signed message, and this SDK would disagree with every
    // other dstack component about whether a given blob is valid.
    if sig.normalize_s().is_some() {
        bail!("non-canonical (high-S) secp256k1 signature");
    }
    Ok(sig)
}

/// Verifies one signature against `public_key`.
///
/// `algorithm` is `ed25519`, `secp256k1` (alias `k256`), or `secp256k1_prehashed`,
/// where `data` is already a 32-byte digest. Returns `Ok(false)` when the inputs
/// are well-formed but the signature does not check out, and `Err` when they are
/// not well-formed at all (bad key encoding, wrong signature length, unknown
/// algorithm) -- a malformed input is a caller bug, not a verdict.
pub fn verify_signature(
    algorithm: &str,
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool> {
    match normalize_algorithm(algorithm) {
        "ed25519" => {
            let key_bytes: [u8; 32] = public_key
                .try_into()
                .ok()
                .context("ed25519 public key must be 32 bytes")?;
            let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
                .context("invalid ed25519 public key")?;
            let signature = ed25519_dalek::Signature::from_slice(signature)
                .context("invalid ed25519 signature")?;
            Ok(ed25519_dalek::Verifier::verify(&verifying_key, data, &signature).is_ok())
        }
        "secp256k1" => {
            let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
                .context("invalid secp256k1 public key")?;
            let signature = parse_k256_signature(signature)?;
            // k256's `sign` hashes with SHA-256, so verification must too.
            Ok(k256::ecdsa::signature::Verifier::verify(&verifying_key, data, &signature).is_ok())
        }
        "secp256k1_prehashed" => {
            if data.len() != 32 {
                bail!(
                    "pre-hashed verification requires a 32-byte digest, but received {} bytes",
                    data.len()
                );
            }
            let verifying_key = VerifyingKey::from_sec1_bytes(public_key)
                .context("invalid secp256k1 public key")?;
            let signature = parse_k256_signature(signature)?;
            Ok(verifying_key.verify_prehash(data, &signature).is_ok())
        }
        other => bail!("unsupported algorithm: {other}"),
    }
}

/// Recovers the compressed public key that produced a 65-byte `r ‖ s ‖ recid`
/// signature over `keccak256(message)`.
fn recover_compressed(message: &[u8], signature: &[u8]) -> Result<Vec<u8>> {
    if signature.len() != 65 {
        bail!(
            "recoverable signature must be 65 bytes, but received {}",
            signature.len()
        );
    }
    let sig = parse_k256_signature(&signature[..64])?;
    let recid = RecoveryId::from_byte(signature[64])
        .with_context(|| format!("invalid recovery id {}", signature[64]))?;
    let digest = <Keccak256 as sha3::Digest>::new_with_prefix(message);
    let recovered = VerifyingKey::recover_from_digest(digest, &sig, recid)
        .context("failed to recover public key")?;
    Ok(recovered.to_sec1_bytes().to_vec())
}

/// What a verified chain establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedChain {
    /// The app root public key, recovered from the chain and confirmed to be the
    /// one this KMS root signed. Compressed SEC1, 33 bytes.
    pub app_root_pubkey: Vec<u8>,
}

/// Inputs to [`verify_signature_chain`].
///
/// A struct rather than a positional argument list so that adding an input later
/// does not break callers.
#[derive(Debug, Clone)]
pub struct SignatureChain<'a> {
    /// Algorithm the payload was signed with.
    pub algorithm: &'a str,
    /// The signed payload; a 32-byte digest for `secp256k1_prehashed`.
    pub data: &'a [u8],
    /// `SignResponse::public_key` -- the key that signed `data`.
    pub public_key: &'a [u8],
    /// `SignResponse::signature_chain`, exactly 3 elements.
    pub signature_chain: &'a [Vec<u8>],
    /// The 20-byte app identity to hold the chain to.
    ///
    /// This must be the app id you *expect*, not merely whatever `AppInfo`
    /// echoed back -- that comes from the CVM being checked. Comparing a chain
    /// against an app id the same CVM supplied proves only that it is
    /// self-consistent.
    pub app_id: &'a [u8],
    /// The KMS root public key you already trust, compressed or uncompressed SEC1.
    ///
    /// Get it from the `DstackKms` contract (`kmsInfo().k256Pubkey`) or pin it.
    /// Reading it from the KMS you are verifying against proves nothing.
    pub kms_root_pubkey: &'a [u8],
    /// Purpose bound into the app-root link. Always [`SIGN_PURPOSE`] for `Sign`.
    pub purpose: &'a str,
}

impl<'a> SignatureChain<'a> {
    /// A chain as produced by the `Sign` RPC, which fixes purpose to `signing`.
    pub fn from_sign_response(
        algorithm: &'a str,
        data: &'a [u8],
        public_key: &'a [u8],
        signature_chain: &'a [Vec<u8>],
        app_id: &'a [u8],
        kms_root_pubkey: &'a [u8],
    ) -> Self {
        Self {
            algorithm,
            data,
            public_key,
            signature_chain,
            app_id,
            kms_root_pubkey,
            purpose: SIGN_PURPOSE,
        }
    }
}

/// Verifies a `Sign` signature chain end to end.
///
/// Three links, all of which must hold:
///
/// 1. `chain[0]` is a signature over `data` by `public_key`.
/// 2. `chain[1]` is the app root key attesting `"{purpose}:{hex(public_key)}"`.
/// 3. `chain[2]` is `kms_root_pubkey` attesting that app root key for `app_id`.
///
/// Link 3 is the one that matters. Without comparing against a KMS root key you
/// independently trust, a chain is just three signatures an attacker could have
/// produced with their own keys.
pub fn verify_signature_chain(chain: &SignatureChain<'_>) -> Result<VerifiedChain> {
    if chain.signature_chain.len() != 3 {
        bail!(
            "signature chain must have 3 elements, but received {}",
            chain.signature_chain.len()
        );
    }
    if chain.app_id.len() != 20 {
        bail!(
            "app_id must be 20 bytes, but received {}",
            chain.app_id.len()
        );
    }

    // Link 1: the payload signature. chain[0] *is* that signature; what matters
    // is that it checks out under `public_key`, which links 2 and 3 then cover.
    if !verify_signature(
        chain.algorithm,
        chain.data,
        &chain.signature_chain[0],
        chain.public_key,
    )
    .context("failed to check the payload signature")?
    {
        bail!("payload signature is not valid for the given public key");
    }

    // Link 2: recover the app root key that vouched for the signing key.
    let message = format!("{}:{}", chain.purpose, hex::encode(chain.public_key));
    let app_root_pubkey = recover_compressed(message.as_bytes(), &chain.signature_chain[1])
        .context("failed to recover the app root key")?;

    // Link 3: recover the KMS root key that vouched for the app root key, and
    // check it is the one we were told to trust.
    let kms_message = [
        KMS_ISSUED_PREFIX,
        b":",
        chain.app_id,
        app_root_pubkey.as_slice(),
    ]
    .concat();
    let recovered_kms = recover_compressed(&kms_message, &chain.signature_chain[2])
        .context("failed to recover the KMS root key")?;

    // Normalize the expected key so callers may pass either SEC1 encoding.
    let expected_kms = VerifyingKey::from_sec1_bytes(chain.kms_root_pubkey)
        .context("invalid KMS root public key")?
        .to_sec1_bytes()
        .to_vec();
    if recovered_kms != expected_kms {
        bail!("signature chain is not anchored at the expected KMS root key");
    }

    Ok(VerifiedChain { app_root_pubkey })
}
