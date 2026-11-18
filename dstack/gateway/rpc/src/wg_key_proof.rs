// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! WireGuard key proof-of-possession for `RegisterCvm`.
//!
//! The CVM computes `X25519(client_sk, gateway_pk)`, which only it and the
//! named gateway node can compute, derives a MAC key from it with HKDF-SHA256,
//! and MACs both public keys plus its attested app and instance ids. The node
//! recomputes the shared secret from its own private key and the claimed
//! client key; a match shows the registrant holds the client private key.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::WgKeyProof;

const LABEL: &[u8] = b"dstack-gateway-wg-key-proof-v1";

/// Build the proof for `gateway_public_key` from the CVM's WireGuard private
/// key and its attested identity.
pub fn compute(
    client_private_key: &str,
    gateway_public_key: &str,
    app_id: &[u8],
    instance_id: &[u8],
) -> Result<WgKeyProof> {
    let client_sk =
        StaticSecret::from(decode_key(client_private_key).context("client private key")?);
    let gateway_pk = decode_key(gateway_public_key).context("gateway public key")?;
    let client_pk = PublicKey::from(&client_sk).to_bytes();
    let mac = new_mac(
        &client_sk,
        gateway_pk,
        client_pk,
        gateway_pk,
        app_id,
        instance_id,
    )?;
    Ok(WgKeyProof {
        gateway_public_key: gateway_public_key.to_string(),
        mac: mac.finalize().into_bytes().to_vec(),
    })
}

/// Check `proof` on the gateway node holding `gateway_private_key`.
pub fn verify(
    proof: &WgKeyProof,
    gateway_private_key: &str,
    client_public_key: &str,
    app_id: &[u8],
    instance_id: &[u8],
) -> Result<()> {
    let gateway_sk =
        StaticSecret::from(decode_key(gateway_private_key).context("gateway private key")?);
    let gateway_pk = PublicKey::from(&gateway_sk).to_bytes();
    let target = decode_key(&proof.gateway_public_key).context("proof gateway public key")?;
    if target != gateway_pk {
        bail!(
            "proof targets gateway key {}, not this node's",
            proof.gateway_public_key
        );
    }
    let client_pk = decode_key(client_public_key).context("client public key")?;
    new_mac(
        &gateway_sk,
        client_pk,
        client_pk,
        gateway_pk,
        app_id,
        instance_id,
    )?
    .verify_slice(&proof.mac)
    .ok()
    .context("proof MAC does not verify for this key and identity")
}

fn new_mac(
    our_sk: &StaticSecret,
    their_pk: [u8; 32],
    client_pk: [u8; 32],
    gateway_pk: [u8; 32],
    app_id: &[u8],
    instance_id: &[u8],
) -> Result<Hmac<Sha256>> {
    let shared = our_sk.diffie_hellman(&PublicKey::from(their_pk));
    // A low-order point yields a secret anyone can compute.
    if !shared.was_contributory() {
        bail!("low-order WireGuard public key");
    }
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared.as_bytes())
        .expand(LABEL, &mut key)
        .ok()
        .context("hkdf expand failed")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key)
        .ok()
        .context("bad hmac key")?;
    for field in [&client_pk[..], &gateway_pk[..], app_id, instance_id] {
        mac.update(&(field.len() as u32).to_be_bytes());
        mac.update(field);
    }
    Ok(mac)
}

/// Decode a WireGuard key in the padded base64 form `wg` uses.
fn decode_key(key: &str) -> Result<[u8; 32]> {
    let bytes = STANDARD.decode(key).context("invalid base64")?;
    bytes
        .try_into()
        .ok()
        .context("WireGuard key must be 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair(seed: u8) -> (String, String) {
        let sk = StaticSecret::from([seed; 32]);
        let pk = PublicKey::from(&sk);
        (
            STANDARD.encode(sk.to_bytes()),
            STANDARD.encode(pk.to_bytes()),
        )
    }

    #[test]
    fn round_trip_verifies() {
        let (client_sk, client_pk) = keypair(1);
        let (gw_sk, gw_pk) = keypair(2);
        let proof = compute(&client_sk, &gw_pk, b"app", b"instance").unwrap();
        verify(&proof, &gw_sk, &client_pk, b"app", b"instance").unwrap();
    }

    #[test]
    fn rejects_another_client_key() {
        let (client_sk, _) = keypair(1);
        let (_, victim_pk) = keypair(3);
        let (gw_sk, gw_pk) = keypair(2);
        let proof = compute(&client_sk, &gw_pk, b"app", b"instance").unwrap();
        assert!(verify(&proof, &gw_sk, &victim_pk, b"app", b"instance").is_err());
    }

    #[test]
    fn rejects_another_gateway_key() {
        let (client_sk, client_pk) = keypair(1);
        let (_, gw_pk) = keypair(2);
        let (other_sk, _) = keypair(4);
        let proof = compute(&client_sk, &gw_pk, b"app", b"instance").unwrap();
        let err = verify(&proof, &other_sk, &client_pk, b"app", b"instance").unwrap_err();
        assert!(format!("{err:#}").contains("targets gateway key"));
    }

    #[test]
    fn rejects_another_identity() {
        let (client_sk, client_pk) = keypair(1);
        let (gw_sk, gw_pk) = keypair(2);
        let proof = compute(&client_sk, &gw_pk, b"app", b"instance").unwrap();
        assert!(verify(&proof, &gw_sk, &client_pk, b"app", b"other").is_err());
        assert!(verify(&proof, &gw_sk, &client_pk, b"other", b"instance").is_err());
        // Length prefixes keep the boundary between the ids significant.
        assert!(verify(&proof, &gw_sk, &client_pk, b"appi", b"nstance").is_err());
    }

    #[test]
    fn rejects_low_order_point() {
        let (client_sk, _) = keypair(1);
        let (gw_sk, _) = keypair(2);
        let low_order = STANDARD.encode([0u8; 32]);
        assert!(compute(&client_sk, &low_order, b"app", b"instance").is_err());
        let mut proof = compute(&client_sk, &keypair(2).1, b"app", b"instance").unwrap();
        proof.mac = vec![0; 32];
        let err = verify(&proof, &gw_sk, &low_order, b"app", b"instance").unwrap_err();
        assert!(format!("{err:#}").contains("low-order"));
    }

    #[test]
    fn rejects_malformed_keys() {
        let (client_sk, _) = keypair(1);
        assert!(compute(&client_sk, "not base64!", b"app", b"instance").is_err());
        assert!(compute(&client_sk, &STANDARD.encode([1u8; 31]), b"a", b"i").is_err());
    }
}
