// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Verifiable threshold PRF over P-256.
//!
//! Each node evaluates a hash-to-curve point with its Shamir share and proves
//! equality of discrete logarithms against the public share commitment. A
//! quorum combines verified evaluations at zero without reconstructing the
//! cluster secret scalar.

use anyhow::{ensure, Context, Result};
use p256::{
    elliptic_curve::{
        bigint::U256,
        ff::Field,
        group::Group,
        hash2curve::{ExpandMsgXmd, GroupDigest},
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        PrimeField,
    },
    AffinePoint, EncodedPoint, NistP256, ProjectivePoint, Scalar,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const HASH_TO_CURVE_DST: &[u8] = b"DSTACK-MPC-THRESHOLD-PRF-P256_XMD:SHA-256_SSWU_RO_V1";
const CHALLENGE_DOMAIN: &[u8] = b"dstack-mpc-threshold-prf-dleq-v1";
const OUTPUT_DOMAIN: &[u8] = b"dstack-mpc-threshold-prf-output-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PrfPartial {
    pub keygen_index: u16,
    #[serde(with = "hex_bytes")]
    pub evaluation: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub commitment_g: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub commitment_h: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub response: Vec<u8>,
}

pub(crate) fn evaluate<R: RngCore + CryptoRng>(
    keygen_index: u16,
    secret_share: &[u8; 32],
    public_share: &[u8],
    input: &[u8],
    request_hash: &[u8; 32],
    rng: &mut R,
) -> Result<PrfPartial> {
    let secret = scalar(secret_share).context("invalid threshold PRF secret share")?;
    ensure!(!bool::from(secret.is_zero()), "threshold PRF share is zero");
    let public = point(public_share).context("invalid threshold PRF public share")?;
    ensure!(
        ProjectivePoint::GENERATOR * secret == public,
        "threshold PRF secret does not match public share"
    );
    let h = hash_to_curve(input)?;
    let evaluation = h * secret;
    let nonce = Scalar::random(rng);
    let commitment_g = ProjectivePoint::GENERATOR * nonce;
    let commitment_h = h * nonce;
    let challenge = challenge(
        keygen_index,
        input,
        request_hash,
        public,
        h,
        evaluation,
        commitment_g,
        commitment_h,
    );
    let response = nonce + challenge * secret;
    Ok(PrfPartial {
        keygen_index,
        evaluation: encode_point(evaluation),
        commitment_g: encode_point(commitment_g),
        commitment_h: encode_point(commitment_h),
        response: response.to_bytes().to_vec(),
    })
}

pub(crate) fn verify(
    partial: &PrfPartial,
    public_share: &[u8],
    input: &[u8],
    request_hash: &[u8; 32],
) -> Result<ProjectivePoint> {
    let public = point(public_share).context("invalid threshold PRF public share")?;
    let h = hash_to_curve(input)?;
    let evaluation = point(&partial.evaluation).context("invalid PRF evaluation")?;
    let commitment_g = point(&partial.commitment_g).context("invalid DLEQ commitment")?;
    let commitment_h = point(&partial.commitment_h).context("invalid DLEQ commitment")?;
    let response_bytes: [u8; 32] = partial
        .response
        .as_slice()
        .try_into()
        .context("invalid DLEQ response length")?;
    let response = scalar(&response_bytes).context("invalid DLEQ response")?;
    let challenge = challenge(
        partial.keygen_index,
        input,
        request_hash,
        public,
        h,
        evaluation,
        commitment_g,
        commitment_h,
    );
    ensure!(
        ProjectivePoint::GENERATOR * response == commitment_g + public * challenge,
        "invalid threshold PRF proof for generator relation"
    );
    ensure!(
        h * response == commitment_h + evaluation * challenge,
        "invalid threshold PRF proof for evaluation relation"
    );
    Ok(evaluation)
}

pub(crate) fn combine(
    mut evaluations: Vec<(u16, ProjectivePoint)>,
    context: &[u8],
) -> Result<[u8; 32]> {
    ensure!(!evaluations.is_empty(), "no threshold PRF evaluations");
    evaluations.sort_by_key(|(index, _)| *index);
    ensure!(
        evaluations.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "duplicate threshold PRF share index"
    );
    let indexes: Vec<_> = evaluations
        .iter()
        .map(|(index, _)| Scalar::from(u64::from(*index) + 1))
        .collect();
    let mut combined = ProjectivePoint::IDENTITY;
    for (position, (_, evaluation)) in evaluations.iter().enumerate() {
        let x_i = indexes[position];
        let mut numerator = Scalar::ONE;
        let mut denominator = Scalar::ONE;
        for (other, x_j) in indexes.iter().enumerate() {
            if other != position {
                numerator *= -*x_j;
                denominator *= x_i - x_j;
            }
        }
        let inverse = Option::<Scalar>::from(denominator.invert())
            .context("invalid threshold PRF interpolation set")?;
        combined += *evaluation * (numerator * inverse);
    }
    ensure!(
        !bool::from(combined.is_identity()),
        "threshold PRF output is identity"
    );
    let mut hash = Sha256::new();
    hash.update((OUTPUT_DOMAIN.len() as u32).to_be_bytes());
    hash.update(OUTPUT_DOMAIN);
    hash.update((context.len() as u32).to_be_bytes());
    hash.update(context);
    hash.update(encode_point(combined));
    Ok(hash.finalize().into())
}

fn hash_to_curve(input: &[u8]) -> Result<ProjectivePoint> {
    NistP256::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[input], &[HASH_TO_CURVE_DST])
        .map_err(|_| anyhow::anyhow!("failed to hash threshold PRF input to P-256"))
}

#[allow(clippy::too_many_arguments)]
fn challenge(
    keygen_index: u16,
    input: &[u8],
    request_hash: &[u8; 32],
    public: ProjectivePoint,
    h: ProjectivePoint,
    evaluation: ProjectivePoint,
    commitment_g: ProjectivePoint,
    commitment_h: ProjectivePoint,
) -> Scalar {
    let mut hash = Sha256::new();
    hash.update((CHALLENGE_DOMAIN.len() as u32).to_be_bytes());
    hash.update(CHALLENGE_DOMAIN);
    hash.update(keygen_index.to_be_bytes());
    hash.update((input.len() as u32).to_be_bytes());
    hash.update(input);
    hash.update(request_hash);
    for value in [
        ProjectivePoint::GENERATOR,
        public,
        h,
        evaluation,
        commitment_g,
        commitment_h,
    ] {
        hash.update(encode_point(value));
    }
    <Scalar as Reduce<U256>>::reduce_bytes(&hash.finalize())
}

fn scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    Option::from(Scalar::from_repr((*bytes).into()))
}

fn point(bytes: &[u8]) -> Result<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes).context("invalid P-256 point encoding")?;
    Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .map(ProjectivePoint::from)
        .context("P-256 point is not on curve")
}

fn encode_point(point: ProjectivePoint) -> Vec<u8> {
    point.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        hex::decode(value.strip_prefix("0x").unwrap_or(&value)).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand::rngs::OsRng;

    #[test]
    fn verifies_and_combines_two_of_three_without_reconstructing_secret() {
        let secret = Scalar::random(&mut OsRng);
        let slope = Scalar::random(&mut OsRng);
        let shares: Vec<_> = (1u64..=3)
            .map(|index| secret + slope * Scalar::from(index))
            .collect();
        let input = b"app-id\0instance-id\0disk-key";
        let request_hash = [9u8; 32];
        let mut evaluations = vec![];
        for index in [0usize, 2] {
            let share_bytes: [u8; 32] = shares[index].to_bytes().into();
            let public = (ProjectivePoint::GENERATOR * shares[index])
                .to_affine()
                .to_encoded_point(true);
            let partial = evaluate(
                index as u16,
                &share_bytes,
                public.as_bytes(),
                input,
                &request_hash,
                &mut OsRng,
            )
            .unwrap();
            evaluations.push((
                index as u16,
                verify(&partial, public.as_bytes(), input, &request_hash).unwrap(),
            ));
        }
        let output = combine(evaluations, input).unwrap();
        let expected = combine(vec![(0, hash_to_curve(input).unwrap() * secret)], input).unwrap();
        assert_eq!(output, expected);
    }

    #[test]
    fn rejects_tampered_partial() {
        let share = Scalar::random(&mut OsRng);
        let share_bytes: [u8; 32] = share.to_bytes().into();
        let public = encode_point(ProjectivePoint::GENERATOR * share);
        let mut partial =
            evaluate(0, &share_bytes, &public, b"input", &[1; 32], &mut OsRng).unwrap();
        partial.response[0] ^= 1;
        assert!(verify(&partial, &public, b"input", &[1; 32]).is_err());
    }
}
