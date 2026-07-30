// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Verifiable Shamir resharing while preserving the group public key.
//!
//! Exactly an old threshold of dealers contributes a polynomial whose constant
//! is its Lagrange-weighted old share. New recipients verify private
//! evaluations against public coefficient commitments before summing them.

use anyhow::{ensure, Context, Result};
use cggmp21::{
    generic_ec::{Curve, Point, Scalar},
    IncompleteKeyShare,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PublicContribution {
    pub dealer_index: u16,
    pub commitments: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PrivateContribution {
    pub dealer_index: u16,
    pub recipient_index: u16,
    pub evaluation: Vec<u8>,
}

pub(crate) struct ResharedMaterial<E: Curve> {
    pub secret_share: Scalar<E>,
    pub public_shares: Vec<Point<E>>,
    pub shared_public_key: Point<E>,
}

pub(crate) fn create_contribution<E: Curve, R: RngCore + CryptoRng>(
    old_share: &IncompleteKeyShare<E>,
    old_dealers: &[u16],
    new_member_count: u16,
    new_threshold: u16,
    rng: &mut R,
) -> Result<(PublicContribution, Vec<PrivateContribution>)> {
    ensure!(
        old_share.vss_setup.is_some(),
        "resharing requires an old Shamir share"
    );
    ensure!(
        old_dealers.len() == usize::from(old_share.vss_setup.as_ref().unwrap().min_signers),
        "resharing must use exactly the old threshold of dealers"
    );
    ensure!(
        old_dealers.windows(2).all(|pair| pair[0] < pair[1]),
        "old resharing dealers must be unique and ordered"
    );
    ensure!(
        old_dealers.contains(&old_share.i),
        "local old share is not a resharing dealer"
    );
    ensure!(
        new_threshold >= 2 && new_threshold <= new_member_count,
        "invalid new resharing threshold"
    );
    let setup = old_share.vss_setup.as_ref().unwrap();
    let dealer_position = old_dealers
        .iter()
        .position(|index| *index == old_share.i)
        .expect("dealer membership checked");
    let dealer_points = old_dealers
        .iter()
        .map(|index| {
            setup
                .I
                .get(usize::from(*index))
                .map(|point| Scalar::from(point.clone()))
                .context("old dealer index is out of bounds")
        })
        .collect::<Result<Vec<_>>>()?;
    let lambda = lagrange_at_zero(dealer_position, &dealer_points)?;
    let mut coefficients = Vec::with_capacity(usize::from(new_threshold));
    let old_secret: &Scalar<E> = old_share.x.as_ref();
    coefficients.push(lambda * old_secret);
    coefficients.extend((1..new_threshold).map(|_| Scalar::<E>::random(rng)));
    let commitments = coefficients
        .iter()
        .map(|coefficient| {
            (Point::generator() * coefficient)
                .to_bytes(true)
                .as_bytes()
                .to_vec()
        })
        .collect();
    let private = (0..new_member_count)
        .map(|recipient_index| {
            let x = Scalar::from(u64::from(recipient_index) + 1);
            PrivateContribution {
                dealer_index: old_share.i,
                recipient_index,
                evaluation: evaluate_polynomial(&coefficients, x)
                    .to_be_bytes()
                    .as_bytes()
                    .to_vec(),
            }
        })
        .collect();
    Ok((
        PublicContribution {
            dealer_index: old_share.i,
            commitments,
        },
        private,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_and_combine<E: Curve>(
    old_reference: &IncompleteKeyShare<E>,
    old_dealers: &[u16],
    new_member_count: u16,
    new_threshold: u16,
    recipient_index: u16,
    public: &[PublicContribution],
    private: &[PrivateContribution],
) -> Result<ResharedMaterial<E>> {
    ensure!(
        recipient_index < new_member_count,
        "new recipient index out of bounds"
    );
    ensure!(
        public.len() == old_dealers.len(),
        "missing public resharing contribution"
    );
    ensure!(
        private.len() == old_dealers.len(),
        "missing private resharing contribution"
    );
    let setup = old_reference
        .vss_setup
        .as_ref()
        .context("resharing requires an old Shamir setup")?;
    let dealer_points = old_dealers
        .iter()
        .map(|index| {
            setup
                .I
                .get(usize::from(*index))
                .map(|point| Scalar::from(point.clone()))
                .context("old dealer index is out of bounds")
        })
        .collect::<Result<Vec<_>>>()?;
    let recipient_x = Scalar::from(u64::from(recipient_index) + 1);
    let mut aggregate_commitments = vec![Point::<E>::zero(); usize::from(new_threshold)];
    let mut secret_share = Scalar::<E>::zero();
    for (position, dealer_index) in old_dealers.iter().enumerate() {
        let public = public
            .iter()
            .find(|item| item.dealer_index == *dealer_index)
            .context("missing dealer public contribution")?;
        ensure!(
            public.commitments.len() == usize::from(new_threshold),
            "dealer commitment degree does not match new threshold"
        );
        let commitments = public
            .commitments
            .iter()
            .map(|encoded| Point::<E>::from_bytes(encoded).context("invalid resharing commitment"))
            .collect::<Result<Vec<_>>>()?;
        let lambda = lagrange_at_zero(position, &dealer_points)?;
        let expected_constant = old_reference
            .key_info
            .public_shares
            .get(usize::from(*dealer_index))
            .context("missing old dealer public share")?
            * lambda;
        ensure!(
            commitments[0] == expected_constant,
            "dealer changed its weighted old share"
        );
        let private = private
            .iter()
            .find(|item| {
                item.dealer_index == *dealer_index && item.recipient_index == recipient_index
            })
            .context("missing recipient resharing contribution")?;
        let evaluation = Scalar::<E>::from_be_bytes(&private.evaluation)
            .context("invalid private resharing scalar")?;
        ensure!(
            Point::generator() * evaluation == evaluate_commitments(&commitments, recipient_x),
            "private resharing contribution does not match commitments"
        );
        secret_share += evaluation;
        for (aggregate, commitment) in aggregate_commitments.iter_mut().zip(commitments) {
            *aggregate += commitment;
        }
    }
    ensure!(
        aggregate_commitments[0] == *old_reference.shared_public_key(),
        "resharing changed the group public key"
    );
    let public_shares = (0..new_member_count)
        .map(|index| {
            evaluate_commitments(&aggregate_commitments, Scalar::from(u64::from(index) + 1))
        })
        .collect::<Vec<_>>();
    ensure!(
        Point::generator() * secret_share == public_shares[usize::from(recipient_index)],
        "combined reshared secret does not match its public share"
    );
    Ok(ResharedMaterial {
        secret_share,
        public_shares,
        shared_public_key: aggregate_commitments[0],
    })
}

fn lagrange_at_zero<E: Curve>(position: usize, indexes: &[Scalar<E>]) -> Result<Scalar<E>> {
    let x_i = indexes[position];
    let mut numerator = Scalar::one();
    let mut denominator = Scalar::one();
    for (other, x_j) in indexes.iter().enumerate() {
        if other != position {
            numerator *= -*x_j;
            denominator *= x_i - x_j;
        }
    }
    Ok(numerator
        * denominator
            .invert()
            .context("duplicate resharing evaluation point")?)
}

fn evaluate_polynomial<E: Curve>(coefficients: &[Scalar<E>], x: Scalar<E>) -> Scalar<E> {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::zero(), |value, coefficient| value * x + coefficient)
}

fn evaluate_commitments<E: Curve>(coefficients: &[Point<E>], x: Scalar<E>) -> Point<E> {
    coefficients
        .iter()
        .rev()
        .fold(Point::zero(), |value, coefficient| value * x + coefficient)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cggmp21::{generic_ec::NonZero, supported_curves::Secp256k1};
    use key_share::trusted_dealer;
    use rand::rngs::OsRng;

    #[test]
    fn reshares_two_of_three_into_three_of_five_without_changing_key() {
        let old = trusted_dealer::builder::<Secp256k1>(3)
            .set_threshold(Some(2))
            .generate_shares(&mut OsRng)
            .unwrap();
        let dealers = [0u16, 2];
        let mut publics = vec![];
        let mut private_by_recipient = vec![vec![]; 5];
        for dealer in dealers {
            let (public, private) =
                create_contribution(&old[usize::from(dealer)], &dealers, 5, 3, &mut OsRng).unwrap();
            publics.push(public);
            for contribution in private {
                private_by_recipient[usize::from(contribution.recipient_index)].push(contribution);
            }
        }
        let materials = private_by_recipient
            .iter()
            .enumerate()
            .map(|(recipient, private)| {
                verify_and_combine(&old[0], &dealers, 5, 3, recipient as u16, &publics, private)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(materials.iter().all(|material| {
            material.shared_public_key == *old[0].shared_public_key()
                && material.public_shares == materials[0].public_shares
        }));
        let indexes = [Scalar::from(1u16), Scalar::from(2u16), Scalar::from(3u16)];
        let reconstructed = (0..3).fold(Scalar::zero(), |secret, position| {
            secret
                + lagrange_at_zero(position, &indexes).unwrap() * materials[position].secret_share
        });
        assert_eq!(
            Point::generator() * reconstructed,
            *old[0].shared_public_key()
        );
        assert!(NonZero::from_point(materials[0].shared_public_key).is_some());
    }

    #[test]
    fn rejects_a_dealer_that_changes_the_group_key() {
        let old = trusted_dealer::builder::<Secp256k1>(3)
            .set_threshold(Some(2))
            .generate_shares(&mut OsRng)
            .unwrap();
        let dealers = [0u16, 1];
        let (mut first_public, first_private) =
            create_contribution(&old[0], &dealers, 3, 2, &mut OsRng).unwrap();
        let (second_public, second_private) =
            create_contribution(&old[1], &dealers, 3, 2, &mut OsRng).unwrap();
        first_public.commitments[0] = (Point::<Secp256k1>::generator() * Scalar::one())
            .to_bytes(true)
            .as_bytes()
            .to_vec();
        assert!(verify_and_combine(
            &old[0],
            &dealers,
            3,
            2,
            0,
            &[first_public, second_public],
            &[first_private[0].clone(), second_private[0].clone()],
        )
        .is_err());
    }
}
