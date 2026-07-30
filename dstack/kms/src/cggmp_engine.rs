// SPDX-FileCopyrightText: © 2024-2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! CGGMP21 key-share persistence and protocol context binding.

use std::{fs::Permissions, os::unix::fs::PermissionsExt, path::Path};

use anyhow::{ensure, Context, Result};
use cggmp21::{
    supported_curves::{Secp256k1, Secp256r1},
    IncompleteKeyShare, KeyShare,
};
use fs_err as fs;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) type K256IncompleteShare = IncompleteKeyShare<Secp256k1>;
pub(crate) type P256IncompleteShare = IncompleteKeyShare<Secp256r1>;
pub(crate) type K256KeyShare = KeyShare<Secp256k1>;
pub(crate) type P256KeyShare = KeyShare<Secp256r1>;

const SHARE_FORMAT_VERSION: u16 = 1;
const EXECUTION_ID_DOMAIN: &[u8] = b"dstack-cggmp21-execution-id-v1";
const SHARE_COMMITMENT_DOMAIN: &[u8] = b"dstack-mpc-share-commitment-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CggmpCurve {
    P256,
    K256,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredShare {
    version: u16,
    cluster_id: String,
    epoch: u64,
    node_id: String,
    curve: CggmpCurve,
    payload: serde_json::Value,
    checksum: String,
}

#[derive(Serialize)]
struct ShareChecksum<'a> {
    version: u16,
    cluster_id: &'a str,
    epoch: u64,
    node_id: &'a str,
    curve: CggmpCurve,
    payload: &'a serde_json::Value,
}

pub(crate) fn execution_id(
    cluster_id: &str,
    epoch: u64,
    curve: CggmpCurve,
    operation_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    for field in [
        EXECUTION_ID_DOMAIN,
        cluster_id.as_bytes(),
        &epoch.to_be_bytes(),
        match curve {
            CggmpCurve::P256 => b"p256" as &[u8],
            CggmpCurve::K256 => b"k256" as &[u8],
        },
        operation_nonce,
    ] {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    hash.finalize().into()
}

pub(crate) fn share_commitment(
    p256_public_share: &[u8],
    k256_public_share: &[u8],
    derivation_public_share: &[u8],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((SHARE_COMMITMENT_DOMAIN.len() as u32).to_be_bytes());
    hash.update(SHARE_COMMITMENT_DOMAIN);
    for value in [
        p256_public_share,
        k256_public_share,
        derivation_public_share,
    ] {
        hash.update((value.len() as u32).to_be_bytes());
        hash.update(value);
    }
    hash.finalize().into()
}

pub(crate) fn store_share<T: Serialize>(
    path: &Path,
    cluster_id: &str,
    epoch: u64,
    node_id: &str,
    curve: CggmpCurve,
    share: &T,
) -> Result<()> {
    ensure!(!cluster_id.is_empty(), "cluster_id must not be empty");
    ensure!(epoch > 0, "epoch must be greater than zero");
    ensure!(!node_id.is_empty(), "node_id must not be empty");
    let payload = serde_json::to_value(share).context("failed to encode CGGMP share")?;
    let checksum = checksum(cluster_id, epoch, node_id, curve, &payload)?;
    let stored = StoredShare {
        version: SHARE_FORMAT_VERSION,
        cluster_id: cluster_id.into(),
        epoch,
        node_id: node_id.into(),
        curve,
        payload,
        checksum: hex::encode(checksum),
    };
    let encoded = serde_jcs::to_vec(&stored).context("failed to serialize stored CGGMP share")?;
    safe_write::safe_write(path, &encoded).context("failed to persist CGGMP share")?;
    fs::set_permissions(path, Permissions::from_mode(0o600))
        .context("failed to restrict CGGMP share permissions")?;
    Ok(())
}

pub(crate) fn load_share<T: DeserializeOwned>(
    path: &Path,
    expected_cluster_id: &str,
    expected_epoch: u64,
    expected_node_id: &str,
    expected_curve: CggmpCurve,
) -> Result<T> {
    let metadata = fs::metadata(path).context("failed to stat CGGMP share")?;
    ensure!(
        metadata.permissions().mode() & 0o077 == 0,
        "CGGMP share file permissions are too broad"
    );
    let stored: StoredShare =
        serde_json::from_slice(&fs::read(path).context("failed to read CGGMP share")?)
            .context("failed to parse CGGMP share")?;
    ensure!(
        stored.version == SHARE_FORMAT_VERSION,
        "unsupported CGGMP share version"
    );
    ensure!(
        stored.cluster_id == expected_cluster_id,
        "CGGMP share cluster mismatch"
    );
    ensure!(
        stored.epoch == expected_epoch,
        "CGGMP share epoch mismatch or rollback"
    );
    ensure!(
        stored.node_id == expected_node_id,
        "CGGMP share node mismatch"
    );
    ensure!(stored.curve == expected_curve, "CGGMP share curve mismatch");
    let expected_checksum = checksum(
        &stored.cluster_id,
        stored.epoch,
        &stored.node_id,
        stored.curve,
        &stored.payload,
    )?;
    ensure!(
        stored.checksum == hex::encode(expected_checksum),
        "CGGMP share checksum mismatch"
    );
    serde_json::from_value(stored.payload).context("CGGMP share validation failed")
}

fn checksum(
    cluster_id: &str,
    epoch: u64,
    node_id: &str,
    curve: CggmpCurve,
    payload: &serde_json::Value,
) -> Result<[u8; 32]> {
    let canonical = serde_jcs::to_vec(&ShareChecksum {
        version: SHARE_FORMAT_VERSION,
        cluster_id,
        epoch,
        node_id,
        curve,
        payload,
    })?;
    Ok(Sha256::digest(canonical).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cggmp21::ExecutionId;
    use rand::rngs::OsRng;

    #[test]
    fn cggmp_threshold_dkg_produces_consistent_validated_shares() {
        let n = 3;
        let threshold = 2;
        let eid = execution_id("test-cluster", 1, CggmpCurve::K256, &[9; 32]);
        let outputs = round_based::sim::run(n, |i, party| async move {
            cggmp21::keygen::<Secp256k1>(ExecutionId::new(&eid), i, n)
                .set_threshold(threshold)
                .start(&mut OsRng, party)
                .await
        })
        .unwrap()
        .expect_ok()
        .into_vec();
        let public_key = serde_json::to_vec(&outputs[0].shared_public_key()).unwrap();
        assert!(outputs.iter().all(|share| {
            serde_json::to_vec(&share.shared_public_key()).unwrap() == public_key
        }));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("k256-share.json");
        store_share(
            &path,
            "test-cluster",
            1,
            "kms-1",
            CggmpCurve::K256,
            &outputs[0],
        )
        .unwrap();
        let loaded: K256IncompleteShare =
            load_share(&path, "test-cluster", 1, "kms-1", CggmpCurve::K256).unwrap();
        assert_eq!(
            serde_json::to_vec(&loaded.shared_public_key()).unwrap(),
            public_key
        );
        assert!(load_share::<K256IncompleteShare>(
            &path,
            "test-cluster",
            2,
            "kms-1",
            CggmpCurve::K256
        )
        .is_err());
    }

    #[test]
    fn cggmp_p256_threshold_dkg_roundtrips_validated_share() {
        let n = 3;
        let threshold = 2;
        let eid = execution_id("test-cluster", 1, CggmpCurve::P256, &[8; 32]);
        let outputs = round_based::sim::run(n, |i, party| async move {
            cggmp21::keygen::<Secp256r1>(ExecutionId::new(&eid), i, n)
                .set_threshold(threshold)
                .start(&mut OsRng, party)
                .await
        })
        .unwrap()
        .expect_ok()
        .into_vec();
        let public_key = serde_json::to_vec(&outputs[0].shared_public_key()).unwrap();
        assert!(outputs.iter().all(|share| {
            serde_json::to_vec(&share.shared_public_key()).unwrap() == public_key
        }));

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("p256-share.json");
        store_share(
            &path,
            "test-cluster",
            1,
            "kms-1",
            CggmpCurve::P256,
            &outputs[0],
        )
        .unwrap();
        let loaded: P256IncompleteShare =
            load_share(&path, "test-cluster", 1, "kms-1", CggmpCurve::P256).unwrap();
        assert_eq!(
            serde_json::to_vec(&loaded.shared_public_key()).unwrap(),
            public_key
        );
    }
}
