// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! KMS root epoch chain hashes, computed as the DstackKms contract does.

use sha3::{Digest, Keccak256};

/// Chain hashes of root epochs 0, 1, ... given each epoch's
/// `(ca_pubkey, k256_pubkey)`. Epoch `n`'s hash is
/// `keccak256(previous || keccak256(ca_pubkey) || keccak256(k256_pubkey))`
/// with a zero previous hash for epoch 0, so it commits to every key up to `n`;
/// the position in the chain fixes the epoch number.
pub fn chain_hashes<'a>(epochs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Vec<[u8; 32]> {
    let mut previous = [0u8; 32];
    epochs
        .into_iter()
        .map(|(ca_pubkey, k256_pubkey)| {
            previous = Keccak256::new()
                .chain_update(previous)
                .chain_update(Keccak256::digest(ca_pubkey))
                .chain_update(Keccak256::digest(k256_pubkey))
                .finalize()
                .into();
            previous
        })
        .collect()
}
