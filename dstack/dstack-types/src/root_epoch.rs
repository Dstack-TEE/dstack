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

#[cfg(test)]
mod tests {
    use super::*;

    /// Well-formed root public keys whose point bytes are all `fill`.
    fn test_keys(ca_fill: u8, k256_fill: u8) -> (Vec<u8>, Vec<u8>) {
        let mut ca = hex::decode("3059301306072a8648ce3d020106082a8648ce3d03010703420004").unwrap();
        ca.resize(91, ca_fill);
        let mut k256 = vec![0x02];
        k256.resize(33, k256_fill);
        (ca, k256)
    }

    /// Shared with the DstackKms contract and dstack-auth tests.
    #[test]
    fn matches_the_contract_vectors() {
        let epochs = [test_keys(0xa0, 0xb0), test_keys(0xa1, 0xb1)];
        let hashes = chain_hashes(epochs.iter().map(|(ca, k256)| (&ca[..], &k256[..])));
        assert_eq!(
            hex::encode(hashes[0]),
            "10ab6b6c8e7601901b0f1767985bf40d35bf3129e0866fe12dcc7c8f04a298f2"
        );
        assert_eq!(
            hex::encode(hashes[1]),
            "50152a82023f2219a31723b476c13bc5f608ab4147946dabdec15d4f3d648ed4"
        );
    }
}
