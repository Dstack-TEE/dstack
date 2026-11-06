// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! KMS root epoch chain hashes, computed as the DstackKms contract does.

use sha3::{Digest, Keccak256};

/// Chain hashes of root epochs 0, 1, ... given each epoch's
/// `(ca_pubkey, k256_pubkey)`. Epoch `n`'s hash is
/// `keccak256(previous || uint256(n) || keccak256(ca_pubkey) || keccak256(k256_pubkey))`
/// with a zero previous hash for epoch 0, so it commits to every key up to `n`.
pub fn chain_hashes<'a>(epochs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Vec<[u8; 32]> {
    let mut previous = [0u8; 32];
    (0u64..)
        .zip(epochs)
        .map(|(epoch, (ca_pubkey, k256_pubkey))| {
            let mut epoch_word = [0u8; 32];
            epoch_word[24..].copy_from_slice(&epoch.to_be_bytes());
            previous = Keccak256::new()
                .chain_update(previous)
                .chain_update(epoch_word)
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

    /// Shared with the DstackKms contract and auth-simple tests.
    #[test]
    fn matches_the_contract_vectors() {
        let hashes = chain_hashes([(&[0xa0u8][..], &[0xb0u8][..]), (&[0xa1][..], &[0xb1][..])]);
        assert_eq!(
            hex::encode(hashes[0]),
            "f5f9a7455970becbb0d8441e53cf06df6290b34419cf783eb5869107867ec9ae"
        );
        assert_eq!(
            hex::encode(hashes[1]),
            "2219fc74439588d8f9d514f4e897d4a1dc692519b0899d93f5ac5661b8e2850a"
        );
    }
}
