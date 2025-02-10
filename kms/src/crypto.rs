use anyhow::{Context, Result};
use k256::ecdsa::{RecoveryId, Signature, SigningKey};
use sha3::{Digest, Keccak256};

use ra_tls::kdf;

pub(crate) fn derive_k256_key(
    parent_key: &SigningKey,
    app_id: &[u8],
) -> Result<(SigningKey, Signature, RecoveryId)> {
    let context_data = [app_id, b"app-key"];
    let derived_key_bytes: [u8; 32] =
        kdf::derive_ecdsa_key(&parent_key.to_bytes(), &context_data, 32)?
            .try_into()
            .ok()
            .context("Invalid derived key len")?;
    let derived_signing_key = SigningKey::from_bytes(&derived_key_bytes.into())?;
    let pubkey = derived_signing_key.verifying_key();
    let digest = Keccak256::new_with_prefix(
        [b"dstack-kms-issued:", app_id, &pubkey.to_sec1_bytes()].concat(),
    );
    let (signature, recid) = parent_key.sign_digest_recoverable(digest)?;

    Ok((derived_signing_key, signature, recid))
}
