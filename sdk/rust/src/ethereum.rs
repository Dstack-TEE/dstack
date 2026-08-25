// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
//
// SPDX-License-Identifier: Apache-2.0

use alloy::signers::local::PrivateKeySigner;
use dstack_sdk_types::dstack_v0::GetKeyResponse;

/// Build a signer from a `get_key` response.
///
/// A v0-era adapter, and deliberately still typed against the v0 response: the
/// v1 surface has no chain-related functionality. v1's story ends at "`GetKey`
/// returns key material"; what an application builds from those bytes is its
/// own business, not something this SDK models.
pub fn to_account(
    get_key_response: &GetKeyResponse,
) -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(&get_key_response.key)?;
    let wallet = PrivateKeySigner::from_slice(&key_bytes)?;
    Ok(wallet)
}
