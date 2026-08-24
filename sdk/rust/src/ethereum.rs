// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Daniel Sharifi <daniel.sharifi@nearone.org>
//
// SPDX-License-Identifier: Apache-2.0

use alloy::signers::local::PrivateKeySigner;
use dstack_sdk_types::dstack::GetKeyResponse;
use dstack_sdk_types::dstack_v1::GetKeyResponse as GetKeyResponseV1;

/// Build a signer from a v1 `get_key` response.
///
/// Separate from [`to_account`] rather than generic: the two responses are
/// different contracts that happen to agree on this one field today, and a
/// signer built from the wrong surface would hold a different key than the
/// caller thinks. Naming the surface at the call site keeps that visible.
pub fn to_account_v1(
    get_key_response: &GetKeyResponseV1,
) -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(&get_key_response.key)?;
    let wallet = PrivateKeySigner::from_slice(&key_bytes)?;
    Ok(wallet)
}

/// Build a signer from a frozen v0 `get_key` response.
pub fn to_account(
    get_key_response: &GetKeyResponse,
) -> Result<PrivateKeySigner, Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(&get_key_response.key)?;
    let wallet = PrivateKeySigner::from_slice(&key_bytes)?;
    Ok(wallet)
}
