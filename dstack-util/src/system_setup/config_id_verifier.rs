// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use dstack_types::{mr_config::MrConfig, KeyProviderKind};
use tracing::info;

fn read_mr_config_id() -> Result<[u8; 48]> {
    let (_, quote) = tdx_attest::get_quote(&[0u8; 64], None).context("Failed to get quote")?;
    let quote = dcap_qvl::quote::Quote::parse(&quote).context("Failed to parse quote")?;
    let configid = quote
        .report
        .as_td10()
        .context("Failed to get TD10 report")?
        .mr_config_id;
    Ok(configid)
}

/// Verify the mr_config_id matches the expected value
///
/// Configuration ID format
/// The mr_config_id is a 48 bytes value in the following format:
/// The first byte is the version of the format.
/// When version is 1, the next 32 bytes are the compose hash.
/// When version is 2, the next 32 bytes are the keccak256 hash of the instance info.
/// Where the instance info is a concatenated bytes of the following fields:
/// - compose_hash: [u8; 32]
/// - app_id: [u8; 20]
/// - key_provider_type: u8 // 0: none, 1: local, 2: kms
/// - key_provider_id: [u8] // the ca pubkey for KMS or the MR enclave for local-sgx provider, empty for none
pub fn verify_mr_config_id(
    compose_hash: &[u8; 32],
    app_id: &[u8; 20],
    key_provider: KeyProviderKind,
    key_provider_id: &[u8],
) -> Result<()> {
    let read_mr_config_id = read_mr_config_id().context("Failed to read mr_config_id")?;
    info!("mr_config_id: {}", hex::encode(read_mr_config_id));
    if read_mr_config_id == [0u8; 48] {
        return Ok(());
    }
    let mr_config = match read_mr_config_id[0] {
        1 => MrConfig::V1 { compose_hash },
        2 => MrConfig::V2 {
            compose_hash,
            app_id,
            key_provider,
            key_provider_id,
        },
        _ => bail!("Invalid mr_config_id version"),
    };
    if mr_config.to_mr_config_id() != read_mr_config_id {
        bail!("Invalid mr_config_id");
    }
    Ok(())
}
