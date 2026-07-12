// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::Path;

use anyhow::{Context, Result};
use fs_err as fs;
use serde::de::DeserializeOwned;

pub use dstack_types::{AppCompose, AppKeys, KeyProviderKind, SysConfig};

pub fn deserialize_json_file<T: DeserializeOwned>(path: impl AsRef<Path>) -> Result<T> {
    let data = fs::read_to_string(path).context("Failed to read file")?;
    serde_json::from_str(&data).context("Failed to parse json")
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut sha256 = sha2::Sha256::new();
    sha256.update(data);
    sha256.finalize().into()
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<[u8; 32]> {
    let data = fs::read(path).context("Failed to read file")?;
    Ok(sha256(&data))
}
