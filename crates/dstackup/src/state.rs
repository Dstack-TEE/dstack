// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! install-state persistence: what an install put in place, so re-runs are
//! idempotent and `destroy` can reverse it cleanly.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct State {
    pub(crate) prefix: String,
    pub(crate) client_url: String,
    pub(crate) auth_port: u16,
    /// systemd unit names (without the `.service` suffix).
    #[serde(default)]
    pub(crate) vmm_unit: String,
    #[serde(default)]
    pub(crate) auth_unit: String,
    #[serde(default)]
    pub(crate) kms_vm_id: Option<String>,
    #[serde(default)]
    pub(crate) kms_url: String,
    /// docker-compose project for a key provider we started ourselves.
    #[serde(default)]
    pub(crate) kp_own_project: Option<String>,
}

pub(crate) fn state_path(prefix: &Path) -> PathBuf {
    prefix.join("dstackup-state.json")
}

pub(crate) fn read_state(prefix: &Path) -> Option<State> {
    let body = fs::read_to_string(state_path(prefix)).ok()?;
    serde_json::from_str(&body).ok()
}

pub(crate) fn write_state(prefix: &Path, st: &State) -> Result<()> {
    write(&state_path(prefix), &serde_json::to_string_pretty(st)?)
}

/// write a file atomically (temp + rename), so a crash mid-write never leaves
/// a torn config or state file.
pub(crate) fn write(path: &Path, body: &str) -> Result<()> {
    dstack_cli_core::fsutil::write_atomic(path, body)
        .with_context(|| format!("writing {}", path.display()))
}
