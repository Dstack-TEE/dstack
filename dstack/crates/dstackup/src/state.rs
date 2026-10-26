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
    /// Backward-compatible data prefix. New clients should use the explicit
    /// directory fields below.
    pub(crate) prefix: String,
    #[serde(default)]
    pub(crate) install_prefix: Option<String>,
    #[serde(default)]
    pub(crate) config_dir: String,
    #[serde(default)]
    pub(crate) state_dir: String,
    #[serde(default)]
    pub(crate) cache_dir: String,
    #[serde(default)]
    pub(crate) run_dir: String,
    #[serde(default)]
    pub(crate) allowlist_path: String,
    #[serde(default)]
    pub(crate) platform: String,
    pub(crate) client_url: String,
    /// path to the management-API bearer token file the local `dstack` CLI
    /// reads to authenticate against the VMM.
    #[serde(default)]
    pub(crate) client_token_path: String,
    pub(crate) auth_port: u16,
    /// vsock CID pool start this install chose, so a re-run reuses it instead of
    /// picking a fresh window and moving a live instance's pool. Absent in state
    /// files written before this was recorded.
    #[serde(default)]
    pub(crate) cid_start: Option<u32>,
    /// systemd unit names (without the `.service` suffix).
    #[serde(default)]
    pub(crate) vmm_unit: String,
    #[serde(default)]
    pub(crate) auth_unit: String,
    #[serde(default)]
    pub(crate) kms_vm_id: Option<String>,
    #[serde(default)]
    pub(crate) kms_url: String,
    /// guest image selected by install for KMS and app deployments.
    #[serde(default)]
    pub(crate) image: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `read_state` swallows a parse error into `None`, which an install reads as
    /// "nothing here" — it would then re-pick the CID window and ports of a live
    /// install. So a state file written before a field existed must still load.
    #[test]
    fn a_state_file_without_cid_start_still_loads() {
        let dir = tempfile::tempdir().unwrap();
        let body = r#"{
            "prefix": "/var/lib/dstack",
            "client_url": "http://127.0.0.1:9080",
            "auth_port": 8090
        }"#;
        fs::write(state_path(dir.path()), body).unwrap();

        let st = read_state(dir.path()).expect("legacy state file must still parse");
        assert_eq!(st.cid_start, None);
        assert_eq!(st.auth_port, 8090);
    }
}
