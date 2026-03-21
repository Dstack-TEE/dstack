// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! VMM instance discovery via registration files.
//!
//! On startup each `dstack-vmm` process writes a JSON file to a well-known
//! directory so that CLI tools can discover all running instances on the host.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::{info, warn};
use uuid::Uuid;

/// Returns the discovery directory path.
/// Uses $XDG_RUNTIME_DIR/dstack-vmm if set, otherwise falls back to /run/dstack-vmm.
fn discovery_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        PathBuf::from(xdg).join("dstack-vmm")
    } else {
        PathBuf::from("/run/dstack-vmm")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmmInstanceInfo {
    /// Unique identifier for this VMM instance (random UUID).
    pub id: String,
    /// Process ID.
    pub pid: u32,
    /// Address the external API listens on (e.g. "unix:./vmm.sock" or "0.0.0.0:9080").
    pub address: String,
    /// Working directory of the VMM process.
    pub working_dir: String,
    /// Path to the configuration file (if provided via -c).
    pub config_file: Option<String>,
    /// Path where VM images are stored.
    pub image_path: String,
    /// Path where VM runtime data is stored.
    pub run_path: String,
    /// Node name from configuration.
    pub node_name: String,
    /// VMM version string.
    pub version: String,
    /// Unix timestamp (seconds) when the instance started.
    pub started_at: u64,
}

/// Handle that manages the lifecycle of a discovery registration file.
/// The file is removed when this handle is dropped.
pub struct DiscoveryRegistration {
    path: PathBuf,
}

impl DiscoveryRegistration {
    /// Register a new VMM instance. Creates the discovery directory if needed
    /// and writes the instance info JSON file.
    pub fn register(
        listen_address: &str,
        config_file: Option<&str>,
        image_path: &Path,
        run_path: &Path,
        node_name: &str,
        version: &str,
    ) -> Result<Self> {
        let dir = discovery_dir();
        fs_err::create_dir_all(&dir).context("failed to create discovery directory")?;

        let id = Uuid::new_v4().to_string();
        let path = dir.join(format!("{id}.json"));

        let cwd = std::env::current_dir().context("failed to get current directory")?;

        let info = VmmInstanceInfo {
            id: id.clone(),
            pid: std::process::id(),
            address: listen_address.to_string(),
            working_dir: cwd.to_string_lossy().to_string(),
            config_file: config_file.map(|s| s.to_string()),
            image_path: image_path.to_string_lossy().to_string(),
            run_path: run_path.to_string_lossy().to_string(),
            node_name: node_name.to_string(),
            version: version.to_string(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let json =
            serde_json::to_string_pretty(&info).context("failed to serialize instance info")?;
        fs_err::write(&path, &json).context("failed to write discovery file")?;

        info!("registered VMM instance {id} at {}", path.display());
        Ok(Self { path })
    }
}

impl Drop for DiscoveryRegistration {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => info!("unregistered VMM instance at {}", self.path.display()),
            Err(e) => warn!(
                "failed to remove discovery file {}: {e}",
                self.path.display()
            ),
        }
    }
}

/// Clean up stale discovery files from dead processes.
pub fn cleanup_stale_registrations() {
    let dir = discovery_dir();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let info: VmmInstanceInfo = match serde_json::from_str(&content) {
            Ok(i) => i,
            Err(_) => continue,
        };
        // Check if the process is still alive
        let alive = Path::new(&format!("/proc/{}", info.pid)).exists();
        if !alive {
            info!(
                "removing stale discovery file for pid {} at {}",
                info.pid,
                path.display()
            );
            let _ = std::fs::remove_file(&path);
        }
    }
}
