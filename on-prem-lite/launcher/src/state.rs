// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use tokio::sync::{Mutex, RwLock};

use crate::config::Config;
use crate::license::InstalledLicense;

/// Coarse phase reported by /healthz.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// process up, config loaded, no persisted/valid license yet
    Booting,
    /// courier API serving, awaiting the operator's install
    Waiting,
    /// a valid license is installed and the workload is (meant to be) running
    Running,
    /// the license expired (past expires_at + grace); workload stopped
    Expired,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::Booting => "booting",
            Phase::Waiting => "waiting",
            Phase::Running => "running",
            Phase::Expired => "expired",
        }
    }
}

pub struct AppState {
    /// Raw 32-byte X25519 transport private scalar for the current courier
    /// session (used to HPKE-open the sealed CEK). Never leaves TEE memory.
    pub transport_secret: RwLock<Option<[u8; 32]>>,
    pub transport_pub: RwLock<Option<[u8; 32]>>,
    pub config: Config,
    pub phase: RwLock<Phase>,
    /// The currently installed license (metadata only — no secrets), if any.
    pub installed: RwLock<Option<InstalledLicense>>,
    /// Last error category surfaced on /status (never secret material).
    pub last_error: RwLock<Option<String>>,
    /// Generation counter bumped on each successful install so a stale expiry
    /// watchdog (from a superseded license) exits instead of stopping a renewed
    /// workload. The watchdog captures the generation it was started with.
    pub generation: Mutex<u64>,
}
