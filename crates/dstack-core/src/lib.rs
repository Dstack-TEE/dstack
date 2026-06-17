// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! shared internals for the `dstack` (client) and `dstackup` (host setup) binaries.
//!
//! `vmm` is a thin typed client over the VMM `Vmm` prpc service; `compose` builds
//! the app-compose manifest; `ports` does host-port allocation. `config` (config
//! rendering for `dstackup install`) is still a stub — see
//! docs/onboarding-redesign.md §7.

/// re-export the generated VMM rpc types (VmConfiguration, PortMapping, …).
pub use dstack_vmm_rpc as rpc;

/// identifier string attached to outbound RPC calls.
pub fn user_agent() -> String {
    format!("dstack-cli/{}", env!("CARGO_PKG_VERSION"))
}

pub mod compose;
pub mod config;
pub mod host;
pub mod ports;
pub mod vmm;
