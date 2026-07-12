// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pub const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = git_version::git_version!(
    args = ["--abbrev=20", "--always", "--dirty=-modified"],
    prefix = "git:",
    fallback = "unknown"
);

pub mod backend;
pub mod config;
mod guest_api_service;
mod http_routes;
mod models;
pub mod rpc_service;
mod server;
mod socket_activation;

pub use rpc_service::AppState;
pub use server::{app_version, run as run_server};
