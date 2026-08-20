// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pub const CARGO_PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GIT_REV: &str = dstack_build_info::git_revision!();

pub mod backend;
pub mod config;
mod container_health;
mod guest_api_service;
mod http_routes;
mod models;
pub mod rpc_service;
mod server;
mod socket_activation;

pub use rpc_service::AppState;
pub use server::{app_version, run as run_server};
