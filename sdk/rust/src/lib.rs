// SPDX-FileCopyrightText: © 2025 Created-for-a-purpose <rachitchahar@gmail.com>
// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

pub mod dstack_client;
pub mod dstack_client_v1;

/// The recommended client: the v1 guest-agent surface.
///
/// See [`dstack_client_v1::DstackClient`] for what changed in 0.6.0.
pub use dstack_client_v1::{DstackClient, DstackClientV1};
pub mod ethereum;
pub mod tappd_client;
