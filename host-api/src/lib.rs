// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: BUSL-1.1

extern crate alloc;

pub use generated::*;

mod generated;

#[cfg(feature = "client")]
pub mod client;
