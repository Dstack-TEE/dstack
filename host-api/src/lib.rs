// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

extern crate alloc;

pub use generated::*;

mod generated;

#[cfg(feature = "client")]
pub mod client;
