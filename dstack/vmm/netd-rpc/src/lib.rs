// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! RPC protocol between the VMM and `netd`, its privileged host networking
//! broker.

extern crate alloc;

pub use generated::*;

mod generated;
