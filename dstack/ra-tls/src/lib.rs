// SPDX-FileCopyrightText: © 2024 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! RATLS library for Phala
#![deny(missing_docs)]

pub extern crate rcgen;

pub mod attestation;

pub mod api_v1;
pub mod cert;
pub mod kdf;
pub mod oids;
#[cfg(feature = "test-pki")]
pub mod test_pki;
pub mod traits;
