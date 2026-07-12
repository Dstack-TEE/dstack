// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! CVM verification library
//!
//! This library provides functionality to verify Confidential VM (CVM) attestations,
//! including TDX quote verification, event log replay, and OS image hash validation.
//!
//! Can be used both as a library and as a standalone binary/HTTP server.

mod types;
mod verification;

// Re-export TdxMeasurements from dstack-mr for convenience
pub use dstack_mr::TdxMeasurements;

pub use types::{
    AcpiTables, RtmrEventEntry, RtmrEventStatus, RtmrMismatch, VerificationDetails,
    VerificationRequest, VerificationResponse,
};
pub use verification::CvmVerifier;
