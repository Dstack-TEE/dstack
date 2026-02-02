// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Dummy implementation for non-Linux/non-x86_64 platforms.
//!
//! All functions return `NotSupported` error.

use thiserror::Error;

use crate::{Result, TdxReport, TdxReportData};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TdxAttestError {
    #[error("unexpected error")]
    Unexpected,
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("out of memory")]
    OutOfMemory,
    #[error("vsock failure")]
    VsockFailure,
    #[error("report failure")]
    ReportFailure,
    #[error("extend failure")]
    ExtendFailure,
    #[error("not supported")]
    NotSupported,
    #[error("quote failure")]
    QuoteFailure,
    #[error("device busy")]
    Busy,
    #[error("device failure")]
    DeviceFailure,
    #[error("invalid RTMR index")]
    InvalidRtmrIndex,
    #[error("unsupported attestation key ID")]
    UnsupportedAttKeyId,
}

pub fn get_quote(_report_data: &TdxReportData) -> Result<Vec<u8>> {
    Err(TdxAttestError::NotSupported)
}

pub fn get_report(_report_data: &TdxReportData) -> Result<TdxReport> {
    Err(TdxAttestError::NotSupported)
}

pub fn extend_rtmr(_index: u32, _event_type: u32, _digest: [u8; 48]) -> Result<()> {
    Err(TdxAttestError::NotSupported)
}
