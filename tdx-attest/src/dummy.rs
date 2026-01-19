// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use num_enum::FromPrimitive;
use thiserror::Error;

use crate::{TdxReport, TdxReportData, TdxUuid};

type Result<T> = std::result::Result<T, TdxAttestError>;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, Error)]
pub enum TdxAttestError {
    #[error("unexpected")]
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
    #[error("busy")]
    Busy,
    #[error("device failure")]
    DeviceFailure,
    #[error("invalid rtmr index")]
    InvalidRtmrIndex,
    #[error("unsupported att key id")]
    UnsupportedAttKeyId,
    #[num_enum(catch_all)]
    #[error("unknown error ({0})")]
    UnknownError(u32),
}

pub fn extend_rtmr(_index: u32, _event_type: u32, _digest: [u8; 48]) -> Result<()> {
    Err(TdxAttestError::NotSupported)
}
pub fn get_report(_report_data: &TdxReportData) -> Result<TdxReport> {
    Err(TdxAttestError::NotSupported)
}
pub fn get_quote(_report_data: &TdxReportData) -> Result<Vec<u8>> {
    let _ = _report_data;
    Err(TdxAttestError::NotSupported)
}
pub fn get_supported_att_key_ids() -> Result<Vec<TdxUuid>> {
    Err(TdxAttestError::NotSupported)
}
