// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use tdx_attest_sys as sys;

use std::ptr;
use std::slice;
use std::sync::Mutex;

use sys::*;

/// Global lock for TDX attestation operations. The TDX driver does not support concurrent access.
static TDX_LOCK: Mutex<()> = Mutex::new(());

use num_enum::FromPrimitive;
use thiserror::Error;

use crate::TdxReport;
use crate::TdxReportData;
use crate::{Result, TdxUuid};

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, Error)]
pub enum TdxAttestError {
    #[error("TDX_ATTEST_ERROR_UNEXPECTED")]
    Unexpected = _tdx_attest_error_t::TDX_ATTEST_ERROR_UNEXPECTED,
    #[error("TDX_ATTEST_ERROR_INVALID_PARAMETER")]
    InvalidParameter = _tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_PARAMETER,
    #[error("TDX_ATTEST_ERROR_OUT_OF_MEMORY")]
    OutOfMemory = _tdx_attest_error_t::TDX_ATTEST_ERROR_OUT_OF_MEMORY,
    #[error("TDX_ATTEST_ERROR_VSOCK_FAILURE")]
    VsockFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_VSOCK_FAILURE,
    #[error("TDX_ATTEST_ERROR_REPORT_FAILURE")]
    ReportFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_REPORT_FAILURE,
    #[error("TDX_ATTEST_ERROR_EXTEND_FAILURE")]
    ExtendFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_EXTEND_FAILURE,
    #[error("TDX_ATTEST_ERROR_NOT_SUPPORTED")]
    NotSupported = _tdx_attest_error_t::TDX_ATTEST_ERROR_NOT_SUPPORTED,
    #[error("TDX_ATTEST_ERROR_QUOTE_FAILURE")]
    QuoteFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_QUOTE_FAILURE,
    #[error("TDX_ATTEST_ERROR_BUSY")]
    Busy = _tdx_attest_error_t::TDX_ATTEST_ERROR_BUSY,
    #[error("TDX_ATTEST_ERROR_DEVICE_FAILURE")]
    DeviceFailure = _tdx_attest_error_t::TDX_ATTEST_ERROR_DEVICE_FAILURE,
    #[error("TDX_ATTEST_ERROR_INVALID_RTMR_INDEX")]
    InvalidRtmrIndex = _tdx_attest_error_t::TDX_ATTEST_ERROR_INVALID_RTMR_INDEX,
    #[error("TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID")]
    UnsupportedAttKeyId = _tdx_attest_error_t::TDX_ATTEST_ERROR_UNSUPPORTED_ATT_KEY_ID,
    #[num_enum(catch_all)]
    #[error("unknown tdx attest error ({0})")]
    UnknownError(u32),
}

pub fn get_quote(report_data: &TdxReportData) -> Result<Vec<u8>> {
    // Lock to prevent concurrent access - TDX driver doesn't support it
    let _guard = TDX_LOCK.lock().map_err(|_| TdxAttestError::Busy)?;

    let mut att_key_id = TdxUuid([0; TDX_UUID_SIZE as usize]);
    let mut quote_ptr = ptr::null_mut();
    let mut quote_size = 0;

    let error = unsafe {
        let key_id_list_ptr = ptr::null();
        tdx_att_get_quote(
            report_data as *const TdxReportData as *const tdx_report_data_t,
            key_id_list_ptr,
            0,
            &mut att_key_id as *mut TdxUuid as *mut tdx_uuid_t,
            &mut quote_ptr,
            &mut quote_size,
            0,
        )
    };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    let quote = unsafe { slice::from_raw_parts(quote_ptr, quote_size as usize).to_vec() };

    unsafe {
        tdx_att_free_quote(quote_ptr);
    }

    Ok(quote)
}

pub fn get_report(report_data: &TdxReportData) -> Result<TdxReport> {
    let mut report = TdxReport([0; TDX_REPORT_SIZE as usize]);

    let error = unsafe {
        tdx_att_get_report(
            report_data as *const TdxReportData as *const tdx_report_data_t,
            &mut report as *mut TdxReport as *mut tdx_report_t,
        )
    };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    Ok(report)
}

pub fn extend_rtmr(index: u32, event_type: u32, digest: [u8; 48]) -> Result<()> {
    let event = tdx_rtmr_event_t {
        version: 1,
        rtmr_index: index as u64,
        extend_data: digest,
        event_type,
        event_data_size: 0,
        event_data: Default::default(),
    };
    let error = unsafe { tdx_att_extend(&event) };
    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }
    Ok(())
}

pub fn get_supported_att_key_ids() -> Result<Vec<TdxUuid>> {
    let mut list_size = 0;
    let error = unsafe { tdx_att_get_supported_att_key_ids(ptr::null_mut(), &mut list_size) };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    let mut att_key_id_list = vec![TdxUuid([0; TDX_UUID_SIZE as usize]); list_size as usize];

    let error = unsafe {
        tdx_att_get_supported_att_key_ids(
            att_key_id_list.as_mut_ptr() as *mut tdx_uuid_t,
            &mut list_size,
        )
    };

    if error != _tdx_attest_error_t::TDX_ATTEST_SUCCESS {
        return Err(error.into());
    }

    Ok(att_key_id_list)
}
