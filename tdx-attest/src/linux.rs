// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pure Rust implementation of TDX attestation operations.
//!
//! This module provides TDX quote generation, report retrieval, and RTMR extension
//! without depending on the C tdx-attest library. It supports three methods for
//! quote generation (in priority order):
//!
//! 1. ConfigFS - via `/sys/kernel/config/tsm/report/` (Linux 6.7+)
//! 2. VSock - via QGS (Quote Generation Service) over vsock
//! 3. TDVMCALL - via `/dev/tdx_guest` ioctl (legacy)

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::{Result, TdxReport, TdxReportData};

// ============================================================================
// Constants
// ============================================================================

const TDX_GUEST_DEVICE: &str = "/dev/tdx_guest";
const CONFIGFS_BASE: &str = "/sys/kernel/config/tsm/report";
const CONFIGFS_DEFAULT: &str = "/sys/kernel/config/tsm/report/com.intel.dcap";
const CONFIGFS_PATH_ENV: &str = "DCAP_TDX_QUOTE_CONFIGFS_PATH";
const RTMR_SYSFS_BASE: &str = "/sys/devices/virtual/misc/tdx_guest/measurements";
const TDX_ATTEST_CONFIG_PATH: &str = "/etc/tdx-attest.conf";

const TDX_REPORT_DATA_SIZE: usize = 64;
const TDX_REPORT_SIZE: usize = 1024;
const RTMR_EXTEND_DATA_SIZE: usize = 48;
const QUOTE_BUF_SIZE: usize = 8 * 1024;
const QUOTE_MIN_SIZE: usize = 1020;

// QGS message constants
const QGS_MSG_LEN_PREFIX_SIZE: usize = 4; // 4-byte length prefix
const QGS_REQ_BUF_SIZE: usize = 16 * 1024; // 16KB buffer for request/response

// QGS message types
const QGS_MSG_GET_QUOTE_REQ: u32 = 0;
const QGS_MSG_GET_QUOTE_RESP: u32 = 1;

// QGS message version
const QGS_MSG_VERSION_MAJOR: u16 = 1;
const QGS_MSG_VERSION_MINOR: u16 = 0;

// ============================================================================
// ioctl definitions for /dev/tdx_guest
// ============================================================================

// ioctl request type varies between glibc and musl
#[cfg(target_env = "musl")]
type IoctlRequest = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlRequest = libc::c_ulong;

// ioctl command encoding
const fn ioc(dir: u32, ty: u8, nr: u8, size: usize) -> IoctlRequest {
    (((dir as IoctlRequest) << 30)
        | ((ty as IoctlRequest) << 8)
        | (nr as IoctlRequest)
        | ((size as IoctlRequest) << 16)) as IoctlRequest
}

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

fn iowr<T>(ty: u8, nr: u8) -> IoctlRequest {
    ioc(IOC_READ | IOC_WRITE, ty, nr, std::mem::size_of::<T>())
}

fn ior<T>(ty: u8, nr: u8) -> IoctlRequest {
    ioc(IOC_READ, ty, nr, std::mem::size_of::<T>())
}

// TDX ioctl commands
fn tdx_cmd_get_report0() -> IoctlRequest {
    iowr::<TdxReportReq>(b'T', 1)
}

// Note: Kernel driver uses _IOR (not _IOW) for extend RTMR
fn tdx_cmd_extend_rtmr() -> IoctlRequest {
    ior::<TdxExtendRtmrReq>(b'T', 3)
}

// ============================================================================
// Kernel interface structures
// ============================================================================

#[repr(C)]
struct TdxReportReq {
    reportdata: [u8; TDX_REPORT_DATA_SIZE],
    tdreport: [u8; TDX_REPORT_SIZE],
}

#[repr(C)]
struct TdxExtendRtmrReq {
    data: [u8; RTMR_EXTEND_DATA_SIZE],
    index: u8,
}

// ============================================================================
// Error types
// ============================================================================

#[derive(Debug, Error)]
pub enum TdxAttestError {
    #[error("unexpected error: {0}")]
    Unexpected(String),
    #[error("invalid parameter")]
    InvalidParameter,
    #[error("out of memory")]
    OutOfMemory,
    #[error("vsock failure: {0}")]
    VsockFailure(#[from] std::io::Error),
    #[error("report failure: {0}")]
    ReportFailure(String),
    #[error("extend failure: {0}")]
    ExtendFailure(String),
    #[error("not supported: {0}")]
    NotSupported(String),
    #[error("quote failure: {0}")]
    QuoteFailure(String),
    #[error("device busy")]
    Busy,
    #[error("device failure: {0}")]
    DeviceFailure(String),
    #[error("invalid RTMR index: {0}")]
    InvalidRtmrIndex(u32),
    #[error("unsupported attestation key ID")]
    UnsupportedAttKeyId,
}

// ============================================================================
// Global state
// ============================================================================

/// Global lock for TDX operations - the driver doesn't support concurrent access
static TDX_LOCK: Mutex<()> = Mutex::new(());

/// Track if we've already tried to create the configfs directory
static CONFIGFS_MKDIR_TRIED: Mutex<bool> = Mutex::new(false);

// ============================================================================
// Public API
// ============================================================================

/// Get a TDX quote for the given report data.
///
/// Tries multiple methods in order:
/// 1. ConfigFS (Linux 6.7+)
/// 2. VSock to QGS service
pub fn get_quote(report_data: &TdxReportData) -> Result<Vec<u8>> {
    let _guard = TDX_LOCK.lock().map_err(|_| TdxAttestError::Busy)?;

    if is_configfs_available() {
        return get_quote_via_configfs(report_data);
    }

    if is_vsock_available() {
        return get_quote_via_vsock(report_data);
    }

    Err(TdxAttestError::NotSupported(
        "no quote method available (configfs not mounted, no vsock port configured)".to_string(),
    ))
}

fn is_configfs_available() -> bool {
    Path::new(CONFIGFS_DEFAULT).is_dir() || Path::new(CONFIGFS_BASE).is_dir()
}

fn is_vsock_available() -> bool {
    read_vsock_port().map(|p| p > 0).unwrap_or(false)
}

/// Get a TDX report for the given report data.
pub fn get_report(report_data: &TdxReportData) -> Result<TdxReport> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_GUEST_DEVICE)
        .map_err(|e| TdxAttestError::DeviceFailure(format!("open {TDX_GUEST_DEVICE}: {e}")))?;

    let mut req = TdxReportReq {
        reportdata: *report_data,
        tdreport: [0u8; TDX_REPORT_SIZE],
    };

    let ret = unsafe { libc::ioctl(file.as_raw_fd(), tdx_cmd_get_report0(), &mut req) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(TdxAttestError::ReportFailure(format!("ioctl: {err}")));
    }

    Ok(TdxReport(req.tdreport))
}

/// Extend a TDX RTMR (Runtime Measurement Register).
///
/// RTMR[index] = SHA384(RTMR[index] || digest)
///
/// Only RTMR indices 2 and 3 are user-extensible.
///
/// Tries two methods:
/// 1. sysfs interface at `/sys/devices/virtual/misc/tdx_guest/measurements/rtmrN:sha384`
/// 2. ioctl on `/dev/tdx_guest` (legacy)
pub fn extend_rtmr(index: u32, _event_type: u32, digest: [u8; 48]) -> Result<()> {
    if index > 3 {
        return Err(TdxAttestError::InvalidRtmrIndex(index));
    }

    if is_rtmr_sysfs_available() {
        return extend_rtmr_via_sysfs(index, &digest);
    }

    if Path::new(TDX_GUEST_DEVICE).exists() {
        return extend_rtmr_via_ioctl(index, digest);
    }

    Err(TdxAttestError::NotSupported(
        "no extend_rtmr method available (no sysfs measurements, no /dev/tdx_guest)".to_string(),
    ))
}

fn is_rtmr_sysfs_available() -> bool {
    Path::new(RTMR_SYSFS_BASE).is_dir()
}

fn extend_rtmr_via_sysfs(index: u32, digest: &[u8; 48]) -> Result<()> {
    let path = format!("{}/rtmr{}:sha384", RTMR_SYSFS_BASE, index);

    let mut file = OpenOptions::new()
        .write(true)
        .open(&path)
        .map_err(|e| TdxAttestError::ExtendFailure(format!("open {path}: {e}")))?;

    file.write_all(digest).map_err(|e| match e.raw_os_error() {
        Some(libc::EINVAL) => TdxAttestError::InvalidRtmrIndex(index),
        Some(libc::EPERM) | Some(libc::EACCES) => {
            TdxAttestError::ExtendFailure(format!("permission denied for RTMR {index}"))
        }
        _ => TdxAttestError::ExtendFailure(format!("write {path}: {e}")),
    })
}

fn extend_rtmr_via_ioctl(index: u32, digest: [u8; 48]) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(TDX_GUEST_DEVICE)
        .map_err(|e| TdxAttestError::ExtendFailure(format!("open {TDX_GUEST_DEVICE}: {e}")))?;

    let req = TdxExtendRtmrReq {
        data: digest,
        index: index as u8,
    };

    let ret = unsafe { libc::ioctl(file.as_raw_fd(), tdx_cmd_extend_rtmr(), &req) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);
        if errno == libc::EINVAL {
            return Err(TdxAttestError::InvalidRtmrIndex(index));
        }
        return Err(TdxAttestError::ExtendFailure(format!("ioctl: {err}")));
    }

    Ok(())
}

// ============================================================================
// ConfigFS Quote Generation
// ============================================================================

/// Get quote using Linux ConfigFS TSM interface (Linux 6.7+)
fn get_quote_via_configfs(report_data: &TdxReportData) -> Result<Vec<u8>> {
    let configfs_path = prepare_configfs()?;

    let inblob_path = format!("{}/inblob", configfs_path);
    let outblob_path = format!("{}/outblob", configfs_path);
    let generation_path = format!("{}/generation", configfs_path);

    let lock_file = OpenOptions::new()
        .write(true)
        .open(&inblob_path)
        .map_err(|e| TdxAttestError::Unexpected(format!("open {inblob_path}: {e}")))?;

    let ret = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        let err = std::io::Error::last_os_error();
        return Err(TdxAttestError::Unexpected(format!(
            "flock {inblob_path}: {err}"
        )));
    }

    let gen1 = read_generation(&generation_path)?;
    write_inblob_with_retry(&inblob_path, report_data)?;

    let gen2 = wait_for_generation_change(&generation_path, gen1)?;
    if gen2 != gen1 + 1 {
        return Err(TdxAttestError::Busy);
    }

    let quote = read_outblob_with_retry(&outblob_path)?;

    let gen3 = read_generation(&generation_path)?;
    if gen3 != gen2 {
        return Err(TdxAttestError::Busy);
    }

    if quote.len() <= QUOTE_MIN_SIZE || quote.len() >= QUOTE_BUF_SIZE {
        return Err(TdxAttestError::QuoteFailure(format!(
            "invalid quote size: {}",
            quote.len()
        )));
    }

    Ok(quote)
}

fn prepare_configfs() -> Result<String> {
    if let Ok(path) = std::env::var(CONFIGFS_PATH_ENV) {
        if path.len() < 240 && Path::new(&path).is_dir() && verify_configfs_provider(&path)? {
            return Ok(path);
        }
        return Err(TdxAttestError::NotSupported(format!(
            "invalid configfs path from env: {path}"
        )));
    }

    let default_path = CONFIGFS_DEFAULT;
    if Path::new(default_path).is_dir() && verify_configfs_provider(default_path)? {
        return Ok(default_path.to_string());
    }

    {
        let mut tried = CONFIGFS_MKDIR_TRIED
            .lock()
            .map_err(|_| TdxAttestError::Busy)?;
        if *tried {
            return Err(TdxAttestError::NotSupported(
                "configfs already tried".to_string(),
            ));
        }
        *tried = true;
    }

    if !Path::new(CONFIGFS_BASE).is_dir() {
        return Err(TdxAttestError::NotSupported(format!(
            "configfs base not found: {CONFIGFS_BASE}"
        )));
    }

    if fs::create_dir(default_path).is_ok() || Path::new(default_path).is_dir() {
        let provider_path = format!("{}/provider", default_path);
        for i in 0..5 {
            if Path::new(&provider_path).exists() {
                if verify_configfs_provider(default_path)? {
                    return Ok(default_path.to_string());
                }
                break;
            }
            thread::sleep(Duration::from_micros(i as u64));
        }
    }

    Err(TdxAttestError::NotSupported(format!(
        "failed to prepare configfs: {default_path}"
    )))
}

fn verify_configfs_provider(path: &str) -> Result<bool> {
    let provider_path = format!("{}/provider", path);
    let provider = fs::read_to_string(&provider_path)
        .map_err(|e| TdxAttestError::Unexpected(format!("read {provider_path}: {e}")))?;

    Ok(provider.trim().starts_with("tdx_guest"))
}

fn read_generation(path: &str) -> Result<i64> {
    let content = fs::read_to_string(path)
        .map_err(|e| TdxAttestError::Unexpected(format!("read {path}: {e}")))?;
    content
        .trim()
        .parse()
        .map_err(|e| TdxAttestError::Unexpected(format!("parse generation: {e}")))
}

fn write_inblob_with_retry(path: &str, data: &TdxReportData) -> Result<()> {
    const RETRY_WAIT_MS: u64 = 10000; // 10 seconds
    const MAX_RETRIES: usize = 3;

    let mut last_err = None;
    for _ in 0..MAX_RETRIES {
        let mut file = match OpenOptions::new().write(true).open(path) {
            Ok(f) => f,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        match file.write_all(data) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if e.raw_os_error() == Some(libc::EBUSY) {
                    thread::sleep(Duration::from_millis(RETRY_WAIT_MS));
                    last_err = Some(e);
                    continue;
                }
                return Err(TdxAttestError::Unexpected(format!("write {path}: {e}")));
            }
        }
    }

    match last_err {
        Some(e) if e.raw_os_error() == Some(libc::EBUSY) => Err(TdxAttestError::Busy),
        Some(e) => Err(TdxAttestError::Unexpected(format!("write {path}: {e}"))),
        None => Err(TdxAttestError::Unexpected("unknown error".to_string())),
    }
}

fn wait_for_generation_change(path: &str, current: i64) -> Result<i64> {
    loop {
        let gen = read_generation(path)?;
        if gen != current {
            return Ok(gen);
        }
        thread::sleep(Duration::from_micros(1));
    }
}

fn read_outblob_with_retry(path: &str) -> Result<Vec<u8>> {
    const RETRY_WAIT_MS: u64 = 10000;
    const MAX_RETRIES: usize = 3;

    let mut last_err = None;
    for _ in 0..MAX_RETRIES {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) => {
                last_err = Some(e);
                continue;
            }
        };

        let mut buf = vec![0u8; QUOTE_BUF_SIZE];
        match file.read(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(_) => {
                return Err(TdxAttestError::QuoteFailure("empty outblob".to_string()));
            }
            Err(e) => {
                let errno = e.raw_os_error().unwrap_or(0);
                if errno == libc::EBUSY || errno == libc::EINTR || errno == libc::ETIMEDOUT {
                    thread::sleep(Duration::from_millis(RETRY_WAIT_MS));
                    last_err = Some(e);
                    continue;
                }
                return Err(TdxAttestError::QuoteFailure(format!("read {path}: {e}")));
            }
        }
    }

    match last_err {
        Some(e) if e.raw_os_error() == Some(libc::EBUSY) => Err(TdxAttestError::Busy),
        Some(e) => Err(TdxAttestError::QuoteFailure(format!("read {path}: {e}"))),
        None => Err(TdxAttestError::Unexpected("unknown error".to_string())),
    }
}

// ============================================================================
// VSock Quote Generation (QGS Protocol)
// ============================================================================

fn get_quote_via_vsock(report_data: &TdxReportData) -> Result<Vec<u8>> {
    use std::io::{Read as _, Write as _};

    let vsock_port = read_vsock_port()?;
    if vsock_port == 0 {
        return Err(TdxAttestError::NotSupported(format!(
            "no vsock port configured in {TDX_ATTEST_CONFIG_PATH}"
        )));
    }

    let report = get_report(report_data)?;
    let request = build_qgs_get_quote_request(&report.0);

    let mut stream = vsock::VsockStream::connect_with_cid_port(vsock::VMADDR_CID_HOST, vsock_port)?;

    let len_header = (request.len() as u32).to_be_bytes();
    stream.write_all(&len_header)?;
    stream.write_all(&request)?;

    let mut len_buf = [0u8; QGS_MSG_LEN_PREFIX_SIZE];
    stream.read_exact(&mut len_buf)?;
    let msg_len = u32::from_be_bytes(len_buf) as usize;

    if msg_len > QGS_REQ_BUF_SIZE {
        return Err(TdxAttestError::QuoteFailure(format!(
            "response too large: {msg_len}"
        )));
    }

    let mut response = vec![0u8; msg_len];
    stream.read_exact(&mut response)?;

    parse_qgs_get_quote_response(&response)
}

fn read_vsock_port() -> Result<u32> {
    let content = match fs::read_to_string(TDX_ATTEST_CONFIG_PATH) {
        Ok(c) => c,
        Err(_) => return Ok(0),
    };

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("port") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let port_str = rest.trim();
                if let Ok(port) = port_str.parse::<u32>() {
                    return Ok(port);
                }
            }
        }
    }

    Ok(0)
}

/// Build QGS get_quote request message
///
/// Message format:
/// - qgs_msg_header_t (16 bytes)
/// - report_size (4 bytes)
/// - id_list_size (4 bytes)
/// - report data (1024 bytes)
fn build_qgs_get_quote_request(report: &[u8; TDX_REPORT_SIZE]) -> Vec<u8> {
    let report_size = TDX_REPORT_SIZE as u32;
    let id_list_size: u32 = 0;

    // Calculate total message size (header + fields + report)
    let msg_size: u32 = 16 + 4 + 4 + report_size;

    let mut msg = Vec::with_capacity(msg_size as usize);

    // QGS message header (16 bytes)
    msg.extend_from_slice(&QGS_MSG_VERSION_MAJOR.to_le_bytes()); // major_version
    msg.extend_from_slice(&QGS_MSG_VERSION_MINOR.to_le_bytes()); // minor_version
    msg.extend_from_slice(&QGS_MSG_GET_QUOTE_REQ.to_le_bytes()); // type
    msg.extend_from_slice(&msg_size.to_le_bytes()); // size
    msg.extend_from_slice(&0u32.to_le_bytes()); // error_code (unused in request)

    // Request body
    msg.extend_from_slice(&report_size.to_le_bytes()); // report_size
    msg.extend_from_slice(&id_list_size.to_le_bytes()); // id_list_size
    msg.extend_from_slice(report); // report data

    msg
}

/// Parse QGS get_quote response and extract the quote
///
/// Response format:
/// - qgs_msg_header_t (16 bytes)
/// - selected_id_size (4 bytes)
/// - quote_size (4 bytes)
/// - selected_id data (variable)
/// - quote data (variable)
fn parse_qgs_get_quote_response(data: &[u8]) -> Result<Vec<u8>> {
    // Minimum size: header (16) + selected_id_size (4) + quote_size (4) = 24 bytes
    if data.len() < 24 {
        return Err(TdxAttestError::QuoteFailure(format!(
            "response too short: {} bytes",
            data.len()
        )));
    }

    // Parse header
    let msg_type = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let error_code = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    if msg_type != QGS_MSG_GET_QUOTE_RESP {
        return Err(TdxAttestError::QuoteFailure(format!(
            "unexpected message type: {msg_type}"
        )));
    }

    if error_code != 0 {
        return Err(TdxAttestError::QuoteFailure(format!(
            "QGS error code: 0x{error_code:x}"
        )));
    }

    // Parse response body
    let selected_id_size = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    let quote_size = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

    // Validate sizes
    let expected_len = 24 + selected_id_size + quote_size;
    if data.len() < expected_len {
        return Err(TdxAttestError::QuoteFailure(format!(
            "response truncated: got {} bytes, expected {expected_len}",
            data.len()
        )));
    }

    // Extract quote (skip selected_id)
    let quote_offset = 24 + selected_id_size;
    let quote = data[quote_offset..quote_offset + quote_size].to_vec();

    if quote.len() < QUOTE_MIN_SIZE {
        return Err(TdxAttestError::QuoteFailure(format!(
            "quote too short: {} bytes",
            quote.len()
        )));
    }

    Ok(quote)
}
