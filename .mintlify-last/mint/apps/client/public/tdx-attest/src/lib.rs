#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
pub use linux::*;
#[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu"))]
mod linux;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
pub use dummy::*;

#[cfg(not(all(target_os = "linux", target_arch = "x86_64", target_env = "gnu")))]
mod dummy;

pub use cc_eventlog as eventlog;

pub type Result<T> = std::result::Result<T, TdxAttestError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxUuid(pub [u8; 16]);

pub type TdxReportData = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxReport(pub [u8; 1024]);

pub fn extend_rtmr3(event: &str, payload: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context;
    // This code is not defined in the TCG specification.
    // See https://trustedcomputinggroup.org/wp-content/uploads/PC-ClientSpecific_Platform_Profile_for_TPM_2p0_Systems_v51.pdf
    let event_type = 0x08000001;
    let index = 3;
    let log = eventlog::TdxEventLog::new(index, event_type, event.to_string(), payload.to_vec());
    extend_rtmr(index, event_type, log.digest).context("Failed to extend RTMR")?;
    log_rtmr_event(&log).context("Failed to log RTMR event")
}
