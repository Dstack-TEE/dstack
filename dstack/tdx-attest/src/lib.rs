// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// Linux x86_64 with glibc or musl
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use linux::*;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod linux;

// Fallback for non-Linux/non-x86_64 platforms (dummy implementation)
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub use dummy::*;
#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod dummy;

pub use cc_eventlog as eventlog;

pub type Result<T> = std::result::Result<T, TdxAttestError>;

pub type TdxReportData = [u8; 64];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxReport(pub [u8; 1024]);

pub struct TdxMeasurements {
    pub mrtd: [u8; 48],
    pub rtmrs: [[u8; 48]; 4],
}

impl TdxReport {
    /// Extract the measurements from the TDINFO section of a TDREPORT0.
    pub fn measurements(&self) -> TdxMeasurements {
        const MRTD_OFFSET: usize = 512 + 16; // TDINFO starts with ATTRIBUTES and XFAM.
        const RTMR0_OFFSET: usize = MRTD_OFFSET + 4 * 48; // After MRTD and three owner/config hashes.

        let digest_at = |offset| {
            let mut digest = [0; 48];
            let bytes = &self.0[offset..offset + digest.len()];
            digest.copy_from_slice(bytes);
            digest
        };
        TdxMeasurements {
            mrtd: digest_at(MRTD_OFFSET),
            rtmrs: std::array::from_fn(|index| digest_at(RTMR0_OFFSET + index * 48)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::TdxReport;

    #[test]
    fn extracts_the_tdinfo_measurements() {
        let mut bytes = [0xff; 1024];
        bytes[528..576].fill(1);
        bytes[720..768].fill(2);
        bytes[768..816].fill(3);
        bytes[816..864].fill(4);
        bytes[864..912].fill(5);

        let measurements = TdxReport(bytes).measurements();
        assert_eq!(measurements.mrtd, [1; 48]);
        assert_eq!(measurements.rtmrs, [[2; 48], [3; 48], [4; 48], [5; 48]]);
    }
}
