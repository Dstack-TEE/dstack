// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Local sealing with an explicit legacy VCEK and a fixed VM identity policy.
//!
//! Linux's `root_key_select` contains firmware ROOT_KEY_SELECT in bit 0 and
//! KEY_SEL in bits 2:1. The pinned sev crate's Boolean constructor cannot
//! express KEY_SEL=1, so use the Linux UAPI directly. There is no alternate root.

use std::{fs::OpenOptions, os::fd::AsRawFd};

use anyhow::{bail, Context, Result};
use sev::firmware::guest::Firmware;
use zeroize::{Zeroize, Zeroizing};

use crate::{SEV_GUEST_DEVICE, SNP_REPORT_SIZE};

const EXPLICIT_VCEK: u32 = 2;
const GUEST_FIELDS: u64 = 0x29; // guest policy, launch measurement, selected TCB

#[repr(C)]
#[derive(Default)]
struct GuestRequest {
    msg_version: u8,
    reserved: [u8; 7],
    req_data: u64,
    resp_data: u64,
    exitinfo2: u64,
}

#[repr(C)]
struct KeyRequest {
    root_key_select: u32,
    reserved: u32,
    guest_field_select: u64,
    vmpl: u32,
    guest_svn: u32,
    tcb_version: u64,
}

impl KeyRequest {
    fn new(tcb_version: u64) -> Self {
        Self {
            root_key_select: EXPLICIT_VCEK,
            reserved: 0,
            guest_field_select: GUEST_FIELDS,
            vmpl: 0,
            guest_svn: 0,
            tcb_version,
        }
    }
}

#[repr(C)]
#[derive(Default)]
struct KeyResponse {
    status: u32,
    reserved: [u8; 28],
    key: [u8; 32],
}

impl Drop for KeyResponse {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

const SNP_GET_DERIVED_KEY: libc::Ioctl = libc::_IOWR::<GuestRequest>(b'S' as u32, 1);

fn tcb_not_newer(requested: u64, available: u64) -> bool {
    requested
        .to_le_bytes()
        .iter()
        .zip(available.to_le_bytes())
        .all(|(requested, available)| *requested <= available)
}

fn report_tcbs(report: &[u8]) -> Result<(u64, u64)> {
    if report.len() != SNP_REPORT_SIZE {
        bail!("invalid SNP sealing report length");
    }
    let read_u64 = |offset| {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(&report[offset..offset + 8]);
        u64::from_le_bytes(bytes)
    };
    let version = u32::from_le_bytes([report[0], report[1], report[2], report[3]]);
    if !(2..=6).contains(&version) {
        bail!("unsupported SNP sealing report version: {version}");
    }
    if report[0x30..0x34] != [0; 4] {
        bail!("snp sealing requires VMPL0");
    }
    if read_u64(8) & (1 << 19) != 0 {
        bail!("snp sealing requires a guest with debugging disabled");
    }
    Ok((read_u64(0x1e0), read_u64(0x1f0)))
}

fn get_tcbs() -> Result<(u64, u64)> {
    let mut firmware = Firmware::open().context("failed to open SNP guest device")?;
    let report = firmware
        .get_report(Some(1), Some([0; 64]), Some(0))
        .map_err(|err| anyhow::anyhow!("failed to get SNP sealing report: {err}"))?;
    report_tcbs(&report)
}

/// Choose a supported initial TCB. Persist it before using the sealing seed;
/// subsequent boots must reuse it, including after firmware updates.
pub fn initial_tcb_version() -> Result<u64> {
    let (committed, launch) = get_tcbs()?;
    if !tcb_not_newer(committed, launch) {
        bail!("committed SNP TCB exceeds launch TCB");
    }
    Ok(committed)
}

fn check_status(exitinfo2: u64, status: u32) -> Result<()> {
    if exitinfo2 != 0 || status != 0 {
        bail!(
            "snp key derivation failed: firmware={:#x}, VMM={:#x}, response={status:#x}",
            exitinfo2 as u32,
            exitinfo2 >> 32,
        );
    }
    Ok(())
}

/// Derive a sealing seed bound to policy, launch measurement, HOST_DATA,
/// launch identity, VMPL0, and the persisted TCB. Never logs the seed.
pub fn derive_sealing_seed(tcb_version: u64) -> Result<Zeroizing<[u8; 32]>> {
    let (_, launch) = get_tcbs()?;
    if !tcb_not_newer(tcb_version, launch) {
        bail!("stored SNP sealing TCB exceeds launch TCB");
    }
    let device = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .context("failed to open SNP guest device for derivation")?;
    let request = KeyRequest::new(tcb_version);
    let mut response = KeyResponse::default();
    let mut io = GuestRequest {
        msg_version: 1,
        req_data: (&request as *const KeyRequest) as u64,
        resp_data: (&mut response as *mut KeyResponse) as u64,
        ..Default::default()
    };
    // SAFETY: the descriptor is /dev/sev-guest; all buffers use the Linux UAPI
    // layout, remain alive for the ioctl, and have the required size/alignment.
    let rc = unsafe { libc::ioctl(device.as_raw_fd(), SNP_GET_DERIVED_KEY, &mut io) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!(
                "snp key derivation ioctl failed (exitinfo2={:#x})",
                io.exitinfo2
            )
        });
    }
    check_status(io.exitinfo2, response.status)?;
    Ok(Zeroizing::new(response.key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn linux_abi_and_sealing_policy() {
        assert_eq!(size_of::<GuestRequest>(), 32);
        assert_eq!(offset_of!(GuestRequest, req_data), 8);
        assert_eq!(offset_of!(GuestRequest, resp_data), 16);
        assert_eq!(offset_of!(GuestRequest, exitinfo2), 24);
        assert_eq!(size_of::<KeyRequest>(), 32);
        assert_eq!(offset_of!(KeyRequest, tcb_version), 24);
        assert_eq!(size_of::<KeyResponse>(), 64);
        assert_eq!(offset_of!(KeyResponse, key), 32);
        assert_eq!(SNP_GET_DERIVED_KEY, 0xc0205301);
        let request = KeyRequest::new(0x1234);
        assert_eq!(request.root_key_select & 1, 0);
        assert_eq!(request.root_key_select >> 1, 1);
        assert_eq!(request.guest_field_select, (1 << 0) | (1 << 3) | (1 << 5));
        assert_eq!(request.vmpl, 0);
        assert_eq!(request.guest_svn, 0);
    }

    #[test]
    fn rejects_firmware_vmm_and_response_failures() {
        assert!(check_status(0, 0).is_ok());
        for (exitinfo2, status) in [(0x16, 0), (1 << 32, 0), (0, 0x27)] {
            assert!(check_status(exitinfo2, status).is_err());
        }
    }

    #[test]
    fn tcb_comparison_is_componentwise() {
        assert!(tcb_not_newer(0x0101, 0x0202));
        assert!(tcb_not_newer(0x0202, 0x0202));
        assert!(!tcb_not_newer(0x0103, 0x0202));
        assert!(!tcb_not_newer(0x0301, 0x0202));
    }

    #[test]
    fn rejects_invalid_report_and_debug_guest() {
        let mut report = vec![0; SNP_REPORT_SIZE];
        assert!(report_tcbs(&report).is_err());
        report[0] = 3;
        report[0x1e0..0x1e8].copy_from_slice(&1u64.to_le_bytes());
        report[0x1f0..0x1f8].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(report_tcbs(&report).unwrap(), (1, 2));
        report[0x30] = 1;
        assert!(report_tcbs(&report).is_err());
        report[0x30] = 0;
        report[8..16].copy_from_slice(&(1u64 << 19).to_le_bytes());
        assert!(report_tcbs(&report).is_err());
        assert!(report_tcbs(&report[..100]).is_err());
    }
}
