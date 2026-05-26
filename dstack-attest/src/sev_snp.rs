// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal AMD SEV-SNP guest report support.

use std::{fs::OpenOptions, io, path::Path};

use anyhow::{bail, Context, Result};

use crate::attestation::{SnpQuote, SNP_REPORT_DATA_RANGE};

const TSM_REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";
const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
const SNP_REPORT_SIZE: usize = 1184;
const SNP_REPORT_RESP_SIZE: usize = 4000;
const SNP_GET_REPORT: libc::c_ulong = 0xc020_5300;

#[repr(C)]
#[derive(Clone, Copy)]
struct SnpReportReq {
    report_data: [u8; 64],
    vmpl: u32,
    rsvd: [u8; 28],
}

#[repr(C)]
struct SnpReportResp {
    data: [u8; SNP_REPORT_RESP_SIZE],
}

#[repr(C)]
struct SnpGuestRequestIoctl {
    msg_version: u8,
    req_data: u64,
    resp_data: u64,
    fw_err: u64,
}

pub fn get_report(report_data: [u8; 64]) -> Result<SnpQuote> {
    if Path::new(TSM_REPORT_ROOT).exists() {
        match get_report_configfs(report_data) {
            Ok(quote) => return Ok(quote),
            Err(err) => tracing::debug!("failed to get sev-snp report from configfs tsm: {err:#}"),
        }
    }
    if Path::new(SEV_GUEST_DEVICE).exists() {
        return get_report_ioctl(report_data);
    }
    bail!("sev-snp report is unavailable: neither {TSM_REPORT_ROOT} nor {SEV_GUEST_DEVICE} exists")
}

fn get_report_configfs(report_data: [u8; 64]) -> Result<SnpQuote> {
    let root = Path::new(TSM_REPORT_ROOT);
    let dir = root.join(format!("dstack-{}", std::process::id()));
    if !dir.exists() {
        fs_err::create_dir(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }

    let hex_report_data = hex::encode(report_data);
    write_first_existing(
        &[
            dir.join("inblob"),
            dir.join("reportdata"),
            dir.join("report_data"),
        ],
        &report_data,
        hex_report_data.as_bytes(),
    )?;

    let report = read_first_existing(&[dir.join("outblob"), dir.join("report")])?;
    if report.is_empty() {
        bail!("sev-snp configfs tsm returned an empty report");
    }
    ensure_report_data_matches(&report, &report_data)?;
    Ok(SnpQuote {
        report,
        cert_chain: read_cert_chain_configfs(&dir),
    })
}

fn write_first_existing(paths: &[std::path::PathBuf], binary: &[u8], hex: &[u8]) -> Result<()> {
    let mut last_err = None;
    for path in paths {
        if !path.exists() {
            continue;
        }
        match fs_err::write(path, binary).or_else(|_| fs_err::write(path, hex)) {
            Ok(()) => return Ok(()),
            Err(err) => last_err = Some(err),
        }
    }
    match last_err {
        Some(err) => Err(err).context("failed to write sev-snp tsm report data"),
        None => bail!("failed to find sev-snp tsm report input file"),
    }
}

fn read_first_existing(paths: &[std::path::PathBuf]) -> Result<Vec<u8>> {
    for path in paths {
        if path.exists() {
            return fs_err::read(path)
                .with_context(|| format!("failed to read {}", path.display()));
        }
    }
    bail!("failed to find sev-snp tsm report output file")
}

fn read_cert_chain_configfs(dir: &Path) -> Vec<Vec<u8>> {
    ["certs", "cert_chain", "auxblob"]
        .iter()
        .filter_map(|name| fs_err::read(dir.join(name)).ok())
        .filter(|bytes| !bytes.is_empty())
        .collect()
}

fn get_report_ioctl(report_data: [u8; 64]) -> Result<SnpQuote> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(SEV_GUEST_DEVICE)
        .with_context(|| format!("failed to open {SEV_GUEST_DEVICE}"))?;
    let mut req = SnpReportReq {
        report_data,
        vmpl: 0,
        rsvd: [0; 28],
    };
    let mut resp = SnpReportResp {
        data: [0; SNP_REPORT_RESP_SIZE],
    };
    let mut ioctl_req = SnpGuestRequestIoctl {
        msg_version: 1,
        req_data: (&mut req as *mut SnpReportReq) as u64,
        resp_data: (&mut resp as *mut SnpReportResp) as u64,
        fw_err: 0,
    };

    let rc = unsafe { libc::ioctl(file.as_raw_fd(), SNP_GET_REPORT, &mut ioctl_req) };
    if rc < 0 {
        return Err(io::Error::last_os_error()).context("sev-snp get report ioctl failed");
    }
    let report = resp.data[..SNP_REPORT_SIZE].to_vec();
    ensure_report_data_matches(&report, &report_data)?;
    Ok(SnpQuote {
        report,
        cert_chain: Vec::new(),
    })
}

fn ensure_report_data_matches(report: &[u8], report_data: &[u8; 64]) -> Result<()> {
    if report.len() < SNP_REPORT_DATA_RANGE.end {
        bail!(
            "sev-snp report too short: expected at least {} bytes, got {}",
            SNP_REPORT_DATA_RANGE.end,
            report.len()
        );
    }
    if &report[SNP_REPORT_DATA_RANGE] != report_data {
        bail!("sev-snp report_data mismatch");
    }
    Ok(())
}

use std::os::fd::AsRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_report_with_wrong_report_data() {
        let expected = [0x42; 64];
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_DATA_RANGE].copy_from_slice(&[0x24; 64]);
        assert!(ensure_report_data_matches(&report, &expected).is_err());
    }

    #[test]
    fn accepts_report_with_matching_report_data() {
        let expected = [0x42; 64];
        let mut report = vec![0u8; SNP_REPORT_SIZE];
        report[SNP_REPORT_DATA_RANGE].copy_from_slice(&expected);
        ensure_report_data_matches(&report, &expected).unwrap();
    }
}
