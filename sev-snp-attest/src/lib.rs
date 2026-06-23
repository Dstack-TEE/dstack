// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Minimal AMD SEV-SNP guest report support.

use std::path::Path;

use anyhow::{bail, Context, Result};
use sev::firmware::{guest::Firmware, host::CertTableEntry};

const TSM_REPORT_ROOT: &str = "/sys/kernel/config/tsm/report";
const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";
const SNP_REPORT_SIZE: usize = 1184;
pub const SNP_REPORT_DATA_RANGE: std::ops::Range<usize> = 0x50..0x90;

/// Represents an AMD SEV-SNP attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnpQuote {
    /// Raw SNP report bytes.
    pub report: Vec<u8>,
    /// Optional certificate chain blobs, when exposed by the kernel/firmware path.
    pub cert_chain: Vec<Vec<u8>>,
}

pub fn get_report(report_data: [u8; 64]) -> Result<SnpQuote> {
    if has_sev_snp_tsm_provider(Path::new(TSM_REPORT_ROOT)) {
        match get_report_configfs(report_data) {
            Ok(quote) => {
                if configfs_report_needs_ioctl_cert_chain_fallback(
                    &quote,
                    Path::new(SEV_GUEST_DEVICE).exists(),
                ) {
                    tracing::debug!(
                        "sev-snp configfs tsm report did not include a certificate chain; falling back to ioctl extended report"
                    );
                    match get_report_ioctl(report_data) {
                        Ok(ioctl_quote) if !ioctl_quote.cert_chain.is_empty() => {
                            return Ok(ioctl_quote)
                        }
                        Ok(_) => return Ok(quote),
                        Err(err) => tracing::debug!(
                            "failed to get sev-snp report from ioctl fallback: {err:#}"
                        ),
                    }
                }
                return Ok(quote);
            }
            Err(err) => tracing::debug!("failed to get sev-snp report from configfs tsm: {err:#}"),
        }
    }
    if Path::new(SEV_GUEST_DEVICE).exists() {
        return get_report_ioctl(report_data);
    }
    bail!("sev-snp report is unavailable: neither {TSM_REPORT_ROOT} nor {SEV_GUEST_DEVICE} exists")
}

fn configfs_report_needs_ioctl_cert_chain_fallback(
    quote: &SnpQuote,
    sev_guest_device_available: bool,
) -> bool {
    sev_guest_device_available && quote.cert_chain.is_empty()
}

pub fn has_sev_snp_tsm_provider(root: &Path) -> bool {
    if !root.exists() {
        return false;
    }

    if provider_file_is_sev_guest(&root.join("provider")) {
        return true;
    }

    let probe = root.join(format!("dstack-probe-{}", std::process::id()));
    if fs_err::create_dir(&probe).is_ok() {
        let is_sev_snp = provider_file_is_sev_guest(&probe.join("provider"));
        let _ = fs_err::remove_dir(&probe);
        if is_sev_snp {
            return true;
        }
    }

    let Ok(entries) = fs_err::read_dir(root) else {
        return false;
    };
    entries.flatten().any(|entry| {
        let Ok(file_type) = entry.file_type() else {
            return false;
        };
        file_type.is_dir() && provider_file_is_sev_guest(&entry.path().join("provider"))
    })
}

fn provider_file_is_sev_guest(path: &Path) -> bool {
    fs_err::read_to_string(path)
        .map(|provider| matches!(provider.trim(), "sev_guest" | "sev-guest"))
        .unwrap_or(false)
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
    for name in ["certs", "cert_chain", "auxblob"] {
        let Ok(bytes) = fs_err::read(dir.join(name)) else {
            continue;
        };
        if !bytes.is_empty() {
            return vec![bytes];
        }
    }
    Vec::new()
}

fn get_report_ioctl(report_data: [u8; 64]) -> Result<SnpQuote> {
    let mut firmware =
        Firmware::open().with_context(|| format!("failed to open {SEV_GUEST_DEVICE}"))?;
    let (report, cert_entries) = firmware
        .get_ext_report(Some(1), Some(report_data), Some(0))
        .map_err(|err| anyhow::anyhow!("sev-snp get extended report ioctl failed: {err}"))?;
    ensure_report_data_matches(&report, &report_data)?;
    let cert_chain = match cert_entries {
        Some(entries) if !entries.is_empty() => {
            vec![CertTableEntry::cert_table_to_vec_bytes(&entries)
                .context("failed to encode sev-snp certificate table")?]
        }
        _ => Vec::new(),
    };
    Ok(SnpQuote { report, cert_chain })
}

fn ensure_report_data_matches(report: &[u8], report_data: &[u8; 64]) -> Result<()> {
    if report.len() != SNP_REPORT_SIZE {
        bail!(
            "sev-snp report has invalid length: expected {} bytes, got {}",
            SNP_REPORT_SIZE,
            report.len()
        );
    }
    if &report[SNP_REPORT_DATA_RANGE] != report_data {
        bail!("sev-snp report_data mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    #[test]
    fn tsm_provider_detection_accepts_only_sev_guest_provider() {
        let root = test_dir("sev-guest");
        fs_err::create_dir_all(root.join("entry")).unwrap();
        fs_err::write(root.join("entry/provider"), "sev_guest\n").unwrap();

        assert!(has_sev_snp_tsm_provider(&root));

        let _ = fs_err::remove_dir_all(root);
    }

    #[test]
    fn tsm_provider_detection_accepts_legacy_hyphenated_sev_guest_provider() {
        let root = test_dir("sev-guest-hyphen");
        fs_err::create_dir_all(root.join("entry")).unwrap();
        fs_err::write(root.join("entry/provider"), "sev-guest\n").unwrap();

        assert!(has_sev_snp_tsm_provider(&root));

        let _ = fs_err::remove_dir_all(root);
    }

    #[test]
    fn tsm_provider_detection_rejects_tdx_guest_provider() {
        let root = test_dir("tdx-guest");
        fs_err::create_dir_all(root.join("entry")).unwrap();
        fs_err::write(root.join("entry/provider"), "tdx-guest\n").unwrap();

        assert!(!has_sev_snp_tsm_provider(&root));

        let _ = fs_err::remove_dir_all(root);
    }

    #[test]
    fn configfs_cert_chain_uses_first_supported_nonempty_blob() {
        let root = test_dir("cert-chain");
        fs_err::create_dir_all(&root).unwrap();
        fs_err::write(root.join("certs"), []).unwrap();
        fs_err::write(root.join("cert_chain"), b"chain").unwrap();
        fs_err::write(root.join("auxblob"), b"auxblob").unwrap();

        assert_eq!(read_cert_chain_configfs(&root), vec![b"chain".to_vec()]);

        let _ = fs_err::remove_dir_all(root);
    }

    #[test]
    fn configfs_report_without_cert_chain_requires_ioctl_fallback_when_available() {
        let quote = SnpQuote {
            report: vec![0u8; SNP_REPORT_SIZE],
            cert_chain: vec![],
        };

        assert!(configfs_report_needs_ioctl_cert_chain_fallback(
            &quote, true
        ));
        assert!(!configfs_report_needs_ioctl_cert_chain_fallback(
            &quote, false
        ));
    }

    fn test_dir(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dstack-sev-snp-test-{name}-{}-{nanos}",
            std::process::id()
        ))
    }
}
