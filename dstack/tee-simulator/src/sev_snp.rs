// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::OsStr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime},
};

use anyhow::{Context, Result};
use dstack_types::TeeSimulatorConfig;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyWrite, Request,
};
use mock_attestation::sev_snp::SevSnpGenerator;

use crate::TeeBackend;

const ROOT: u64 = 1;
const ENTRY: u64 = 2;
const PROVIDER: u64 = 3;
const INBLOB: u64 = 4;
const OUTBLOB: u64 = 5;
const CERTS: u64 = 6;
const TTL: Duration = Duration::ZERO;

pub(crate) struct SevSnpFs {
    generator: Arc<SevSnpGenerator>,
    report: Vec<u8>,
    certs: Vec<u8>,
    uid: u32,
    gid: u32,
    host_data: [u8; 32],
}

impl SevSnpFs {
    fn new(
        generator: Arc<SevSnpGenerator>,
        host_data: [u8; 32],
        measurement: [u8; 48],
    ) -> Result<Self> {
        let evidence = generator.attest_with_measurement([0; 64], host_data, measurement)?;
        Ok(Self {
            generator,
            report: evidence.report,
            certs: encode_cert_table(&evidence.cert_chain)?,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            host_data,
        })
    }

    fn attr(&self, ino: u64) -> Option<FileAttr> {
        let (kind, perm, size) = match ino {
            ROOT | ENTRY => (FileType::Directory, 0o755, 0),
            PROVIDER => (FileType::RegularFile, 0o444, 10),
            INBLOB => (FileType::RegularFile, 0o200, 0),
            OUTBLOB => (FileType::RegularFile, 0o400, self.report.len() as u64),
            CERTS => (FileType::RegularFile, 0o400, self.certs.len() as u64),
            _ => return None,
        };
        Some(FileAttr {
            ino,
            size,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind,
            perm,
            nlink: if kind == FileType::Directory { 2 } else { 1 },
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        })
    }

    fn child(parent: u64, name: &OsStr) -> Option<u64> {
        match (parent, name.to_str()?) {
            (ROOT, "provider") | (ENTRY, "provider") => Some(PROVIDER),
            (ENTRY, "inblob" | "reportdata" | "report_data") => Some(INBLOB),
            (ENTRY, "outblob" | "report") => Some(OUTBLOB),
            (ENTRY, "certs" | "cert_chain" | "auxblob") => Some(CERTS),
            (ROOT, name) if name.starts_with("dstack-") => Some(ENTRY),
            _ => None,
        }
    }

    fn update_report(&mut self, data: &[u8]) -> Result<()> {
        let report_data: [u8; 64] = data
            .try_into()
            .context("SEV-SNP report data must be exactly 64 bytes")?;
        let measurement: [u8; 48] = self
            .report
            .get(0x90..0xc0)
            .context("SEV-SNP report does not contain a measurement")?
            .try_into()
            .context("SEV-SNP measurement has an invalid length")?;
        let evidence =
            self.generator
                .attest_with_measurement(report_data, self.host_data, measurement)?;
        let certs = encode_cert_table(&evidence.cert_chain)?;
        self.report = evidence.report;
        self.certs = certs;
        Ok(())
    }
}

fn bounded_read(data: &[u8], offset: i64, size: u32) -> Result<&[u8], i32> {
    if offset < 0 {
        return Err(libc::EINVAL);
    }
    let start = offset as usize;
    Ok(data
        .get(start..start.saturating_add(size as usize).min(data.len()))
        .unwrap_or_default())
}

impl Filesystem for SevSnpFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        match Self::child(parent, name).and_then(|ino| self.attr(ino).map(|attr| (ino, attr))) {
            Some((_, attr)) => reply.entry(&TTL, &attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.attr(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }
    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        if parent == ROOT
            && name
                .to_str()
                .is_some_and(|name| name.starts_with("dstack-"))
        {
            match self.attr(ENTRY) {
                Some(attr) => reply.entry(&TTL, &attr, 0),
                None => reply.error(libc::EIO),
            }
        } else {
            reply.error(libc::EACCES);
        }
    }
    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, _name: &OsStr, reply: ReplyEmpty) {
        if parent == ROOT {
            reply.ok();
        } else {
            reply.error(libc::EACCES);
        }
    }
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let entries: &[(u64, FileType, &str)] = match ino {
            ROOT => &[
                (ROOT, FileType::Directory, "."),
                (ROOT, FileType::Directory, ".."),
                (PROVIDER, FileType::RegularFile, "provider"),
            ],
            ENTRY => &[
                (ENTRY, FileType::Directory, "."),
                (ROOT, FileType::Directory, ".."),
                (PROVIDER, FileType::RegularFile, "provider"),
                (INBLOB, FileType::RegularFile, "inblob"),
                (OUTBLOB, FileType::RegularFile, "outblob"),
                (CERTS, FileType::RegularFile, "certs"),
            ],
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        for (index, entry) in entries.iter().enumerate().skip(offset.max(0) as usize) {
            if reply.add(entry.0, (index + 1) as i64, entry.1, entry.2) {
                break;
            }
        }
        reply.ok();
    }
    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if matches!(ino, PROVIDER | INBLOB | OUTBLOB | CERTS) {
            reply.opened(0, 1);
        } else {
            reply.error(libc::ENOENT);
        }
    }
    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        match Self::child(parent, name).filter(|ino| *ino == INBLOB) {
            Some(ino) => match self.attr(ino) {
                Some(attr) => reply.created(&TTL, &attr, 0, 0, 1),
                None => reply.error(libc::EIO),
            },
            None => reply.error(libc::EACCES),
        }
    }
    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        let data: &[u8] = match ino {
            PROVIDER => b"sev_guest\n",
            OUTBLOB => &self.report,
            CERTS => &self.certs,
            _ => {
                reply.error(libc::EACCES);
                return;
            }
        };
        match bounded_read(data, offset, size) {
            Ok(data) => reply.data(data),
            Err(errno) => reply.error(errno),
        }
    }
    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyWrite,
    ) {
        if ino != INBLOB || offset != 0 {
            reply.error(libc::EINVAL);
            return;
        }
        match self.update_report(data) {
            Ok(()) => reply.written(data.len() as u32),
            Err(_) if data.len() != 64 => reply.error(libc::EINVAL),
            Err(_) => reply.error(libc::EIO),
        }
    }
}

fn encode_cert_table(cert_chain: &[Vec<u8>]) -> Result<Vec<u8>> {
    const ASK_GUID: [u8; 16] = [
        0x4a, 0xb7, 0xb3, 0x79, 0xbb, 0xac, 0x4f, 0xe4, 0xa0, 0x2f, 0x05, 0xae, 0xf3, 0x27, 0xc7,
        0x82,
    ];
    const VCEK_GUID: [u8; 16] = [
        0x63, 0xda, 0x75, 0x8d, 0xe6, 0x64, 0x45, 0x64, 0xad, 0xc5, 0xf4, 0xb9, 0x3b, 0xe8, 0xac,
        0xcd,
    ];
    let [ask, vcek] = cert_chain else {
        anyhow::bail!("mock SEV-SNP evidence must contain ASK and VCEK");
    };
    let ask = pem::parse(ask)?.into_contents();
    let vcek = pem::parse(vcek)?.into_contents();
    let header_len = 3 * 24;
    let mut output = Vec::with_capacity(header_len + ask.len() + vcek.len());
    for (guid, offset, length) in [
        (ASK_GUID, header_len, ask.len()),
        (VCEK_GUID, header_len + ask.len(), vcek.len()),
    ] {
        output.extend_from_slice(&guid);
        output.extend_from_slice(&(offset as u32).to_le_bytes());
        output.extend_from_slice(&(length as u32).to_le_bytes());
    }
    output.extend_from_slice(&[0u8; 24]);
    output.extend_from_slice(&ask);
    output.extend_from_slice(&vcek);
    Ok(output)
}

pub(crate) struct SevSnpBackend;
impl TeeBackend for SevSnpBackend {
    type Fs = SevSnpFs;
    const PLATFORM: &'static str = "amd-sev-snp";
    const DEFAULT_MOUNTPOINT: &'static str = "/sys/kernel/config/tsm/report";
    fn create_filesystem(config: &TeeSimulatorConfig) -> Result<Self::Fs> {
        let seed = config
            .mock_attestation_seed
            .as_deref()
            .context("tee_simulator.mock_attestation_seed is required")?;
        let mr_config = config
            .mr_config
            .as_deref()
            .context("mr_config is required for SEV-SNP simulation")?;
        let host_data = dstack_types::mr_config::MrConfigV3::snp_host_data_from_document(mr_config);
        let measurement = match config.vm_config.as_deref() {
            Some(vm_config)
                if serde_json::from_str::<serde_json::Value>(vm_config)?
                    .get("sev_snp_measurement")
                    .is_some() =>
            {
                let inputs = dstack_mr::sev::parse_snp_inputs_from_vm_config(vm_config)?;
                dstack_mr::sev::compute_expected_measurement(&inputs.input)?
            }
            _ => [0x33; 48],
        };
        SevSnpFs::new(
            Arc::new(SevSnpGenerator::from_seed(mock_attestation::parse_seed(
                seed,
            )?)?),
            host_data,
            measurement,
        )
    }
    fn prepare_mountpoint(mountpoint: &Path) -> Result<()> {
        crate::tdx::ensure_configfs_mount(mountpoint)
    }
    fn real_tee_available() -> bool {
        Path::new("/dev/sev-guest").exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Arc<SevSnpGenerator>, SevSnpFs) {
        let generator = Arc::new(SevSnpGenerator::from_seed([0x42; 32]).unwrap());
        let fs = SevSnpFs::new(generator.clone(), [0x22; 32], [0x33; 48]).unwrap();
        (generator, fs)
    }

    #[test]
    fn report_update_is_verified_and_failure_atomic() {
        let (generator, mut fs) = fixture();
        let original_report = fs.report.clone();
        let original_certs = fs.certs.clone();
        assert!(fs.update_report(&[0x11; 63]).is_err());
        assert_eq!(fs.report, original_report);
        assert_eq!(fs.certs, original_certs);

        let report_data = [0x55; 64];
        fs.update_report(&report_data).unwrap();
        let evidence = generator
            .attest_with_measurement(report_data, [0x22; 32], [0x33; 48])
            .unwrap();
        let verifier = sev_snp_qvl::QuoteVerifier::new(
            generator.root_ca_pem().into_bytes(),
            generator.root_ca_pem().into_bytes(),
            generator.root_ca_pem().into_bytes(),
        );
        verifier
            .verify(&fs.report, &evidence.cert_chain, &report_data)
            .unwrap();

        let first_report = fs.report.clone();
        fs.update_report(&[0x77; 64]).unwrap();
        assert_ne!(fs.report, first_report);
    }

    #[test]
    fn filesystem_aliases_and_permissions_are_bounded() {
        let (_, fs) = fixture();
        for alias in ["inblob", "reportdata", "report_data"] {
            assert_eq!(SevSnpFs::child(ENTRY, OsStr::new(alias)), Some(INBLOB));
        }
        for alias in ["outblob", "report"] {
            assert_eq!(SevSnpFs::child(ENTRY, OsStr::new(alias)), Some(OUTBLOB));
        }
        for alias in ["certs", "cert_chain", "auxblob"] {
            assert_eq!(SevSnpFs::child(ENTRY, OsStr::new(alias)), Some(CERTS));
        }
        assert_eq!(fs.attr(INBLOB).unwrap().perm, 0o200);
        assert_eq!(fs.attr(OUTBLOB).unwrap().perm, 0o400);
        assert_eq!(fs.attr(CERTS).unwrap().perm, 0o400);
        assert_eq!(bounded_read(&fs.report, -1, 1), Err(libc::EINVAL));
        assert_eq!(bounded_read(&fs.report, 0, 8).unwrap(), &fs.report[..8]);
        assert!(bounded_read(&fs.report, i64::MAX, u32::MAX)
            .unwrap()
            .is_empty());
        assert_eq!(SevSnpFs::child(ENTRY, OsStr::new("unknown")), None);
    }

    #[test]
    fn malformed_certificate_chains_fail_closed() {
        assert!(encode_cert_table(&[]).is_err());
        assert!(
            encode_cert_table(&[b"not a certificate".to_vec(), b"also invalid".to_vec()]).is_err()
        );
        assert!(encode_cert_table(&[
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----".to_vec(),
            b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----".to_vec(),
        ])
        .is_err());
    }
}
