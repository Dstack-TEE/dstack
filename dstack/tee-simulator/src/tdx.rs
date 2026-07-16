// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::ffi::{CString, OsStr};
use std::path::Path;
use std::time::{Duration, SystemTime};

use anyhow::{bail, Context, Result};
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry,
    ReplyOpen, ReplyWrite, Request, TimeOrNow,
};
use sha2::{Digest, Sha384};

use crate::TeeBackend;

const TDX_DEFAULT_MOUNTPOINT: &str = "/sys/kernel/config/tsm/report";
const PROVIDER_NAME: &str = "com.intel.dcap";
const PROVIDER_VALUE: &[u8] = b"tdx_guest\n";
const DIRECT_IO: u32 = 1;
const TTL: Duration = Duration::ZERO;

const ROOT_INO: u64 = 1;
const PROVIDER_DIR_INO: u64 = 2;
const PROVIDER_INO: u64 = 3;
const INBLOB_INO: u64 = 4;
const OUTBLOB_INO: u64 = 5;
const GENERATION_INO: u64 = 6;
const MEASUREMENTS_DIR_INO: u64 = 7;
const RTMR0_INO: u64 = 8;
const CCEL_INO: u64 = 12;

const TDX_QUOTE_MIN_SIZE: usize = 632;
const MR_CONFIG_ID_RANGE: std::ops::Range<usize> = 232..280;
const RTMR0_OFFSET: usize = 376;
const REPORT_DATA_RANGE: std::ops::Range<usize> = 568..632;

const QUOTE_FIXTURE: &[u8] = include_bytes!("../../ra-tls/assets/tdx_quote");
const CCEL_FIXTURE: &[u8] = include_bytes!("../../cc-eventlog/samples/ccel.bin");

#[derive(Clone)]
struct SimulatorState {
    base_quote: Vec<u8>,
    ccel: Vec<u8>,
    rtmrs: [[u8; 48]; 4],
    outblob: Vec<u8>,
    generation: i64,
}

impl SimulatorState {
    fn new(base_quote: &[u8], ccel: &[u8]) -> Result<Self> {
        if base_quote.len() < TDX_QUOTE_MIN_SIZE {
            bail!("tdx quote fixture is too short: {}", base_quote.len());
        }

        let mut state = Self {
            base_quote: base_quote.to_vec(),
            ccel: ccel.to_vec(),
            rtmrs: replay_boot_rtmrs(ccel)?,
            outblob: Vec::new(),
            generation: 0,
        };
        state.outblob = state.make_quote([0u8; 64]);
        Ok(state)
    }

    fn make_quote(&self, report_data: [u8; 64]) -> Vec<u8> {
        let mut quote = self.base_quote.clone();
        quote[MR_CONFIG_ID_RANGE].fill(0);
        for (index, rtmr) in self.rtmrs.iter().enumerate() {
            let start = RTMR0_OFFSET + index * 48;
            quote[start..start + 48].copy_from_slice(rtmr);
        }
        quote[REPORT_DATA_RANGE].copy_from_slice(&report_data);
        quote
    }

    fn request_quote(&mut self, report_data: &[u8]) -> Result<()> {
        let report_data: [u8; 64] = report_data
            .try_into()
            .map_err(|_| anyhow::anyhow!("inblob must be exactly 64 bytes"))?;
        self.outblob = self.make_quote(report_data);
        self.generation = self
            .generation
            .checked_add(1)
            .context("tsm generation overflow")?;
        Ok(())
    }

    fn extend_rtmr(&mut self, index: usize, digest: &[u8]) -> Result<()> {
        if !(2..=3).contains(&index) {
            bail!("rtmr{index} is not userspace extensible");
        }
        if digest.len() != 48 {
            bail!("rtmr digest must be exactly 48 bytes");
        }
        let mut hasher = Sha384::new();
        hasher.update(self.rtmrs[index]);
        hasher.update(digest);
        self.rtmrs[index] = hasher.finalize().into();
        Ok(())
    }

    fn content(&self, ino: u64) -> Option<Vec<u8>> {
        match ino {
            PROVIDER_INO => Some(PROVIDER_VALUE.to_vec()),
            INBLOB_INO => Some(Vec::new()),
            OUTBLOB_INO => Some(self.outblob.clone()),
            GENERATION_INO => Some(format!("{}\n", self.generation).into_bytes()),
            CCEL_INO => Some(self.ccel.clone()),
            RTMR0_INO..=11 => Some(self.rtmrs[(ino - RTMR0_INO) as usize].to_vec()),
            _ => None,
        }
    }
}

fn replay_boot_rtmrs(ccel: &[u8]) -> Result<[[u8; 48]; 4]> {
    let events = cc_eventlog::tdx::decode_ccel(ccel).context("failed to decode CCEL fixture")?;
    let mut rtmrs = [[0u8; 48]; 4];
    for event in events {
        let index = usize::try_from(event.imr).context("invalid CCEL IMR index")?;
        let rtmr = rtmrs
            .get_mut(index)
            .with_context(|| format!("ccel event references unsupported RTMR{index}"))?;
        let digest = event.digest();
        if digest.len() != 48 {
            bail!(
                "ccel RTMR{index} digest has invalid length {}",
                digest.len()
            );
        }
        let mut hasher = Sha384::new();
        hasher.update(*rtmr);
        hasher.update(digest);
        *rtmr = hasher.finalize().into();
    }
    Ok(rtmrs)
}

pub(crate) struct TdxSimulatorFs {
    state: SimulatorState,
    uid: u32,
    gid: u32,
}

impl TdxSimulatorFs {
    fn new() -> Result<Self> {
        Ok(Self {
            state: SimulatorState::new(QUOTE_FIXTURE, CCEL_FIXTURE)?,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        })
    }

    fn attr(&self, ino: u64) -> Option<FileAttr> {
        let (kind, perm, size) = match ino {
            ROOT_INO | PROVIDER_DIR_INO | MEASUREMENTS_DIR_INO => (FileType::Directory, 0o755, 0),
            PROVIDER_INO | OUTBLOB_INO | GENERATION_INO | CCEL_INO => (
                FileType::RegularFile,
                0o400,
                self.state.content(ino)?.len() as u64,
            ),
            INBLOB_INO => (FileType::RegularFile, 0o200, 0),
            RTMR0_INO..=11 => (FileType::RegularFile, 0o600, 48),
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

    fn lookup_ino(parent: u64, name: &OsStr) -> Option<u64> {
        match (parent, name.to_str()?) {
            (ROOT_INO, PROVIDER_NAME) => Some(PROVIDER_DIR_INO),
            (PROVIDER_DIR_INO, "provider") => Some(PROVIDER_INO),
            (PROVIDER_DIR_INO, "inblob") => Some(INBLOB_INO),
            (PROVIDER_DIR_INO, "outblob") => Some(OUTBLOB_INO),
            (PROVIDER_DIR_INO, "generation") => Some(GENERATION_INO),
            (PROVIDER_DIR_INO, "measurements") => Some(MEASUREMENTS_DIR_INO),
            (PROVIDER_DIR_INO, "ccel") => Some(CCEL_INO),
            (MEASUREMENTS_DIR_INO, "rtmr0:sha384") => Some(RTMR0_INO),
            (MEASUREMENTS_DIR_INO, "rtmr1:sha384") => Some(RTMR0_INO + 1),
            (MEASUREMENTS_DIR_INO, "rtmr2:sha384") => Some(RTMR0_INO + 2),
            (MEASUREMENTS_DIR_INO, "rtmr3:sha384") => Some(RTMR0_INO + 3),
            _ => None,
        }
    }
}

impl Filesystem for TdxSimulatorFs {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(ino) = Self::lookup_ino(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        let Some(attr) = self.attr(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        reply.entry(&TTL, &attr, 0);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.attr(ino) {
            Some(attr) => reply.attr(&TTL, &attr),
            None => reply.error(libc::ENOENT),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let truncatable = ino == INBLOB_INO || (RTMR0_INO..=11).contains(&ino);
        if truncatable
            && size == Some(0)
            && mode.is_none()
            && uid.is_none()
            && gid.is_none()
            && flags.is_none()
        {
            if let Some(attr) = self.attr(ino) {
                reply.attr(&TTL, &attr);
            } else {
                reply.error(libc::ENOENT);
            }
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
        let entries: Vec<(u64, FileType, &str)> = match ino {
            ROOT_INO => vec![
                (ROOT_INO, FileType::Directory, "."),
                (ROOT_INO, FileType::Directory, ".."),
                (PROVIDER_DIR_INO, FileType::Directory, PROVIDER_NAME),
            ],
            PROVIDER_DIR_INO => vec![
                (PROVIDER_DIR_INO, FileType::Directory, "."),
                (ROOT_INO, FileType::Directory, ".."),
                (PROVIDER_INO, FileType::RegularFile, "provider"),
                (INBLOB_INO, FileType::RegularFile, "inblob"),
                (OUTBLOB_INO, FileType::RegularFile, "outblob"),
                (GENERATION_INO, FileType::RegularFile, "generation"),
                (MEASUREMENTS_DIR_INO, FileType::Directory, "measurements"),
                (CCEL_INO, FileType::RegularFile, "ccel"),
            ],
            MEASUREMENTS_DIR_INO => vec![
                (MEASUREMENTS_DIR_INO, FileType::Directory, "."),
                (PROVIDER_DIR_INO, FileType::Directory, ".."),
                (RTMR0_INO, FileType::RegularFile, "rtmr0:sha384"),
                (RTMR0_INO + 1, FileType::RegularFile, "rtmr1:sha384"),
                (RTMR0_INO + 2, FileType::RegularFile, "rtmr2:sha384"),
                (RTMR0_INO + 3, FileType::RegularFile, "rtmr3:sha384"),
            ],
            _ => {
                reply.error(libc::ENOTDIR);
                return;
            }
        };

        for (index, (entry_ino, kind, name)) in
            entries.into_iter().enumerate().skip(offset.max(0) as usize)
        {
            if reply.add(entry_ino, (index + 1) as i64, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        if self.attr(ino).is_none() {
            reply.error(libc::ENOENT);
        } else {
            reply.opened(0, DIRECT_IO);
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
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(data) = self.state.content(ino) else {
            reply.error(libc::EISDIR);
            return;
        };
        let start = offset.max(0) as usize;
        if start >= data.len() {
            reply.data(&[]);
            return;
        }
        let end = start.saturating_add(size as usize).min(data.len());
        reply.data(&data[start..end]);
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
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        if offset != 0 {
            reply.error(libc::EINVAL);
            return;
        }
        let result = match ino {
            INBLOB_INO => self.state.request_quote(data),
            RTMR0_INO..=11 => self.state.extend_rtmr((ino - RTMR0_INO) as usize, data),
            _ => {
                reply.error(libc::EACCES);
                return;
            }
        };
        match result {
            Ok(()) => reply.written(data.len() as u32),
            Err(_) => reply.error(libc::EINVAL),
        }
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        _ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }
}

fn ensure_configfs_mount(mountpoint: &Path) -> Result<()> {
    if mountpoint != Path::new(TDX_DEFAULT_MOUNTPOINT) {
        std::fs::create_dir_all(mountpoint)
            .with_context(|| format!("failed to create {}", mountpoint.display()))?;
        return Ok(());
    }

    if !mountpoint.is_dir() {
        let source = CString::new("configfs")?;
        let target = CString::new("/sys/kernel/config")?;
        let fstype = CString::new("configfs")?;
        let rc = unsafe {
            libc::mount(
                source.as_ptr(),
                target.as_ptr(),
                fstype.as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                std::ptr::null(),
            )
        };
        if rc != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EBUSY) {
                return Err(error).context("failed to mount configfs");
            }
        }
    }
    if !mountpoint.is_dir() {
        bail!(
            "tsm report mountpoint is unavailable: {}",
            mountpoint.display()
        );
    }
    Ok(())
}

fn mounted_provider_exists() -> bool {
    ["/dev/tdx_guest", "/dev/sev-guest"]
        .iter()
        .any(|path| Path::new(path).exists())
}

/// Linux TDX/TSM ABI backend for the generic TEE simulator lifecycle.
pub(crate) struct TdxBackend;

impl TeeBackend for TdxBackend {
    type Fs = TdxSimulatorFs;

    const PLATFORM: &'static str = "tdx";
    const DEFAULT_MOUNTPOINT: &'static str = TDX_DEFAULT_MOUNTPOINT;

    fn create_filesystem() -> Result<Self::Fs> {
        TdxSimulatorFs::new()
    }

    fn prepare_mountpoint(mountpoint: &Path) -> Result<()> {
        ensure_configfs_mount(mountpoint)
    }

    fn real_tee_available() -> bool {
        mounted_provider_exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_qvl::quote::Quote;

    #[test]
    fn quote_tracks_report_data_and_rtmr_extensions() {
        let mut state = SimulatorState::new(QUOTE_FIXTURE, CCEL_FIXTURE).unwrap();
        let original_rtmr3 = state.rtmrs[3];
        let digest = [0x42; 48];
        state.extend_rtmr(3, &digest).unwrap();
        assert_ne!(state.rtmrs[3], original_rtmr3);

        let report_data = [0x5a; 64];
        state.request_quote(&report_data).unwrap();
        assert_eq!(state.generation, 1);

        let quote = Quote::parse(&state.outblob).unwrap();
        let report = quote.report.as_td10().unwrap();
        let fixture = Quote::parse(QUOTE_FIXTURE).unwrap();
        let fixture_report = fixture.report.as_td10().unwrap();
        assert_eq!(report.report_data, report_data);
        assert_eq!(report.mr_config_id, [0u8; 48]);
        assert_eq!(report.rt_mr3, state.rtmrs[3]);
        assert_eq!(report.mr_owner, fixture_report.mr_owner);
    }

    #[test]
    fn only_rtmr_two_and_three_are_extensible() {
        let mut state = SimulatorState::new(QUOTE_FIXTURE, CCEL_FIXTURE).unwrap();
        assert!(state.extend_rtmr(0, &[0u8; 48]).is_err());
        assert!(state.extend_rtmr(2, &[0u8; 48]).is_ok());
        assert!(state.extend_rtmr(3, &[0u8; 48]).is_ok());
        assert!(state.extend_rtmr(4, &[0u8; 48]).is_err());
        assert!(state.extend_rtmr(3, &[0u8; 47]).is_err());
    }

    #[test]
    fn boot_rtmrs_replay_the_bundled_ccel() {
        let rtmrs = replay_boot_rtmrs(CCEL_FIXTURE).unwrap();
        assert!(rtmrs[..2].iter().all(|rtmr| *rtmr != [0u8; 48]));
        assert_eq!(rtmrs[3], [0u8; 48]);
    }
}
