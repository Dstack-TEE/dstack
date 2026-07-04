// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pack a directory into a reproducible, verity-protected volume.
//!
//! The output is one file: the squashfs image, then its dm-verity hash tree.
//! squashfs is used because the guest kernel already mounts it (it's the guest's
//! own rootfs), and because `mksquashfs` with a pinned timestamp is reproducible
//! byte for byte. The verity root is a pure function of the squashfs bytes and
//! the salt.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};

/// Fixed build timestamp (2024-01-01), so the image is the same no matter when
/// it's built. It never shows up at runtime: `mksquashfs -all-time` normalizes
/// the store's own timestamps away.
const EPOCH: &str = "1704067200";
const BLOCK: u64 = 4096;

#[derive(Clone, Copy)]
pub enum Compression {
    /// No compression, so nothing is decompressed at read time (the default).
    None,
    Zstd,
    Gzip,
}

impl Compression {
    fn args(self) -> Vec<&'static str> {
        match self {
            // disable every compressible section: inodes, data, fragments,
            // xattrs, id table.
            Compression::None => vec!["-noI", "-noD", "-noF", "-noX", "-noId"],
            Compression::Zstd => vec!["-comp", "zstd"],
            Compression::Gzip => vec![],
        }
    }
}

pub struct BuiltVolume {
    pub verity_root: String,
    /// size of the squashfs region = the verity hash offset.
    pub data_size: u64,
}

/// Build `output`: the squashfs image of `store`, then its dm-verity hash tree.
///
/// `store` is any directory — a docker overlay2 store, or plain data. `salt`
/// fixes the verity root.
///
/// The verity UUID is derived from the squashfs bytes, so two different volumes
/// get two different UUIDs. That matters because a VM can mount several volumes
/// at once, and a fixed UUID would be shared by all of them.
pub fn build_volume(
    store: &Path,
    output: &Path,
    salt_hex: &str,
    compress: Compression,
) -> Result<BuiltVolume> {
    require_tool("mksquashfs")?;
    require_tool("veritysetup")?;
    if output.exists() {
        std::fs::remove_file(output).ok();
    }

    // 1. reproducible squashfs.
    let mut cmd = Command::new("mksquashfs");
    cmd.arg(store).arg(output);
    cmd.args(compress.args());
    cmd.args([
        "-all-time",
        EPOCH,
        "-mkfs-time",
        EPOCH,
        "-noappend",
        "-no-progress",
        "-xattrs",
    ]);
    run(cmd, "mksquashfs")?;

    // 2. the verity data region must be block-aligned; pad the squashfs up.
    let bytes_used = squashfs_bytes_used(output)?;
    let data_size = bytes_used.div_ceil(BLOCK) * BLOCK;
    {
        let f = std::fs::OpenOptions::new().write(true).open(output)?;
        f.set_len(data_size)?;
    }

    // 3. Append the verity hash tree to the same file, at the aligned offset.
    // Pin the superblock UUID too: veritysetup randomizes it otherwise, and we
    // want the whole file reproducible, not just the root. The UUID sits in the
    // hash tree, not the hashed data, so it never changes the root.
    let uuid = uuid_from_data(output, data_size)?;
    let mut cmd = Command::new("veritysetup");
    cmd.args([
        "format",
        "--salt",
        salt_hex,
        "--uuid",
        &uuid,
        "--data-block-size",
        "4096",
        "--hash-block-size",
        "4096",
        "--hash-offset",
        &data_size.to_string(),
    ]);
    cmd.arg(output).arg(output);
    let out = capture(cmd, "veritysetup format")?;
    let verity_root =
        parse_root_hash(&out).context("could not find the root hash in veritysetup output")?;

    Ok(BuiltVolume {
        verity_root,
        data_size,
    })
}

/// squashfs superblock: `bytes_used` is a little-endian u64 at offset 40.
fn squashfs_bytes_used(path: &Path) -> Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path)?;
    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)?;
    if &magic != b"hsqs" {
        bail!("not a squashfs image (bad magic)");
    }
    f.seek(SeekFrom::Start(40))?;
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

/// Derive a UUID from the first `len` bytes of `path`.
///
/// Deterministic, and shaped like a version-4 UUID.
fn uuid_from_data(path: &Path, len: u64) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut remaining = len;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..n])?;
        h.update(&buf[..n]);
        remaining -= n as u64;
    }
    let d = h.finalize();
    let mut u = [0u8; 16];
    u.copy_from_slice(&d[..16]);
    u[6] = (u[6] & 0x0f) | 0x40; // version 4
    u[8] = (u[8] & 0x3f) | 0x80; // RFC 4122 variant
    let hx = hex::encode(u);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hx[0..8],
        &hx[8..12],
        &hx[12..16],
        &hx[16..20],
        &hx[20..32]
    ))
}

fn parse_root_hash(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.strip_prefix("Root hash:"))
        .map(|v| v.trim().to_string())
}

fn require_tool(name: &str) -> Result<()> {
    // spawning at all means the binary is on PATH; a non-zero exit from
    // `--version` (some builds) still counts as present.
    let present = Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok();
    if !present {
        bail!("`{name}` not found on PATH (install squashfs-tools / cryptsetup)");
    }
    Ok(())
}

fn run(mut cmd: Command, what: &str) -> Result<()> {
    let status = cmd
        .stdout(std::process::Stdio::null())
        .status()
        .with_context(|| format!("running {what}"))?;
    if !status.success() {
        bail!("{what} failed with {status}");
    }
    Ok(())
}

fn capture(mut cmd: Command, what: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {what}"))?;
    if !out.status.success() {
        bail!(
            "{what} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_veritysetup_root() {
        let sample = "VERITY header information for x\nUUID:  \nHash type:  1\n\
                      Data blocks:  10\nRoot hash:      abc123def\n";
        assert_eq!(parse_root_hash(sample).as_deref(), Some("abc123def"));
    }

    #[test]
    fn uuid_is_deterministic_and_content_specific() {
        use std::io::Write;
        let mut a = tempfile::NamedTempFile::new().unwrap();
        a.write_all(b"hello world data").unwrap();
        let mut b = tempfile::NamedTempFile::new().unwrap();
        b.write_all(b"different data..").unwrap();
        let ua = uuid_from_data(a.path(), 16).unwrap();
        assert_eq!(ua, uuid_from_data(a.path(), 16).unwrap()); // deterministic
        assert_ne!(ua, uuid_from_data(b.path(), 16).unwrap()); // content-specific
        assert_eq!(ua.len(), 36);
        assert_eq!(&ua[14..15], "4"); // version nibble
    }
}
