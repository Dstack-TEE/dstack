// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Pack a directory into a reproducible, verity-protected disk image.
//!
//! The output is a raw disk with three deterministic GPT partitions:
//!
//!   1. a generic `DSTACK_VOLUME` metadata block
//!   2. the filesystem image
//!   3. the dm-verity superblock and hash tree
//!
//! Keeping the verity data and hash devices in separate partitions means the
//! guest never has to inspect filesystem metadata to find the hash tree. The
//! partition table is only a locator hint; the measured verity root is still the
//! content identity.

use std::collections::BTreeMap;
use std::path::Path;

use crate::volume_format::{DstackVolumeHeader, DSTACK_VOLUME_HEADER_SIZE};
use anyhow::{bail, Context, Result};
use cmd_lib::{run_cmd, run_fun};
use fs_err as fs;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Fixed build timestamp (2024-01-01), so the image is the same no matter when
/// it's built. It never shows up at runtime: `mksquashfs -all-time` normalizes
/// the store's own timestamps away.
const EPOCH: &str = "1704067200";
const BLOCK: u64 = 4096;
const SECTOR: u64 = 512;
// 1 MiB alignment.
const PARTITION_ALIGNMENT_SECTORS: u64 = 2048;
// The `gpt` crate writes the primary/backup headers and partition arrays. We
// still reserve enough trailing sectors in the raw image for the backup array
// (128 entries * 128 bytes) plus the backup header.
const GPT_ENTRY_SECTORS: u64 = 32;
const VOLUME_HEADER_SIZE: usize = DSTACK_VOLUME_HEADER_SIZE;

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
    /// Size of the filesystem data partition.
    pub data_size: u64,
}

/// Build `output`: a GPT disk image with the squashfs data partition and a
/// separate dm-verity hash partition.
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

    let tmp = tempfile::tempdir().context("creating volume scratch dir")?;
    let data_path = tmp.path().join("data.fs");

    // 1. reproducible squashfs.
    let compression_args = compress.args();
    run_cmd!(
        mksquashfs $store $data_path $[compression_args]
            -all-time $EPOCH -mkfs-time $EPOCH -noappend -no-progress -xattrs
            >/dev/null
    )
    .context("running mksquashfs")?;

    // 2. the verity data region must be block-aligned; pad the squashfs up.
    let bytes_used = squashfs_bytes_used(&data_path)?;
    seal_data_image(&data_path, bytes_used, output, salt_hex)
}

/// Wrap an existing filesystem image in the same partitioned verity disk format.
///
/// The input image is copied to a scratch file and padded to a 4096-byte verity
/// block boundary. Its filesystem type is otherwise opaque to the verity layer.
pub fn build_fs_image(fs_image: &Path, output: &Path, salt_hex: &str) -> Result<BuiltVolume> {
    require_tool("veritysetup")?;
    let len = fs::metadata(fs_image)
        .with_context(|| format!("stat {}", fs_image.display()))?
        .len();
    if len == 0 {
        bail!("filesystem image '{}' is empty", fs_image.display());
    }

    let tmp = tempfile::tempdir().context("creating volume scratch dir")?;
    let data_path = tmp.path().join("data.fs");
    fs::copy(fs_image, &data_path)
        .with_context(|| format!("copying {} into scratch", fs_image.display()))?;
    seal_data_image(&data_path, len, output, salt_hex)
}

fn seal_data_image(
    data_path: &Path,
    data_len: u64,
    output: &Path,
    salt_hex: &str,
) -> Result<BuiltVolume> {
    let hash_tmp = tempfile::tempdir().context("creating verity hash scratch dir")?;
    let hash_path = hash_tmp.path().join("verity.hash");
    let data_size = data_len.div_ceil(BLOCK) * BLOCK;
    {
        let f = fs::OpenOptions::new().write(true).open(data_path)?;
        f.set_len(data_size)?;
    }

    // Build the verity hash device as a separate image. At runtime this is
    // partition 2, so no --hash-offset is needed and the guest does not parse
    // filesystem metadata before verity is active.
    // Pin the superblock UUID too: veritysetup randomizes it otherwise, and we
    // want the whole image reproducible, not just the root. The UUID sits in the
    // hash tree, not the hashed data, so it never changes the root.
    let uuid = uuid_from_data(data_path, data_size)?;
    let out = run_fun!(
        veritysetup format --salt $salt_hex --uuid $uuid
            --data-block-size 4096 --hash-block-size 4096 $data_path $hash_path
    )
    .context("running veritysetup format")?;
    let verity_root =
        parse_root_hash(&out).context("could not find the root hash in veritysetup output")?;

    // Wrap the two blobs in a deterministic GPT disk image. Partition 1 is the
    // generic volume envelope, partition 2 is data, and partition 3 is verity.
    build_partitioned_image(data_path, data_size, &hash_path, output, &verity_root)?;

    Ok(BuiltVolume {
        verity_root,
        data_size,
    })
}

/// squashfs superblock: `bytes_used` is a little-endian u64 at offset 40.
fn squashfs_bytes_used(path: &Path) -> Result<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(path)?;
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
fn uuid_from_data(path: &Path, len: u64) -> Result<String> {
    Ok(uuid_from_file(path, len)?.to_string())
}

/// Deterministic, version-4-shaped UUID from arbitrary domain-separated
/// material.
fn uuid_from_material(parts: &[&[u8]]) -> Uuid {
    let mut h = Sha256::new();
    for part in parts {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    uuid_from_digest(&h.finalize())
}

fn uuid_from_file(path: &Path, len: u64) -> Result<Uuid> {
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut remaining = len;
    let mut buf = vec![0u8; 1 << 20];
    while remaining > 0 {
        let n = remaining.min(buf.len() as u64) as usize;
        f.read_exact(&mut buf[..n])?;
        h.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(uuid_from_digest(&h.finalize()))
}

fn uuid_from_digest(d: &[u8]) -> Uuid {
    let mut u = [0u8; 16];
    u.copy_from_slice(&d[..16]);
    u[6] = (u[6] & 0x0f) | 0x40; // version 4
    u[8] = (u[8] & 0x3f) | 0x80; // RFC 4122 variant
    Uuid::from_bytes(u)
}

#[derive(Clone, Copy)]
struct Partition {
    first_lba: u64,
    last_lba: u64,
}

struct GptLayout {
    total_lbas: u64,
    metadata: Partition,
    data: Partition,
    hash: Partition,
}

impl GptLayout {
    fn new(data_size: u64, hash_size: u64) -> Result<Self> {
        if data_size == 0 || hash_size == 0 {
            bail!("data and hash images must be non-empty");
        }
        let data_sectors = data_size.div_ceil(SECTOR);
        let hash_sectors = hash_size.div_ceil(SECTOR);

        let metadata_first = PARTITION_ALIGNMENT_SECTORS;
        let metadata_last = metadata_first + VOLUME_HEADER_SIZE as u64 / SECTOR - 1;
        let data_first = align_up(metadata_last + 1, PARTITION_ALIGNMENT_SECTORS);
        let data_last = data_first + data_sectors - 1;
        let hash_first = align_up(data_last + 1, PARTITION_ALIGNMENT_SECTORS);
        let hash_last = hash_first + hash_sectors - 1;

        // Leave room for the backup GPT entry array and header at the end.
        let min_lbas = hash_last + 1 + GPT_ENTRY_SECTORS + 1;
        let total_lbas = align_up(min_lbas, PARTITION_ALIGNMENT_SECTORS);
        Ok(Self {
            total_lbas,
            metadata: Partition {
                first_lba: metadata_first,
                last_lba: metadata_last,
            },
            data: Partition {
                first_lba: data_first,
                last_lba: data_last,
            },
            hash: Partition {
                first_lba: hash_first,
                last_lba: hash_last,
            },
        })
    }

    fn total_bytes(&self) -> u64 {
        self.total_lbas * SECTOR
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

fn build_partitioned_image(
    data_path: &Path,
    data_size: u64,
    hash_path: &Path,
    output: &Path,
    root_hash: &str,
) -> Result<()> {
    let hash_size = fs::metadata(hash_path)
        .with_context(|| format!("stat {}", hash_path.display()))?
        .len();
    let layout = GptLayout::new(data_size, hash_size)?;

    let mut out = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(output)
        .with_context(|| format!("creating {}", output.display()))?;
    out.set_len(layout.total_bytes())?;

    out = write_gpt(out, &layout, root_hash)?;

    write_volume_header(&mut out, layout.metadata.first_lba * SECTOR, root_hash)?;
    copy_into(data_path, &mut out, layout.data.first_lba * SECTOR)?;
    copy_into(hash_path, &mut out, layout.hash.first_lba * SECTOR)?;
    Ok(())
}

fn write_gpt(mut out: fs::File, layout: &GptLayout, root_hash: &str) -> Result<fs::File> {
    let protective_size = (layout.total_lbas - 1).min(u32::MAX as u64) as u32;
    gpt::mbr::ProtectiveMBR::with_lb_size(protective_size)
        .overwrite_lba0(&mut out)
        .context("writing protective MBR")?;

    let disk_uuid = uuid_from_material(&[b"dstack-verity-disk", root_hash.as_bytes()]);
    let mut disk = gpt::GptConfig::new()
        .writable(true)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .create_from_device(out, Some(disk_uuid))
        .context("initializing GPT")?;

    let mut parts = BTreeMap::new();
    parts.insert(
        1,
        gpt::partition::Partition {
            part_type_guid: gpt::partition_types::LINUX_FS,
            part_guid: uuid_from_material(&[b"dstack-volume-metadata", root_hash.as_bytes()]),
            first_lba: layout.metadata.first_lba,
            last_lba: layout.metadata.last_lba,
            flags: 0,
            name: "dstack-volume".to_string(),
        },
    );
    parts.insert(
        2,
        gpt::partition::Partition {
            part_type_guid: gpt::partition_types::LINUX_FS,
            part_guid: uuid_from_material(&[b"dstack-verity-data", root_hash.as_bytes()]),
            first_lba: layout.data.first_lba,
            last_lba: layout.data.last_lba,
            flags: 0,
            name: "dstack-data".to_string(),
        },
    );
    parts.insert(
        3,
        gpt::partition::Partition {
            part_type_guid: gpt::partition_types::LINUX_FS,
            part_guid: uuid_from_material(&[b"dstack-verity-hash", root_hash.as_bytes()]),
            first_lba: layout.hash.first_lba,
            last_lba: layout.hash.last_lba,
            flags: 0,
            name: "dstack-verity".to_string(),
        },
    );
    disk.update_partitions(parts)
        .context("installing GPT partitions")?;
    disk.write().context("writing GPT")
}

fn write_volume_header(out: &mut fs::File, offset: u64, root_hash: &str) -> Result<()> {
    use std::io::{Seek, SeekFrom, Write};

    let root = hex::decode(root_hash).context("decoding verity root hash")?;
    let root: [u8; 32] = root
        .as_slice()
        .try_into()
        .context("verity root must be a 32-byte SHA-256 digest")?;
    let header = DstackVolumeHeader::new_verity(root)
        .encode()
        .context("encoding volume header")?;

    out.seek(SeekFrom::Start(offset))?;
    out.write_all(&header)?;
    Ok(())
}

fn copy_into(src: &Path, out: &mut fs::File, offset: u64) -> Result<()> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let mut input = fs::File::open(src)?;
    out.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
    }
    Ok(())
}

fn parse_root_hash(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|l| l.strip_prefix("Root hash:"))
        .map(|v| v.trim().to_string())
}

fn require_tool(name: &str) -> Result<()> {
    let present = run_cmd!(which $name >/dev/null 2>&1).is_ok();
    if !present {
        bail!("`{name}` not found on PATH (install squashfs-tools / cryptsetup)");
    }
    Ok(())
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

    #[test]
    fn gpt_layout_uses_three_aligned_partitions() {
        let layout = GptLayout::new(4096, 8192).unwrap();
        assert_eq!(layout.metadata.first_lba, PARTITION_ALIGNMENT_SECTORS);
        assert_eq!(layout.metadata.last_lba, PARTITION_ALIGNMENT_SECTORS + 7);
        assert_eq!(layout.data.first_lba, PARTITION_ALIGNMENT_SECTORS * 2);
        assert_eq!(layout.data.last_lba, PARTITION_ALIGNMENT_SECTORS * 2 + 7);
        assert_eq!(layout.hash.first_lba, PARTITION_ALIGNMENT_SECTORS * 3);
        assert_eq!(layout.hash.last_lba, PARTITION_ALIGNMENT_SECTORS * 3 + 15);
        assert!(layout.total_lbas - 1 - GPT_ENTRY_SECTORS > layout.hash.last_lba);
    }

    #[test]
    fn partitioned_image_is_valid_gpt() -> Result<()> {
        use std::io::{Read, Seek, SeekFrom, Write};

        let tmp = tempfile::tempdir()?;
        let data_path = tmp.path().join("data.fs");
        let hash_path = tmp.path().join("verity.hash");
        let image_path = tmp.path().join("volume.img");
        let data = vec![0x11; 4096];
        let hash = vec![0x22; 8192];
        fs::File::create(&data_path)?.write_all(&data)?;
        fs::File::create(&hash_path)?.write_all(&hash)?;

        let root_hash = "abababababababababababababababababababababababababababababababab";
        build_partitioned_image(
            &data_path,
            data.len() as u64,
            &hash_path,
            &image_path,
            root_hash,
        )?;

        let disk = gpt::GptConfig::new()
            .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
            .open(&image_path)?;
        assert_eq!(
            *disk.guid(),
            uuid_from_material(&[b"dstack-verity-disk", root_hash.as_bytes()])
        );

        let metadata = disk.partitions().get(&1).unwrap();
        let data_partition = disk.partitions().get(&2).unwrap();
        let hash_partition = disk.partitions().get(&3).unwrap();
        assert_eq!(metadata.name, "dstack-volume");
        assert_eq!(data_partition.name, "dstack-data");
        assert_eq!(hash_partition.name, "dstack-verity");
        assert_eq!(
            data_partition.part_guid,
            uuid_from_material(&[b"dstack-verity-data", root_hash.as_bytes()])
        );
        assert_eq!(
            hash_partition.part_guid,
            uuid_from_material(&[b"dstack-verity-hash", root_hash.as_bytes()])
        );
        assert_eq!(metadata.first_lba, PARTITION_ALIGNMENT_SECTORS);
        assert_eq!(data_partition.first_lba, PARTITION_ALIGNMENT_SECTORS * 2);
        assert_eq!(hash_partition.first_lba, PARTITION_ALIGNMENT_SECTORS * 3);

        let mut img = fs::File::open(&image_path)?;
        let mut header = [0u8; VOLUME_HEADER_SIZE];
        img.seek(SeekFrom::Start(metadata.first_lba * SECTOR))?;
        img.read_exact(&mut header)?;
        assert_eq!(&header[..16], b"DSTACK_VOLUME\0\0\0");
        let decoded = DstackVolumeHeader::decode(&header)?;
        assert_eq!(decoded.root_hash.as_slice(), hex::decode(root_hash)?);
        let mut buf = vec![0; data.len()];
        img.seek(SeekFrom::Start(data_partition.first_lba * SECTOR))?;
        img.read_exact(&mut buf)?;
        assert_eq!(buf, data);
        let mut buf = vec![0; hash.len()];
        img.seek(SeekFrom::Start(hash_partition.first_lba * SECTOR))?;
        img.read_exact(&mut buf)?;
        assert_eq!(buf, hash);

        Ok(())
    }
}
