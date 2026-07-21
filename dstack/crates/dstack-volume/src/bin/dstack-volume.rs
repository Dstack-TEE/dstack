// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

//! Discover and activate volumes supplied to a dstack guest.
//!
//! A volume is recognized by a `DSTACK_VOLUME` envelope at the start of its
//! first partition, or at the start of the whole disk when it has no partition
//! table. Everything read from a disk is untrusted: kind handlers use the
//! measured app compose as their source of policy and cryptographic identity.

use std::collections::HashSet;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use cmd_lib::{run_cmd, run_fun};
use dstack_types::{AppCompose, VerityVolume as RequestedVolume};
use dstack_volume::volume_format::{
    DstackVolumeHeader, DSTACK_VOLUME_HEADER_SIZE, DSTACK_VOLUME_KIND_VERITY, DSTACK_VOLUME_MAGIC,
};
use fs_err::{self as fs, File};
use tracing::{info, warn};

const MAX_DISKS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockDisk {
    path: PathBuf,
    partitions: Vec<(u32, PathBuf)>,
}

#[derive(Debug)]
struct VerityVolume {
    data: PathBuf,
    hash: PathBuf,
    root_hash: [u8; 32],
}

fn main() -> Result<()> {
    tracing_subscriber::fmt().init();
    let compose_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("app-compose.json"));
    // Deserialize the complete shared type before probing any untrusted disk.
    // This validates roots and targets as part of parsing the measured compose.
    let compose: AppCompose = serde_json::from_slice(&fs::read(&compose_path)?)
        .with_context(|| format!("parsing {}", compose_path.display()))?;
    if compose.verity_volumes.is_empty() {
        return Ok(());
    }

    let _ = run_cmd!(modprobe dm-verity);
    let _ = run_cmd!(udevadm settle --timeout=5);

    let volumes = discover_volumes()?;
    info!(
        found = volumes.len(),
        requested = compose.verity_volumes.len(),
        "discovered dstack volumes"
    );
    let mut used = HashSet::new();
    let mut failures = 0;
    for (index, requested) in compose.verity_volumes.iter().enumerate() {
        if let Err(err) = activate_requested(index, requested, &volumes, &mut used) {
            failures += 1;
            warn!(index, target = %requested.target.display(), error = %format_args!("{err:#}"), "failed to activate required volume");
        }
    }
    if failures != 0 {
        bail!("failed to activate {failures} required volume(s)");
    }
    Ok(())
}

fn discover_volumes() -> Result<Vec<VerityVolume>> {
    let mut found = Vec::new();
    let disks = list_disks()?;
    if disks.len() > MAX_DISKS {
        warn!(
            found = disks.len(),
            limit = MAX_DISKS,
            "block-device scan truncated"
        );
    }
    for disk in disks.into_iter().take(MAX_DISKS) {
        // A partitioned disk has exactly one envelope location: partition 1.
        // Only a disk with no kernel-recognized partitions is probed at offset 0.
        let probe = if disk.partitions.is_empty() {
            &disk.path
        } else if let Some((_, path)) = disk.partitions.iter().find(|(number, _)| *number == 1) {
            path
        } else {
            continue;
        };
        let Some(header) = read_header(probe)? else {
            continue;
        };
        match header.kind {
            DSTACK_VOLUME_KIND_VERITY => match resolve_verity(&disk, header) {
                Ok(volume) => found.push(volume),
                Err(err) => {
                    warn!(disk = %disk.path.display(), error = %format_args!("{err:#}"), "ignoring malformed verity volume")
                }
            },
            kind => warn!(kind, disk = %disk.path.display(), "ignoring unsupported volume kind"),
        }
    }
    Ok(found)
}

fn list_disks() -> Result<Vec<BlockDisk>> {
    list_disks_at(Path::new("/sys/class/block"), Path::new("/dev"))
}

fn list_disks_at(sysfs: &Path, devfs: &Path) -> Result<Vec<BlockDisk>> {
    struct Entry {
        name: std::ffi::OsString,
        sysfs_path: PathBuf,
        partition: Option<u32>,
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(sysfs)? {
        let entry = entry?;
        let class_path = entry.path();
        let partition = if class_path.join("partition").exists() {
            Some(
                fs::read_to_string(class_path.join("partition"))?
                    .trim()
                    .parse()?,
            )
        } else {
            None
        };
        entries.push(Entry {
            name: entry.file_name(),
            sysfs_path: fs::canonicalize(class_path)?,
            partition,
        });
    }

    let mut disks = entries
        .iter()
        .filter(|entry| entry.partition.is_none() && entry.sysfs_path.join("device").exists())
        .map(|entry| BlockDisk {
            path: devfs.join(&entry.name),
            partitions: entries
                .iter()
                .filter_map(|partition| {
                    let number = partition.partition?;
                    (partition.sysfs_path.parent() == Some(entry.sysfs_path.as_path()))
                        .then(|| (number, devfs.join(&partition.name)))
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    for disk in &mut disks {
        disk.partitions.sort_by_key(|(number, _)| *number);
    }
    disks.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(disks)
}

fn read_header(path: &Path) -> Result<Option<DstackVolumeHeader>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            warn!(path = %path.display(), %err, "cannot open block device");
            return Ok(None);
        }
    };
    let mut bytes = [0u8; DSTACK_VOLUME_HEADER_SIZE];
    if let Err(err) = file.read_exact(&mut bytes) {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(err).with_context(|| format!("reading {}", path.display()));
    }
    parse_header(&bytes).with_context(|| format!("parsing envelope on {}", path.display()))
}

fn parse_header(bytes: &[u8]) -> Result<Option<DstackVolumeHeader>> {
    if bytes.len() < DSTACK_VOLUME_HEADER_SIZE || &bytes[..16] != DSTACK_VOLUME_MAGIC {
        return Ok(None);
    }
    Ok(Some(DstackVolumeHeader::decode(bytes)?))
}

fn resolve_verity(disk: &BlockDisk, header: DstackVolumeHeader) -> Result<VerityVolume> {
    if disk.partitions.is_empty() {
        bail!("raw verity layout is not defined by kind version 1");
    }
    let partition = |number| {
        disk.partitions
            .iter()
            .find(|(n, _)| *n == number)
            .map(|(_, path)| path.clone())
            .with_context(|| format!("missing partition {number}"))
    };
    Ok(VerityVolume {
        data: partition(2)?,
        hash: partition(3)?,
        root_hash: header.root_hash,
    })
}

fn activate_requested(
    index: usize,
    requested: &RequestedVolume,
    volumes: &[VerityVolume],
    used: &mut HashSet<usize>,
) -> Result<()> {
    let (candidate_index, candidate) = volumes
        .iter()
        .enumerate()
        .find(|(candidate_index, volume)| {
            !used.contains(candidate_index) && volume.root_hash == requested.verity_root
        })
        .context("no attached volume advertises the measured root")?;

    let mapper_name = format!("dstack-verity{index}");
    let mapped = PathBuf::from(format!("/dev/mapper/{mapper_name}"));
    let expected_root = hex::encode(requested.verity_root);
    if mapped.exists() {
        if mapping_root(&mapper_name)?.eq_ignore_ascii_case(&expected_root) {
            verify_first_block(&mapped)?;
            mount_volume(requested, &mapped)?;
            used.insert(candidate_index);
            info!(mapper = mapper_name, "reused active verity mapping");
            return Ok(());
        }
        run_cmd!(veritysetup close $mapper_name).context("closing stale verity mapping")?;
    }

    // The on-disk root only selected a candidate. Pass the root from the
    // measured compose to veritysetup, which is the actual trust decision.
    let data = &candidate.data;
    let hash = &candidate.hash;
    run_cmd!(veritysetup open $data $mapper_name $hash $expected_root)
        .context("opening dm-verity volume")?;
    if let Err(err) = verify_first_block(&mapped).and_then(|_| mount_volume(requested, &mapped)) {
        let _ = run_cmd!(veritysetup close $mapper_name);
        return Err(err);
    }
    used.insert(candidate_index);
    Ok(())
}

fn verify_first_block(path: &Path) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut block = [0u8; 4096];
    file.read_exact(&mut block)
        .with_context(|| format!("verifying first block of {}", path.display()))
}

fn mount_volume(requested: &RequestedVolume, mapped: &Path) -> Result<()> {
    let fs_type = run_fun!(blkid -o value -s TYPE $mapped).unwrap_or_default();
    let target = &requested.target;
    fs::create_dir_all(target)?;
    if is_mountpoint(target)? {
        ensure_mounted_from(target, mapped)?;
    } else {
        mount_read_only(mapped, target, fs_type.trim())?;
    }
    info!(root = %hex::encode(requested.verity_root), target = %target.display(), "mounted verity volume");
    Ok(())
}

fn mount_read_only(device: &Path, target: &Path, fs_type: &str) -> Result<()> {
    let options = if matches!(fs_type, "ext3" | "ext4") {
        "ro,noload"
    } else {
        "ro"
    };
    if fs_type.is_empty() {
        run_cmd!(mount -o $options $device $target).context("mounting verity volume")?;
    } else {
        run_cmd!(mount -t $fs_type -o $options $device $target)
            .context("mounting verity volume")?;
    }
    Ok(())
}

fn is_mountpoint(path: &Path) -> Result<bool> {
    Ok(mountpoint_device(path)?.is_some())
}

fn ensure_mounted_from(target: &Path, device: &Path) -> Result<()> {
    let mounted = mountpoint_device(target)?.context("mount point disappeared")?;
    let expected = device_number(fs::metadata(device)?.rdev());
    if mounted != expected {
        bail!(
            "{} is mounted from device {}:{}, expected {}:{}",
            target.display(),
            mounted.0,
            mounted.1,
            expected.0,
            expected.1
        );
    }
    Ok(())
}

fn mountpoint_device(path: &Path) -> Result<Option<(u64, u64)>> {
    let target = path.as_os_str().as_bytes();
    for line in fs::read_to_string("/proc/self/mountinfo")?.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(device) = fields.nth(2) else {
            continue;
        };
        let Some(mountpoint) = fields.nth(1) else {
            continue;
        };
        if unescape_mountinfo(mountpoint.as_bytes()) == target {
            let (major, minor) = device
                .split_once(':')
                .context("invalid mountinfo device number")?;
            return Ok(Some((major.parse()?, minor.parse()?)));
        }
    }
    Ok(None)
}

fn device_number(device: u64) -> (u64, u64) {
    let major = ((device >> 8) & 0xfff) | ((device >> 32) & 0xffff_f000);
    let minor = (device & 0xff) | ((device >> 12) & 0xffff_ff00);
    (major, minor)
}

fn unescape_mountinfo(value: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] == b'\\' && index + 3 < value.len() {
            let octal = &value[index + 1..index + 4];
            if octal.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
                decoded.push((octal[0] - b'0') * 64 + (octal[1] - b'0') * 8 + (octal[2] - b'0'));
                index += 4;
                continue;
            }
        }
        decoded.push(value[index]);
        index += 1;
    }
    decoded
}

fn mapping_root(mapper_name: &str) -> Result<String> {
    let status = run_fun!(veritysetup status $mapper_name)?;
    status
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("root hash:")
                .or_else(|| line.strip_prefix("Root hash:"))
        })
        .map(|root| root.trim().to_string())
        .context("verity mapping status has no root hash")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> DstackVolumeHeader {
        DstackVolumeHeader::new_verity([0x5a; 32])
    }

    #[test]
    fn ignores_non_volume_data() {
        assert_eq!(
            parse_header(&[0u8; DSTACK_VOLUME_HEADER_SIZE]).unwrap(),
            None
        );
    }

    #[test]
    fn verity_kind_uses_second_and_third_partitions() {
        let disk = BlockDisk {
            path: "/dev/test".into(),
            partitions: vec![
                (1, "/dev/test1".into()),
                (2, "/dev/test2".into()),
                (3, "/dev/test3".into()),
            ],
        };
        let volume = resolve_verity(&disk, header()).unwrap();
        assert_eq!(volume.data, Path::new("/dev/test2"));
        assert_eq!(volume.hash, Path::new("/dev/test3"));
    }

    #[test]
    fn verity_kind_rejects_undefined_raw_layout() {
        let disk = BlockDisk {
            path: "/dev/test".into(),
            partitions: vec![],
        };
        assert!(resolve_verity(&disk, header()).is_err());
    }

    #[test]
    fn decodes_mountinfo_escapes() {
        assert_eq!(unescape_mountinfo(b"/run/my\\040volume"), b"/run/my volume");
    }

    #[test]
    fn discovers_partitions_from_sysfs_parentage() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let sysfs = temp.path().join("sys/class/block");
        let devices = temp.path().join("sys/devices/block/vda");
        let partition = devices.join("vda1");
        fs::create_dir_all(&sysfs)?;
        fs::create_dir_all(devices.join("device"))?;
        fs::create_dir_all(&partition)?;
        fs::write(partition.join("partition"), "1\n")?;
        symlink(&devices, sysfs.join("vda"))?;
        symlink(&partition, sysfs.join("vda1"))?;

        assert_eq!(
            list_disks_at(&sysfs, Path::new("/dev"))?,
            vec![BlockDisk {
                path: "/dev/vda".into(),
                partitions: vec![(1, "/dev/vda1".into())],
            }]
        );
        Ok(())
    }
}
