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
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

const MAGIC: &[u8; 16] = b"DSTACK_VOLUME\0\0\0";
const HEADER_SIZE: usize = 4096;
const FORMAT_VERSION: u16 = 1;
const KIND_VERITY: u32 = 1;
const MAX_DISKS: usize = 64;
const DOCKER_STORE: &str = "/var/lib/docker";

#[derive(Debug, Deserialize)]
struct AppCompose {
    #[serde(default)]
    verity_volumes: Vec<RequestedVolume>,
}

#[derive(Debug, Deserialize)]
struct RequestedVolume {
    verity_root: String,
    target: String,
}

#[derive(Clone, Debug)]
struct BlockDisk {
    path: PathBuf,
    partitions: Vec<(u32, PathBuf)>,
}

#[derive(Debug, PartialEq, Eq)]
struct VolumeHeader {
    kind: u32,
    kind_version: u32,
    flags: u32,
    root_hash: [u8; 32],
    data_block_size: u32,
    hash_block_size: u32,
}

#[derive(Debug)]
struct VerityVolume {
    data: PathBuf,
    hash: PathBuf,
    root_hash: [u8; 32],
}

fn main() -> Result<()> {
    let compose_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("app-compose.json"));
    let compose: AppCompose = serde_json::from_slice(
        &fs::read(&compose_path).with_context(|| format!("reading {}", compose_path.display()))?,
    )
    .with_context(|| format!("parsing {}", compose_path.display()))?;
    if compose.verity_volumes.is_empty() {
        return Ok(());
    }

    let _ = run(Command::new("modprobe").arg("dm-verity"));
    let _ = run(Command::new("udevadm").args(["settle", "--timeout=5"]));

    let volumes = discover_volumes()?;
    eprintln!(
        "dstack-volume: found {} volume(s), {} requested",
        volumes.len(),
        compose.verity_volumes.len()
    );
    let mut used = HashSet::new();
    for (index, requested) in compose.verity_volumes.iter().enumerate() {
        if let Err(err) = activate_requested(index, requested, &volumes, &mut used) {
            eprintln!(
                "dstack-volume: volume {index} ({}): {err:#}; skipping",
                requested.target
            );
        }
    }
    Ok(())
}

fn discover_volumes() -> Result<Vec<VerityVolume>> {
    let mut found = Vec::new();
    for disk in list_disks()?.into_iter().take(MAX_DISKS) {
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
            KIND_VERITY => match resolve_verity(&disk, header) {
                Ok(volume) => found.push(volume),
                Err(err) => eprintln!(
                    "dstack-volume: ignoring malformed verity volume {}: {err:#}",
                    disk.path.display()
                ),
            },
            kind => eprintln!(
                "dstack-volume: ignoring unsupported kind {kind} on {}",
                disk.path.display()
            ),
        }
    }
    Ok(found)
}

fn list_disks() -> Result<Vec<BlockDisk>> {
    let output = checked(
        Command::new("lsblk").args(["-rnbpo", "PATH,TYPE,PARTN"]),
        "listing block devices",
    )?;
    let text = String::from_utf8(output.stdout).context("lsblk output is not UTF-8")?;
    let mut disks = Vec::<BlockDisk>::new();
    let mut current = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(path) = fields.next() else { continue };
        let Some(kind) = fields.next() else { continue };
        match kind {
            "disk" => {
                disks.push(BlockDisk {
                    path: PathBuf::from(path),
                    partitions: Vec::new(),
                });
                current = Some(disks.len() - 1);
            }
            "part" => {
                let Some(number) = fields.next().and_then(|v| v.parse::<u32>().ok()) else {
                    continue;
                };
                // lsblk -p emits children immediately below their parent disk.
                if let Some(index) = current {
                    disks[index].partitions.push((number, PathBuf::from(path)));
                }
            }
            _ => {}
        }
    }
    for disk in &mut disks {
        disk.partitions.sort_by_key(|(number, _)| *number);
    }
    Ok(disks)
}

fn read_header(path: &Path) -> Result<Option<VolumeHeader>> {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("dstack-volume: cannot open {}: {err}", path.display());
            return Ok(None);
        }
    };
    let mut bytes = [0u8; HEADER_SIZE];
    if let Err(err) = file.read_exact(&mut bytes) {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(None);
        }
        return Err(err).with_context(|| format!("reading {}", path.display()));
    }
    parse_header(&bytes).with_context(|| format!("parsing envelope on {}", path.display()))
}

fn parse_header(bytes: &[u8]) -> Result<Option<VolumeHeader>> {
    if bytes.len() < HEADER_SIZE || &bytes[..16] != MAGIC {
        return Ok(None);
    }
    let version = u16::from_le_bytes(bytes[16..18].try_into()?);
    let header_size = u16::from_le_bytes(bytes[18..20].try_into()?) as usize;
    if version != FORMAT_VERSION {
        bail!("unsupported envelope version {version}");
    }
    if header_size != HEADER_SIZE {
        bail!("invalid header size {header_size}");
    }
    let root_hash = bytes[32..64].try_into()?;
    Ok(Some(VolumeHeader {
        kind: u32::from_le_bytes(bytes[20..24].try_into()?),
        kind_version: u32::from_le_bytes(bytes[24..28].try_into()?),
        flags: u32::from_le_bytes(bytes[28..32].try_into()?),
        root_hash,
        data_block_size: u32::from_le_bytes(bytes[64..68].try_into()?),
        hash_block_size: u32::from_le_bytes(bytes[68..72].try_into()?),
    }))
}

fn resolve_verity(disk: &BlockDisk, header: VolumeHeader) -> Result<VerityVolume> {
    if header.kind_version != 1 {
        bail!("unsupported verity version {}", header.kind_version);
    }
    if header.flags != 0 {
        bail!("unsupported verity flags {:#x}", header.flags);
    }
    if header.data_block_size != 4096 || header.hash_block_size != 4096 {
        bail!(
            "unsupported verity block sizes {}/{}",
            header.data_block_size,
            header.hash_block_size
        );
    }
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
    let expected = hex::decode(&requested.verity_root).context("invalid verity_root hex")?;
    if expected.len() != 32 {
        bail!("verity_root must contain 32 bytes");
    }
    let candidate = volumes
        .iter()
        .enumerate()
        .find(|(candidate_index, volume)| {
            !used.contains(candidate_index) && volume.root_hash.as_slice() == expected
        })
        .context("no attached volume advertises the measured root")?;

    let mapper_name = format!("dstack-verity{index}");
    // The on-disk root only selected a candidate. Pass the root from the
    // measured compose to veritysetup, which is the actual trust decision.
    checked(
        Command::new("veritysetup")
            .arg("open")
            .arg(&candidate.1.data)
            .arg(&mapper_name)
            .arg(&candidate.1.hash)
            .arg(&requested.verity_root),
        "opening dm-verity volume",
    )?;
    let mapped = PathBuf::from(format!("/dev/mapper/{mapper_name}"));
    if let Err(err) =
        verify_first_block(&mapped).and_then(|_| mount_volume(index, requested, &mapped))
    {
        let _ = run(Command::new("veritysetup").args(["close", &mapper_name]));
        return Err(err);
    }
    used.insert(candidate.0);
    Ok(())
}

fn verify_first_block(path: &Path) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut block = [0u8; 4096];
    file.read_exact(&mut block)
        .with_context(|| format!("verifying first block of {}", path.display()))
}

fn mount_volume(index: usize, requested: &RequestedVolume, mapped: &Path) -> Result<()> {
    let fs_type = command_stdout(
        Command::new("blkid")
            .args(["-o", "value", "-s", "TYPE"])
            .arg(mapped),
    )
    .unwrap_or_default();
    if requested.target == "docker" {
        let mountpoint = PathBuf::from(format!("/run/dstack-verity/{index}"));
        fs::create_dir_all(&mountpoint)?;
        mount_read_only(mapped, &mountpoint, fs_type.trim())?;
        if let Err(err) = seed_docker(&mountpoint) {
            let _ = run(Command::new("umount").arg(&mountpoint));
            return Err(err);
        }
        eprintln!(
            "dstack-volume: seeded docker from {}",
            requested.verity_root
        );
    } else {
        let target = Path::new(&requested.target);
        if !target.is_absolute() {
            bail!("mount target must be absolute");
        }
        fs::create_dir_all(target).with_context(|| format!("creating {}", target.display()))?;
        mount_read_only(mapped, target, fs_type.trim())?;
        eprintln!(
            "dstack-volume: mounted {} at {}",
            requested.verity_root,
            target.display()
        );
    }
    Ok(())
}

fn mount_read_only(device: &Path, target: &Path, fs_type: &str) -> Result<()> {
    let options = if matches!(fs_type, "ext3" | "ext4") {
        "ro,noload"
    } else {
        "ro"
    };
    let mut command = Command::new("mount");
    if !fs_type.is_empty() {
        command.args(["-t", fs_type]);
    }
    checked(
        command.arg("-o").arg(options).arg(device).arg(target),
        "mounting verity volume",
    )?;
    Ok(())
}

fn seed_docker(volume: &Path) -> Result<()> {
    let store = Path::new(DOCKER_STORE);
    let overlay = volume.join("overlay2");
    let mut bound = Vec::new();
    for layer in child_directories(&overlay)? {
        if layer.file_name() == Some(OsStr::new("l")) {
            continue;
        }
        let source = layer.join("diff");
        if !source.is_dir() {
            continue;
        }
        let target = store
            .join("overlay2")
            .join(layer.file_name().unwrap())
            .join("diff");
        fs::create_dir_all(&target)?;
        if !is_mountpoint(&target)? {
            if let Err(err) = checked(
                Command::new("mount")
                    .args(["--bind"])
                    .arg(&source)
                    .arg(&target),
                "binding docker layer",
            ) {
                unwind_binds(&bound);
                return Err(err);
            }
            // A bind inherits neither the intended policy nor all mount flags.
            if let Err(err) = checked(
                Command::new("mount")
                    .args(["-o", "remount,bind,ro"])
                    .arg(&target),
                "making docker layer read-only",
            ) {
                bound.push(target);
                unwind_binds(&bound);
                return Err(err);
            }
            bound.push(target);
        }
    }

    let copy_result = (|| -> Result<()> {
        copy_contents(
            &volume.join("image/overlay2/imagedb"),
            &store.join("image/overlay2/imagedb"),
        )?;
        copy_contents(
            &volume.join("image/overlay2/layerdb"),
            &store.join("image/overlay2/layerdb"),
        )?;
        copy_contents(&volume.join("overlay2/l"), &store.join("overlay2/l"))?;
        merge_repositories(volume, store)?;
        copy_layer_metadata(volume, store)
    })();
    if let Err(err) = copy_result {
        unwind_binds(&bound);
        return Err(err);
    }
    Ok(())
}

fn child_directories(path: &Path) -> Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    for entry in fs::read_dir(path).with_context(|| format!("reading {}", path.display()))? {
        let path = entry?.path();
        if path.is_dir() {
            result.push(path);
        }
    }
    result.sort();
    Ok(result)
}

fn copy_contents(source: &Path, target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    checked(
        Command::new("cp")
            .args(["-a"])
            .arg(source.join("."))
            .arg(target),
        "copying docker metadata",
    )?;
    Ok(())
}

fn merge_repositories(volume: &Path, store: &Path) -> Result<()> {
    let source = volume.join("image/overlay2/repositories.json");
    let target = store.join("image/overlay2/repositories.json");
    if target.exists() {
        let temporary = target.with_extension("json.dstack-tmp");
        let output = checked(
            Command::new("jq")
                .args(["-s", ".[0] * .[1]"])
                .arg(&target)
                .arg(&source),
            "merging docker repositories",
        )?;
        fs::write(&temporary, output.stdout)?;
        fs::rename(&temporary, &target)?;
    } else {
        fs::copy(&source, &target)?;
    }
    Ok(())
}

fn copy_layer_metadata(volume: &Path, store: &Path) -> Result<()> {
    for layer in child_directories(&volume.join("overlay2"))? {
        let Some(id) = layer.file_name() else {
            continue;
        };
        if id == OsStr::new("l") {
            continue;
        }
        let target = store.join("overlay2").join(id);
        if target.join("link").exists() {
            continue;
        }
        fs::create_dir_all(&target)?;
        for entry in fs::read_dir(&layer)? {
            let source = entry?.path();
            if source.file_name() == Some(OsStr::new("diff")) {
                continue;
            }
            checked(
                Command::new("cp").args(["-a"]).arg(&source).arg(&target),
                "copying docker layer metadata",
            )?;
        }
    }
    Ok(())
}

fn is_mountpoint(path: &Path) -> Result<bool> {
    let needle = format!(" {} ", path.display());
    Ok(fs::read_to_string("/proc/self/mountinfo")?
        .lines()
        .any(|line| line.contains(&needle)))
}

fn unwind_binds(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        let _ = run(Command::new("umount").arg(path));
    }
}

fn command_stdout(command: &mut Command) -> Result<String> {
    let output = command.output()?;
    if !output.status.success() {
        bail!("command failed with {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn run(command: &mut Command) -> Result<Output> {
    command.output().context("running command")
}

fn checked(command: &mut Command, operation: &str) -> Result<Output> {
    let output = command.output().with_context(|| operation.to_string())?;
    if !output.status.success() {
        bail!(
            "{operation} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[..16].copy_from_slice(MAGIC);
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
        bytes[20..24].copy_from_slice(&KIND_VERITY.to_le_bytes());
        bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
        bytes[32..64].fill(0x5a);
        bytes[64..68].copy_from_slice(&4096u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&4096u32.to_le_bytes());
        bytes
    }

    #[test]
    fn parses_volume_envelope() {
        assert_eq!(
            parse_header(&header()).unwrap(),
            Some(VolumeHeader {
                kind: KIND_VERITY,
                kind_version: 1,
                flags: 0,
                root_hash: [0x5a; 32],
                data_block_size: 4096,
                hash_block_size: 4096,
            })
        );
    }

    #[test]
    fn ignores_non_volume_data() {
        assert_eq!(parse_header(&[0u8; HEADER_SIZE]).unwrap(), None);
    }

    #[test]
    fn rejects_unknown_envelope_version() {
        let mut bytes = header();
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        assert!(parse_header(&bytes).is_err());
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
        let volume = resolve_verity(&disk, parse_header(&header()).unwrap().unwrap()).unwrap();
        assert_eq!(volume.data, Path::new("/dev/test2"));
        assert_eq!(volume.hash, Path::new("/dev/test3"));
    }

    #[test]
    fn verity_kind_rejects_undefined_raw_layout() {
        let disk = BlockDisk {
            path: "/dev/test".into(),
            partitions: vec![],
        };
        assert!(resolve_verity(&disk, parse_header(&header()).unwrap().unwrap()).is_err());
    }
}
