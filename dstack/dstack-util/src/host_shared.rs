// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
// SPDX-License-Identifier: Apache-2.0

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use dstack_types::shared_filenames::HOST_SHARED_DISK_LABEL;
use fs_err as fs;
use tracing::{info, warn};

#[derive(Parser)]
pub struct HostSharedArgs {
    #[command(subcommand)]
    pub command: HostSharedCommand,
}

#[derive(Subcommand)]
pub enum HostSharedCommand {
    /// Mount the host-provided shared directory read-only.
    Mount(MountHostSharedArgs),
    /// Unmount a host-provided shared directory.
    Unmount(UnmountHostSharedArgs),
}

#[derive(Parser)]
pub struct MountHostSharedArgs {
    /// Directory where the host share is mounted.
    #[arg(long)]
    pub mount_point: PathBuf,
}

#[derive(Parser)]
pub struct UnmountHostSharedArgs {
    /// Mounted host-share directory.
    #[arg(long)]
    pub mount_point: PathBuf,
}

fn find_disk_by_label(label: &str) -> Option<PathBuf> {
    let label_path = PathBuf::from(format!("/dev/disk/by-label/{label}"));
    if label_path.exists() {
        return Some(label_path);
    }

    let entries = fs::read_dir("/sys/block").ok()?;
    for entry in entries.flatten() {
        let dev_path = PathBuf::from("/dev").join(entry.file_name());
        let output = Command::new("blkid")
            .args(["-s", "LABEL", "-o", "value"])
            .arg(&dev_path)
            .output();
        if let Ok(output) = output {
            if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == label {
                return Some(dev_path);
            }
        }
    }
    None
}

/// Mount options for the host share, on both the disk and the 9p path.
///
/// The share is a filesystem the host composes, and in dstack's threat model
/// the host is the adversary. Nothing on it is ever executed and nothing on it
/// is a device node: the guest copies five regular files off it as root and
/// unmounts it. So denying set-user-ID bits, device nodes and execution costs
/// nothing and removes the corresponding paths entirely.
const HOST_SHARED_MOUNT_OPTIONS: &str = "ro,nosuid,nodev,noexec";

fn disk_mount_args(device: &Path, mount_point: &Path) -> Vec<OsString> {
    vec![
        "-o".into(),
        HOST_SHARED_MOUNT_OPTIONS.into(),
        device.into(),
        mount_point.into(),
    ]
}

fn p9_mount_args(mount_point: &Path) -> Vec<OsString> {
    vec![
        "-t".into(),
        "9p".into(),
        "-o".into(),
        format!("trans=virtio,version=9p2000.L,{HOST_SHARED_MOUNT_OPTIONS}").into(),
        "host-shared".into(),
        mount_point.into(),
    ]
}

pub fn mount_host_shared(mount_point: &Path) -> Result<()> {
    fs::create_dir_all(mount_point)
        .with_context(|| format!("failed to create {}", mount_point.display()))?;

    if let Some(device) = find_disk_by_label(HOST_SHARED_DISK_LABEL) {
        info!(device = %device.display(), "found host-shared disk");
        let status = Command::new("mount")
            .args(disk_mount_args(&device, mount_point))
            .status()
            .with_context(|| format!("failed to run mount for {}", device.display()))?;
        if status.success() {
            info!(mount_point = %mount_point.display(), "mounted host-shared disk");
            return Ok(());
        }
        warn!(
            device = %device.display(),
            status = %status,
            "failed to mount host-shared disk, falling back to 9p"
        );
    } else {
        info!("host-shared disk not found, trying 9p");
    }

    let status = Command::new("mount")
        .args(p9_mount_args(mount_point))
        .status()
        .context("failed to run 9p mount")?;
    anyhow::ensure!(
        status.success(),
        "failed to mount host-shared at {}",
        mount_point.display()
    );
    info!(mount_point = %mount_point.display(), "mounted host-shared via 9p");
    Ok(())
}

pub fn unmount_host_shared(mount_point: &Path) -> Result<()> {
    let status = Command::new("umount")
        .arg(mount_point)
        .status()
        .context("failed to run umount")?;
    anyhow::ensure!(
        status.success(),
        "failed to unmount host-shared at {}",
        mount_point.display()
    );
    Ok(())
}

pub fn cmd_host_shared(args: HostSharedArgs) -> Result<()> {
    match args.command {
        HostSharedCommand::Mount(args) => mount_host_shared(&args.mount_point),
        HostSharedCommand::Unmount(args) => unmount_host_shared(&args.mount_point),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The host composes this filesystem. Neither path may let it ship a
    /// set-user-ID binary, a device node or anything executable into the guest.
    #[test]
    fn both_mount_paths_refuse_suid_devices_and_execution() {
        let disk = disk_mount_args(Path::new("/dev/vdb"), Path::new("/dstack/.host-shared"));
        assert_eq!(
            disk,
            [
                "-o",
                "ro,nosuid,nodev,noexec",
                "/dev/vdb",
                "/dstack/.host-shared"
            ]
        );

        let p9 = p9_mount_args(Path::new("/dstack/.host-shared"));
        assert_eq!(
            p9,
            [
                "-t",
                "9p",
                "-o",
                "trans=virtio,version=9p2000.L,ro,nosuid,nodev,noexec",
                "host-shared",
                "/dstack/.host-shared",
            ]
        );
    }

    #[test]
    fn parses_mount_command() {
        let args = HostSharedArgs::try_parse_from([
            "host-shared",
            "mount",
            "--mount-point",
            "/run/dstack/host-shared",
        ])
        .unwrap();
        let HostSharedCommand::Mount(args) = args.command else {
            panic!("expected mount command");
        };
        assert_eq!(args.mount_point, Path::new("/run/dstack/host-shared"));
    }

    #[test]
    fn parses_unmount_command() {
        let args = HostSharedArgs::try_parse_from([
            "host-shared",
            "unmount",
            "--mount-point",
            "/run/dstack/host-shared",
        ])
        .unwrap();
        let HostSharedCommand::Unmount(args) = args.command else {
            panic!("expected unmount command");
        };
        assert_eq!(args.mount_point, Path::new("/run/dstack/host-shared"));
    }
}
