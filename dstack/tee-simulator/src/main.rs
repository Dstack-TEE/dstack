// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use fuser::{Filesystem, MountOption, Session};
use tracing::info;

mod tdx;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum TeePlatform {
    #[default]
    Tdx,
}

#[derive(Parser)]
#[command(about = "Development-only simulator for Linux TEE guest ABIs")]
struct Args {
    /// TEE platform ABI to simulate.
    #[arg(long, value_enum, default_value = "tdx")]
    platform: TeePlatform,

    /// Override the platform backend's default mountpoint.
    #[arg(long)]
    mountpoint: Option<PathBuf>,
}

/// Platform-specific simulator backend.
///
/// Adding another TEE platform only requires a backend implementation and a
/// CLI enum variant; the FUSE lifecycle and safety checks remain shared.
trait TeeBackend {
    type Fs: Filesystem;

    const PLATFORM: &'static str;
    const DEFAULT_MOUNTPOINT: &'static str;

    fn create_filesystem() -> Result<Self::Fs>;
    fn prepare_mountpoint(mountpoint: &Path) -> Result<()>;
    fn real_tee_available() -> bool;
}

fn run_backend<B: TeeBackend>(mountpoint_override: Option<PathBuf>) -> Result<()> {
    let default_mountpoint = Path::new(B::DEFAULT_MOUNTPOINT);
    let mountpoint = mountpoint_override.as_deref().unwrap_or(default_mountpoint);

    if mountpoint == default_mountpoint && B::real_tee_available() {
        bail!(
            "refusing to start the {} simulator when a real TEE device is present",
            B::PLATFORM
        );
    }
    B::prepare_mountpoint(mountpoint)?;

    let fs = B::create_filesystem()?;
    let mut session = Session::new(
        fs,
        mountpoint,
        &[
            MountOption::FSName(format!("dstack-tee-simulator-{}", B::PLATFORM)),
            MountOption::DefaultPermissions,
            MountOption::NoSuid,
            MountOption::NoDev,
            MountOption::NoExec,
        ],
    )
    .with_context(|| format!("failed to mount FUSE at {}", mountpoint.display()))?;

    info!(
        platform = B::PLATFORM,
        mountpoint = %mountpoint.display(),
        "development TEE simulator ready"
    );
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])
        .context("failed to notify systemd")?;
    session.run().context("fuse session failed")?;
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    match args.platform {
        TeePlatform::Tdx => run_backend::<tdx::TdxBackend>(args.mountpoint),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_tdx() {
        let args = Args::try_parse_from(["dstack-tee-simulator"]).unwrap();
        assert_eq!(args.platform, TeePlatform::Tdx);
        assert!(args.mountpoint.is_none());
    }
}
