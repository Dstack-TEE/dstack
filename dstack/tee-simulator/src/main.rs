// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use dstack_types::{SysConfig, TeeSimulatorConfig, TeeSimulatorPlatform};
use fuser::{Filesystem, MountOption, Session};
use mock_attestation::server::MockCollateralState;
use std::sync::Arc;
use tracing::info;

mod tdx;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum TeePlatform {
    #[default]
    Tdx,
    SevSnp,
    Tpm,
    Nsm,
}

impl TeePlatform {
    fn as_str(self) -> &'static str {
        match self {
            Self::Tdx => "tdx",
            Self::SevSnp => "sev-snp",
            Self::Tpm => "tpm",
            Self::Nsm => "nsm",
        }
    }
}

impl From<TeeSimulatorPlatform> for TeePlatform {
    fn from(value: TeeSimulatorPlatform) -> Self {
        match value {
            TeeSimulatorPlatform::Tdx => Self::Tdx,
            TeeSimulatorPlatform::SevSnp => Self::SevSnp,
            TeeSimulatorPlatform::Tpm => Self::Tpm,
            TeeSimulatorPlatform::Nsm => Self::Nsm,
        }
    }
}

#[derive(Parser)]
#[command(about = "Development-only simulator for Linux TEE guest ABIs")]
struct Args {
    /// TEE platform ABI to simulate.
    #[arg(long, value_enum)]
    platform: Option<TeePlatform>,

    /// sys-config used to select the simulated platform when --platform is omitted.
    #[arg(long, default_value = "/dstack/.host-shared/.sys-config.json")]
    sys_config: PathBuf,

    /// Override the platform backend's default mountpoint.
    #[arg(long)]
    mountpoint: Option<PathBuf>,

    /// Runtime state directory (overridable by unprivileged E2E tests).
    #[arg(long, default_value = "/run/dstack")]
    runtime_dir: PathBuf,
}

/// Platform-specific simulator backend.
///
/// Adding another TEE platform only requires a backend implementation and a
/// CLI enum variant; the FUSE lifecycle and safety checks remain shared.
trait TeeBackend {
    type Fs: Filesystem;

    const PLATFORM: &'static str;
    const DEFAULT_MOUNTPOINT: &'static str;

    fn create_filesystem(config: &TeeSimulatorConfig) -> Result<Self::Fs>;
    fn prepare_mountpoint(mountpoint: &Path) -> Result<()>;
    fn real_tee_available() -> bool;
}

fn run_backend<B: TeeBackend>(
    mountpoint_override: Option<PathBuf>,
    config: &TeeSimulatorConfig,
) -> Result<()> {
    let default_mountpoint = Path::new(B::DEFAULT_MOUNTPOINT);
    let mountpoint = mountpoint_override.as_deref().unwrap_or(default_mountpoint);

    if mountpoint == default_mountpoint && B::real_tee_available() {
        bail!(
            "refusing to start the {} simulator when a real TEE device is present",
            B::PLATFORM
        );
    }
    B::prepare_mountpoint(mountpoint)?;

    let fs = B::create_filesystem(config)?;
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

    let config = load_config(&args.sys_config)?;
    let platform = args.platform.unwrap_or(config.platform.into());
    fs_err::create_dir_all(&args.runtime_dir)?;
    fs_err::write(
        args.runtime_dir.join("tee-simulator.env"),
        format!(
            "DSTACK_SIMULATED_TEE_PLATFORM={} DSTACK_MOCK_ATTESTATION_URL=http://127.0.0.1:8088\n",
            platform.as_str()
        ),
    )?;
    match platform {
        TeePlatform::Tdx => run_backend::<tdx::TdxBackend>(args.mountpoint, &config),
        platform => run_mock_service(platform, &config),
    }
}

fn run_mock_service(platform: TeePlatform, config: &TeeSimulatorConfig) -> Result<()> {
    let seed = config
        .mock_attestation_seed
        .as_deref()
        .context("tee_simulator.mock_attestation_seed is required")?;
    let base_url = config
        .collateral_base_url
        .as_deref()
        .unwrap_or("http://127.0.0.1:8088");
    let state = Arc::new(MockCollateralState::from_seed(
        mock_attestation::parse_seed(seed)?,
        base_url,
    )?);
    info!(
        platform = platform.as_str(),
        "development mock attestation service ready"
    );
    sd_notify::notify(true, &[sd_notify::NotifyState::Ready])?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(mock_attestation::server::serve(
        "127.0.0.1:8088".parse()?,
        state,
    ))
}

fn load_config(path: &Path) -> Result<TeeSimulatorConfig> {
    if !path.exists() {
        return Ok(TeeSimulatorConfig::default());
    }
    let config: SysConfig = serde_json::from_slice(
        &fs_err::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(config.tee_simulator.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_tdx() {
        let args = Args::try_parse_from(["dstack-tee-simulator"]).unwrap();
        assert_eq!(args.platform, None);
        assert!(args.mountpoint.is_none());
    }

    #[test]
    fn missing_sys_config_defaults_to_tdx() {
        assert_eq!(
            load_config(Path::new("/definitely/missing/sys-config"))
                .unwrap()
                .platform,
            TeeSimulatorPlatform::Tdx
        );
    }

    #[test]
    fn sys_config_selects_each_platform() {
        for (name, expected) in [
            ("tdx", TeePlatform::Tdx),
            ("sev-snp", TeePlatform::SevSnp),
            ("tpm", TeePlatform::Tpm),
            ("nsm", TeePlatform::Nsm),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sys-config.json");
            fs_err::write(
                &path,
                serde_json::json!({
                    "kms_urls": [], "gateway_urls": [], "pccs_url": null,
                    "docker_registry": null, "host_api_url": null, "vm_config": "{}",
                    "tee_simulator": {"platform": name}
                })
                .to_string(),
            )
            .unwrap();
            assert_eq!(
                TeePlatform::from(load_config(&path).unwrap().platform),
                expected
            );
        }
    }
}
