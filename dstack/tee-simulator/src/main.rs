// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::CString,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use dstack_types::{TeeSimulatorConfig, TeeVariant};
use fuser::{Filesystem, MountOption, Session};
use tracing::info;

mod nsm;
mod sev_snp;
mod tdx;
mod tpm;

#[derive(Parser)]
#[command(about = "Development-only simulator for Linux TEE guest ABIs")]
struct Args {
    /// TEE platform ABI to simulate.
    #[arg(long)]
    platform: Option<TeeVariant>,

    /// Development-only simulator config.
    #[arg(long, default_value = "/dstack/.host-shared/.tee-simulator.json")]
    config: PathBuf,

    /// Override the platform backend's default mountpoint.
    #[arg(long)]
    mountpoint: Option<PathBuf>,

    /// Runtime state directory (overridable by unprivileged E2E tests).
    #[arg(long, default_value = "/run/dstack")]
    runtime_dir: PathBuf,

    /// DMI sysfs directory. Tests may override this with a temporary directory.
    #[arg(long, default_value = "/sys/class/dmi/id")]
    dmi_root: PathBuf,
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

    let config = load_config(&args.config)?;
    let platform = args.platform.unwrap_or(config.platform);
    fs_err::create_dir_all(&args.runtime_dir)?;
    match platform {
        TeeVariant::DstackTdx => {
            simulate_dmi(&args.runtime_dir, &args.dmi_root, "Dstack", "dstack")?;
            run_backend::<tdx::TdxBackend>(args.mountpoint, &config)
        }
        TeeVariant::DstackGcpTdx => {
            simulate_dmi(
                &args.runtime_dir,
                &args.dmi_root,
                "Google",
                "Google Compute Engine",
            )?;
            tpm::start_gcp_vtpm(&args.runtime_dir, &config)?;
            run_backend::<tdx::TdxBackend>(args.mountpoint, &config)
        }
        TeeVariant::DstackNitroEnclave => {
            simulate_dmi(
                &args.runtime_dir,
                &args.dmi_root,
                "AWS Nitro Enclaves",
                "Nitro Enclave",
            )?;
            nsm::run(&config)
        }
        TeeVariant::DstackAwsNitroTpm => {
            simulate_dmi(&args.runtime_dir, &args.dmi_root, "Amazon EC2", "t3.metal")?;
            tpm::run_nitro_vtpm(&args.runtime_dir, &config)
        }
        TeeVariant::DstackAmdSevSnp => {
            simulate_dmi(&args.runtime_dir, &args.dmi_root, "Dstack", "dstack")?;
            run_backend::<sev_snp::SevSnpBackend>(args.mountpoint, &config)
        }
    }
}

/// Override the DMI strings exported by SeaBIOS through sysfs. Platform
/// detection intentionally remains unchanged and observes the same values as
/// it does on a real cloud VM.
fn simulate_dmi(
    runtime_dir: &Path,
    dmi_root: &Path,
    sys_vendor: &str,
    product_name: &str,
) -> Result<()> {
    if dmi_root != Path::new("/sys/class/dmi/id") {
        fs_err::create_dir_all(dmi_root)?;
        fs_err::write(dmi_root.join("sys_vendor"), format!("{sys_vendor}\n"))?;
        fs_err::write(dmi_root.join("product_name"), format!("{product_name}\n"))?;
        return Ok(());
    }
    let dmi_dir = runtime_dir.join("dmi");
    fs_err::create_dir_all(&dmi_dir)?;
    for (name, value) in [("sys_vendor", sys_vendor), ("product_name", product_name)] {
        let source = dmi_dir.join(name);
        let target = dmi_root.join(name);
        fs_err::write(&source, format!("{value}\n"))?;
        let source = CString::new(source.as_os_str().as_bytes())?;
        let target_c = CString::new(target.as_os_str().as_bytes())?;
        let result = unsafe {
            libc::mount(
                source.as_ptr(),
                target_c.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to simulate SeaBIOS DMI file {}", target.display())
            });
        }
    }
    Ok(())
}

fn load_config(path: &Path) -> Result<TeeSimulatorConfig> {
    serde_json::from_slice(
        &fs_err::read(path).with_context(|| format!("failed to read {}", path.display()))?,
    )
    .with_context(|| format!("failed to parse {}", path.display()))
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
    fn missing_config_is_rejected() {
        assert!(load_config(Path::new("/definitely/missing/config")).is_err());
    }

    #[test]
    fn config_selects_each_platform() {
        for (name, expected) in [
            ("dstack-tdx", TeeVariant::DstackTdx),
            ("dstack-gcp-tdx", TeeVariant::DstackGcpTdx),
            ("dstack-amd-sev-snp", TeeVariant::DstackAmdSevSnp),
            ("dstack-nitro-enclave", TeeVariant::DstackNitroEnclave),
            ("dstack-aws-nitro-tpm", TeeVariant::DstackAwsNitroTpm),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("sys-config.json");
            fs_err::write(
                &path,
                serde_json::json!({
                    "kms_urls": [], "gateway_urls": [], "pccs_url": null,
                    "docker_registry": null, "host_api_url": null, "vm_config": "{}",
                "platform": name
                })
                .to_string(),
            )
            .unwrap();
            assert_eq!(load_config(&path).unwrap().platform, expected);
        }
    }
}
