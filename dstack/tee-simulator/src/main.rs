// SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Parser;
use dstack_attest::{attestation::RootCaPaths, trust_anchors};
use dstack_types::{TeeSimulatorConfig, TeeVariant};
use fuser::{Filesystem, MountOption, Session};
use tracing::info;

mod nsm;
mod sev_snp;
mod tdx;
mod tpm;

/// Runtime-directory-relative location of [`trust_anchors::ANCHOR_DIR`].
const TRUST_ANCHOR_SUBDIR: &str = "attestation";

/// Matches `MockCollateralState::new`, used when the host names no service.
const DEFAULT_COLLATERAL_BASE_URL: &str = "http://127.0.0.1:8088";

#[derive(Parser)]
#[command(about = "Development-only simulator for Linux TEE guest ABIs")]
struct Args {
    /// TEE platform ABI to simulate.
    #[arg(long)]
    platform: Option<TeeVariant>,

    /// Development-only simulator config. The systemd unit overrides this
    /// standalone default with its early-mounted runtime path.
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
    if is_mounted(mountpoint)? {
        bail!(
            "refusing to mount the {} simulator over an existing mount at {}",
            B::PLATFORM,
            mountpoint.display()
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

fn is_mounted(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let target = path
        .canonicalize()
        .with_context(|| format!("failed to resolve mountpoint {}", path.display()))?;
    let mountinfo = fs_err::read_to_string("/proc/self/mountinfo")
        .context("failed to read process mount table")?;
    Ok(mountinfo.lines().any(|line| {
        line.split_whitespace()
            .nth(4)
            .map(decode_mountinfo_path)
            .is_some_and(|mounted| Path::new(&mounted) == target)
    }))
}

fn decode_mountinfo_path(value: &str) -> String {
    value
        .replace(r"\134", "\\")
        .replace(r"\040", " ")
        .replace(r"\011", "\t")
        .replace(r"\012", "\n")
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let args = Args::parse();

    let config = load_config(&args.config)?;
    let platform = args.platform.unwrap_or(config.platform);
    fs_err::create_dir_all(&args.runtime_dir)?;
    publish_trust_anchors(&args.runtime_dir, &config)?;
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

/// Publish the external trust anchors the guest verifier reads.
///
/// The roots come from the same seed that signs the simulated evidence, so
/// nothing has to travel from the host: it supplies the seed for a fake TEE
/// device and never names a trust anchor. This binary ships only in the
/// development image, and the systemd unit orders it before `dstack-prepare`,
/// so `dstack-util` sees the roots when they exist and vendor production roots
/// everywhere else.
///
/// Every platform's root is published regardless of the simulated platform: a
/// development guest also verifies a KMS and a gateway, and those need not run
/// on the platform this guest simulates.
fn publish_trust_anchors(runtime_dir: &Path, config: &TeeSimulatorConfig) -> Result<()> {
    let seed = config
        .mock_attestation_seed
        .as_deref()
        .context("tee_simulator.mock_attestation_seed is required")?;
    let seed = mock_attestation::parse_seed(seed)?;
    let base_url = config
        .collateral_base_url
        .as_deref()
        .unwrap_or(DEFAULT_COLLATERAL_BASE_URL);
    let pki = mock_attestation::server::MockCollateralState::from_seed(seed, base_url)?;

    let dir = trust_anchor_dir(runtime_dir);
    fs_err::create_dir_all(&dir).context("failed to create the trust anchor directory")?;
    // The reader refuses anything group- or world-writable, so the directory
    // has to be tightened even when it already existed with a laxer mode.
    fs_err::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .context("failed to restrict the trust anchor directory")?;
    let tdx = write_root(&dir, "tdx-root-ca.pem", &pki.tdx.root_ca_pem())?;
    let tpm = write_root(&dir, "tpm-root-ca.pem", &pki.tpm.root_ca_pem())?;
    let nsm = write_root(&dir, "nsm-root-ca.pem", &pki.nsm.root_ca_pem())?;
    let sev_snp = write_root(&dir, "sev-snp-root-ca.pem", &pki.sev_snp.root_ca_pem())?;

    let root_ca = RootCaPaths {
        tdx: Some(tdx),
        gcp_tpm: Some(tpm.clone()),
        aws_nitro_tpm: Some(tpm),
        aws_nitro_enclave: Some(nsm),
        sev_snp_milan: Some(sev_snp.clone()),
        sev_snp_genoa: Some(sev_snp.clone()),
        sev_snp_turin: Some(sev_snp),
    };
    safe_write::safe_write_with_mode(
        trust_anchors::roots_path(&dir),
        serde_json::to_vec_pretty(&root_ca).context("failed to serialize published roots")?,
        0o600,
    )
    .context("failed to write the published roots")?;
    info!(dir = %dir.display(), "published external attestation trust anchors");
    Ok(())
}

fn write_root(dir: &Path, name: &str, pem: &str) -> Result<PathBuf> {
    let path = dir.join(name);
    safe_write::safe_write_with_mode(&path, pem.as_bytes(), 0o600)
        .with_context(|| format!("failed to write {name}"))?;
    Ok(path)
}

fn trust_anchor_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join(TRUST_ANCHOR_SUBDIR)
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
    fn default_runtime_dir_matches_the_verifier_handoff_path() {
        let args = Args::try_parse_from(["dstack-tee-simulator"]).unwrap();
        assert_eq!(
            trust_anchor_dir(&args.runtime_dir),
            Path::new(trust_anchors::ANCHOR_DIR)
        );
    }

    #[test]
    fn published_tdx_root_matches_the_seeded_pki() {
        let dir = tempfile::tempdir().unwrap();
        let seed = [0x21; 32];
        publish_trust_anchors(
            dir.path(),
            &TeeSimulatorConfig {
                mock_attestation_seed: Some(hex::encode(seed)),
                ..Default::default()
            },
        )
        .unwrap();

        let roots = trust_anchors::load_anchors(&trust_anchor_dir(dir.path()))
            .unwrap()
            .expect("simulator should publish trust anchors");
        let published = fs_err::read(roots.tdx.as_ref().unwrap()).unwrap();
        let expected = mock_attestation::tdx::TdxGenerator::from_seed(seed)
            .unwrap()
            .root_ca_pem();
        assert_eq!(String::from_utf8(published).unwrap(), expected);
    }

    #[test]
    fn a_seedless_config_publishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(publish_trust_anchors(dir.path(), &TeeSimulatorConfig::default()).is_err());
        assert!(trust_anchors::load_anchors(&trust_anchor_dir(dir.path()))
            .unwrap()
            .is_none());
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
                    "platform": name
                })
                .to_string(),
            )
            .unwrap();
            assert_eq!(load_config(&path).unwrap().platform, expected);
        }
    }
}
