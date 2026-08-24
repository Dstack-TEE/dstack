// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

use fs_err as fs;
use path_absolutize::Absolutize;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dstack_types::{
    version::Version, AwsOsImageMeasurementDocument, AwsPcrReplay, GcpOsImageMeasurementDocument,
    GcpTpmReplay, SevOsImageMeasurementDocument, TdxOsImageMeasurementDocument,
    GCP_MEASUREMENT_FILENAME, SNP_MEASUREMENT_FILENAME, TDX_MEASUREMENT_FILENAME,
};
use serde::{Deserialize, Serialize};

const AWS_MEASUREMENT_FILENAME: &str = "measurement.aws.cbor";
const AWS_PCR_REPLAY_FILENAME: &str = "measurement.aws.replay.json";
const GCP_TPM_EVENT_LOG_FILENAME: &str = "measurement.gcp.eventlog.bin";

#[derive(Debug, Serialize, Deserialize)]
pub struct ImageInfo {
    pub cmdline: Option<String>,
    pub kernel: String,
    pub initrd: String,
    pub hda: Option<String>,
    pub rootfs: Option<String>,
    pub bios: Option<String>,
    /// AMD SEV firmware (e.g. ovmf-sev.fd). Present on unified TDX+SEV images;
    /// used instead of `bios` when launching as an AMD SEV-SNP guest.
    #[serde(default, rename = "bios-sev")]
    pub bios_sev: Option<String>,
    #[serde(default)]
    pub rootfs_hash: Option<String>,
    #[serde(default)]
    pub shared_ro: bool,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub is_dev: bool,
    /// OVMF measurement layout declared by the image. Older metadata.json files
    /// do not have this — verifiers fall back to version-based heuristics when
    /// it's missing.
    #[serde(default)]
    pub ovmf_variant: Option<dstack_types::OvmfVariant>,
}

impl ImageInfo {
    /// Parse `version` with the shared dstack version grammar.
    ///
    /// Prerelease and build-metadata suffixes are stripped, so `0.6.1-rc1`,
    /// `0.6.1.rc1` and `0.6.1` all compare equal. That is deliberate: image
    /// version comparisons here gate guest features, and a release candidate
    /// is built from the code of the version it is a candidate for.
    ///
    /// Returns `None` when `version` is absent or unparseable; callers must
    /// decide explicitly whether that is fatal.
    pub fn version(&self) -> Option<Version> {
        Version::parse(&self.version)
    }
}

impl ImageInfo {
    pub fn load(filename: impl AsRef<Path>) -> Result<Self> {
        let file = fs::File::open(filename.as_ref()).context("failed to open image info")?;
        let info: ImageInfo =
            serde_json::from_reader(file).context("failed to parse image info")?;
        Ok(info)
    }
}

#[derive(Debug)]
pub struct Image {
    pub info: ImageInfo,
    pub initrd: PathBuf,
    pub kernel: PathBuf,
    pub hda: Option<PathBuf>,
    pub rootfs: Option<PathBuf>,
    pub bios: Option<PathBuf>,
    pub bios_sev: Option<PathBuf>,
    pub digest: Option<String>,
    /// TDX no-image-download measurement material.
    pub tdx_measurement: Option<TdxOsImageMeasurementDocument>,
    /// AMD SEV-SNP no-image-download measurement material.
    pub sev_measurement: Option<SevOsImageMeasurementDocument>,
    /// GCP TDX no-image-download measurement material.
    pub gcp_measurement: Option<GcpOsImageMeasurementDocument>,
    /// AWS NitroTPM no-image-download measurement material.
    pub aws_measurement: Option<AwsOsImageMeasurementDocument>,
    /// AWS boot events consumed only by the development NitroTPM simulator.
    pub aws_pcr_replay: Option<AwsPcrReplay>,
    /// GCP TPM event log consumed only by the development simulator.
    pub gcp_tpm_replay: Option<GcpTpmReplay>,
}

impl Image {
    /// Firmware blob to launch with, given whether this is an AMD SEV-SNP guest.
    /// SEV-SNP prefers the dedicated SEV firmware (`bios_sev`) and falls back to
    /// the generic `bios`; TDX always uses `bios`.
    pub fn firmware(&self, is_amd_sev_snp: bool) -> Option<&PathBuf> {
        if is_amd_sev_snp {
            self.bios_sev.as_ref().or(self.bios.as_ref())
        } else {
            self.bios.as_ref()
        }
    }
}

impl Image {
    pub fn load(base_path: impl AsRef<Path>) -> Result<Self> {
        let base_path = base_path
            .as_ref()
            .absolutize()?
            .canonicalize()
            .context("failed to resolve image directory")?;
        let mut info = ImageInfo::load(base_path.join("metadata.json"))?;
        let initrd = resolve_artifact(&base_path, &info.initrd, "Initrd")?;
        let kernel = resolve_artifact(&base_path, &info.kernel, "Kernel")?;
        let hda = resolve_optional_artifact(&base_path, info.hda.as_deref(), "Hda")?;
        let rootfs = resolve_optional_artifact(&base_path, info.rootfs.as_deref(), "Rootfs")?;
        let bios = resolve_optional_artifact(&base_path, info.bios.as_deref(), "Bios")?;
        let bios_sev = resolve_optional_artifact(&base_path, info.bios_sev.as_deref(), "SEV bios")?;
        let digest = fs::read_to_string(base_path.join("digest.txt"))
            .ok()
            .map(|s| s.trim().to_string());
        let sha256sum_path = base_path.join("sha256sum.txt");
        let sha256sum = if sha256sum_path.exists() {
            Some(
                fs::read(&sha256sum_path)
                    .with_context(|| format!("failed to read {}", sha256sum_path.display()))?,
            )
        } else {
            None
        };
        let tdx_path = base_path.join(TDX_MEASUREMENT_FILENAME);
        let tdx_cbor = if tdx_path.exists() {
            Some(
                fs::read(&tdx_path)
                    .with_context(|| format!("failed to read {}", tdx_path.display()))?,
            )
        } else {
            None
        };
        let tdx_measurement = match (&sha256sum, tdx_cbor) {
            (Some(sha256sum), Some(measurement)) => Some(TdxOsImageMeasurementDocument::new(
                sha256sum.clone(),
                measurement,
            )),
            _ => None,
        };
        let snp_path = base_path.join(SNP_MEASUREMENT_FILENAME);
        let snp_cbor = if snp_path.exists() {
            Some(
                fs::read(&snp_path)
                    .with_context(|| format!("failed to read {}", snp_path.display()))?,
            )
        } else {
            None
        };
        let sev_measurement = match (&sha256sum, snp_cbor) {
            (Some(sha256sum), Some(measurement)) => Some(SevOsImageMeasurementDocument::new(
                sha256sum.clone(),
                measurement,
            )),
            _ => None,
        };
        let gcp_measurement = load_measurement_document(
            &base_path,
            &sha256sum,
            GCP_MEASUREMENT_FILENAME,
            GcpOsImageMeasurementDocument::new,
        )?;
        let aws_measurement = load_measurement_document(
            &base_path,
            &sha256sum,
            AWS_MEASUREMENT_FILENAME,
            AwsOsImageMeasurementDocument::new,
        )?;
        let aws_pcr_replay_path = base_path.join(AWS_PCR_REPLAY_FILENAME);
        let aws_pcr_replay = if aws_pcr_replay_path.exists() {
            Some(
                serde_json::from_slice(&fs::read(&aws_pcr_replay_path).with_context(|| {
                    format!("failed to read {}", aws_pcr_replay_path.display())
                })?)
                .with_context(|| format!("failed to parse {}", aws_pcr_replay_path.display()))?,
            )
        } else {
            None
        };
        let gcp_event_log_path = base_path.join(GCP_TPM_EVENT_LOG_FILENAME);
        let gcp_tpm_replay = if gcp_event_log_path.exists() {
            Some(GcpTpmReplay {
                event_log: fs::read(&gcp_event_log_path)
                    .with_context(|| format!("failed to read {}", gcp_event_log_path.display()))?,
            })
        } else {
            None
        };
        if info.version.is_empty() {
            // Older images does not have version field. Fallback to the version of the image folder name
            info.version = guess_version(&base_path).unwrap_or_default();
        }
        Self {
            info,
            hda,
            initrd,
            kernel,
            rootfs,
            bios,
            bios_sev,
            digest,
            tdx_measurement,
            sev_measurement,
            gcp_measurement,
            aws_measurement,
            aws_pcr_replay,
            gcp_tpm_replay,
        }
        .ensure_exists()
    }

    fn ensure_exists(self) -> Result<Self> {
        if !self.initrd.exists() {
            bail!("Initrd does not exist: {}", self.initrd.display());
        }
        if !self.kernel.exists() {
            bail!("Kernel does not exist: {}", self.kernel.display());
        }
        if let Some(hda) = &self.hda {
            if !hda.exists() {
                bail!("Hda does not exist: {}", hda.display());
            }
        }
        if let Some(rootfs) = &self.rootfs {
            if !rootfs.exists() {
                bail!("Rootfs does not exist: {}", rootfs.display());
            }
        }
        if let Some(bios) = &self.bios {
            if !bios.exists() {
                bail!("Bios does not exist: {}", bios.display());
            }
        }
        if let Some(bios_sev) = &self.bios_sev {
            if !bios_sev.exists() {
                bail!("SEV bios does not exist: {}", bios_sev.display());
            }
        }
        Ok(self)
    }
}

fn resolve_artifact(base_path: &Path, value: &str, label: &str) -> Result<PathBuf> {
    let candidate = base_path.join(value);
    let resolved = candidate
        .canonicalize()
        .with_context(|| format!("{label} does not exist: {}", candidate.display()))?;
    if !resolved.starts_with(base_path) {
        bail!("{label} escapes image directory: {}", candidate.display());
    }
    if !resolved.is_file() {
        bail!("{label} is not a file: {}", candidate.display());
    }
    Ok(resolved)
}

fn resolve_optional_artifact(
    base_path: &Path,
    value: Option<&str>,
    label: &str,
) -> Result<Option<PathBuf>> {
    value
        .map(|value| resolve_artifact(base_path, value, label))
        .transpose()
}

fn load_measurement_document<T>(
    base_path: &Path,
    checksum_file: &Option<Vec<u8>>,
    filename: &str,
    constructor: impl FnOnce(Vec<u8>, Vec<u8>) -> T,
) -> Result<Option<T>> {
    let path = base_path.join(filename);
    if !path.exists() {
        return Ok(None);
    }
    let Some(checksum_file) = checksum_file else {
        return Ok(None);
    };
    let measurement =
        fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(Some(constructor(checksum_file.clone(), measurement)))
}

fn guess_version(base_path: &Path) -> Option<String> {
    // name pattern: dstack-dev-0.2.3 or dstack-0.2.3
    let basename = base_path.file_name()?.to_str()?.to_string();
    let version = if basename.starts_with("dstack-dev-") {
        basename.strip_prefix("dstack-dev-")?
    } else if basename.starts_with("dstack-") {
        basename.strip_prefix("dstack-")?
    } else {
        return None;
    };
    Some(version.to_string())
}

#[cfg(test)]
mod tests {
    use super::{Image, ImageInfo, Version};
    use std::{fs, sync::Arc, thread};
    use tempfile::TempDir;

    fn fixture(name: &str, kernel: &str) -> (TempDir, std::path::PathBuf) {
        let root = TempDir::new().unwrap();
        let image = root.path().join(name);
        fs::create_dir(&image).unwrap();
        let metadata = format!(
            r#"{{"cmdline":null,"kernel":"{kernel}","initrd":"initrd","hda":null,"rootfs":null,"bios":null}}"#
        );
        fs::write(image.join("metadata.json"), metadata).unwrap();
        fs::write(image.join("initrd"), b"initrd").unwrap();
        (root, image)
    }

    #[test]
    fn loads_minimal_metadata_and_guesses_legacy_version() {
        let (_root, image) = fixture("dstack-dev-1.2.3", "vmlinuz");
        fs::write(image.join("vmlinuz"), b"kernel").unwrap();
        let loaded = Image::load(&image).unwrap();
        assert_eq!(loaded.info.version, "1.2.3");
        assert_eq!(loaded.info.version(), Some(Version::new(1, 2, 3)));
        assert!(!loaded.info.shared_ro);
    }

    #[test]
    fn parses_version_boundaries_and_rejects_missing_artifact() {
        for (version, expected) in [
            ("0.0.0", Some(Version::new(0, 0, 0))),
            ("65535.1.2", Some(Version::new(65535, 1, 2))),
            // A missing patch component defaults to 0.
            ("1.2", Some(Version::new(1, 2, 0))),
            // A non-numeric patch is not silently coerced to 0.
            ("1.2.invalid", None),
            // u16 no longer bounds the components.
            ("65536.1.2", Some(Version::new(65536, 1, 2))),
            // Prerelease and build metadata compare equal to the release.
            ("0.6.1-rc1", Some(Version::new(0, 6, 1))),
            ("0.6.1.rc1", Some(Version::new(0, 6, 1))),
            ("0.6.1+build.5", Some(Version::new(0, 6, 1))),
            ("0.6.1-rc.1+build.5", Some(Version::new(0, 6, 1))),
            // Still garbage in, None out.
            ("", None),
            ("nvidia-0.6.0", None),
            ("v0.6.1", None),
        ] {
            let json = format!(
                r#"{{"cmdline":null,"kernel":"k","initrd":"i","hda":null,"rootfs":null,"bios":null,"version":"{version}"}}"#
            );
            let info: ImageInfo = serde_json::from_str(&json).unwrap();
            assert_eq!(info.version(), expected, "{version}");
        }
        let (_root, image) = fixture("missing", "missing");
        assert!(Image::load(image).is_err());
    }

    #[test]
    fn rejects_parent_traversal_artifact() {
        let (root, image) = fixture("escaped", "../outside");
        fs::write(root.path().join("outside"), b"outside").unwrap();
        assert!(Image::load(image).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape_and_concurrent_reads_converge() {
        use std::os::unix::fs::symlink;
        let (root, image) = fixture("candidate", "kernel-link");
        fs::write(root.path().join("outside"), b"outside").unwrap();
        symlink(root.path().join("outside"), image.join("kernel-link")).unwrap();
        assert!(Image::load(&image).is_err());
        fs::remove_file(image.join("kernel-link")).unwrap();
        fs::write(image.join("kernel-link"), b"kernel").unwrap();
        let image = Arc::new(image);
        let workers: Vec<_> = (0..4)
            .map(|_| {
                let image = Arc::clone(&image);
                thread::spawn(move || Image::load(image.as_path()).unwrap().info.version)
            })
            .collect();
        for worker in workers {
            assert_eq!(worker.join().unwrap(), "");
        }
    }
}
